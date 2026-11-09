// Package vault stores secrets (passwords, key passphrases, tokens) encrypted
// with AES-256-GCM, each bound to its name. The key is derived with scrypt
// from $KOMANDO_VAULT_PASS when set (N=2^17, r=8, p=1: the OWASP minimum),
// otherwise from a random 32-byte key. A new vault keeps that key in the
// operating system's keychain (keychain.go), or, where there is none, in a
// key file beside the vault (vault.key, mode 0600).
package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/sgnd/komando/internal/cloud"
	"github.com/sgnd/komando/internal/store"
)

type file struct {
	Version int               `json:"version"`
	Salt    []byte            `json:"salt"`
	Mode    string            `json:"mode"`               // keyfile | passphrase | keychain
	ScryptN int               `json:"scrypt_n,omitempty"` // scrypt cost; 0 is the old 2^15
	Entries map[string]*entry `json:"entries"`

	// isNew: there is no vault.json yet, so its first key also decides where
	// the key is kept (key)
	isNew bool
}

// legacyN is the scrypt cost of vaults made before it was stored. A random
// key file needs no more; a passphrase vault moves to PassphraseN on its next
// change (upgrade).
const legacyN = 1 << 15

// PassphraseN is the scrypt cost for passphrase vaults (OWASP Password
// Storage Cheat Sheet: N=2^17, r=8, p=1). Tests lower it.
var PassphraseN = 1 << 17

type entry struct {
	Nonce     []byte    `json:"nonce"`
	Data      []byte    `json:"data"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Info struct {
	Name      string    `json:"name"`
	UpdatedAt time.Time `json:"updated_at"`
}

func vaultPath() string { return store.Path("vault.json") }

var (
	passMu sync.Mutex
	pass   string
)

// Passphrase returns $KOMANDO_VAULT_PASS and removes it from this process's
// environment, so programs komando starts (kubectl, credential plugins,
// VPN clients, docker) never inherit it.
func Passphrase() string {
	passMu.Lock()
	defer passMu.Unlock()
	if p, ok := os.LookupEnv("KOMANDO_VAULT_PASS"); ok {
		pass = p
		_ = os.Unsetenv("KOMANDO_VAULT_PASS")
	}
	return pass
}

// SelfEnv is the environment for komando processes started by komando
// that need the vault: a command the menu runs. A background process that
// runs for long gets the passphrase on stdin instead (PassOnStdin): its
// environment stays in view for as long as it runs (`ps eww`,
// /proc/PID/environ), to every program of the user.
func SelfEnv() []string {
	env := os.Environ()
	if p := Passphrase(); p != "" {
		env = append(env, "KOMANDO_VAULT_PASS="+p)
	}
	return env
}

// PassStdinFlag tells a komando process started with PassOnStdin to read
// the vault passphrase from stdin.
const PassStdinFlag = "--vault-pass-stdin"

// PassOnStdin readies c, a background komando process that needs the
// vault (`tunnel serve`, `vpn serve`): its environment is komando's own,
// without KOMANDO_VAULT_PASS, and the passphrase, when there is one, goes
// to it on stdin, with PassStdinFlag added to its arguments. It comes last:
// after what c.Stdin already holds (vpn serve's own lines), up to the end.
func PassOnStdin(c *exec.Cmd) {
	c.Env = os.Environ() // Passphrase took KOMANDO_VAULT_PASS out of it
	if p := Passphrase(); p != "" {
		var in io.Reader = strings.NewReader(p)
		if c.Stdin != nil {
			in = io.MultiReader(c.Stdin, in)
		}
		c.Stdin = in
		c.Args = append(c.Args, PassStdinFlag)
	}
}

// ReadPassStdin reads the passphrase PassOnStdin sends, up to the end of
// r, and uses it for the vault from now on.
func ReadPassStdin(r io.Reader) error {
	b, err := io.ReadAll(io.LimitReader(r, 64<<10))
	if err != nil {
		return fmt.Errorf("reading the vault passphrase from stdin: %w", err)
	}
	passMu.Lock()
	defer passMu.Unlock()
	pass = string(b)
	return nil
}

func load() (*file, error) {
	if err := store.EnsureHome(); err != nil {
		return nil, err
	}
	f := &file{Version: 1, Entries: map[string]*entry{}}
	b, err := os.ReadFile(vaultPath())
	if errors.Is(err, os.ErrNotExist) {
		f.isNew = true
		f.Salt = make([]byte, 16)
		if _, err := rand.Read(f.Salt); err != nil {
			return nil, err
		}
		if Passphrase() != "" {
			f.Mode, f.ScryptN = "passphrase", PassphraseN
		} else {
			f.Mode = "keyfile" // or keychain, once its key is made (key)
		}
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, f); err != nil {
		return nil, err
	}
	if f.Entries == nil {
		f.Entries = map[string]*entry{}
	}
	return f, nil
}

func (f *file) save() error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return store.WriteFileAtomic(vaultPath(), b, 0o600)
}

var (
	aeadMu    sync.Mutex
	aeadCache = map[string]cipher.AEAD{} // scrypt is slow on purpose: once per process
)

func (f *file) aead() (cipher.AEAD, error) {
	secret, err := f.key()
	if err != nil {
		return nil, err
	}
	return f.aeadFor(secret)
}

// key is what the vault's key is derived from, by its mode: the
// passphrase, the key in the keychain or the key in vault.key (made when
// the vault holds nothing yet). A new vault without a passphrase gets its
// key in the keychain when this computer has one that keeps it and can
// tell it holds no other key for this folder (keychainNewKey), and
// otherwise in vault.key: a copy of the komando folder (a backup, a synced
// home) then holds no key that opens it.
func (f *file) key() ([]byte, error) {
	var secret []byte
	switch f.Mode {
	case "passphrase":
		p := Passphrase()
		if p == "" {
			return nil, ErrLocked
		}
		secret = []byte(p)
	case "keychain":
		k, err := keychainGet()
		if err != nil {
			return nil, err
		}
		secret = k
	default:
		kp := store.Path("vault.key")
		b, err := os.ReadFile(kp)
		if errors.Is(err, os.ErrNotExist) {
			if len(f.Entries) > 0 {
				// a new key would open none of them, and secrets saved with
				// it would be lost once the old key is back
				return nil, fmt.Errorf("%w: %s is missing but the vault holds %d secrets; restore it from a backup", ErrKey, kp, len(f.Entries))
			}
			if f.isNew {
				if k, ok := keychainNewKey(); ok {
					f.Mode = "keychain"
					return k, nil
				}
			}
			b, err = newKeyFile(kp)
		}
		if err != nil {
			return nil, err
		}
		if len(b) < keyLen {
			// an empty or cut-short key would quietly encrypt new secrets
			// with a key anyone can derive from vault.json
			return nil, fmt.Errorf("%w: %s holds %d bytes, not %d (cut short?); restore it from a backup", ErrKey, kp, len(b), keyLen)
		}
		secret = b
	}
	return secret, nil
}

// aeadFor derives the AES key from secret with the vault's salt and scrypt
// cost.
func (f *file) aeadFor(secret []byte) (cipher.AEAD, error) {
	n := f.ScryptN
	if n == 0 {
		n = legacyN
	}
	id := fmt.Sprintf("%s/%x/%d/%x", f.Mode, f.Salt, n, sha256.Sum256(secret))
	aeadMu.Lock()
	defer aeadMu.Unlock()
	if a, ok := aeadCache[id]; ok {
		return a, nil
	}
	key, err := scrypt.Key(secret, f.Salt, n, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(blk)
	if err == nil {
		aeadCache[id] = a
	}
	return a, err
}

// keyLen is the size of the random key in vault.key.
const keyLen = 32

// newKeyFile creates vault.key with a new random key, but never replaces
// one that is already there: when another komando process made it first,
// that key is returned, so every process encrypts with the key on disk.
// The key is written in full before it appears under its name.
func newKeyFile(kp string) ([]byte, error) {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(kp), ".tmp-key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(key)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	// a hard link fails when the name exists, and never shows a half-written key
	switch err = os.Link(tmp.Name(), kp); {
	case err == nil:
		return key, nil
	case errors.Is(err, os.ErrExist):
		return os.ReadFile(kp)
	}
	// a file system without hard links: create the name exclusively
	f, err := os.OpenFile(kp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return os.ReadFile(kp)
	}
	if err != nil {
		return nil, err
	}
	_, err = f.Write(key)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(kp)
		return nil, err
	}
	return key, nil
}

// lockName is the lock file that serializes changes to the vault between
// komando processes (store.Update uses its own, so neither waits on the other).
const lockName = ".vault.lock"

// change loads the vault under an exclusive lock, applies fn and saves it,
// so komando processes running at the same time (parallel agents) never
// drop each other's secrets.
func change(fn func(f *file) error) error {
	if store.DryRun {
		return store.ErrDryRun
	}
	unlock, err := store.Lock(lockName)
	if err != nil {
		return err
	}
	defer unlock()
	f, err := load()
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		return err
	}
	return f.save()
}

// upgrade re-encrypts a passphrase vault made with a weaker scrypt cost,
// with a new salt, before it is changed.
func (f *file) upgrade() error {
	if f.Mode != "passphrase" || f.ScryptN >= PassphraseN {
		return nil
	}
	if len(f.Entries) == 0 {
		f.ScryptN = PassphraseN
		return nil
	}
	old, err := f.aead()
	if err != nil {
		return err
	}
	plain, err := f.openAll(old)
	if err != nil {
		return err
	}
	defer wipe(plain)
	salt, err := newSalt()
	if err != nil {
		return err
	}
	f.Salt, f.ScryptN = salt, PassphraseN
	a, err := f.aead()
	if err != nil {
		return err
	}
	return f.sealAll(a, plain)
}

// Strength describes the vault's protection for `komando doctor`: the mode,
// the scrypt cost and, for a passphrase, whether it is long enough (NIST SP
// 800-63B asks for 15 characters when it is the only factor).
type Strength struct {
	Mode       string `json:"mode"`
	ScryptN    int    `json:"scrypt_n"`
	ShortPass  bool   `json:"short_passphrase,omitempty"`
	OldKDF     bool   `json:"old_kdf,omitempty"`
	NoVaultYet bool   `json:"no_vault_yet,omitempty"`
}

// MinPassphrase is the shortest passphrase doctor accepts without a warning.
const MinPassphrase = 15

func Check() (Strength, error) {
	if _, err := os.Stat(vaultPath()); errors.Is(err, os.ErrNotExist) {
		return Strength{NoVaultYet: true}, nil
	}
	f, err := load()
	if err != nil {
		return Strength{}, err
	}
	s := Strength{Mode: f.Mode, ScryptN: f.ScryptN}
	if s.ScryptN == 0 {
		s.ScryptN = legacyN
	}
	if f.Mode == "passphrase" {
		s.OldKDF = s.ScryptN < PassphraseN
		s.ShortPass = len([]rune(Passphrase())) < MinPassphrase
	}
	return s, nil
}

func Set(name, value string) error {
	return change(func(f *file) error {
		if err := f.upgrade(); err != nil {
			return err
		}
		a, err := f.aead()
		if err != nil {
			return err
		}
		if err := f.checkKey(a); err != nil {
			return err
		}
		nonce := make([]byte, a.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		f.Entries[name] = &entry{Nonce: nonce, Data: a.Seal(nil, nonce, []byte(value), []byte(name)), UpdatedAt: time.Now().UTC()}
		return nil
	})
}

// checkKey: a opens the secrets already in the vault, so a mistyped
// KOMANDO_VAULT_PASS never seals a new one under a second key.
func (f *file) checkKey(a cipher.AEAD) error {
	for name, e := range f.Entries {
		if _, err := a.Open(nil, e.Nonce, e.Data, []byte(name)); err != nil {
			return fmt.Errorf("%w %q (wrong KOMANDO_VAULT_PASS or vault.key?): nothing was saved", ErrDecrypt, name)
		}
		return nil // one is enough: every entry has the same key
	}
	return nil
}

var ErrNotFound = errors.New("secret not found")

// The vault cannot be opened: no passphrase given for a passphrase vault
// (ErrLocked), its key file is missing or broken (ErrKey), or a secret
// does not decrypt with the key or passphrase given (ErrDecrypt).
var (
	ErrLocked  = errors.New("the vault is locked with a passphrase; set KOMANDO_VAULT_PASS")
	ErrKey     = errors.New("the vault's key cannot be used")
	ErrDecrypt = errors.New("cannot decrypt secret")
)

func Get(name string) (string, error) {
	f, err := load()
	if err != nil {
		return "", err
	}
	e, ok := f.Entries[name]
	if !ok {
		return "", ErrNotFound
	}
	a, err := f.aead()
	if err != nil {
		return "", err
	}
	pt, err := a.Open(nil, e.Nonce, e.Data, []byte(name))
	if err != nil {
		return "", fmt.Errorf("%w %q (wrong KOMANDO_VAULT_PASS or vault.key?)", ErrDecrypt, name)
	}
	return string(pt), nil
}

func Delete(name string) error {
	return change(func(f *file) error {
		if _, ok := f.Entries[name]; !ok {
			return ErrNotFound
		}
		delete(f.Entries, name)
		return nil
	})
}

// ErrExists is returned by Copy and Rename when the new name is taken and
// overwrite is false.
var ErrExists = errors.New("secret already exists")

// Copy stores the value of from under the name to as well. The value is
// decrypted and sealed again inside the vault (each value is bound to its
// name) and never leaves this package.
func Copy(from, to string, overwrite bool) error { return copyEntry(from, to, overwrite, false) }

// Rename moves the value of from to the name to, in one change of the vault.
func Rename(from, to string, overwrite bool) error { return copyEntry(from, to, overwrite, true) }

func copyEntry(from, to string, overwrite, move bool) error {
	if from == to {
		return errors.New("the old and the new name are the same")
	}
	return change(func(f *file) error {
		if _, ok := f.Entries[from]; !ok {
			return ErrNotFound
		}
		if _, ok := f.Entries[to]; ok && !overwrite {
			return ErrExists
		}
		if err := f.upgrade(); err != nil {
			return err
		}
		a, err := f.aead()
		if err != nil {
			return err
		}
		e := f.Entries[from]
		pt, err := a.Open(nil, e.Nonce, e.Data, []byte(from))
		if err != nil {
			return fmt.Errorf("%w %q (wrong KOMANDO_VAULT_PASS or vault.key?)", ErrDecrypt, from)
		}
		defer clear(pt)
		nonce := make([]byte, a.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		// the value did not change, so neither does its UpdatedAt
		f.Entries[to] = &entry{Nonce: nonce, Data: a.Seal(nil, nonce, pt, []byte(to)), UpdatedAt: e.UpdatedAt}
		if move {
			delete(f.Entries, from)
		}
		return nil
	})
}

func List() ([]Info, error) {
	f, err := load()
	if err != nil {
		return nil, err
	}
	out := []Info{}
	for n, e := range f.Entries {
		out = append(out, Info{Name: n, UpdatedAt: e.UpdatedAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Refs are the kinds of secret reference komando understands, with an
// example each, for help texts and errors.
var Refs = []string{
	"secret:NAME (komando's vault)",
	"env:VAR",
	"file:PATH",
	"op://VAULT/ITEM/FIELD (1Password Connect)",
	"bw://ITEM/FIELD (Bitwarden, Vaultwarden)",
	"kdbx:FILE#GROUP/ENTRY[#FIELD] (KeePass, KeePassXC)",
	"vault:PATH#FIELD (HashiCorp Vault or OpenBao, KV)",
	"aws-sm:NAME[#JSON_KEY] (AWS Secrets Manager)",
	"gcp-sm:NAME[@PROJECT] (Google Secret Manager)",
	"azure-kv:VAULT/NAME[#JSON_KEY] (Azure Key Vault)",
}

// ValidRef reports whether ref has a known form.
func ValidRef(ref string) bool {
	for _, p := range []string{"secret:", "env:", "file:", "op://", "bw://", "kdbx:", "vault:", "aws-sm:", "gcp-sm:", "azure-kv:"} {
		if strings.HasPrefix(ref, p) && len(ref) > len(p) {
			return true
		}
	}
	return false
}

// RefGuard, when set, is asked before Resolve reads a vault secret (kind
// "secret"), a file on this computer (kind "file") or an environment
// variable (kind "env") for a reference. komando's CLI sets it, so a
// reference, which komando sends to a server as a password, never reads a
// secret komando keeps for itself, and an AI agent cannot point one at
// secrets it must not have.
var RefGuard func(kind, name string) error

// RefHelp is the hint for an invalid reference.
func RefHelp() string { return "use one of: " + strings.Join(Refs, ", ") }

// Resolve turns a reference into a value:
//
//	secret:<name>        -> komando's vault
//	env:<VAR>            -> environment variable
//	file:<path>          -> file contents (trailing newline trimmed)
//	op://v/item/field    -> 1Password Connect (OP_CONNECT_HOST, OP_CONNECT_TOKEN)
//	bw://item/field      -> Bitwarden or Vaultwarden, decrypted here (KOMANDO_BW_*)
//	kdbx:file#group/entry[#field] -> a KeePass file (KOMANDO_KDBX_PASSWORD / KOMANDO_KDBX_KEYFILE)
//	vault:path#field     -> HashiCorp Vault / OpenBao KV (VAULT_ADDR and a token, as the CLI uses them)
//	aws-sm:name[#key]    -> AWS Secrets Manager (the usual AWS credentials; a JSON key when given)
//	gcp-sm:name[@project]-> Google Secret Manager, latest version (application-default credentials)
//	azure-kv:vault/name[/version][#key] -> Azure Key Vault (a service principal, the Azure CLI's token or a managed identity)
//
// komando talks to those services itself (internal/cloud); the login stays
// with the person and komando never stores the values.
func Resolve(ref string) (string, error) {
	switch {
	case ref == "":
		return "", nil
	case strings.HasPrefix(ref, "secret:"):
		name := strings.TrimPrefix(ref, "secret:")
		if RefGuard != nil {
			if err := RefGuard("secret", name); err != nil {
				return "", err
			}
		}
		return Get(name)
	case strings.HasPrefix(ref, "env:"):
		name := strings.TrimPrefix(ref, "env:")
		if RefGuard != nil {
			if err := RefGuard("env", name); err != nil {
				return "", err
			}
		}
		v, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("environment variable %s not set", name)
		}
		return v, nil
	case strings.HasPrefix(ref, "file:"):
		p := strings.TrimPrefix(ref, "file:")
		if RefGuard != nil {
			if err := RefGuard("file", p); err != nil {
				return "", err
			}
		}
		b, err := os.ReadFile(p)
		return strings.TrimRight(string(b), "\r\n"), err
	case strings.HasPrefix(ref, "op://"):
		// only through 1Password Connect: the op CLI is closed source
		// (docs/design/built-in.md)
		v, err := cloud.OnePassword(context.Background(), ref)
		if errors.Is(err, cloud.ErrNoConnect) {
			return "", fmt.Errorf("op:// needs 1Password Connect (set OP_CONNECT_HOST and OP_CONNECT_TOKEN); the op program is no longer used. Or use bw://, kdbx: or a komando secret")
		}
		return v, err
	case strings.HasPrefix(ref, "bw://"):
		return cloud.Bitwarden(context.Background(), ref)
	case strings.HasPrefix(ref, "kdbx:"):
		return cloud.KeePass(strings.TrimPrefix(ref, "kdbx:"))
	case strings.HasPrefix(ref, "vault:"):
		path, field, ok := strings.Cut(strings.TrimPrefix(ref, "vault:"), "#")
		if !ok || field == "" {
			return "", fmt.Errorf("vault: references need #FIELD, e.g. vault:secret/shop#db_password")
		}
		return cloud.VaultKV(context.Background(), path, field)
	case strings.HasPrefix(ref, "aws-sm:"):
		name, key, _ := strings.Cut(strings.TrimPrefix(ref, "aws-sm:"), "#")
		v, err := cloud.AWSSecret(context.Background(), name)
		if errors.Is(err, cloud.ErrAWSLogin) {
			return "", fmt.Errorf("aws: %v (a person runs `komando login aws` once)", err)
		}
		if err != nil || key == "" {
			return v, err
		}
		return jsonKey(v, key)
	case strings.HasPrefix(ref, "gcp-sm:"):
		name, project, _ := strings.Cut(strings.TrimPrefix(ref, "gcp-sm:"), "@")
		v, err := cloud.GCPSecret(context.Background(), name, project)
		if errors.Is(err, cloud.ErrGCPLogin) {
			return "", fmt.Errorf("google cloud: %v (set GOOGLE_APPLICATION_CREDENTIALS to a key file, or run on Google Cloud)", err)
		}
		return v, err
	case strings.HasPrefix(ref, "azure-kv:"):
		path, key, _ := strings.Cut(strings.TrimPrefix(ref, "azure-kv:"), "#")
		v, err := cloud.AzureSecret(context.Background(), path)
		if errors.Is(err, cloud.ErrAzureLogin) {
			return "", fmt.Errorf("azure: %v (%s)", err, cloud.AzureLoginHint(cloud.KeyVaultResource(path)))
		}
		if err != nil || key == "" {
			return v, err
		}
		return jsonKey(v, key)
	}
	return "", fmt.Errorf("invalid secret reference %q (%s)", ref, RefHelp())
}

func firstLine(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return strings.SplitN(s, "\n", 2)[0]
}

func jsonKey(doc, key string) (string, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		return "", fmt.Errorf("the secret is not JSON, so #%s does not apply", key)
	}
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("the secret has no key %q", key)
	}
	if s, ok := v.(string); ok {
		return s, nil
	}
	b, _ := json.Marshal(v)
	return string(b), nil
}
