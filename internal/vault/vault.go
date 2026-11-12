// Package vault stores secrets (passwords, key passphrases, tokens) encrypted
// with AES-256-GCM, each bound to its name. The key is derived with scrypt
// from $KOMANDO_VAULT_PASS when set (N=2^17, r=8, p=1: the OWASP minimum),
// otherwise from the sealed store's key (sealed.go). An earlier komando kept
// the vault in vault.json; `komando seal` reads it (move.go).
package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
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
}

// legacyN is the scrypt cost of vaults of before that did not store it
// (read by `komando seal`).
const legacyN = 1 << 15

// PassphraseN is the scrypt cost for passphrase vaults (OWASP Password
// Storage Cheat Sheet: N=2^17, r=8, p=1). Tests lower it.
var PassphraseN = 1 << 17

type entry struct {
	Nonce     []byte    `json:"nonce"`
	Data      []byte    `json:"data"`
	UpdatedAt time.Time `json:"updated_at"`

	id string // its record in the sealed store
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

// UnlockVars are the variables, besides KOMANDO_VAULT_PASS, that unlock
// the secret stores komando reads (KeePass, Bitwarden, 1Password Connect,
// HashiCorp Vault / OpenBao).
var UnlockVars = []string{"KOMANDO_KDBX_PASSWORD", "KOMANDO_KDBX_KEYFILE", "KOMANDO_BW_PASSWORD",
	"KOMANDO_BW_CLIENT_SECRET", "OP_CONNECT_TOKEN", "VAULT_TOKEN", "BAO_TOKEN"}

// unlock holds the UnlockVars TakeUnlockEnv took (under passMu).
var unlock = map[string]string{}

func init() { cloud.UnlockEnv = unlockEnv }

// TakeUnlockEnv takes KOMANDO_VAULT_PASS and the UnlockVars out of this
// process's environment when komando starts, so no program it starts
// (ssh, kubectl, a VPN client, a dump tool, a background tunnel) inherits
// them: a long-running one would show them for hours (`ps eww`,
// /proc/PID/environ). komando reads them from memory (cloud.UnlockEnv);
// its own background processes get them on stdin (PassOnStdin).
func TakeUnlockEnv() {
	Passphrase()
	passMu.Lock()
	defer passMu.Unlock()
	for _, n := range UnlockVars {
		if v, ok := os.LookupEnv(n); ok {
			unlock[n] = v
			_ = os.Unsetenv(n)
		}
	}
}

// unlockEnv is cloud.UnlockEnv: the environment first (a variable set
// after the start), then what TakeUnlockEnv took.
func unlockEnv(name string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	passMu.Lock()
	defer passMu.Unlock()
	return unlock[name]
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
	passMu.Lock()
	defer passMu.Unlock()
	for _, n := range UnlockVars {
		if v, ok := unlock[n]; ok {
			env = append(env, n+"="+v)
		}
	}
	return env
}

// handoffMark starts what Handoff gives when there is more than the
// passphrase to hand over.
const handoffMark = "komando-unlock 1\n"

// Handoff is what a background komando process needs to open the secret
// stores: the passphrase alone, or with the UnlockVars TakeUnlockEnv took,
// handoffMark and one "NAME base64" line each. ReadPassStdin reads either.
func Handoff() string {
	p := Passphrase()
	passMu.Lock()
	defer passMu.Unlock()
	if len(unlock) == 0 {
		return p
	}
	var b strings.Builder
	b.WriteString(handoffMark + "KOMANDO_VAULT_PASS " + base64.StdEncoding.EncodeToString([]byte(p)) + "\n")
	for _, n := range UnlockVars {
		if v, ok := unlock[n]; ok {
			b.WriteString(n + " " + base64.StdEncoding.EncodeToString([]byte(v)) + "\n")
		}
	}
	return b.String()
}

// takeHandoff uses what Handoff gave (passMu is held).
func takeHandoff(s string) error {
	rest, ok := strings.CutPrefix(s, handoffMark)
	if !ok {
		pass = s
		return nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(rest, "\n"), "\n") {
		name, enc, _ := strings.Cut(line, " ")
		v, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			return fmt.Errorf("reading the vault passphrase from stdin: %w", err)
		}
		switch {
		case name == "KOMANDO_VAULT_PASS":
			pass = string(v)
		case slices.Contains(UnlockVars, name):
			unlock[name] = string(v)
		}
	}
	return nil
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
	c.Env = os.Environ() // TakeUnlockEnv took KOMANDO_VAULT_PASS and the UnlockVars out of it
	if p := Handoff(); p != "" {
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
	return takeHandoff(string(b))
}

func load() (*file, error) {
	if err := store.EnsureHome(); err != nil {
		return nil, err
	}
	return loadSealed()
}

var (
	aeadMu    sync.Mutex
	aeadCache = map[string]cipher.AEAD{} // scrypt is slow on purpose: once per process
)

func (f *file) aead() (cipher.AEAD, error) {
	if f.Mode == modeSealed {
		return sealedAEAD()
	}
	secret, err := f.key()
	if err != nil {
		return nil, err
	}
	return f.aeadFor(secret)
}

// key is what a vault of before (vault.json) derives its key from, by its
// mode: the passphrase, the key in the keychain or the key in vault.key.
// It only reads: `komando seal` opens such a vault to move it.
func (f *file) key() ([]byte, error) {
	switch f.Mode {
	case "passphrase":
		p := Passphrase()
		if p == "" {
			return nil, ErrLocked
		}
		return []byte(p), nil
	case "keychain":
		return keychainGet()
	}
	kp := store.Path("vault.key")
	b, err := os.ReadFile(kp)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s is missing but the vault holds %d secrets; restore it from a backup", ErrKey, kp, len(f.Entries))
	}
	if err != nil {
		return nil, err
	}
	if len(b) < keyLen {
		return nil, fmt.Errorf("%w: %s holds %d bytes, not %d (cut short?); restore it from a backup", ErrKey, kp, len(b), keyLen)
	}
	return b, nil
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

// keyLen is the size of a random vault key.
const keyLen = 32

// change loads the vault, applies fn and writes what changed, in one write
// step of the store, so komando processes running at the same time
// (parallel agents) never drop each other's secrets.
func change(fn func(f *file) error) error {
	if store.DryRun {
		return store.ErrDryRun
	}
	return changeSealed(fn)
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

func Check() (Strength, error) { return sealedStrength() }

func Set(name, value string) error {
	return change(func(f *file) error {
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
			return fmt.Errorf("%w %q (wrong KOMANDO_VAULT_PASS or store.key?): nothing was saved", ErrDecrypt, name)
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
		return "", fmt.Errorf("%w %q (wrong KOMANDO_VAULT_PASS or store.key?)", ErrDecrypt, name)
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

// DeleteMany removes several secrets in one change of the vault: all of
// them, or none when one is missing (an error that matches ErrNotFound and
// ends with ": NAME").
func DeleteMany(names []string) error {
	return change(func(f *file) error {
		for _, n := range names {
			if _, ok := f.Entries[n]; !ok {
				return fmt.Errorf("%w: %s", ErrNotFound, n)
			}
		}
		for _, n := range names {
			delete(f.Entries, n)
		}
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
		a, err := f.aead()
		if err != nil {
			return err
		}
		e := f.Entries[from]
		pt, err := a.Open(nil, e.Nonce, e.Data, []byte(from))
		if err != nil {
			return fmt.Errorf("%w %q (wrong KOMANDO_VAULT_PASS or store.key?)", ErrDecrypt, from)
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

// OnResolve, when set, gets every value Resolve read. komando's CLI sets
// it to hide the value in its output: a value from env:, file:, op://, a
// cloud secret manager... is in no list komando keeps.
var OnResolve func(value string)

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
	v, err := resolve(ref)
	if err == nil && v != "" && OnResolve != nil {
		OnResolve(v)
	}
	return v, err
}

func resolve(ref string) (string, error) {
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
			return "", fmt.Errorf("vault: references need #FIELD, for example vault:secret/shop#db_password")
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
	return "", fmt.Errorf("%q is not a secret reference (%s)", ref, RefHelp())
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
