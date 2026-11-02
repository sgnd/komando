// Package vault stores secrets (passwords, key passphrases, tokens) encrypted
// with AES-256-GCM. The key is derived with scrypt from $KOMANDO_VAULT_PASS
// when set, otherwise from a random 32-byte key file (vault.key, mode 0600).
package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/sgnd/komando/internal/store"
)

type file struct {
	Version int               `json:"version"`
	Salt    []byte            `json:"salt"`
	Mode    string            `json:"mode"` // keyfile | passphrase
	Entries map[string]*entry `json:"entries"`
}

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

// SelfEnv is the environment for komando's own background processes
// (`vpn serve`, `tunnel serve`), which need the vault.
func SelfEnv() []string {
	env := os.Environ()
	if p := Passphrase(); p != "" {
		env = append(env, "KOMANDO_VAULT_PASS="+p)
	}
	return env
}

func load() (*file, error) {
	if err := store.EnsureHome(); err != nil {
		return nil, err
	}
	f := &file{Version: 1, Entries: map[string]*entry{}}
	b, err := os.ReadFile(vaultPath())
	if errors.Is(err, os.ErrNotExist) {
		f.Salt = make([]byte, 16)
		_, _ = rand.Read(f.Salt)
		if Passphrase() != "" {
			f.Mode = "passphrase"
		} else {
			f.Mode = "keyfile"
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

func (f *file) aead() (cipher.AEAD, error) {
	var secret []byte
	switch f.Mode {
	case "passphrase":
		p := Passphrase()
		if p == "" {
			return nil, errors.New("vault is passphrase-protected: set KOMANDO_VAULT_PASS")
		}
		secret = []byte(p)
	default:
		kp := store.Path("vault.key")
		b, err := os.ReadFile(kp)
		if errors.Is(err, os.ErrNotExist) {
			b = make([]byte, 32)
			_, _ = rand.Read(b)
			if err := store.WriteFileAtomic(kp, b, 0o600); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
		secret = b
	}
	key, err := scrypt.Key(secret, f.Salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func Set(name, value string) error {
	if store.DryRun {
		return store.ErrDryRun
	}
	f, err := load()
	if err != nil {
		return err
	}
	a, err := f.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, a.NonceSize())
	_, _ = rand.Read(nonce)
	f.Entries[name] = &entry{Nonce: nonce, Data: a.Seal(nil, nonce, []byte(value), []byte(name)), UpdatedAt: time.Now().UTC()}
	return f.save()
}

var ErrNotFound = errors.New("secret not found")

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
		return "", fmt.Errorf("cannot decrypt secret %q (wrong KOMANDO_VAULT_PASS or vault.key?)", name)
	}
	return string(pt), nil
}

func Delete(name string) error {
	if store.DryRun {
		return store.ErrDryRun
	}
	f, err := load()
	if err != nil {
		return err
	}
	if _, ok := f.Entries[name]; !ok {
		return ErrNotFound
	}
	delete(f.Entries, name)
	return f.save()
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
	"op://VAULT/ITEM/FIELD (1Password CLI)",
	"vault:PATH#FIELD (HashiCorp Vault CLI, KV)",
	"aws-sm:NAME[#JSON_KEY] (AWS Secrets Manager)",
	"gcp-sm:NAME[@PROJECT] (Google Secret Manager)",
}

// ValidRef reports whether ref has a known form.
func ValidRef(ref string) bool {
	for _, p := range []string{"secret:", "env:", "file:", "op://", "vault:", "aws-sm:", "gcp-sm:"} {
		if strings.HasPrefix(ref, p) && len(ref) > len(p) {
			return true
		}
	}
	return false
}

// RefHelp is the hint for an invalid reference.
func RefHelp() string { return "use one of: " + strings.Join(Refs, ", ") }

// Resolve turns a reference into a value:
//
//	secret:<name>        -> komando's vault
//	env:<VAR>            -> environment variable
//	file:<path>          -> file contents (trailing newline trimmed)
//	op://v/item/field    -> `op read` (1Password CLI, signed in)
//	vault:path#field     -> `vault kv get -field` (HashiCorp Vault CLI, VAULT_ADDR and a token set)
//	aws-sm:name[#key]    -> `aws secretsmanager get-secret-value` (a JSON key when given)
//	gcp-sm:name[@project]-> `gcloud secrets versions access latest`
//
// The external ones run that tool, so its login (and any MFA) stays with the
// person; komando never stores those values.
func Resolve(ref string) (string, error) {
	switch {
	case ref == "":
		return "", nil
	case strings.HasPrefix(ref, "secret:"):
		return Get(strings.TrimPrefix(ref, "secret:"))
	case strings.HasPrefix(ref, "env:"):
		v, ok := os.LookupEnv(strings.TrimPrefix(ref, "env:"))
		if !ok {
			return "", fmt.Errorf("environment variable %s not set", strings.TrimPrefix(ref, "env:"))
		}
		return v, nil
	case strings.HasPrefix(ref, "file:"):
		b, err := os.ReadFile(strings.TrimPrefix(ref, "file:"))
		return strings.TrimRight(string(b), "\r\n"), err
	case strings.HasPrefix(ref, "op://"):
		return external("op", "read", "--no-newline", ref)
	case strings.HasPrefix(ref, "vault:"):
		path, field, ok := strings.Cut(strings.TrimPrefix(ref, "vault:"), "#")
		if !ok || field == "" {
			return "", fmt.Errorf("vault: references need #FIELD, e.g. vault:secret/shop#db_password")
		}
		return external("vault", "kv", "get", "-field="+field, path)
	case strings.HasPrefix(ref, "aws-sm:"):
		name, key, _ := strings.Cut(strings.TrimPrefix(ref, "aws-sm:"), "#")
		v, err := external("aws", "secretsmanager", "get-secret-value", "--secret-id", name, "--query", "SecretString", "--output", "text")
		if err != nil || key == "" {
			return v, err
		}
		return jsonKey(v, key)
	case strings.HasPrefix(ref, "gcp-sm:"):
		name, project, _ := strings.Cut(strings.TrimPrefix(ref, "gcp-sm:"), "@")
		args := []string{"secrets", "versions", "access", "latest", "--secret=" + name}
		if project != "" {
			args = append(args, "--project="+project)
		}
		return external("gcloud", args...)
	}
	return "", fmt.Errorf("invalid secret reference %q (%s)", ref, RefHelp())
}

// external runs a secret manager's CLI and returns its output. The value
// is never logged; errors carry the tool's message, which names no secret.
func external(tool string, args ...string) (string, error) {
	if _, err := exec.LookPath(tool); err != nil {
		return "", fmt.Errorf("%s is not installed (needed for this secret reference)", tool)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, tool, args...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return "", fmt.Errorf("%s: %s (is it signed in?)", tool, firstLine(msg, err.Error()))
	}
	return strings.TrimRight(string(out), "\r\n"), nil
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
