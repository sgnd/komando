package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// The vault key can live in the operating system's keychain instead of
// vault.key: the macOS login keychain (through the `security` tool every
// Mac has) or the Secret Service on Linux (GNOME Keyring, KWallet, through
// `secret-tool`). The key never goes on a command line: `security -i` and
// `secret-tool store` read it from standard input. Moving the key does not
// re-encrypt anything: it is the same key, kept elsewhere.

// keychainService names this komando home's key, so two homes (a test
// one, say) keep two keys.
func keychainService() string {
	h := sha256.Sum256([]byte(store.Path("")))
	return "komando vault " + hex.EncodeToString(h[:6])
}

const keychainAccount = "komando"

// keychainOS picks the tool; tests set it.
var keychainOS = runtime.GOOS

// keychainFile is a keychain file to use instead of the login keychain
// (macOS; KOMANDO_KEYCHAIN, for tests and separate keychains).
func keychainFile() string { return os.Getenv("KOMANDO_KEYCHAIN") }

// KeychainTool says which tool keeps the key here, or why there is none.
func KeychainTool() (string, error) {
	switch keychainOS {
	case "darwin":
		if _, err := exec.LookPath("security"); err != nil {
			return "", errors.New("macOS's security tool is missing")
		}
		return "macOS keychain", nil
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err != nil {
			return "", errors.New("secret-tool is not installed (it comes with libsecret: apt install libsecret-tools)")
		}
		return "Secret Service (secret-tool)", nil
	}
	return "", fmt.Errorf("no keychain support on %s", keychainOS)
}

func keychainSet(key []byte) error {
	v := hex.EncodeToString(key)
	switch keychainOS {
	case "darwin":
		line := fmt.Sprintf("add-generic-password -U -a %s -s %q -l %q -w %s", keychainAccount, keychainService(), keychainService(), v)
		if kc := keychainFile(); kc != "" {
			line += fmt.Sprintf(" %q", kc)
		}
		return run(exec.Command("security", "-i"), line+"\n")
	case "linux":
		return run(exec.Command("secret-tool", "store", "--label="+keychainService(), "service", keychainService(), "account", keychainAccount), v)
	}
	_, err := KeychainTool()
	return err
}

func keychainGet() ([]byte, error) {
	var c *exec.Cmd
	switch keychainOS {
	case "darwin":
		args := []string{"find-generic-password", "-a", keychainAccount, "-s", keychainService(), "-w"}
		if kc := keychainFile(); kc != "" {
			args = append(args, kc)
		}
		c = exec.Command("security", args...)
	case "linux":
		c = exec.Command("secret-tool", "lookup", "service", keychainService(), "account", keychainAccount)
	default:
		_, err := KeychainTool()
		return nil, err
	}
	var errb bytes.Buffer
	c.Stderr = &errb
	b, err := c.Output()
	if err != nil {
		return nil, fmt.Errorf("the vault key is not in the keychain (%s); is it unlocked?", strings.TrimSpace(firstLine(strings.TrimSpace(errb.String()), err.Error())))
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("the keychain holds something else under komando's vault key name")
	}
	return key, nil
}

func keychainDel() error {
	switch keychainOS {
	case "darwin":
		args := []string{"delete-generic-password", "-a", keychainAccount, "-s", keychainService()}
		if kc := keychainFile(); kc != "" {
			args = append(args, kc)
		}
		return run(exec.Command("security", args...), "")
	case "linux":
		return run(exec.Command("secret-tool", "clear", "service", keychainService(), "account", keychainAccount), "")
	}
	return nil
}

func run(c *exec.Cmd, stdin string) error {
	c.Stdin = strings.NewReader(stdin)
	var errb bytes.Buffer
	c.Stdout, c.Stderr = &errb, &errb
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s: %s", c.Path, strings.TrimSpace(firstLine(strings.TrimSpace(errb.String()), err.Error())))
	}
	// `security -i` reports a failed command but still exits 0
	if out := errb.String(); strings.Contains(out, "security: ") || strings.Contains(out, "Error:") {
		return fmt.Errorf("%s", strings.TrimSpace(firstLine(strings.TrimSpace(out), "")))
	}
	return nil
}

// KeyToKeychain moves the vault key from vault.key into the keychain.
func KeyToKeychain() (string, error) {
	tool, err := KeychainTool()
	if err != nil {
		return "", err
	}
	f, err := load()
	if err != nil {
		return "", err
	}
	switch f.Mode {
	case "keychain":
		return tool, nil
	case "passphrase":
		return "", errors.New("this vault is unlocked with KOMANDO_VAULT_PASS, not a key file: nothing to move")
	}
	if _, err := f.aead(); err != nil { // makes vault.key when there is none yet
		return "", err
	}
	kp := store.Path("vault.key")
	key, err := os.ReadFile(kp)
	if err != nil {
		return "", err
	}
	if err := keychainSet(key); err != nil {
		return "", err
	}
	back, err := keychainGet()
	if err != nil || !bytes.Equal(back, key) {
		return "", fmt.Errorf("the keychain did not keep the key: %v", err)
	}
	f.Mode = "keychain"
	if err := f.save(); err != nil {
		return "", err
	}
	// overwrite, then remove: the key now lives only in the keychain
	_ = os.WriteFile(kp, make([]byte, len(key)), 0o600)
	return tool, os.Remove(kp)
}

// KeyToFile moves the vault key back from the keychain into vault.key.
func KeyToFile() error {
	f, err := load()
	if err != nil {
		return err
	}
	if f.Mode != "keychain" {
		return nil
	}
	key, err := keychainGet()
	if err != nil {
		return err
	}
	if err := store.WriteFileAtomic(store.Path("vault.key"), key, 0o600); err != nil {
		return err
	}
	f.Mode = "keyfile"
	if err := f.save(); err != nil {
		return err
	}
	return keychainDel()
}
