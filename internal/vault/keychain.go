package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// The vault key can live in the operating system's keychain instead of
// store.key: the macOS login keychain (through the `security` tool every
// Mac has), the Secret Service on Linux (GNOME Keyring, KWallet, through
// `secret-tool`), or the Windows Credential Manager (advapi32, called
// directly: credman_windows.go). The key never goes on a command line: `security -i` and
// `secret-tool store` read it from standard input. Moving the key does not
// re-encrypt anything: it is the same key, kept elsewhere.
//
// A new vault without a passphrase starts with its key in the keychain
// when there is one (keychainNewKey); KOMANDO_KEYCHAIN=off keeps komando
// away from the keychain (CI runners, containers, test runs), and then a
// new vault keeps its key in store.key, as it does where there is none.

// keychainService names this komando home's key, so two homes (a test
// one, say) keep two keys.
func keychainService() string {
	h := sha256.Sum256([]byte(store.Path("")))
	return "komando vault " + hex.EncodeToString(h[:6])
}

const keychainAccount = "komando"

// keychainOS picks the tool; tests set it.
var keychainOS = runtime.GOOS

// The tools are run from system folders only, never found through PATH:
// a fake `security` or `secret-tool` earlier in PATH would otherwise be
// handed the vault key, or hand komando a key of its choosing. The approval
// window's tools are found the same way (cli.systemTool).
var (
	securityTool = "/usr/bin/security" // every Mac has it there
	toolDirs     = []string{"/usr/bin", "/bin", "/usr/local/bin"}
)

// systemTool is the path of name in a system folder, or "".
func systemTool(name string) string {
	for _, d := range toolDirs {
		p := filepath.Join(d, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// keychainCmd runs the keychain tool of this system with args.
func keychainCmd(args ...string) *exec.Cmd {
	return keychainCmdCtx(context.Background(), args...)
}

// keychainCmdCtx is keychainCmd, stopped when ctx ends.
func keychainCmdCtx(ctx context.Context, args ...string) *exec.Cmd {
	tool := securityTool
	if keychainOS != "darwin" {
		tool = systemTool("secret-tool")
	}
	c := exec.CommandContext(ctx, tool, args...)
	c.WaitDelay = time.Second // a child holding the pipes must not keep komando waiting
	return c
}

// newKeyTimeout bounds each keychain call when a new vault makes its key:
// komando holds the vault lock then, and a Secret Service that waits for an
// unlock prompt (or a slow D-Bus) must not hang it and every komando
// waiting on that lock. Past it, the new vault keeps its key in store.key.
// `komando secret keychain` has no such limit: a person is there to answer
// the prompt. Tests shorten it.
var newKeyTimeout = 5 * time.Second

// errNoKeychainKey: the keychain answered, and holds no key under this
// komando home's name. Any other error (locked, a dismissed prompt, a
// timeout) says nothing about whether a key is there.
var errNoKeychainKey = errors.New("the vault key is not in the keychain")

// keychainFile is a keychain file to use instead of the login keychain
// (macOS; KOMANDO_KEYCHAIN, for tests and separate keychains).
func keychainFile() string {
	if keychainOff() {
		return ""
	}
	return os.Getenv("KOMANDO_KEYCHAIN")
}

// keychainOff: KOMANDO_KEYCHAIN=off, komando uses no keychain here.
func keychainOff() bool { return os.Getenv("KOMANDO_KEYCHAIN") == "off" }

// KeychainTool says which tool keeps the key here, or why there is none.
func KeychainTool() (string, error) {
	if keychainOff() {
		return "", errors.New("komando uses no keychain on this computer (KOMANDO_KEYCHAIN is off)")
	}
	switch keychainOS {
	case "darwin":
		if fi, err := os.Stat(securityTool); err != nil || fi.IsDir() {
			return "", errors.New("macOS's security tool is missing from " + securityTool)
		}
		return "macOS keychain", nil
	case "linux":
		if systemTool("secret-tool") == "" {
			return "", errors.New("secret-tool is not installed in " + strings.Join(toolDirs, ", ") + " (install it with apt install libsecret-tools)")
		}
		return "Secret Service (secret-tool)", nil
	case "windows":
		if err := credAvailable(); err != nil {
			return "", err
		}
		return "Windows Credential Manager", nil
	}
	return "", fmt.Errorf("no keychain support on %s", keychainOS)
}

// defaultKeychainTimeout bounds `security default-keychain`.
var defaultKeychainTimeout = 3 * time.Second

var (
	defaultKCMu   sync.Mutex
	defaultKCSeen = map[string]error{} // securityTool + HOME -> the answer
)

// macDefaultKeychain is nil unless komando would use the login keychain
// on macOS and this user has no default keychain. `security
// add-generic-password` without a keychain file then makes macOS show a
// "Keychain Not Found" dialog on the person's screen (a changed HOME:
// sudo -E, a sandbox, CI, a test run; or no login keychain), while
// `security default-keychain` only exits 1, with no dialog. So komando
// asks that first, once per process.
func macDefaultKeychain() error {
	if keychainOS != "darwin" || keychainFile() != "" {
		return nil
	}
	home := os.Getenv("HOME")
	id := securityTool + "\x00" + home
	defaultKCMu.Lock()
	defer defaultKCMu.Unlock()
	if err, ok := defaultKCSeen[id]; ok {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultKeychainTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, securityTool, "default-keychain")
	c.WaitDelay = time.Second
	var err error
	if out, rerr := c.CombinedOutput(); rerr != nil || len(bytes.TrimSpace(out)) == 0 {
		err = fmt.Errorf("no default macOS keychain for this user (HOME=%s); open Keychain Access, or run komando with your usual HOME", home)
	}
	defaultKCSeen[id] = err
	return err
}

// autoKeychainTool is KeychainTool for a keychain use komando makes on its
// own (a new store's key, the store's change count) and for `secret
// keychain`: on macOS it also needs a default keychain, so komando never
// makes macOS show a dialog. A use nobody asked for then goes on without
// the keychain.
func autoKeychainTool() (string, error) {
	tool, err := KeychainTool()
	if err != nil {
		return "", err
	}
	if err := macDefaultKeychain(); err != nil {
		return "", err
	}
	return tool, nil
}

// ErrKeychainTaken: the keychain already holds another key under this
// komando folder's name, most likely the only key of a vault that was
// moved aside, so komando does not replace it.
var ErrKeychainTaken = errors.New("another vault's key is already in the keychain for this komando folder")

func keychainPut(key []byte) error { return keychainPutCtx(context.Background(), key) }

// keychainPutCtx stores key under this komando home's name. macOS refuses
// the add when an item is there already, but `secret-tool store` replaces
// one with the same attributes in the default collection (a locked one
// asks to be unlocked first, then replaces), so the callers first make sure
// there is none (keychainHas).
func keychainPutCtx(ctx context.Context, key []byte) error {
	v := hex.EncodeToString(key)
	switch keychainOS {
	case "darwin":
		line := fmt.Sprintf("add-generic-password -a %s -s %q -l %q -w %s", keychainAccount, keychainService(), keychainService(), v)
		if kc := keychainFile(); kc != "" {
			line += fmt.Sprintf(" %q", kc)
		}
		return run(keychainCmdCtx(ctx, "-i"), line+"\n")
	case "linux":
		return run(keychainCmdCtx(ctx, "store", "--label="+keychainService(), "service", keychainService(), "account", keychainAccount), v)
	case "windows":
		return credWrite(keychainService(), keychainAccount, []byte(v))
	}
	_, err := KeychainTool()
	return err
}

func keychainGet() ([]byte, error) { return keychainGetCtx(context.Background()) }

// keychainGetCtx reads the key; errNoKeychainKey when the tool finds none
// it can read (security exit 44; secret-tool exit 1 with no output). On
// Linux that is not proof there is none: `secret-tool lookup` says the
// same for an item in a locked collection (a dismissed unlock prompt,
// KeePassXC while locked), so keychainHas decides before anything is
// stored.
func keychainGetCtx(ctx context.Context) ([]byte, error) {
	if _, err := KeychainTool(); err != nil {
		return nil, err
	}
	if keychainOS == "windows" {
		b, err := credRead(keychainService())
		if err != nil {
			if errors.Is(err, errNoKeychainKey) {
				return nil, err
			}
			return nil, fmt.Errorf("the vault key is not in the Windows Credential Manager (%v)", err)
		}
		key, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(key) != 32 {
			return nil, errors.New("the Credential Manager holds something else under komando's vault key name")
		}
		return key, nil
	}
	var c *exec.Cmd
	switch keychainOS {
	case "darwin":
		args := []string{"find-generic-password", "-a", keychainAccount, "-s", keychainService(), "-w"}
		if kc := keychainFile(); kc != "" {
			args = append(args, kc)
		}
		c = keychainCmdCtx(ctx, args...)
	default:
		c = keychainCmdCtx(ctx, "lookup", "service", keychainService(), "account", keychainAccount)
	}
	var errb bytes.Buffer
	c.Stderr = &errb
	b, err := c.Output()
	var ee *exec.ExitError
	if err != nil && ctx.Err() == nil && errors.As(err, &ee) {
		code := ee.ExitCode()
		if (keychainOS == "darwin" && code == 44) || (keychainOS != "darwin" && code == 1 && len(bytes.TrimSpace(b)) == 0 && errb.Len() == 0) {
			return nil, errNoKeychainKey
		}
	}
	if err != nil {
		return nil, fmt.Errorf("the vault key is not in the keychain (%s); unlock the keychain and try again", strings.TrimSpace(firstLine(strings.TrimSpace(errb.String()), err.Error())))
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("the keychain holds something else under komando's vault key name")
	}
	return key, nil
}

// keychainHas says whether the keychain holds an item under this home's
// name (the attributes keychainPutCtx stores it with), and an error when
// it cannot tell. macOS: find-generic-password without -w reads only the
// item's attributes, from a locked keychain too; exit 44 means there is
// none. Linux: a search cannot see into every locked collection (KeePassXC
// skips locked databases; gnome-keyring lists their items), and `secret-tool
// store` goes to the default collection and replaces an item there once it
// is unlocked. So the default collection must be unlocked first
// (defaultCollectionUnlocked); then `secret-tool search --all` lists a
// matching item in it ("[/org/freedesktop/secrets/...]" and its
// attributes; komando never shows this output) and exits 0 with no output
// when there is none. Any other answer (locked, an error, output only on
// stderr, ctx ending) is "cannot tell".
func keychainHas(ctx context.Context) (bool, error) {
	if _, err := KeychainTool(); err != nil {
		return false, err
	}
	if keychainOS == "windows" { // a lookup reads the item; the Credential Manager has no locked state
		_, err := credRead(keychainService())
		if errors.Is(err, errNoKeychainKey) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("cannot tell whether the Credential Manager holds a vault key for this komando folder (%v)", err)
		}
		return true, nil
	}
	var c *exec.Cmd
	switch keychainOS {
	case "darwin":
		args := []string{"find-generic-password", "-a", keychainAccount, "-s", keychainService()}
		if kc := keychainFile(); kc != "" {
			args = append(args, kc)
		}
		c = keychainCmdCtx(ctx, args...)
	default:
		if err := defaultCollectionUnlocked(ctx); err != nil {
			return false, fmt.Errorf("cannot tell whether the keychain holds a vault key for this komando folder (%v); unlock the keychain (your keyring or KeePassXC) and try again", err)
		}
		c = keychainCmdCtx(ctx, "search", "--all", "service", keychainService(), "account", keychainAccount)
	}
	var outb, errb bytes.Buffer
	c.Stdout, c.Stderr = &outb, &errb
	err := c.Run()
	found, quiet := len(bytes.TrimSpace(outb.Bytes())) > 0, errb.Len() == 0
	var ee *exec.ExitError
	switch {
	case ctx.Err() != nil:
		err = ctx.Err()
	case err == nil && (keychainOS == "darwin" || found):
		return true, nil
	case err == nil && quiet:
		return false, nil
	case keychainOS == "darwin" && errors.As(err, &ee) && ee.ExitCode() == 44:
		return false, nil
	case err == nil:
		err = errors.New("unexpected output")
	}
	return false, fmt.Errorf("cannot tell whether the keychain holds a vault key for this komando folder (%s); unlock the keychain and try again", strings.TrimSpace(firstLine(strings.TrimSpace(errb.String()), err.Error())))
}

// secretsDefault is the Secret Service's default collection, where
// `secret-tool store` puts an item.
const secretsDefault = "/org/freedesktop/secrets/aliases/default"

// defaultCollectionUnlocked is nil only when the Secret Service says its
// default collection is unlocked, read with gdbus or busctl from a system
// folder (reading the Locked property asks no one to unlock anything). A
// locked collection, no such tool, an error or any other answer is an
// error: komando then cannot tell what that collection holds.
func defaultCollectionUnlocked(ctx context.Context) error {
	var tool, want string
	var args []string
	if tool = systemTool("gdbus"); tool != "" {
		args = []string{"call", "--session", "--dest", "org.freedesktop.secrets", "--object-path", secretsDefault,
			"--method", "org.freedesktop.DBus.Properties.Get", "org.freedesktop.Secret.Collection", "Locked"}
		want = "(<false>,)"
	} else if tool = systemTool("busctl"); tool != "" {
		args = []string{"--user", "get-property", "org.freedesktop.secrets", secretsDefault, "org.freedesktop.Secret.Collection", "Locked"}
		want = "b false"
	} else {
		return errors.New("neither gdbus nor busctl is installed to ask whether the keychain is locked")
	}
	c := exec.CommandContext(ctx, tool, args...)
	c.WaitDelay = time.Second
	var outb, errb bytes.Buffer
	c.Stdout, c.Stderr = &outb, &errb
	err := c.Run()
	got := strings.TrimSpace(outb.String())
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case err != nil:
		return fmt.Errorf("%s: %s", filepath.Base(tool), strings.TrimSpace(firstLine(strings.TrimSpace(errb.String()), err.Error())))
	case got == want:
		return nil
	case got == "(<true>,)" || got == "b true":
		return errors.New("the default keychain collection is locked")
	}
	return fmt.Errorf("%s gave an unexpected answer about the keychain's lock", filepath.Base(tool))
}

func keychainDel() error {
	switch keychainOS {
	case "darwin":
		args := []string{"delete-generic-password", "-a", keychainAccount, "-s", keychainService()}
		if kc := keychainFile(); kc != "" {
			args = append(args, kc)
		}
		return run(keychainCmd(args...), "")
	case "linux":
		if _, err := KeychainTool(); err != nil {
			return err
		}
		return run(keychainCmd("clear", "service", keychainService(), "account", keychainAccount), "")
	case "windows":
		return credDelete(keychainService())
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

// keychainNewKey is the key of a new vault and whether the keychain keeps
// it. A key already there under this home's name is used, never replaced:
// it may open a vault that was moved aside (a backup of this folder). A new
// random key goes in only when the keychain finds no key it can read and,
// on Linux, keychainHas says there is no item under this name; it counts
// only once it reads back the same. When the keychain cannot tell (locked,
// a dismissed prompt, an error, a call past newKeyTimeout), nothing is
// stored in it: the new vault keeps its key in store.key, which `komando
// doctor` points out.
func keychainNewKey() ([]byte, bool) {
	if _, err := autoKeychainTool(); err != nil {
		return nil, false
	}
	ctx := func() (context.Context, context.CancelFunc) {
		return context.WithTimeout(context.Background(), newKeyTimeout)
	}
	get := func() ([]byte, error) {
		c, cancel := ctx()
		defer cancel()
		return keychainGetCtx(c)
	}
	k, err := get()
	if err == nil {
		return k, true
	}
	if !errors.Is(err, errNoKeychainKey) {
		return nil, false
	}
	if keychainOS != "darwin" { // macOS refuses to add over an item; secret-tool and CredWrite replace it
		c, cancel := ctx()
		has, err := keychainHas(c)
		cancel()
		if err != nil || has {
			return nil, false
		}
	}
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, false
	}
	c, cancel := ctx()
	err = keychainPutCtx(c, key)
	cancel()
	if err != nil {
		return nil, false
	}
	back, err := get()
	if err != nil || !bytes.Equal(back, key) {
		return nil, false
	}
	return key, true
}

// KeyToKeychain moves the vault key from store.key into the keychain. It
// never replaces a key the keychain already holds for this komando folder
// (ErrKeychainTaken): that one may be the only key of a vault moved aside.
// The same key there (a move that stopped before vault.json said so) is
// fine. When keychainHas cannot tell (on Linux, a locked default
// collection among other things) it stores nothing and asks for the
// keychain to be unlocked first.
func KeyToKeychain() (string, error) { return sealedKeyToKeychain() }

// keychainAdopt puts key in the keychain for this komando folder, unless
// it is there already. It never replaces another key there
// (ErrKeychainTaken), and checks that the keychain gives it back.
func keychainAdopt(key []byte) error {
	has, err := keychainHas(context.Background())
	if err != nil {
		return err
	}
	if has {
		back, err := keychainGet()
		if errors.Is(err, errNoKeychainKey) { // listed, but lookup finds nothing: locked
			return errors.New("the keychain holds a vault key for this komando folder but keeps it locked; unlock the keychain and try again")
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(back, key) {
			return fmt.Errorf("%w (%s, account %s); komando does not replace it, as it may be the only key of a vault you moved aside: put that vault back, or once no vault needs that key, delete the item from the keychain yourself, then run it again", ErrKeychainTaken, keychainService(), keychainAccount)
		}
	} else if err := keychainPut(key); err != nil {
		return err
	}
	back, err := keychainGet()
	if err != nil || !bytes.Equal(back, key) {
		return fmt.Errorf("the keychain did not keep the key: %v", err)
	}
	return nil
}

// KeyToFile moves the store key back from the keychain into a key file.
func KeyToFile() error { return sealedKeyToFile() }
