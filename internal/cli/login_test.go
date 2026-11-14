package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// keyOnlyServer is a loopback SSH server that lets in only the key pub
// and answers every command like a server where sudo needs a password.
func keyOnlyServer(t *testing.T, pub ssh.PublicKey) string {
	t.Helper()
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		if sshx.SameKey(k, pub) {
			return nil, nil
		}
		return nil, errors.New("not this key")
	}}
	cfg.AddHostKey(trustSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &fakeServer{}
	s.reply("u\nweb1\nsudo-no\n")
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, cfg)
		}
	}()
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
}

// scratchAgentWith serves an in-process ssh-agent on a short socket path
// under /tmp and points SSH_AUTH_SOCK at it (never the user's own agent).
func scratchAgentWith(t *testing.T, keys ...any) {
	t.Helper()
	base := "/tmp" // short: a Unix socket path has a small limit
	if runtime.GOOS == "windows" {
		base = "" // no /tmp there; the user's TEMP is short enough
	}
	dir, err := os.MkdirTemp(base, "kag")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ln, err := net.Listen("unix", filepath.Join(dir, "a.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	kr := agent.NewKeyring()
	for _, k := range keys {
		if err := kr.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = agent.ServeAgent(kr, c); c.Close() }()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", ln.Addr().String())
}

// The macOS case: `import ssh-config` makes an encrypted ~/.ssh/id_ed25519
// the host's --identity, and ssh-agent holds it. `komando test` logs in
// with the agent's copy, as ssh does. Without it, the error names commands
// that work, and following them logs in with the passphrase from the vault.
func TestTestWithEncryptedIdentityInAgent(t *testing.T) {
	invHome(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir reads USERPROFILE on Windows
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	const pass = "correct horse battery"
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	addr := keyOnlyServer(t, signer.PublicKey())
	mustRun(t, "host", "add", "web1", "u@"+addr, "--identity", keyPath)

	scratchAgentWith(t, priv)
	mustRun(t, "test", "web1")

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	scratchAgentWith(t, other)
	d, top := invRun(t, "test", "web1")
	if top == nil || top.Code != "KEY_PASSPHRASE_REQUIRED" || top.Exit != out.ExitUsage {
		t.Fatalf("want KEY_PASSPHRASE_REQUIRED exit 2, got %+v", top)
	}
	res, _ := d["results"].([]any)
	if len(res) != 1 {
		t.Fatalf("results: %v", d)
	}
	hint, _ := res[0].(map[string]any)["error"].(map[string]any)["hint"].(string)
	for _, cmd := range []string{
		"`ssh-add ~/.ssh/id_ed25519`",
		"`komando secret set id_ed25519-pass`",
		"`komando key add id_ed25519 ~/.ssh/id_ed25519 --passphrase-ref secret:id_ed25519-pass`",
		"`komando host edit web1 --key id_ed25519 --unset identity`",
	} {
		if !strings.Contains(hint, cmd) {
			t.Errorf("hint lacks %s: %s", cmd, hint)
		}
	}

	// follow the hint (a value from --from-env instead of the hidden prompt)
	t.Setenv("KOMANDO_TEST_KEY_PASS", pass)
	mustRun(t, "secret", "set", "id_ed25519-pass", "--from-env", "KOMANDO_TEST_KEY_PASS")
	mustRun(t, "key", "add", "id_ed25519", keyPath, "--passphrase-ref", "secret:id_ed25519-pass")
	mustRun(t, "host", "edit", "web1", "--key", "id_ed25519", "--unset", "identity")
	t.Setenv("SSH_AUTH_SOCK", "")
	mustRun(t, "test", "web1")
}

// sshx words the HOSTKEY_MISMATCH hint for a person only when interactive()
// says one is at the terminal.
func TestHostKeyHintFollowsInteractive(t *testing.T) {
	// a person's call, whatever a test before left in tcl: not an agent,
	// not in CI, and the one call running (sshx.PersonAtTerminal)
	t.Setenv("CI", "")
	savedTerm, savedCaller := tcl.terminal, tcl.caller()
	t.Cleanup(func() { tcl.terminal = savedTerm; tcl.setCaller(savedCaller) })
	tcl.setCaller(engine.Caller{Kind: engine.Person})
	if soleCall() != tcl {
		t.Fatal("tcl is not the one call running")
	}
	tcl.terminal = true
	if !strings.Contains(sshx.HostKeyMismatch("web1", "SHA256:x", nil).Hint, "compare this fingerprint") {
		t.Error("a person gets the agent's hint")
	}
	tcl.terminal = false
	if !strings.Contains(sshx.HostKeyMismatch("web1", "SHA256:x", nil).Hint, "report this to the user") {
		t.Error("an agent or a script gets the person's hint")
	}
}

// `komando login aws` is the AWS login, so a server named aws could never be
// logged in to: add, rename and import refuse the names of login's
// subcommands, in any case.
func TestLoginCloudNamesReserved(t *testing.T) {
	var subs []string
	for _, c := range loginCmd(tcl).Commands() {
		subs = append(subs, c.Name())
	}
	slices.Sort(subs)
	if want := slices.Sorted(slices.Values(loginClouds)); !slices.Equal(subs, want) {
		t.Fatalf("login subcommands %v, loginClouds %v", subs, want)
	}
	invHome(t)
	for _, n := range []string{"aws", "GCP", "azure"} {
		e := wantCode(t, "USAGE", "host", "add", n, "u@192.0.2.7")
		if !strings.Contains(e.Message, "komando login") {
			t.Errorf("%s: %+v", n, e)
		}
	}
	mustRun(t, "host", "add", "aws-1", "u@192.0.2.7")
	wantCode(t, "USAGE", "host", "mv", "aws-1", "aws")
	f := filepath.Join(t.TempDir(), "h.json")
	os.WriteFile(f, []byte(`{"format":"komando-export/1","hosts":[{"name":"azure","address":"192.0.2.8"},{"name":"b1","address":"192.0.2.9"}]}`), 0o600)
	d, e := invRun(t, "import", "komando", f)
	if e == nil || e.Code != "IMPORT_INCOMPLETE" || fmt.Sprint(d["hosts"]) != "[b1]" || !strings.Contains(fmt.Sprint(d["skipped"]), "azure") {
		t.Errorf("import: %v %+v", d, e)
	}
	if p := formNameProblem(&store.State{}, "host", "aws"); !strings.Contains(p, "cloud login") {
		t.Errorf("form: %q", p)
	}
}

// logout of a name that is neither a server nor a kept login is an error,
// as login's is; --all with names is refused, not read as --all.
func TestLogoutArgs(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@192.0.2.7")
	if d := mustRun(t, "logout", "web1"); fmt.Sprint(d["not_logged_in"]) != "[web1]" {
		t.Errorf("logout web1: %v", d)
	}
	wantCode(t, "HOST_NOT_FOUND", "logout", "nosuch")
	wantCode(t, "USAGE", "logout", "--all", "web1")
	mustRun(t, "logout", "--all")
}

// awsHome points the AWS SDK at a throwaway config (never the person's own
// ~/.aws) with an SSO profile, a role assumed from it and a keys-only
// profile without keys.
func awsHome(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte("[profile sso]\nsso_session = s\nsso_account_id = 1\nsso_role_name = r\n[sso-session s]\n"+
		"sso_start_url = https://x.awsapps.com/start\nsso_region = eu-west-1\n"+
		"[profile role]\nrole_arn = arn:aws:iam::111122223333:role/r\nsource_profile = sso\n"+
		"[profile plain]\nregion = eu-west-1\n"), 0o600)
	t.Setenv("AWS_CONFIG_FILE", cfg)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for _, k := range []string{"AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		t.Setenv(k, "")
	}
}

// An AI agent cannot log in to AWS (the sign-in is in a person's browser):
// it gets NEEDS_PERSON with the exact command, a dry run says so in
// would_be_blocked, and a script gets NEEDS_TERMINAL.
func TestLoginAWSNeedsPerson(t *testing.T) {
	invHome(t)
	awsHome(t)
	e := wantCode(t, "NEEDS_TERMINAL", "login", "aws", "--profile", "sso")
	if !strings.Contains(e.Hint, "komando login aws --profile sso") {
		t.Errorf("script hint %q", e.Hint)
	}
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	e = wantCode(t, "NEEDS_PERSON", "login", "aws", "--profile", "sso")
	if e.Exit != out.ExitPolicy || !strings.Contains(e.Hint, "`komando login aws --profile sso`") {
		t.Errorf("agent: exit %d hint %q", e.Exit, e.Hint)
	}
	if e := wantCode(t, "NEEDS_PERSON", "login", "aws", "--profile", "it's"); !strings.Contains(e.Hint, `--profile 'it'\''s'`) {
		t.Errorf("profile not quoted: %q", e.Hint)
	}
	d := mustRun(t, "--dry-run", "login", "aws", "--profile", "role")
	if d["sso_start_url"] != "https://x.awsapps.com/start" || d["_meta"] == nil {
		t.Errorf("dry run %v", d)
	} else if wb, _ := d["_meta"].(map[string]any)["would_be_blocked"].(map[string]any); wb["code"] != "NEEDS_PERSON" {
		t.Errorf("would_be_blocked %v", d["_meta"])
	}
	if e := wantCode(t, "AWS_FAILED", "--dry-run", "login", "aws", "--profile", "plain"); !strings.Contains(e.Hint, "~/.aws/credentials") {
		t.Errorf("non-SSO profile hint %q", e.Hint)
	}
	wantCode(t, "AWS_PROFILE_NOT_FOUND", "--dry-run", "login", "aws", "--profile", "nope")
}

// A profile without SSO and without keys is not "log in again": `komando
// login aws` cannot help it, so the hint says where its keys go.
func TestAWSErrNoDeadEnd(t *testing.T) {
	awsHome(t)
	_, err := awsCredentials(context.Background(), "plain")
	if e := toErr(err); e.Code != "AWS_FAILED" || strings.Contains(e.Hint, "komando login aws --profile") || !strings.Contains(e.Hint, "[plain]") {
		t.Errorf("keys-only profile: %+v", e)
	}
	_, err = awsCredentials(context.Background(), "role")
	if e := toErr(err); e.Code != "AWS_LOGIN_REQUIRED" || !strings.Contains(e.Hint, "komando login aws --profile role") {
		t.Errorf("role from an SSO profile: %+v", e)
	}
	// a role from static keys whose STS call fails: not a login either
	cfg := os.Getenv("AWS_CONFIG_FILE")
	b, _ := os.ReadFile(cfg)
	os.WriteFile(cfg, append(b, "[profile keyrole]\nrole_arn = arn:aws:iam::111122223333:role/k\nsource_profile = src\nregion = us-east-1\n"...), 0o600)
	os.WriteFile(os.Getenv("AWS_SHARED_CREDENTIALS_FILE"), []byte("[src]\naws_access_key_id = AKIA1\naws_secret_access_key = s\n"), 0o600)
	t.Setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:1")
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
	_, err = awsCredentials(context.Background(), "keyrole")
	if e := toErr(err); e.Code != "AWS_FAILED" || !strings.Contains(e.Hint, "assumes arn:aws:iam::111122223333:role/k") {
		t.Errorf("role from keys: %+v", e)
	}
	if e := toErr(awsErr("sso", context.Canceled)); e.Code != "CANCELLED" {
		t.Errorf("Ctrl-C: %+v", e)
	}
}

// login gcp and login azure are not built yet: they say so, and what works
// today, for any arguments; they never look up a server named gcp.
func TestLoginCloudComing(t *testing.T) {
	invHome(t)
	for _, c := range []string{"gcp", "azure"} {
		e := wantCode(t, "USAGE", "login", c, "my-project")
		if !strings.Contains(e.Message, "later release") || !strings.Contains(e.Hint, "--password-ref secret:") {
			t.Errorf("%s: %+v", c, e)
		}
	}
}

// `login AWS` is the AWS login (no server can be named so), and a server
// name close to aws that does not exist points at it too.
func TestLoginCloudTypos(t *testing.T) {
	invHome(t)
	if e := wantCode(t, "USAGE", "login", "AWS"); e.Hint != "komando login aws" {
		t.Errorf("AWS: %+v", e)
	}
	if e := wantCode(t, "HOST_NOT_FOUND", "login", "asw"); !strings.Contains(e.Hint, "komando login aws") {
		t.Errorf("asw: %+v", e)
	}
	if e := wantCode(t, "HOST_NOT_FOUND", "login", "web1"); strings.Contains(e.Hint, "login aws") {
		t.Errorf("web1: %+v", e)
	}
}

func TestBrowserOpener(t *testing.T) {
	const u = "https://device.sso.example/?code=AB&x=1"
	for goos, want := range map[string][]string{
		"darwin":  {"open", u},
		"linux":   {"xdg-open", u},
		"freebsd": {"xdg-open", u},
		"windows": {"rundll32", "url.dll,FileProtocolHandler", u},
	} {
		if got := browserOpener(goos, u); !slices.Equal(got, want) {
			t.Errorf("%s: %q, want %q", goos, got, want)
		}
	}
}
