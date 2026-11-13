package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"golang.org/x/crypto/ssh"
)

// invHome gives a test its own komando home and vault.
func invHome(t *testing.T) {
	t.Helper()
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long-enough")
	t.Cleanup(func() {
		tcl.flags.dryRun, tcl.flags.yes, tcl.flags.allowDangerous, store.DryRun = false, false, false, false
		tcl.out.Format = "json"
	})
}

// invRun runs komando and returns the envelope's data, or the error.
func invRun(t *testing.T, args ...string) (map[string]any, *out.Error) {
	t.Helper()
	closeStoreAtEnd(t)
	tcl.flags.dryRun, tcl.flags.yes, store.DryRun = false, false, false
	root := newRoot(tcl)
	root.SetArgs(append([]string{"-o", "json"}, args...))
	var buf bytes.Buffer
	saved := tcl.out.W
	tcl.out.W = &buf
	defer func() { tcl.out.W = saved }()
	cmd, err := root.ExecuteC()
	var oe *out.Error
	if err != nil && !errors.As(err, &oe) && isUsageErr(err) {
		err = usageErr(tcl, cmd, err) // as Execute does: a flag or argument error is USAGE
	}
	var env struct {
		Data  map[string]any `json:"data"`
		Error *out.Error     `json:"error"`
		Meta  map[string]any `json:"meta"`
	}
	if b := bytes.TrimSpace(buf.Bytes()); len(b) > 0 {
		lines := bytes.Split(b, []byte("\n"))
		_ = json.Unmarshal(lines[len(lines)-1], &env)
	}
	if env.Data != nil && env.Meta != nil {
		env.Data["_meta"] = env.Meta
	}
	if err != nil {
		var ec exitCode
		if errors.As(err, &ec) {
			if env.Error != nil {
				env.Error.Exit = int(ec)
			}
			return env.Data, env.Error
		}
		return env.Data, toErr(err)
	}
	return env.Data, nil
}

func mustRun(t *testing.T, args ...string) map[string]any {
	t.Helper()
	d, e := invRun(t, args...)
	if e != nil {
		t.Fatalf("%v: %s: %s", args, e.Code, e.Message)
	}
	return d
}

func wantCode(t *testing.T, code string, args ...string) *out.Error {
	t.Helper()
	_, e := invRun(t, args...)
	if e == nil || e.Code != code {
		t.Fatalf("%v: want %s, got %+v", args, code, e)
	}
	return e
}

func TestInvAuditLimit(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "a1", "u@10.0.0.1")
	if e := wantCode(t, "USAGE", "audit", "-n", "-1"); e.Exit != out.ExitUsage {
		t.Errorf("exit %d", e.Exit)
	}
	if d := mustRun(t, "audit", "-n", "0"); d["count"].(float64) < 1 {
		t.Errorf("-n 0 shows all: %v", d)
	}
}

func TestInvHostAddValidation(t *testing.T) {
	invHome(t)
	id := filepath.Join(t.TempDir(), "id")
	os.WriteFile(id, []byte("x"), 0o600)
	mustRun(t, "host", "add", "b1", "u@10.0.0.9")
	for _, c := range []struct {
		code string
		args []string
	}{
		{"USAGE", []string{"x@h:99999"}},
		{"USAGE", []string{"@h"}},
		{"USAGE", []string{"h", "--port", "-5"}},
		{"USAGE", []string{"h", "--user", "a b"}},
		{"USAGE", []string{"u@10.0.0.5:2201", "--port", "2200"}},
		{"USAGE", []string{"u@10.0.0.5", "--user", "v"}},
		{"VIA_NOT_FOUND", []string{"h", "--via", "nosuch"}},
		{"VIA_CYCLE", []string{"h", "--via", "n1"}},
		{"FILE_NOT_FOUND", []string{"h", "--identity", "/no/such/key"}},
		{"USAGE", []string{"h", "-g", "x y"}},
		{"USAGE", []string{"h", "-t", "tag:x"}},
		{"USAGE", []string{"h", "--label", "a,b=1"}},
	} {
		wantCode(t, c.code, append([]string{"host", "add", "n1"}, c.args...)...)
	}
	mustRun(t, "host", "add", "n2", "u@10.0.0.5:2201", "--port", "2201", "--user", "u") // agreeing is fine
	mustRun(t, "host", "add", "n1", "h", "--identity", id, "--via", "b1")
	// a loop through another host
	wantCode(t, "VIA_CYCLE", "host", "edit", "b1", "--via", "n1")
}

func TestInvProtectedTwin(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "prod", "u@db.example.com", "--protected")
	d := mustRun(t, "host", "add", "alias", "u@DB.Example.com.")
	if d["protected"] != true || d["warnings"] == nil || d["address"] != "db.example.com" {
		t.Errorf("same server under another spelling: %v", d)
	}
	mustRun(t, "conn", "add", "maria", "mysql://shop@maria:3306/shop", "--protected")
	d = mustRun(t, "conn", "add", "m2", "mysql://shop@MARIA.:3306/shop")
	if d["protected"] != true || !strings.Contains(d["url"].(string), "@maria:3306") {
		t.Errorf("conn twin: %v", d)
	}
}

func TestInvProtectedEditNeedsYes(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "jump", "u@10.0.0.1")
	mustRun(t, "host", "add", "prod", "u@10.0.0.2", "--protected")
	wantCode(t, "PROTECTED_HOST", "host", "edit", "prod", "--via", "jump")
	wantCode(t, "PROTECTED_HOST", "host", "edit", "prod", "--address", "10.0.0.3")
	d := mustRun(t, "host", "edit", "prod", "--via", "jump", "--dry-run")
	if d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("dry-run shows the stop: %v", d)
	}
	mustRun(t, "host", "edit", "prod", "--add-tag", "x") // a label is no login change
	mustRun(t, "conn", "add", "db", "postgres://a@10.0.0.5/app", "--protected")
	wantCode(t, "PROTECTED_TARGET", "conn", "edit", "db", "--via", "jump")
	wantCode(t, "PROTECTED_TARGET", "conn", "edit", "db", "--password-ref", "env:X")
}

func TestInvHostEditConflicts(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "h1", "u@10.0.0.1", "-t", "a")
	wantCode(t, "USAGE", "host", "edit", "h1")
	wantCode(t, "USAGE", "host", "edit", "h1", "--user", "x", "--unset", "user")
	wantCode(t, "USAGE", "host", "edit", "h1", "--add-tag", "x", "--rm-tag", "X")
	d := mustRun(t, "host", "edit", "h1", "--add-tag", "a")
	if d["changed"] != false {
		t.Errorf("no change: %v", d)
	}
	d = mustRun(t, "host", "edit", "H1", "-g", "web", "-t", "b")
	if d["changed"] != true || len(d["groups"].([]any)) != 1 || len(d["tags"].([]any)) != 2 {
		t.Errorf("-g/-t add, names match in any case: %v", d)
	}
}

func TestInvHostRmBatch(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "a", "u@10.0.0.1")
	mustRun(t, "host", "add", "b", "u@10.0.0.2", "--via", "a")
	wantCode(t, "HOST_IN_USE", "host", "rm", "a")
	mustRun(t, "host", "rm", "a", "b")
}

func TestInvHostImportJSON(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "prod", "u@10.0.0.2", "--protected")
	f := filepath.Join(t.TempDir(), "h.json")
	os.WriteFile(f, []byte(`{"format":"komando-export/1","hosts":[
		{"name":"prod","address":"10.9.9.9"},
		{"name":"px","address":"10.0.0.7","proxy_command":"nc %h %p"},
		{"name":"bad","address":"10.0.0.8","port":99999}]}`), 0o600)
	// a proxy command from a file is dropped, protected and invalid hosts skipped
	d, e := invRun(t, "import", "komando", f, "--overwrite")
	if e == nil || e.Code != "IMPORT_INCOMPLETE" || fmt.Sprint(d["hosts"]) != "[px]" {
		t.Fatalf("import komando --overwrite: %v %+v", d, e)
	}
	if s := fmt.Sprint(d["skipped"], d["not_imported"]); !strings.Contains(s, "prod") || !strings.Contains(s, "bad") || !strings.Contains(s, "proxy_command") {
		t.Errorf("protected, invalid hosts and the proxy command are reported: %s", s)
	}
	if st, _ := store.Load(); st.Hosts["px"].ProxyCommand != "" {
		t.Error("a proxy command came in from a file")
	}
	mustRun(t, "host", "rm", "px")
	// prod exists (skipped, fine), bad is refused: the rest comes in, and
	// the refusal makes the import fail (exit 1), not a quiet skip
	d, e = invRun(t, "import", "komando", f)
	if e == nil || e.Code != "IMPORT_INCOMPLETE" || e.Exit != 1 || len(d["hosts"].([]any)) != 1 {
		t.Errorf("import komando: %v %+v", d, e)
	}
}

func TestInvTrustDryRun(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "h", "u@10.0.0.1")
	k, _, _, _, _ := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"))
	if _, err := sshx.PinHostKey("10.0.0.1:22", k, false); err != nil {
		t.Fatal(err)
	}
	d := mustRun(t, "host", "trust", "h", "--reset", "--dry-run")
	if r := trustRow0(d); r["would_remove_entries"].(float64) != 1 || r["would_fetch_from"] != "the server directly" {
		t.Errorf("count: %v", d)
	}
	if pins, _ := sshx.PinnedKeys("10.0.0.1:22"); len(pins) != 1 {
		t.Error("--dry-run changed the pins")
	}
}

func TestInvKeys(t *testing.T) {
	invHome(t)
	wantCode(t, "USAGE", "key", "gen", "k", "--type", "rsa", "-b", "1024")
	wantCode(t, "USAGE", "key", "gen", "k", "-C", "a\nssh-rsa AAAA evil")
	d := mustRun(t, "key", "gen", "k", "--type", "ECDSA", "--dry-run")
	if d["fingerprint"] != nil || d["action"] != "would_add" {
		t.Errorf("dry-run: %v", d)
	}
	mustRun(t, "key", "gen", "k", "--type", "ecdsa", "-b", "384")
	st, _ := loadState()
	pub := filepath.Join(t.TempDir(), "k.pub")
	os.WriteFile(pub, []byte(st.Keys["k"].PublicKey+"\n"), 0o600)
	e := wantCode(t, "KEY_INVALID", "key", "add", "p", pub)
	if !strings.Contains(e.Hint, "public key") || e.Exit != out.ExitUsage {
		t.Errorf("hint: %+v", e)
	}
	wantCode(t, "USAGE", "key", "add", "p", pub, "--passphrase-ref", "pw123")
	wantCode(t, "USAGE", "key", "edit", "k", "--passphrase-ref", "pw123")
	// key edit says what it did, warns about a secret not stored yet, and
	// clears with --unset like host and conn edit ('' still works)
	d = mustRun(t, "key", "edit", "k", "--passphrase-ref", "secret:kp")
	if d["action"] != "changed" || !strings.Contains(fmt.Sprint(d["warnings"]), "secret kp is not in the vault") {
		t.Errorf("key edit: %v", d)
	}
	if d = mustRun(t, "key", "edit", "k", "--passphrase-ref", "secret:kp"); d["action"] != "unchanged" {
		t.Errorf("same again: %v", d)
	}
	wantCode(t, "USAGE", "key", "edit", "k", "--unset", "passphrase-ref", "--passphrase-ref", "secret:kp")
	wantCode(t, "USAGE", "key", "edit", "k", "--unset", "path")
	if d = mustRun(t, "key", "edit", "k", "--unset", "passphrase-ref"); d["passphrase_ref"] != nil || d["action"] != "changed" {
		t.Errorf("--unset: %v", d)
	}
	mustRun(t, "key", "edit", "k", "--passphrase-ref", "secret:kp")
	mustRun(t, "key", "edit", "k", "--passphrase-ref", "")

	ext := filepath.Join(t.TempDir(), "ext")
	b, _ := store.ReadPrivateKey(st.Keys["k"])
	os.WriteFile(ext, b, 0o600)
	// the same key under a second name is added, with a warning naming the first
	if d = mustRun(t, "key", "add", "ext", ext); !strings.Contains(fmt.Sprint(d["warnings"]), "same key as k") {
		t.Errorf("same key twice: %v", d)
	}
	d = mustRun(t, "key", "rm", "ext", "--delete-file")
	if d["file_deleted"] != false {
		t.Errorf("an added key's file stays: %v", d)
	}
	if _, err := os.Stat(ext); err != nil {
		t.Error("the file was deleted")
	}
	audit := mustRun(t, "audit", "-n", "0", "--command", "key.")
	if audit["count"].(float64) < 4 {
		t.Errorf("key changes are audited: %v", audit["count"])
	}
}

func TestInvCleanPubLine(t *testing.T) {
	invHome(t)
	mustRun(t, "key", "gen", "k")
	st, _ := loadState()
	f := filepath.Join(t.TempDir(), "x.pub")
	os.WriteFile(f, []byte(st.Keys["k"].PublicKey+" a\rb\n"), 0o600)
	_, line, err := deployKey(tcl, st, f)
	if err != nil || strings.ContainsAny(line, "\r\n") {
		t.Errorf("line %q, %v", line, err)
	}
}

func TestInvSecrets(t *testing.T) {
	invHome(t)
	for _, n := range []string{"s1", "s2"} {
		t.Setenv("INV_S", "value-"+n)
		mustRun(t, "secret", "set", n, "--from-env", "INV_S")
	}
	d := mustRun(t, "secret", "get", "s1")
	if _, ok := d["length"]; ok {
		t.Error("secret get leaks the length")
	}
	e := wantCode(t, "SECRET_NOT_FOUND", "secret", "get", "s3")
	if e.Suggestion == "" || !strings.Contains(e.Hint, e.Suggestion) {
		t.Errorf("no suggestion: %+v", e)
	}
	mustRun(t, "host", "add", "prod", "u@10.0.0.2", "--protected", "--password-ref", "secret:s1")
	wantCode(t, "PROTECTED_TARGET", "secret", "set", "s1", "--from-env", "INV_S")
	d = mustRun(t, "secret", "set", "s2", "--from-env", "INV_S")
	if d["replaced"] != true {
		t.Errorf("replaced: %v", d)
	}
	wantCode(t, "SECRET_IN_USE", "secret", "rm", "s1", "s2")
	mustRun(t, "host", "rm", "prod", "--yes")
	wantCode(t, "POLICY_BLOCKED", "secret", "rm", "s1", "s2") // a deleted secret has no copy (OD-7)
	personTypes(t, "2")                                       // a person types how many go
	mustRun(t, "secret", "rm", "s1", "s2")
	d = mustRun(t, "secret", "list")
	if d["count"].(float64) != 0 {
		t.Errorf("both removed: %v", d)
	}
}

func TestInvGroups(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "a", "u@10.0.0.1", "-g", "web")
	mustRun(t, "host", "add", "b", "u@10.0.0.2", "-g", "web")
	mustRun(t, "host", "add", "c", "u@10.0.0.3")
	wantCode(t, "USAGE", "group", "add", "bad name", "a")
	if e := wantCode(t, "GROUP_NOT_FOUND", "group", "rm", "wbe", "a"); !strings.Contains(e.Hint, "web") || e.Exit != out.ExitNotFound {
		t.Errorf("did you mean: %+v", e)
	}
	d := mustRun(t, "group", "rm", "web", "all", "--dry-run")
	if got := d["would_remove"].([]any); len(got) != 2 {
		t.Errorf("only members: %v", got)
	}
	d = mustRun(t, "group", "list", "WEB")
	if len(d["members"].([]any)) != 2 {
		t.Errorf("members: %v", d)
	}
	mustRun(t, "group", "rm", "web")
	wantCode(t, "GROUP_NOT_FOUND", "group", "list", "web")
}

func TestInvConfig(t *testing.T) {
	invHome(t)
	wantCode(t, "USAGE", "config", "set", "max_output_bytes", "1")
	wantCode(t, "USAGE", "config", "set", "default_timeout", "0s")
	wantCode(t, "USAGE", "config", "set", "parallel", "-3")
	wantCode(t, "USAGE", "config", "set", "vpn_idle", "--", "-1s")
	if e := wantCode(t, "UNKNOWN_SETTING", "config", "set", "paralel", "3"); !strings.Contains(e.Hint, "parallel") {
		t.Errorf("hint %q", e.Hint)
	}
	mustRun(t, "config", "set", "vpn_idle", "10m") // shorter: no yes needed (0 or longer is a safety setting)
	d := mustRun(t, "config", "set", "parallel", "20")
	if d["old"] != "10" || d["value"] != "20" {
		t.Errorf("set: %v", d)
	}
	if d := mustRun(t, "config", "get", "parallel"); d["value"] != "20" || d["default"] != "10" {
		t.Errorf("get: %v", d)
	}
	a := mustRun(t, "audit", "--command", "config.set")
	if a["count"].(float64) != 2 {
		t.Errorf("config changes audited: %v", a)
	}
}

func TestInvPolicy(t *testing.T) {
	invHome(t)
	wantCode(t, "BUILTIN_RULE", "policy", "rm", "rm-root")
	wantCode(t, "RULE_NOT_FOUND", "policy", "rm", "nonexistent")
	wantCode(t, "USAGE", "policy", "deny", " ")
	mustRun(t, "policy", "deny", `kubectl\s+apply`)
	mustRun(t, "policy", "rm", policy.CustomID(`kubectl\s+apply`), "--yes")
	if a := mustRun(t, "audit", "--command", "policy.rm"); a["count"].(float64) != 1 {
		t.Errorf("policy rm is audited as policy.rm: %v", a)
	}
	if e := wantCode(t, "POLICY_BLOCKED", "policy", "check", "rm -rf //"); e.Exit != out.ExitPolicy {
		t.Errorf("exit %d", e.Exit)
	}
	mustRun(t, "policy", "check", "grep mkfs notes.txt")
	if a := mustRun(t, "audit", "--command", "policy."); a["count"].(float64) != 2 {
		t.Errorf("policy changes audited: %v", a)
	}
}

func TestInvSelectors(t *testing.T) {
	st := testState()
	for expr, want := range map[string]string{
		"!dev-1":         "db-1,web-1,web-2",
		"WEB-1":          "web-1",
		"127.0.0.1:3323": "127.0.0.1:3323",
	} {
		hs, err := resolveTargets(tcl, st, expr)
		if err != nil {
			t.Errorf("%s: %v", expr, err)
			continue
		}
		if got := strings.Join(hostNames(hs), ","); got != want {
			t.Errorf("%s: got %s want %s", expr, got, want)
		}
	}
	_, err := resolveSelection(tcl, st, "@wbe")
	if e := toErr(err); !strings.Contains(e.Message, `no group named "wbe"`) || !strings.Contains(e.Hint, "@web") {
		t.Errorf("group not found: %+v", e)
	}
}

func TestInvSSHCommand(t *testing.T) {
	invHome(t)
	st := &store.State{Hosts: map[string]*store.Host{}, Keys: map[string]*store.Key{}, Vpns: map[string]*store.Vpn{}, Sessions: map[string]*store.VpnSession{}}
	st.Keys["k"] = &store.Key{Name: "k", Path: "/keys/k"}
	st.Hosts["b"] = &store.Host{Name: "b", Address: "10.0.0.1", Port: 2222, User: "jump", Key: "k"}
	st.Hosts["t"] = &store.Host{Name: "t", Address: "10.0.0.2", User: "app", Key: "k", Via: "b"}
	parts, err := sshCommandFor(tcl, st, st.Hosts["t"])
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(parts, " ")
	// the known_hosts path is quoted when it needs it (a Windows path)
	for _, want := range []string{"ProxyCommand=ssh -o ", "UserKnownHostsFile=", "-p 2222 -i /keys/k -W 10.0.0.2:22 jump@10.0.0.1", "app@10.0.0.2"} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %q in %s", want, line)
		}
	}
	st.Vpns["v"] = &store.Vpn{Name: "v", Kind: "socks", Address: "127.0.0.1:1080"}
	st.Hosts["b"].Via = "v"
	parts, _ = sshCommandFor(tcl, st, st.Hosts["t"])
	if line = strings.Join(parts, " "); !strings.Contains(line, "nc -X 5 -x 127.0.0.1:1080 %%h %%p") {
		t.Errorf("socks first hop, escaped once for nesting: %s", line)
	}
	st.Vpns["v"].Kind = "wireguard"
	if _, err := sshCommandFor(tcl, st, st.Hosts["t"]); toErr(err).Code != "VPN_NOT_FOR_OPENSSH" {
		t.Errorf("wireguard: %v", err)
	}
}

func TestInvSSHConfigNotes(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	os.WriteFile(cfg, []byte("Include missing.conf\nHost web\n  HostName %h.example.com\nHost *.lan\n  User x\n"), 0o600)
	hosts, notes, err := parseSSHConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].Address != "web.example.com" {
		t.Errorf("%%h: %+v", hosts)
	}
	j := strings.Join(notes, "\n")
	if !strings.Contains(j, "missing.conf") || !strings.Contains(j, "Host *.lan") {
		t.Errorf("notes: %q", notes)
	}
}

func TestInvDoctorInventory(t *testing.T) {
	invHome(t)
	st := &store.State{Hosts: map[string]*store.Host{}, Keys: map[string]*store.Key{}, Conns: map[string]*store.Conn{}, Vpns: map[string]*store.Vpn{}}
	st.Hosts["a"] = &store.Host{Name: "a", Address: "x", Port: 99999, Via: "nosuch", PasswordRef: "hunter2", ProxyCommand: "nc %h %p"}
	cs := inventoryChecks(tcl, st)
	var fails, warns int
	for _, c := range cs {
		if c.Warning {
			warns++
		} else if !c.OK {
			fails++
		}
	}
	if fails != 3 || warns != 1 {
		t.Errorf("fails %d warns %d: %+v", fails, warns, cs)
	}
}

func TestInvRmSelector(t *testing.T) {
	invHome(t)
	if e := wantCode(t, "TARGET_EMPTY", "test", "all"); !strings.Contains(e.Hint, "host add") {
		t.Errorf("empty inventory hint: %q", e.Hint)
	}
	mustRun(t, "host", "add", "tmp-1", "u@10.0.0.1", "-g", "old")
	mustRun(t, "host", "add", "tmp-2", "u@10.0.0.2", "-g", "old", "--via", "tmp-1")
	mustRun(t, "host", "add", "keep", "u@10.0.0.3", "--via", "tmp-1")
	mustRun(t, "host", "add", "prod", "u@10.0.0.4", "-g", "old", "--protected")
	wantCode(t, "HOST_IN_USE", "host", "rm", "tmp-*") // keep still goes through tmp-1
	mustRun(t, "host", "edit", "keep", "--unset", "via")
	wantCode(t, "PROTECTED_HOST", "host", "rm", "@old")
	d := mustRun(t, "host", "rm", "@old", "--dry-run")
	if got := d["would_remove"].([]any); len(got) != 3 || d["removed"] != nil {
		t.Errorf("dry-run lists all: %v", got)
	}
	mustRun(t, "host", "rm", "tmp-*")
	if d := mustRun(t, "list"); d["count"].(float64) != 2 {
		t.Errorf("tmp-* removed: %v", d)
	}
	mustRun(t, "conn", "add", "r1", "rediss://default@10.0.0.7:6379/0")
	mustRun(t, "conn", "add", "r2", "rediss://default@10.0.0.8:6379/0")
	if d := mustRun(t, "conn", "rm", "kind:redis"); len(d["removed"].([]any)) != 2 {
		t.Errorf("conn rm selector: %v", d)
	}
	wantCode(t, "HOST_NOT_FOUND", "host", "rm", "nosuch")
}

func TestInvEmptyListText(t *testing.T) {
	if s := (targetList{Targets: []targetRow{}, empty: true}).Text(); !strings.Contains(s, "No servers, databases or other services yet") || strings.Contains(s, "conns") {
		t.Errorf("text: %q", s)
	}
}

// Moving to another computer keeps the servers that log in with a
// keychain key: the export names the keys (whose files it never holds),
// and the import adds the server and says how to bring its key along,
// instead of leaving the server out.
func TestExportImportKeepsServersWithKeys(t *testing.T) {
	invHome(t)
	mustRun(t, "key", "gen", "deploy")
	mustRun(t, "host", "add", "db1", "root@10.0.0.20", "--key", "deploy")
	mustRun(t, "host", "add", "web1", "u@10.0.0.21")
	f := filepath.Join(t.TempDir(), "backup.json")
	d := mustRun(t, "export", "--to", f)
	// a key komando made has no file: it is named as sealed instead
	if fmt.Sprint(d["keys_needed"]) != "[deploy]" || fmt.Sprint(d["keys_sealed"]) != "[deploy]" || d["key_files"] != nil {
		t.Errorf("export names the key as sealed, with no file: %v", d)
	}
	b, _ := os.ReadFile(f)
	if strings.Contains(string(b), "PRIVATE KEY") || !strings.Contains(string(b), `"keys_needed": [`) {
		t.Errorf("export file: %s", b)
	}

	invHome(t) // the other computer
	d = mustRun(t, "import", "komando", f)
	if len(d["hosts"].([]any)) != 2 {
		t.Fatalf("both servers come in: %v", d)
	}
	if !strings.Contains(fmt.Sprint(d), "run `komando key add deploy PATH`") || !strings.Contains(fmt.Sprint(d), "`komando key gen deploy`") || !strings.Contains(fmt.Sprint(d), "then `komando host edit db1 --key deploy`") {
		t.Errorf("the import says how to bring the key: %v", d)
	}
	h := mustRun(t, "host", "show", "db1")
	if h["key"] != nil && h["key"] != "" {
		t.Errorf("db1 points at a key this computer does not have: %v", h)
	}
}

// A whole export carries your own deny rules (import adds them: they only
// stop more) and your settings (import says which differ and how to set
// them, but changes none: a file from someone else must not turn a check
// off).
func TestExportImportCarriesRulesAndSettings(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.21")
	mustRun(t, "policy", "deny", `rm -rf /srv`)
	mustRun(t, "config", "set", "parallel", "5")
	f := filepath.Join(t.TempDir(), "backup.json")
	if d := mustRun(t, "export", "--to", f); d["deny_rules"] != float64(1) || d["settings"] != true {
		t.Errorf("export: %v", d)
	}

	invHome(t) // the other computer
	d := mustRun(t, "import", "komando", f)
	if fmt.Sprint(d["deny_rules_added"]) != "[rm -rf /srv]" {
		t.Errorf("deny rules: %v", d)
	}
	if !strings.Contains(fmt.Sprint(d["settings_differ"]), "komando config set parallel 5") {
		t.Errorf("settings: %v", d)
	}
	if v := mustRun(t, "config", "get", "parallel"); fmt.Sprint(v["value"]) == "5" {
		t.Error("import changed a setting")
	}
	if _, e := invRun(t, "exec", "web1", "--", "rm -rf /srv"); e == nil || e.Code != "POLICY_BLOCKED" {
		t.Errorf("the imported rule stops it: %+v", e)
	}
	// importing again adds nothing new
	if d := mustRun(t, "import", "komando", f); d["deny_rules_added"] != nil {
		t.Errorf("again: %v", d)
	}
}

// One ProxyCommand server in an ssh config does not hold back the others
// for an AI agent: they come in, and it is listed with what it needs.
func TestImportSSHConfigProxyCommandAgent(t *testing.T) {
	invHome(t)
	cfg := filepath.Join(t.TempDir(), "config")
	os.WriteFile(cfg, []byte("Host a1\n  HostName 192.0.2.1\nHost px\n  HostName 192.0.2.2\n  ProxyCommand nc %h %p\n"), 0o600)
	asAgent(t, false, true)
	d, e := invRun(t, "import", "ssh-config", cfg)
	if e == nil || e.Code != "IMPORT_INCOMPLETE" || fmt.Sprint(d["hosts"]) != "[a1]" || !strings.Contains(fmt.Sprint(d["skipped"]), "px") {
		t.Errorf("import: %v %+v", d, e)
	}
}

// With -o text, export still prints JSON that import reads back, since the
// output is meant to go to a file.
func TestExportTextIsImportable(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@192.0.2.10")
	textOut := func(args ...string) []byte {
		t.Helper()
		root := newRoot(tcl)
		root.SetArgs(append([]string{"-o", "text"}, args...))
		var buf bytes.Buffer
		saved := tcl.out.W
		tcl.out.W = &buf
		defer func() { tcl.out.W = saved; tcl.out.Format = "json" }()
		if err := root.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return buf.Bytes()
	}
	f := filepath.Join(t.TempDir(), "exp.json")
	os.WriteFile(f, textOut("export"), 0o600)
	if p, err := importKomando(tcl, f); err != nil || len(p.Hosts) != 1 {
		t.Errorf("export -o text: %v %v", p, err)
	}
}

// Custom rule ids stay with their rule: removing one does not move another
// to its id, so a second rm from an old list cannot hit the wrong rule.
func TestPolicyCustomIDsStay(t *testing.T) {
	invHome(t)
	noAgent(t)
	mustRun(t, "policy", "deny", `shutdown\s+-h`)
	mustRun(t, "policy", "deny", `kubectl\s+delete`)
	ids := map[string]string{}
	for _, r := range mustRun(t, "policy", "list")["custom_rules"].([]any) {
		m := r.(map[string]any)
		ids[m["pattern"].(string)] = m["id"].(string)
	}
	kube := ids[`kubectl\s+delete`]
	mustRun(t, "policy", "rm", ids[`shutdown\s+-h`], "--yes")
	wantCode(t, "RULE_NOT_FOUND", "policy", "rm", ids[`shutdown\s+-h`], "--yes")
	wantCode(t, "RULE_NOT_FOUND", "policy", "rm", "custom-0", "--yes")
	if r := mustRun(t, "policy", "list")["custom_rules"].([]any); len(r) != 1 || r[0].(map[string]any)["id"] != kube {
		t.Errorf("after rm: %v", r)
	}
}

// policy deny refuses a pattern that matches empty text: it would block
// every command.
func TestPolicyDenyMatchesEverything(t *testing.T) {
	invHome(t)
	for _, p := range []string{".*", "^", "x*", "(?i)"} {
		wantCode(t, "USAGE", "policy", "deny", p)
	}
	mustRun(t, "policy", "deny", ".+")
}

// policy check --conn-kind: a kind it does not rate says which it does, MongoDB
// commands are rated, and a destructive verdict exits 6 like a blocked
// shell command.
func TestPolicyCheckFor(t *testing.T) {
	invHome(t)
	for _, k := range []string{"bogus", "sql"} {
		if e := wantCode(t, "USAGE", "policy", "check", "--conn-kind", k, "x"); !strings.Contains(e.Message, "not a kind komando rates") || !strings.Contains(e.Hint, "postgres") {
			t.Errorf("%s: %+v", k, e)
		}
	}
	if d := mustRun(t, "policy", "check", "--conn-kind", "postgres", "select 1"); d["risk"] != "read" {
		t.Errorf("read: %v", d)
	}
	if e := wantCode(t, "POLICY_BLOCKED", "policy", "check", "--conn-kind", "postgres", "drop table users"); e.Exit != out.ExitPolicy {
		t.Errorf("drop: exit %d", e.Exit)
	}
	if e := wantCode(t, "POLICY_BLOCKED", "policy", "check", "--conn-kind", "mongodb", `{"dropDatabase": 1}`); !strings.Contains(e.Message, "mongo-drop") {
		t.Errorf("mongodb: %+v", e)
	}
	if d := mustRun(t, "policy", "check", "--conn-kind", "MongoDB", `{"find": "users"}`); d["risk"] != "read" {
		t.Errorf("mongodb find: %v", d)
	}
	wantCode(t, "POLICY_BLOCKED", "policy", "check", "--conn-kind", "redis", "FLUSHALL")
	// split as cache run splits it, so both rate a quoted command the same
	wantCode(t, "POLICY_BLOCKED", "policy", "check", "--conn-kind", "redis", `"FLUSHALL"`)
	wantCode(t, "POLICY_BLOCKED", "policy", "check", "--conn-kind", "redis", `FLUSHALL ASYNC`)
}

// policy deny and rm say "would" in a dry run, and show the pattern as
// written, not Go-quoted.
func TestPolicyChangeText(t *testing.T) {
	t.Cleanup(func() { tcl.flags.dryRun = false })
	yes := true
	for _, tc := range []struct {
		dry  bool
		p    policyChange
		want string
	}{
		{false, policyChange{Custom: []string{`a\s+b`}, Added: &yes, pattern: `a\s+b`}.denied(tcl), "added the deny rule a\\s+b as " + policy.CustomID(`a\s+b`) + " (1 custom rule now)\n"},
		{true, policyChange{Custom: []string{`a\s+b`}, Added: &yes, pattern: `a\s+b`}.denied(tcl), "would add the deny rule a\\s+b as " + policy.CustomID(`a\s+b`) + " (dry run; 1 custom rule then)\n"},
		{false, policyChange{Custom: []string{}, Removed: `a\s+b`}, "removed the deny rule a\\s+b (0 custom rules left)\n"},
		{true, policyChange{Custom: []string{}, Removed: `a\s+b`}, "would remove the deny rule a\\s+b (dry run; 0 custom rules left then)\n"},
	} {
		if got := tc.p.TextFor(&out.Printer{DryRun: tc.dry}); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

// config show JSON has every setting in data.keys, in the form config get
// and set use, with its default and allowed values, and the approval code.
func TestConfigShowJSONKeys(t *testing.T) {
	invHome(t)
	d := mustRun(t, "config", "show")
	keys := map[string]map[string]any{}
	for _, k := range d["keys"].([]any) {
		m := k.(map[string]any)
		keys[m["key"].(string)] = m
	}
	if len(keys) != len(settings) {
		t.Errorf("%d keys, want %d", len(keys), len(settings))
	}
	for _, want := range []string{"default_user", "audit_syslog", "audit"} {
		if keys[want] == nil {
			t.Errorf("no %s: %v", want, keys)
		}
	}
	if keys["audit"]["value"] != "on" || keys["audit_syslog"]["value"] != "off" || keys["parallel"]["default"] != "10" || keys["audit"]["values"] != "on | off" {
		t.Errorf("values: %v", keys)
	}
	if d["approval_code"] != "off" || d["settings"] == nil {
		t.Errorf("approval_code / settings: %v", d)
	}
}
