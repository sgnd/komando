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
	"github.com/sgnd/komando/internal/store"
)

// invHome gives a test its own komando home and vault.
func invHome(t *testing.T) {
	t.Helper()
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long-enough")
	t.Cleanup(func() {
		g.dryRun, g.yes, g.allowDangerous, store.DryRun = false, false, false, false
		out.P.Format = "json"
	})
}

// invRun runs komando and returns the envelope's data, or the error.
func invRun(t *testing.T, args ...string) (map[string]any, *out.Error) {
	t.Helper()
	g.dryRun, g.yes, store.DryRun = false, false, false
	root := newRoot()
	root.SetArgs(append([]string{"-o", "json"}, args...))
	var buf bytes.Buffer
	saved := out.P.W
	out.P.W = &buf
	defer func() { out.P.W = saved }()
	err := root.Execute()
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
		{"VIA_NOT_FOUND", []string{"h", "--via", "nosuch"}},
		{"VIA_CYCLE", []string{"h", "--via", "n1"}},
		{"FILE_NOT_FOUND", []string{"h", "--identity", "/no/such/key"}},
		{"USAGE", []string{"h", "-g", "x y"}},
		{"USAGE", []string{"h", "-t", "tag:x"}},
		{"USAGE", []string{"h", "--label", "a,b=1"}},
	} {
		wantCode(t, c.code, append([]string{"host", "add", "n1"}, c.args...)...)
	}
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
	os.WriteFile(f, []byte(`{"ok":true,"command":"host.export","data":{"hosts":[
		{"name":"prod","address":"10.9.9.9"},
		{"name":"px","address":"10.0.0.7","proxy_command":"nc %h %p"},
		{"name":"bad","address":"10.0.0.8","port":99999}]}}`), 0o600)
	asAgent(t, false, true) // the person says no
	_, e := invRun(t, "host", "import", "--json", f, "--overwrite", "--yes")
	if e == nil || e.Code != "SAFETY_SETTING" {
		t.Fatalf("agent proxy command needs a person: %+v", e)
	}
	// without --yes the proxy command server is left out, with the reason,
	// and nothing else is held back (a dry run says the same)
	for _, dry := range []bool{true, false} {
		args := []string{"host", "import", "--json", f}
		if dry {
			args = append(args, "--dry-run")
		}
		d := mustRun(t, args...)
		skipped := fmt.Sprint(d["skipped_invalid"])
		if !strings.Contains(skipped, "px") || !strings.Contains(skipped, "--yes") {
			t.Errorf("dry %v: px is left out with the reason: %v", dry, d)
		}
	}
	if _, e := invRun(t, "host", "show", "px"); e == nil {
		t.Error("px was added without a person's yes")
	}
	noAgent(t)
	d := mustRun(t, "host", "import", "--json", f, "--overwrite")
	if d["skipped_protected"] == nil || d["skipped_invalid"] == nil {
		t.Errorf("protected and invalid hosts are reported: %v", d)
	}
	// komando import reads host export output too
	mustRun(t, "host", "rm", "px")
	// prod exists (skipped, fine), bad is refused: the rest comes in, and
	// the refusal makes the import fail (exit 1), not a quiet skip
	d, e = invRun(t, "import", "komando", f)
	if e == nil || e.Code != "IMPORT_INCOMPLETE" || e.Exit != 1 || len(d["hosts"].([]any)) != 1 {
		t.Errorf("import komando of a host export: %v %+v", d, e)
	}
}

func TestInvTrustDryRun(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "h", "u@10.0.0.1")
	kh := store.Path("known_hosts")
	line := "10.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
	os.WriteFile(kh, []byte(line), 0o600)
	d := mustRun(t, "host", "trust", "h", "--reset", "--dry-run")
	if d["would_remove_entries"].(float64) != 1 || d["would_fetch_from"] != "the server directly" {
		t.Errorf("count: %v", d)
	}
	if b, _ := os.ReadFile(kh); string(b) != line {
		t.Error("--dry-run changed known_hosts")
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
	// a key file left behind
	os.WriteFile(store.Path("keys", "old"), []byte("x"), 0o600)
	wantCode(t, "KEY_FILE_EXISTS", "key", "gen", "old")
	mustRun(t, "key", "gen", "old", "--overwrite")

	pub := store.Path("keys", "k.pub")
	e := wantCode(t, "KEY_INVALID", "key", "add", "p", pub)
	if !strings.Contains(e.Hint, "public key") || e.Exit != out.ExitUsage {
		t.Errorf("hint: %+v", e)
	}
	wantCode(t, "USAGE", "key", "add", "p", store.Path("keys", "k"), "--passphrase-ref", "pw123")
	wantCode(t, "USAGE", "key", "edit", "k", "--passphrase-ref", "pw123")
	mustRun(t, "key", "edit", "k", "--passphrase-ref", "secret:kp")

	ext := filepath.Join(t.TempDir(), "ext")
	b, _ := os.ReadFile(store.Path("keys", "k"))
	os.WriteFile(ext, b, 0o600)
	mustRun(t, "key", "add", "ext", ext)
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
	pub, _ := os.ReadFile(store.Path("keys", "k.pub"))
	f := filepath.Join(t.TempDir(), "x.pub")
	os.WriteFile(f, []byte(strings.TrimSpace(string(pub))+" a\rb\n"), 0o600)
	st, _ := loadState()
	_, line, err := deployKey(st, f)
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
	if !strings.Contains(e.Hint, "did you mean") {
		t.Errorf("hint %q", e.Hint)
	}
	mustRun(t, "host", "add", "prod", "u@10.0.0.2", "--protected", "--password-ref", "secret:s1")
	wantCode(t, "PROTECTED_TARGET", "secret", "set", "s1", "--from-env", "INV_S")
	d = mustRun(t, "secret", "set", "s2", "--from-env", "INV_S")
	if d["replaced"] != true {
		t.Errorf("replaced: %v", d)
	}
	wantCode(t, "SECRET_IN_USE", "secret", "rm", "s1", "s2")
	mustRun(t, "host", "rm", "prod", "--yes")
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
	mustRun(t, "config", "set", "vpn_idle", "0")
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
	wantCode(t, "BUILTIN_RULE", "policy", "allow", "rm-root")
	wantCode(t, "RULE_NOT_FOUND", "policy", "allow", "nonexistent")
	wantCode(t, "USAGE", "policy", "deny", " ")
	mustRun(t, "policy", "deny", `kubectl\s+apply`)
	mustRun(t, "policy", "allow", "custom-0", "--yes")
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
		hs, err := resolveTargets(st, expr)
		if err != nil {
			t.Errorf("%s: %v", expr, err)
			continue
		}
		if got := strings.Join(hostNames(hs), ","); got != want {
			t.Errorf("%s: got %s want %s", expr, got, want)
		}
	}
	_, err := resolveSelection(st, "@wbe")
	if e := toErr(err); !strings.Contains(e.Message, `no group named "wbe"`) || !strings.Contains(e.Hint, "@web") {
		t.Errorf("group not found: %+v", e)
	}
}

func TestInvSSHCommand(t *testing.T) {
	st := &store.State{Hosts: map[string]*store.Host{}, Keys: map[string]*store.Key{}, Vpns: map[string]*store.Vpn{}, Sessions: map[string]*store.VpnSession{}}
	st.Keys["k"] = &store.Key{Name: "k", Path: "/keys/k"}
	st.Hosts["b"] = &store.Host{Name: "b", Address: "10.0.0.1", Port: 2222, User: "jump", Key: "k"}
	st.Hosts["t"] = &store.Host{Name: "t", Address: "10.0.0.2", User: "app", Key: "k", Via: "b"}
	parts, err := sshCommandFor(st, st.Hosts["t"])
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(parts, " ")
	for _, want := range []string{"ProxyCommand=ssh -o UserKnownHostsFile=", "-p 2222 -i /keys/k -W 10.0.0.2:22 jump@10.0.0.1", "app@10.0.0.2"} {
		if !strings.Contains(line, want) {
			t.Errorf("missing %q in %s", want, line)
		}
	}
	st.Vpns["v"] = &store.Vpn{Name: "v", Kind: "socks", Address: "127.0.0.1:1080"}
	st.Hosts["b"].Via = "v"
	parts, _ = sshCommandFor(st, st.Hosts["t"])
	if line = strings.Join(parts, " "); !strings.Contains(line, "nc -X 5 -x 127.0.0.1:1080 %%h %%p") {
		t.Errorf("socks first hop, escaped once for nesting: %s", line)
	}
	st.Vpns["v"].Kind = "wireguard"
	if _, err := sshCommandFor(st, st.Hosts["t"]); toErr(err).Code != "VPN_NOT_FOR_OPENSSH" {
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
	cs := inventoryChecks(st)
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
	if got := d["removed"].([]any); len(got) != 3 {
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
	if s := (targetList{Targets: []targetRow{}, empty: true}).Text(); !strings.Contains(s, "No servers or conns yet") {
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
	if fmt.Sprint(d["keys_needed"]) != "[deploy]" || len(d["key_files"].([]any)) != 1 {
		t.Errorf("export names the key and its file: %v", d)
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
	if !strings.Contains(fmt.Sprint(d), "run `komando key add deploy PATH` and `komando host edit db1 --key deploy`") {
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
