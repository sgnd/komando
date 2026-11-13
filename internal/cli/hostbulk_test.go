package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// windowText records what komando's approval window would show an AI
// agent, and answers allow.
func windowText(t *testing.T, allow bool) *[]string {
	t.Helper()
	t.Setenv("CLAUDECODE", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	var texts []string
	saved := askOnScreen
	askOnScreen = func(text string) (bool, bool) {
		texts = append(texts, text)
		return allow, true
	}
	t.Cleanup(func() { askOnScreen = saved; resetApproval() })
	resetApproval()
	return &texts
}

func TestHostMv(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "jump", "u@10.0.0.1", "-g", "edge", "-t", "prod", "--sudo-ref", "secret:j")
	mustRun(t, "host", "add", "web", "u@10.0.0.2", "--via", "jump")
	mustRun(t, "conn", "add", "db", "postgres://a@10.0.0.5/app", "--via", "jump")
	if err := store.Update(func(s *store.State) error {
		s.Jobs["j1"] = &store.Job{ID: "j1", Host: "jump", Command: "sleep 1"}
		s.Tunnels["t1"] = &store.Tunnel{ID: "t1", Host: "jump", Via: "jump", Kind: "local"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	d := mustRun(t, "host", "mv", "jump", "bastion", "--dry-run")
	if d["action"] != "would_rename" || len(d["updated"].([]any)) != 5 {
		t.Errorf("dry run: %v", d)
	}
	st, _ := store.Load()
	if st.Hosts["jump"] == nil || st.Hosts["web"].Via != "jump" {
		t.Fatal("a dry run changed the inventory")
	}

	d = mustRun(t, "host", "mv", "jump", "bastion")
	if d["action"] != "renamed" || d["from"] != "jump" || d["to"] != "bastion" {
		t.Errorf("mv: %v", d)
	}
	st, _ = store.Load()
	b := st.Hosts["bastion"]
	if st.Hosts["jump"] != nil || b == nil || b.Name != "bastion" || b.SudoRef != "secret:j" || len(b.Groups) != 1 || len(b.Tags) != 1 {
		t.Fatalf("the entry keeps everything: %+v", b)
	}
	if st.Hosts["web"].Via != "bastion" || st.Conns["db"].Via != "bastion" || st.Jobs["j1"].Host != "bastion" ||
		st.Tunnels["t1"].Host != "bastion" || st.Tunnels["t1"].Via != "bastion" {
		t.Errorf("references follow the new name: %+v %+v %+v %+v", st.Hosts["web"], st.Conns["db"], st.Jobs["j1"], st.Tunnels["t1"])
	}

	wantCode(t, "NAME_TAKEN", "host", "mv", "bastion", "db")
	wantCode(t, "HOST_NOT_FOUND", "host", "mv", "nosuch", "x")
	wantCode(t, "USAGE", "host", "mv", "web", "bad name")
	wantCode(t, "USAGE", "host", "mv", "web", "all")
	if d := mustRun(t, "host", "mv", "web", "web"); d["action"] != "unchanged" {
		t.Errorf("same name: %v", d)
	}
	mustRun(t, "host", "mv", "web", "WEB") // only the case changes

	// protected: a person's yes, once
	mustRun(t, "host", "add", "prod", "u@10.0.0.9", "--protected")
	wantCode(t, "PROTECTED_HOST", "host", "mv", "prod", "prod1")
	if d := mustRun(t, "host", "mv", "prod", "prod1", "--dry-run"); d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("dry run shows the stop: %v", d)
	}
	texts := windowText(t, true)
	mustRun(t, "host", "mv", "prod", "prod1", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "renaming protected host: prod") {
		t.Errorf("one window that says why: %q", *texts)
	}
	st, _ = store.Load()
	if !st.Hosts["prod1"].Protected {
		t.Error("the protected mark stays")
	}
}

func TestConnMv(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "db", "postgres://a@10.0.0.5/app", "--protected", "-t", "x")
	if err := store.Update(func(s *store.State) error {
		s.Tunnels["t1"] = &store.Tunnel{ID: "t1", Host: "h", Conn: "db", Kind: "local"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, "PROTECTED_TARGET", "conn", "mv", "db", "main-db")
	mustRun(t, "conn", "mv", "db", "main-db", "--yes")
	st, _ := store.Load()
	c := st.Conns["main-db"]
	if c == nil || !c.Protected || len(c.Tags) != 1 || st.Tunnels["t1"].Conn != "main-db" {
		t.Errorf("conn mv: %+v %+v", c, st.Tunnels["t1"])
	}
}

func TestVpnMv(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "add", "lab", "socks", "--proxy-address", "127.0.0.1:1080")
	mustRun(t, "host", "add", "h1", "u@10.0.0.1", "--via", "lab")
	mustRun(t, "host", "add", "h2", "u@10.0.0.2", "--via", "lab,h1")
	d := mustRun(t, "vpn", "mv", "lab", "office")
	if d["action"] != "renamed" || len(d["updated"].([]any)) != 2 {
		t.Errorf("vpn mv: %v", d)
	}
	st, _ := store.Load()
	if st.Vpns["office"] == nil || st.Vpns["lab"] != nil || st.Hosts["h1"].Via != "office" || st.Hosts["h2"].Via != "office,h1" {
		t.Errorf("vpn references: %+v %+v", st.Hosts["h1"], st.Hosts["h2"])
	}
	wantCode(t, "VPN_NOT_FOUND", "vpn", "mv", "lab", "x")
	wantCode(t, "NAME_TAKEN", "vpn", "mv", "office", "h1")
	if err := store.Update(func(s *store.State) error {
		s.Sessions["office"] = &store.VpnSession{Vpn: "office", PID: os.Getpid(), StartedAt: time.Now(), LastUsed: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	wantCode(t, "VPN_IN_USE", "vpn", "mv", "office", "lab")
}

func TestHostEditMany(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "a", "u@10.0.0.1", "-g", "ubuntu")
	mustRun(t, "host", "add", "b", "u@10.0.0.2", "-g", "ubuntu", "--protected")
	mustRun(t, "host", "add", "c", "u@10.0.0.3", "-g", "ubuntu", "--protected")
	mustRun(t, "host", "add", "d", "u@10.0.0.4")

	wantCode(t, "PROTECTED_HOST", "host", "edit", "@ubuntu", "--sudo-ref", "secret:ubuntu-sudo")
	d := mustRun(t, "host", "edit", "@ubuntu", "--sudo-ref", "secret:ubuntu-sudo", "--dry-run")
	if len(d["changed"].([]any)) != 3 || len(d["protected"].([]any)) != 2 || d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("dry run lists every server and the stop: %v", d)
	}
	st, _ := store.Load()
	if st.Hosts["a"].SudoRef != "" {
		t.Fatal("a dry run changed the inventory")
	}

	// an AI agent: one window that names every server
	texts := windowText(t, true)
	mustRun(t, "host", "edit", "@ubuntu", "--sudo-ref", "secret:ubuntu-sudo", "--yes")
	if len(*texts) != 1 {
		t.Fatalf("one window for the whole command, got %d", len(*texts))
	}
	if w := (*texts)[0]; !strings.Contains(w, "changes 3 servers: a, b, c (protected: b, c)") {
		t.Errorf("window text: %q", w)
	}
	st, _ = store.Load()
	for _, n := range []string{"a", "b", "c"} {
		if st.Hosts[n].SudoRef != "secret:ubuntu-sudo" {
			t.Errorf("%s not changed", n)
		}
	}
	if st.Hosts["d"].SudoRef != "" {
		t.Error("d is not in the group")
	}
	noAgent(t)
	resetApproval()

	// names and selectors together, each server once; the same again changes nothing
	d = mustRun(t, "host", "edit", "a", "d", "@ubuntu", "--add-tag", "lab")
	if len(d["changed"].([]any)) != 4 {
		t.Errorf("a, d, b, c: %v", d)
	}
	d = mustRun(t, "host", "edit", "a", "d", "--add-tag", "lab")
	if len(d["changed"].([]any)) != 0 || len(d["unchanged"].([]any)) != 2 {
		t.Errorf("nothing to change: %v", d)
	}
	// one server's value only
	wantCode(t, "USAGE", "host", "edit", "a", "d", "--address", "10.9.9.9")
	wantCode(t, "HOST_NOT_FOUND", "host", "edit", "a", "nosuch", "--add-tag", "x")
	wantCode(t, "TARGET_EMPTY", "host", "edit", "@nosuch", "--add-tag", "x")
	// all or nothing: a bad value for one server stops every change
	wantCode(t, "KEY_NOT_FOUND", "host", "edit", "a", "d", "--key", "nokey")
	// one name keeps its old output
	d = mustRun(t, "host", "edit", "a", "--add-tag", "one")
	if d["name"] != "a" || d["changed"] != true {
		t.Errorf("single edit output: %v", d)
	}
}

func writeCSV(t *testing.T, text string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "hosts.csv")
	if err := os.WriteFile(f, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestImportCSV(t *testing.T) {
	invHome(t)
	if err := vault.Set("ubuntu-sudo", "pw"); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "host", "add", "old", "u@10.0.0.99")
	f := writeCSV(t, "\xef\xbb\xbfName,IP,User,Port,Role,Tags,Sudo_Ref,Protected,Via,Notes\n"+
		"# a comment\n"+
		"bastion,10.0.0.1,ubuntu,,edge,prod,secret:ubuntu-sudo,no,,\n"+
		"web1,10.0.0.11,ubuntu,2222,\"web,ubuntu\",prod,secret:ubuntu-sudo,yes,bastion,front end\n"+
		"old,10.0.0.98,ubuntu,,,,,,,\n")
	d := mustRun(t, "import", "csv", f, "--dry-run")
	if d["action"] != "would_add" || len(d["hosts"].([]any)) != 2 || len(d["skipped"].([]any)) != 1 {
		t.Errorf("dry run: %v", d)
	}
	if st, _ := store.Load(); st.Hosts["web1"] != nil {
		t.Fatal("a dry run imported")
	}
	mustRun(t, "import", "csv", f, "-g", "fleet")
	st, _ := store.Load()
	w := st.Hosts["web1"]
	if w == nil || w.Port != 2222 || w.User != "ubuntu" || !w.Protected || w.Via != "bastion" || w.SudoRef != "secret:ubuntu-sudo" ||
		strings.Join(w.Groups, ",") != "fleet,ubuntu,web" || w.Notes != "front end" {
		t.Errorf("web1: %+v", w)
	}
	if st.Hosts["old"].Address != "10.0.0.99" {
		t.Error("an existing server is skipped without --overwrite")
	}
	mustRun(t, "import", "csv", f, "--overwrite")
	if st, _ := store.Load(); st.Hosts["old"].Address != "10.0.0.98" {
		t.Error("--overwrite replaces it")
	}

	for _, c := range []struct{ text, want string }{
		{"name,address,colour\nx,10.0.0.1,red\n", `does not import: "colour"`},
		{"name,address,env\nx,10.0.0.1,prod\n", `does not import: "env"`},
		{"name,user\nx,u\n", "name and an address column"},
		{"name,address,address\n", "appears twice"},
		{"name,address\n", "only the header row"},
		{"name,address,port,protected\nok,10.0.0.1,22,no\nbad name,10.0.0.2,,\ny,10.0.0.3,99999,\nz,10.0.0.4,,maybe\nok,10.0.0.5,,\n",
			"4 bad rows"},
		{"name,address\nnew1,10.0.0.1\nnew2,10.0.0.2,extra\n", "wrong number of fields"},
	} {
		e := wantCode(t, "USAGE", "import", "csv", writeCSV(t, c.text))
		if !strings.Contains(e.Message, c.want) {
			t.Errorf("%q: %s", c.text, e.Message)
		}
	}
	// checks that need the inventory stop the whole file too
	e := wantCode(t, "USAGE", "import", "csv", writeCSV(t, "name,address,via\nnew1,10.0.0.1,\nnew2,10.0.0.2,nosuch\n"))
	if !strings.Contains(e.Message, "new2") {
		t.Errorf("via check: %s", e.Message)
	}
	if st, _ := store.Load(); st.Hosts["new1"] != nil {
		t.Error("one bad row: nothing is imported")
	}

	// an AI agent cannot point the import at komando's own folder
	t.Setenv("CLAUDECODE", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	p := filepath.Join(os.Getenv("KOMANDO_HOME"), "x.csv")
	os.WriteFile(p, []byte("name,address\nx,10.0.0.1\n"), 0o600)
	wantCode(t, "SENSITIVE_FILE", "import", "csv", p)
}
