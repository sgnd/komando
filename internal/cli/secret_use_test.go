package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// secretHome is invHome with a vault secret db-pass whose value has a $.
func secretHome(t *testing.T) {
	t.Helper()
	invHome(t)
	resetApproval()
	if err := vault.Set("db-pass", "pa$$1word"); err != nil {
		t.Fatal(err)
	}
}

// {{secret:NAME}} in text written to a server: a reserved secret never
// goes, and an AI agent needs --yes and a person's yes in the window,
// which names the secret and the file.
func TestSecretRefsInTextNeedAPerson(t *testing.T) {
	secretHome(t)
	defer func() { tcl.flags.yes, tcl.flags.dryRun = false, false }()

	// a person or a script: no window (askOnScreen panics)
	got, err := expandSecretRefs(tcl, "DB={{secret:db-pass}}", "web1:/etc/app.env", false)
	if err != nil || got != "DB=pa$$1word" {
		t.Fatalf("script: %q %v", got, err)
	}
	if got, _ := expandSecretRefs(tcl, "x={{ secret:db-pass }}", "web1:/f", true); got != "x=pa$$$$1word" {
		t.Errorf("a regexp replacement gets $$ for each $: %q", got)
	}
	if got, _ := expandSecretRefs(tcl, "no reference here", "web1:/f", false); got != "no reference here" {
		t.Errorf("text without a reference: %q", got)
	}
	// the approval code's key never goes, for anyone
	if _, err := expandSecretRefs(tcl, "{{secret:"+approvalSecret+"}}", "web1:/f", false); toErr(err).Code != "RESERVED_SECRET" {
		t.Fatalf("reserved secret: %v", err)
	}

	mustRun(t, "host", "add", "web1", "deploy@10.255.255.1")
	texts := windowText(t, true)
	// the stop comes before komando connects
	wantCode(t, "SECRET_DESTINATION", "fs", "write", "web1", "/etc/app.env", "--content", "DB={{secret:db-pass}}")
	wantCode(t, "SECRET_DESTINATION", "fs", "write", "web1", "/etc/app.env", "--value", "DB={{secret:db-pass}}") // the synonym: the same stop
	wantCode(t, "SECRET_DESTINATION", "fs", "replace", "web1", "/etc/app.env", "--old", "DB=[hidden]", "--new", "DB={{secret:db-pass}}")
	wantCode(t, "RESERVED_SECRET", "fs", "write", "web1", "/etc/app.env", "--content", "{{secret:"+approvalSecret+"}}")
	if _, err := expandSecretRefs(tcl, "DB={{secret:db-pass}}", "web1:/etc/app.env", false); toErr(err).Code != "SECRET_DESTINATION" || toErr(err).Exit != out.ExitPolicy {
		t.Fatalf("agent without --yes: %v", err)
	}
	if len(*texts) != 0 {
		t.Fatal("no flag, no window")
	}
	if _, err := expandSecretRefs(tcl, "{{secret:"+approvalSecret+"}}", "web1:/f", false); toErr(err).Code != "RESERVED_SECRET" {
		t.Fatalf("agent, reserved secret: %v", err)
	}
	tcl.flags.yes = true
	got, err = expandSecretRefs(tcl, "DB={{secret:db-pass}}", "web1:/etc/app.env", false)
	if err != nil || got != "DB=pa$$1word" {
		t.Fatalf("agent, allowed: %q %v", got, err)
	}
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "the secret secret:db-pass, sent to web1:/etc/app.env") {
		t.Errorf("the window names the secret and the file: %q", *texts)
	}

	// a person who says no
	windowText(t, false)
	resetApproval()
	if _, err := expandSecretRefs(tcl, "{{secret:db-pass}}", "web1:/f", false); toErr(err).Code != "SECRET_DESTINATION" {
		t.Fatalf("denied: %v", err)
	}

	// a dry run never asks and reads no secret: the reference stays
	tcl.flags.yes, tcl.flags.dryRun = false, true
	resetApproval()
	tcl.out.Reset()
	got, err = expandSecretRefs(tcl, "DB={{secret:db-pass}}", "web1:/f", false)
	if err != nil || got != "DB={{secret:db-pass}}" || tcl.out.Blocked() == nil {
		t.Errorf("agent dry run: %q %v blocked=%v", got, err, tcl.out.Blocked())
	}
}

// exec --env K=secret:NAME sends the value into a command on the server.
func TestEnvSecretNeedsAPerson(t *testing.T) {
	secretHome(t)
	mustRun(t, "host", "add", "web1", "deploy@10.255.255.1")
	hosts := []*store.Host{{Name: "web1"}}
	if _, err := parseEnvTo(tcl, []string{"DB=secret:db-pass"}, hosts); err != nil {
		t.Fatalf("script: %v", err)
	}
	texts := windowText(t, true)
	if env, err := parseEnvTo(tcl, []string{"PLAIN=1"}, hosts); err != nil || env["PLAIN"] != "1" {
		t.Fatalf("a plain value: %v %v", env, err)
	}
	wantCode(t, "SECRET_DESTINATION", "exec", "web1", "-e", "DB=secret:db-pass", "--", "true")
	if _, err := parseEnvTo(tcl, []string{"K=secret:" + approvalSecret}, hosts); toErr(err).Code != "RESERVED_SECRET" {
		t.Fatalf("reserved: %v", err)
	}
	d := mustRun(t, "exec", "web1", "-e", "DB=secret:db-pass", "--dry-run", "--", "true")
	if d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("the dry run says the real run would stop: %v", d)
	}
	if len(*texts) != 0 {
		t.Errorf("no window without --yes: %q", *texts)
	}
}

// A server or conn sends its password to its address on every connection:
// an AI agent that attaches a secret to a new place, or moves an entry
// that has one, needs a person's yes. Other edits ask nothing.
func TestSecretDestinationsNeedAPerson(t *testing.T) {
	secretHome(t)
	// a script is not asked, but a reserved secret is refused
	mustRun(t, "conn", "add", "shop", "postgres://app@10.0.0.5/app", "--password-ref", "secret:db-pass")
	mustRun(t, "host", "add", "jump", "u@10.0.0.3")
	wantCode(t, "RESERVED_SECRET", "host", "add", "x", "u@10.0.0.9", "--password-ref", "secret:"+approvalSecret)
	wantCode(t, "RESERVED_SECRET", "conn", "edit", "shop", "--password-ref", "secret:"+approvalSecret)
	if _, err := vault.Resolve("secret:" + approvalSecret); toErr(err).Code != "RESERVED_SECRET" {
		t.Errorf("a reference never reads the approval code's key: %v", err)
	}

	texts := windowText(t, true)
	wantCode(t, "SECRET_DESTINATION", "conn", "add", "shop2", "postgres://app@evil.example/app", "--password-ref", "secret:db-pass")
	wantCode(t, "SECRET_DESTINATION", "conn", "edit", "shop", "--url", "postgres://app@evil.example/app")
	wantCode(t, "SECRET_DESTINATION", "conn", "edit", "shop", "--via", "jump")
	wantCode(t, "SECRET_DESTINATION", "host", "add", "web1", "deploy@10.0.0.1", "--password-ref", "env:GITHUB_TOKEN")
	wantCode(t, "SECRET_DESTINATION", "host", "add", "web1", "deploy@10.0.0.1", "--env", "TOKEN=secret:db-pass")
	if len(*texts) != 0 {
		t.Fatalf("no flag, no window: %q", *texts)
	}
	// no reference, or the same place: nothing to ask
	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1")
	mustRun(t, "conn", "add", "cache", "rediss://default@10.0.0.7:6379/0")
	mustRun(t, "conn", "edit", "shop", "--add-tag", "live", "--url", "postgres://other@10.0.0.5/app")
	mustRun(t, "host", "edit", "web1", "--user", "root")
	if len(*texts) != 0 {
		t.Fatalf("nothing new goes anywhere: %q", *texts)
	}

	mustRun(t, "host", "edit", "web1", "--password-ref", "secret:db-pass", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "secret:db-pass to 10.0.0.1:22 (server web1)") {
		t.Fatalf("window: %q", *texts)
	}
	resetApproval()
	mustRun(t, "host", "edit", "web1", "--add-tag", "web")
	wantCode(t, "SECRET_DESTINATION", "host", "edit", "web1", "--address", "10.6.6.6")
	wantCode(t, "SECRET_DESTINATION", "host", "edit", "web1", "--port", "2222")
	resetApproval()
	mustRun(t, "conn", "add", "shop3", "postgres://app@10.0.0.6/app", "--password-ref", "env:SHOP_PASS", "--yes")
	if w := (*texts)[len(*texts)-1]; !strings.Contains(w, "env:SHOP_PASS to 10.0.0.6:5432 (conn shop3)") {
		t.Errorf("window: %q", w)
	}

	// a protected server: one window asks about both
	resetApproval()
	mustRun(t, "host", "add", "db1", "deploy@10.0.0.2", "--protected")
	n := len(*texts)
	mustRun(t, "host", "edit", "db1", "--sudo-ref", "secret:db-pass", "--yes")
	if len(*texts) != n+1 || !strings.Contains((*texts)[n], "protected host: db1") || !strings.Contains((*texts)[n], "secret:db-pass to 10.0.0.2:22 (server db1)") {
		t.Errorf("one window for the protected server and the secret: %q", (*texts)[n:])
	}

	// the person says no
	windowText(t, false)
	wantCode(t, "SECRET_DESTINATION", "conn", "edit", "cache", "--password-ref", "secret:db-pass", "--yes")
	st, _ := store.Load()
	if st.Conns["cache"].PasswordRef != "" || st.Hosts["web1"].Address != "10.0.0.1" {
		t.Error("a refused change was saved")
	}
}

// Settings in a conn URL that turn its network protection down need a
// person's yes when an AI agent adds them.
func TestWeakTLS(t *testing.T) {
	for _, c := range []struct {
		old, now string
		want     string
	}{
		{"", "postgres://a@db/app?sslmode=disable", "sslmode=disable"},
		{"", "postgres://a@db/app?sslmode=prefer", "sslmode=prefer"},
		{"", "postgres://a@db/app?sslmode=verify-full", ""},
		{"", "postgres://a@db/app", ""},
		{"", "mysql://a@db/shop?tls=skip-verify", "tls=skip-verify"},
		{"", "mysql://a@db/shop?tls=false", "tls=false"},
		{"", "mysql://a@db/shop?tls=true", ""},
		{"", "registry://u@reg.example?tls=skip-verify", "tls=skip-verify"},
		{"", "registry://u@reg.example?tls=false", "tls=false"},
		{"", "ftps://u@files.example/www?tls=skip-verify", "tls=skip-verify"},
		{"", "ftp://u@files.example/www?insecure=1", "insecure=1"},
		{"", "redis://default@cache:6379/0", ""},
		{"", "redis://default@cache:6379/0?insecure=1", "insecure=1"},
		{"", "memcached://cache:11211?insecure=1", "insecure=1"},
		{"", "rediss://default@cache:6379/0?insecure=1", ""},
		{"rediss://default@cache:6379/0", "redis://default@cache:6379/0", "no TLS any more"},
		{"memcacheds://cache:11211", "memcached://cache:11211", "no TLS any more"},
		{"postgres://a@db/app?sslmode=disable", "postgres://b@db/app?sslmode=disable", ""}, // it had it before
		{"redis://default@cache:6379/0", "redis://default@cache:6379/1", ""},
		{"", "s3://b?endpoint=http://10.0.0.5:9000&insecure=1", "insecure=1"},
		{"", "gs://b?endpoint=http://10.0.0.5:4443&insecure=1", "insecure=1"},
		{"", "azblob://acct@media?endpoint=http://10.0.0.5:10000/acct&insecure=1", "insecure=1"},
	} {
		got := strings.Join(weakTLS(c.old, c.now), "; ")
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("weakTLS(%q, %q) = %q, want %q", c.old, c.now, got, c.want)
		}
	}

	secretHome(t)
	mustRun(t, "conn", "add", "pg", "postgres://a@10.0.0.5/app?sslmode=disable") // a script
	mustRun(t, "conn", "add", "cache", "rediss://default@10.0.0.7:6379/0")
	texts := windowText(t, true)
	e := wantCode(t, "SAFETY_SETTING", "conn", "add", "pg2", "postgres://a@10.0.0.5/app?sslmode=disable")
	if !strings.Contains(e.Message, "sslmode=disable") {
		t.Errorf("message: %q", e.Message)
	}
	wantCode(t, "SAFETY_SETTING", "conn", "edit", "cache", "--url", "redis://default@10.0.0.7:6379/0?insecure=1")
	wantCode(t, "SAFETY_SETTING", "conn", "add", "reg", "registry://u@reg.example?tls=skip-verify")
	// an s3 conn with aws_profile has no secret reference, but its AWS
	// session token would travel in clear: a person says yes first
	wantCode(t, "SAFETY_SETTING", "conn", "add", "files3", "s3://b?endpoint=http://10.0.0.5:9000&insecure=1", "--option", "aws_profile=dev")
	mustRun(t, "conn", "edit", "pg", "--add-tag", "x") // nothing new
	if len(*texts) != 0 {
		t.Fatalf("no flag, no window: %q", *texts)
	}
	mustRun(t, "conn", "add", "files", "ftp://u@10.0.0.8/www?insecure=1", "--password-ref", "secret:db-pass", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "secret:db-pass to 10.0.0.8:21 (conn files)") || !strings.Contains((*texts)[0], "files: insecure=1") {
		t.Errorf("one window for the secret and the setting: %q", *texts)
	}
}

// Imports: an agent's import that names a secret for a new place asks too.
func TestImportSecretDestinationsNeedAPerson(t *testing.T) {
	secretHome(t)
	csv := filepath.Join(t.TempDir(), "hosts.csv")
	os.WriteFile(csv, []byte("name,address,user,password-ref\nweb9,10.0.0.9,deploy,secret:db-pass\n"), 0o600)
	texts := windowText(t, true)
	wantCode(t, "SECRET_DESTINATION", "import", "csv", csv)
	st, _ := store.Load()
	if st.Hosts["web9"] != nil {
		t.Fatal("a refused import added a server")
	}
	mustRun(t, "import", "csv", csv, "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "secret:db-pass to 10.0.0.9:22 (server web9)") {
		t.Errorf("window: %q", *texts)
	}
}

// For an AI agent, KOMANDO_HOME naming another folder than ~/.komando
// needs a person's yes on every command; a link to ~/.komando does not.
func TestAgentOtherHome(t *testing.T) {
	usual := filepath.Join(t.TempDir(), ".komando")
	os.MkdirAll(usual, 0o700)
	saved := defaultHome
	defaultHome = func() string { return usual }
	defer func() { defaultHome = saved }()
	invHome(t)
	other := os.Getenv("KOMANDO_HOME")

	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1") // a script: not asked
	texts := windowText(t, true)
	e := wantCode(t, "SAFETY_SETTING", "list")
	if !strings.Contains(e.Message, "KOMANDO_HOME points komando at "+other) {
		t.Errorf("message: %q", e.Message)
	}
	wantCode(t, "SAFETY_SETTING", "host", "add", "prod", "root@10.0.0.2")
	// a synonym is typed like the command it names: the same stop
	for _, syn := range [][]string{{"tunnel", "show", "t1"}, {"recipe", "show", "r1"}, {"group", "show", "prod"}, {"cluster", "info", "k1"}} {
		wantCode(t, "SAFETY_SETTING", syn...)
	}
	for _, free := range [][]string{{"version"}, {"schema"}, {"guide"}} {
		mustRun(t, free...)
	}
	d := mustRun(t, "list", "--dry-run")
	if d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("a dry run goes on and says the real run would stop: %v", d)
	}
	if len(*texts) != 0 {
		t.Fatalf("no flag, no window: %q", *texts)
	}
	mustRun(t, "list", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "KOMANDO_HOME="+other) {
		t.Errorf("window: %q", *texts)
	}

	// the usual folder, by its name or through a link
	link := filepath.Join(t.TempDir(), "k")
	if err := os.Symlink(usual, link); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{usual, usual + "/", link} {
		setHome(t, h)
		if otherHome(tcl) != "" {
			t.Errorf("KOMANDO_HOME=%s is the usual folder", h)
		}
	}
	mustRun(t, "list")
	t.Setenv("KOMANDO_HOME", "")
	if otherHome(tcl) != "" {
		t.Error("no KOMANDO_HOME, no other folder")
	}
	if len(*texts) != 1 {
		t.Errorf("the usual folder asks nothing: %q", *texts)
	}
}

// For an AI agent, the audit record keeps the agent and the computer
// account as facts, and marks KOMANDO_ACTOR as the name it claims.
func TestAuditActorClaimed(t *testing.T) {
	invHome(t)
	t.Setenv("KOMANDO_ACTOR", "alice")
	mustRun(t, "host", "add", "web1", "deploy@10.0.0.1")
	t.Setenv("CLAUDECODE", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	mustRun(t, "host", "add", "web2", "deploy@10.0.0.2")
	var recs []map[string]any
	for _, line := range strings.Split(auditText(t), "\n") {
		var r map[string]any
		json.Unmarshal([]byte(line), &r)
		recs = append(recs, r)
	}
	if len(recs) != 2 {
		t.Fatalf("records: %v", recs)
	}
	if p := recs[0]; p["actor"] != "alice" || p["actor_claimed"] != nil || p["os_user"] != nil {
		t.Errorf("a person's record: %v", p)
	}
	a := recs[1]
	if a["actor"] != "alice" || a["agent"] != "Claude Code" || a["actor_claimed"] != true || a["os_user"] == "" || a["os_user"] == nil {
		t.Errorf("an agent's record: %v", a)
	}
	if txt := (auditList{Entries: recs}).Text(); !strings.Contains(txt, "Claude Code (as alice)") {
		t.Errorf("text view:\n%s", txt)
	}
}

// db user add sends the password to the conn's server, which may be one
// the agent set up itself.
func TestDBUserPasswordNeedsAPerson(t *testing.T) {
	secretHome(t)
	mustRun(t, "conn", "add", "local", "sqlite://"+filepath.Join(t.TempDir(), "app.db"))
	texts := windowText(t, true)
	e := wantCode(t, "SECRET_DESTINATION", "db", "user", "add", "local", "app", "--password-ref", "secret:db-pass")
	if !strings.Contains(e.Message, "database user app (conn local)") {
		t.Errorf("message: %q", e.Message)
	}
	if len(*texts) != 0 {
		t.Errorf("no flag, no window: %q", *texts)
	}
}
