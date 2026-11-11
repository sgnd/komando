package cli

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestImportPgpass(t *testing.T) {
	p, err := importPgpass(writeTemp(t, "pgpass", "db.lan:5432:shop:app:se\\:cret\n*:*:*:x:y\n10.0.0.5:5432:shop:ro:pw\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Conns) != 2 || p.Conns[0].Name != "shop" || p.Conns[1].Name != "shop-2" {
		t.Fatalf("conns: %+v", p.Conns)
	}
	if p.Secrets["shop-pass"] != "se:cret" || strings.Contains(p.Conns[0].URL, "cret") {
		t.Errorf("password must move to the vault: %q / %q", p.Secrets["shop-pass"], p.Conns[0].URL)
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "wildcard") {
		t.Errorf("wildcard line should be reported: %v", p.Notes)
	}
}

func TestImportEnv(t *testing.T) {
	p, err := importEnv(writeTemp(t, ".env", "export DATABASE_URL=postgres://app:pw@db:5432/app\nREDIS_URL='redis://default:rpw@cache:6379/0'\nSENTRY_URL=https://x@s/1\nPLAIN=1\nMONGO_URI=mongodb+srv://app@c.mongodb.net/shop\nAPI_URI=https://x/y\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Conns) != 3 || p.Conns[0].Name != "database" || p.Conns[1].Name != "redis" || p.Conns[2].Name != "mongo" {
		t.Fatalf("conns: %+v", p.Conns)
	}
	if p.Conns[1].PasswordRef != "secret:redis-pass" || p.Secrets["redis-pass"] != "rpw" {
		t.Errorf("redis password: %q %q", p.Conns[1].PasswordRef, p.Secrets["redis-pass"])
	}
	if len(p.Notes) != 2 || !strings.Contains(p.Notes[0], "SENTRY_URL") || !strings.Contains(p.Notes[1], "API_URI") {
		t.Errorf("unknown URL should be reported: %v", p.Notes)
	}
}

func TestImportMycnf(t *testing.T) {
	p, err := importMycnf(writeTemp(t, "my.cnf", "[client]\nuser=root\npassword=\"top\"\nhost=db\ndatabase=shop\n[mysqld]\ndatadir=/x\n[client_reports]\nuser=ro\nsocket=/tmp/s\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Conns) != 1 || p.Conns[0].Name != "shop" || p.Secrets["shop-pass"] != "top" {
		t.Fatalf("conns: %+v secrets %v", p.Conns, len(p.Secrets))
	}
	if len(p.Notes) != 1 || !strings.Contains(p.Notes[0], "socket") {
		t.Errorf("socket-only section should be reported: %v", p.Notes)
	}
}

func TestImportKomandoIsDefensive(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "x")
	if err := vault.Set("prod-db-pass", "s3cret"); err != nil {
		t.Fatal(err)
	}
	file := writeTemp(t, "exp.json", `{"format":"komando-export/1",
		"hosts":[{"name":"evil","address":"attacker.example","password_ref":"secret:prod-db-pass","sudo_ref":"file:/etc/passwd"}],
		"conns":[{"name":"newdb","url":"postgres://a@h/d","password_ref":"secret:newdb-pass"}],
		"vpns":[{"name":"v","kind":"anyconnect","portal":"--script=/tmp/x"}],
		"recipes":[{"name":"wipe","command":"rm -rf /srv","read_only":true}]}`)
	p, err := importKomando(file)
	if err != nil {
		t.Fatal(err)
	}
	if p.Conns[0].PasswordRef != "secret:newdb-pass" {
		t.Errorf("a ref to a secret not set yet may stay: %q", p.Conns[0].PasswordRef)
	}
	if len(p.Vpns) != 0 {
		t.Error("a VPN with an option-like portal must be skipped")
	}
	if p.Recipes[0].ReadOnly {
		t.Error("imported recipes must count as changes")
	}
}

// A host file may come from someone else: whichever way it is imported, its
// hosts may not use this computer's secrets or files, as a password, a sudo
// password or an env value (sent with every command run there).
func TestImportedHostsCannotUseLocalSecrets(t *testing.T) {
	hosts := `[{"name":"evil","address":"attacker.example",
		"password_ref":"secret:prod-db-pass","sudo_ref":"file:/etc/passwd",
		"env":{"DB_PASSWORD":"secret:prod-db-pass","LATER":"secret:not-set-yet","APP_ENV":"secret-less prod"}}]`
	for _, tc := range []struct {
		name string
		file string
		args []string
	}{
		{"import komando", `{"format":"komando-export/1","hosts":` + hosts + `}`, []string{"import", "komando"}},
		{"host import --json", `{"hosts":` + hosts + `}`, []string{"host", "import", "--json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invHome(t)
			if err := vault.Set("prod-db-pass", "s3cret"); err != nil {
				t.Fatal(err)
			}
			file := writeTemp(t, "hosts.json", tc.file)
			d := mustRun(t, append(tc.args, file)...)
			notes := fmt.Sprint(d["not_imported"], d["notes"])
			for _, what := range []string{"password_ref", "sudo_ref", "env DB_PASSWORD"} {
				if !strings.Contains(notes, "dropped "+what) {
					t.Errorf("no note for %s: %s", what, notes)
				}
			}
			st, err := store.Load()
			if err != nil {
				t.Fatal(err)
			}
			h := st.Hosts["evil"]
			if h == nil {
				t.Fatalf("not imported: %v", d)
			}
			if h.PasswordRef != "" || h.SudoRef != "" {
				t.Errorf("refs to existing secrets and files must be dropped: %+v", h)
			}
			want := map[string]string{"LATER": "secret:not-set-yet", "APP_ENV": "secret-less prod"}
			if !maps.Equal(h.Env, want) {
				t.Errorf("env %v, want %v", h.Env, want)
			}
		})
	}
}

func TestImportFileZillaRcloneDBeaver(t *testing.T) {
	fz, err := importFileZilla(writeTemp(t, "sitemanager.xml", `<?xml version="1.0"?><FileZilla3><Servers>
<Server><Host>web.example</Host><Port>2222</Port><Protocol>1</Protocol><User>deploy</User><Pass encoding="base64">czNjcmV0</Pass><Name>Web</Name></Server>
<Folder><Server><Host>ftp.example</Host><Port>21</Port><Protocol>0</Protocol><User>x</User><Name>Old FTP</Name></Server></Folder>
</Servers></FileZilla3>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(fz.Hosts) != 1 || fz.Hosts[0].Name != "web" || fz.Hosts[0].Port != 2222 || fz.Secrets["web-pass"] != "s3cret" || len(fz.Notes) != 1 {
		t.Errorf("filezilla: %+v %v %v", fz.Hosts, len(fz.Secrets), fz.Notes)
	}
	rc, err := importRclone(writeTemp(t, "rclone.conf", "[box]\ntype = sftp\nhost = box.lan\nuser = me\nkey_file = ~/.ssh/id_ed25519\n\n[b2]\ntype = b2\naccount = x\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.Hosts) != 1 || rc.Hosts[0].Address != "box.lan" || len(rc.Notes) != 1 {
		t.Errorf("rclone: %+v %v", rc.Hosts, rc.Notes)
	}
	db, err := importDBeaver(writeTemp(t, "data-sources.json", `{"connections":{
		"postgres-1":{"name":"Shop prod","provider":"postgresql","configuration":{"host":"db.lan","port":"5432","database":"shop","user":"app"}},
		"x":{"name":"Mongo","provider":"mongodb","configuration":{}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(db.Conns) != 1 || db.Conns[0].Name != "shop-prod" || db.Conns[0].URL != "postgres://app@db.lan:5432/shop" {
		t.Errorf("dbeaver: %+v", db.Conns)
	}
	// an Oracle connection by SID, and one by service name
	ora, err := importDBeaver(writeTemp(t, "data-sources.json", `{"connections":{
		"oracle-1":{"name":"Old ERP","provider":"oracle","configuration":{"host":"erp.lan","port":"1521","database":"ORCL","user":"app",
			"provider-properties":{"@dbeaver-sid-service@":"SID"}}},
		"oracle-2":{"name":"New ERP","provider":"oracle","configuration":{"host":"erp.lan","port":"1521","database":"ERPPDB","user":"app",
			"provider-properties":{"@dbeaver-sid-service@":"SERVICE"}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range ora.Conns {
		got[c.Name] = c.URL
	}
	if got["old-erp"] != "oracle://app@erp.lan:1521?sid=ORCL" || got["new-erp"] != "oracle://app@erp.lan:1521/ERPPDB" {
		t.Errorf("dbeaver oracle: %v", got)
	}
}

// DBeaver keeps passwords elsewhere, so the import says how to set each
// one. The note names the conn as it was added: when shop-prod is taken by
// another database it becomes shop-prod-2, and the note must not point the
// user's own shop-prod at the new password. A connection that is not added
// gets no such note.
func TestImportDBeaverPasswordNote(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "shop-prod", "postgres://me@other.lan:5432/shop")
	d := mustRun(t, "import", "dbeaver", writeTemp(t, "data-sources.json", `{"connections":{
		"a":{"name":"Shop prod","provider":"postgresql","configuration":{"host":"db.lan","port":"5432","database":"shop","user":"app"}},
		"b":{"name":"Broken","provider":"postgresql","configuration":{"host":"db.lan","port":"not-a-port","database":"x","user":"app"}}}}`))
	notes := fmt.Sprint(d["not_imported"])
	if fmt.Sprint(d["conns"]) != "[shop-prod-2]" ||
		!strings.Contains(notes, "shop-prod-2: set its password with `komando secret set shop-prod-2-pass` and `komando conn edit shop-prod-2 --password-ref secret:shop-prod-2-pass`") ||
		strings.Contains(notes, "conn edit shop-prod ") || strings.Contains(notes, "broken: set its password") {
		t.Errorf("conns %v, notes %s", d["conns"], notes)
	}
}

// A missing file or an unknown source gets a hint about that source, not
// the ssh-config example.
func TestImportUsageHints(t *testing.T) {
	invHome(t)
	for src, want := range map[string]string{"komando": "komando import komando komando-backup.json", "csv": "komando import csv servers.csv"} {
		if e := wantCode(t, "USAGE", "import", src, "--dry-run"); !strings.Contains(e.Hint, want) {
			t.Errorf("%s: %+v", src, e)
		}
	}
	if e := wantCode(t, "USAGE", "import", "bogus"); !strings.Contains(e.Hint, "ssh-config, pgpass") || !strings.Contains(e.Hint, "csv") {
		t.Errorf("unknown source: %+v", e)
	}
}
