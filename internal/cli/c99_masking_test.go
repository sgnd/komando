package cli

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/store"
)

// A column in mask_columns is hidden by its name in the result. A query
// that names the column anywhere may rename it, compute from it or filter
// on it, and komando cannot tell which results come from it: for an AI
// agent such a query is refused. SELECT * shows the column as hidden.
func TestHiddenColumnCannotBeRenamed(t *testing.T) {
	personalDB(t)
	mustRun(t, "conn", "edit", "dev", "--option", "mask_columns=Name card")
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	for _, q := range []string{
		"select name as customer from users",
		"select upper(name) from users",
		"select name || '' from users",
		"select id from users where name like 'A%'",
		`select "Name" x from users`,
		"select * from (select card c from users)",
		"select id, name from users",
	} {
		e := wantCode(t, "REVEAL_NEEDS_PERSON", "db", "query", "dev", q)
		if strings.Contains(e.Message+e.Hint, "Ada") || !strings.Contains(e.Hint, "*") {
			t.Errorf("%s: %+v", q, e)
		}
	}
	// queries that do not name it work, the column hidden by its name
	if got := strs(customer(t, "dev")); got[1] != "[hidden: column]" || got[4] != "[hidden: column]" {
		t.Errorf("select *: %v", got)
	}
	mustRun(t, "db", "query", "dev", "select id, email from users where id = 1")
	mustRun(t, "db", "query", "dev", "select count(*) as names from users") // "names" is another word
	// a person's query is theirs
	os.Unsetenv("KOMANDO_AGENT")
	resetApproval()
	d := mustRun(t, "db", "query", "dev", "select name as customer from users")
	if b, _ := json.Marshal(d); !strings.Contains(string(b), "Ada Lovelace") {
		t.Errorf("a person: %s", b)
	}
}

// Taking a column out of mask_columns, or turning mask_personal off for a
// conn, shows an AI agent what a person chose to hide: it needs a
// person's yes, as lowering the mask_personal setting does.
func TestConnEditKeepsMasking(t *testing.T) {
	personalDB(t)
	mustRun(t, "conn", "edit", "dev", "--option", "mask_columns=name card", "--option", "mask_personal=on")
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	for _, opt := range []string{"mask_columns=", "mask_columns=card", "mask_personal=", "mask_personal=off"} {
		e := wantCode(t, "SAFETY_SETTING", "conn", "edit", "dev", "--option", opt)
		if !strings.Contains(e.Message+e.Hint, "personal") && !strings.Contains(e.Message+e.Hint, "hidden") {
			t.Errorf("%s: %+v", opt, e)
		}
	}
	mustRun(t, "conn", "edit", "dev", "--option", "mask_columns=name card email") // more hiding needs no yes
	if got := strs(customer(t, "dev")); got[1] != "[hidden: column]" || got[2] != "[hidden: column]" {
		t.Errorf("still hidden: %v", got)
	}
}

// A dump is every row in a file on this computer, which an AI agent then
// reads with its own tools: where personal data is hidden from the agent,
// the dump is refused (a person allows it with --reveal).
func TestDumpRefusedWherePersonalDataIsHidden(t *testing.T) {
	personalDB(t)
	dir := t.TempDir()
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	e := wantCode(t, "SENSITIVE_FILE", "db", "dump", "prod", "--to", filepath.Join(dir, "prod.db"))
	if !strings.Contains(e.Hint, "--reveal") {
		t.Errorf("hint: %+v", e)
	}
	if _, err := os.Stat(filepath.Join(dir, "prod.db")); err == nil {
		t.Error("the dump was written")
	}
	if d, e := invRun(t, "--dry-run", "db", "dump", "prod", "--to", filepath.Join(dir, "prod.db")); e != nil || blockedCode(d) != "SENSITIVE_FILE" {
		t.Errorf("a dry run reports the stop: %v %+v", d, e)
	}
	tcl.flags.dryRun = false
	mustRun(t, "db", "dump", "dev", "--to", filepath.Join(dir, "dev.db")) // nothing hidden there
	os.Unsetenv("KOMANDO_AGENT")
	resetApproval()
	mustRun(t, "conn", "edit", "dev", "--option", "mask_columns=name")
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	wantCode(t, "SENSITIVE_FILE", "db", "dump", "dev", "--to", filepath.Join(dir, "dev2.db"))
	os.Unsetenv("KOMANDO_AGENT")
	resetApproval()
	mustRun(t, "db", "dump", "prod", "--to", filepath.Join(dir, "person.db")) // a person's own
}

// blockedCode is the code of the stop a dry run reports, or "".
func blockedCode(d map[string]any) string {
	meta, _ := d["_meta"].(map[string]any)
	wb, _ := meta["would_be_blocked"].(map[string]any)
	code, _ := wb["code"].(string)
	return code
}

// Every command that copies a target's data to this computer hides
// personal data as download does; fs replace shows the file too.
func TestCopiesHidePersonalData(t *testing.T) {
	for _, id := range []string{"cp", "sync", "download", "fs replace", "storage download"} {
		if !personalCmds[id] {
			t.Errorf("%s shows or saves a target's data, but personal data is never hidden for it", id)
		}
	}
}

// A link is the raw file for whoever holds it: an AI agent gets one only
// with a person's yes (--reveal), and never for a file that is a secret
// by its name.
func TestStorageLinkForAgents(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "s3l", "s3://AKIAEXAMPLE@bucket?region=eu-west-1&endpoint=http://127.0.0.1:9")
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	e := wantCode(t, "SENSITIVE_FILE", "storage", "link", "s3l", "reports/a.txt")
	if !strings.Contains(e.Hint, "--reveal") {
		t.Errorf("hint: %+v", e)
	}
	wantCode(t, "SENSITIVE_FILE", "storage", "link", "s3l", "app/.env")
	if d, e := invRun(t, "--dry-run", "storage", "link", "s3l", "reports/a.txt"); e != nil || blockedCode(d) != "SENSITIVE_FILE" {
		t.Errorf("a dry run reports the stop: %v %+v", d, e)
	}
	tcl.flags.dryRun = false
}

// What an AI agent reads on stdout is shown as text with its secrets
// hidden; a binary object cannot be shown that way, so one that holds a
// vault value is refused, as the download to a file is.
func TestStdoutBinaryIsScanned(t *testing.T) {
	p := &out.Printer{Mask: true, Secrets: func() map[string]string { return map[string]string{"db-pass": "Sup3rS3cretPw"} }}
	saved := tcl.out
	tcl.out = p
	t.Cleanup(func() { tcl.out = saved })
	if text, err := agentStdout(tcl, "backup.bin", []byte("\x00\x01 login Sup3rS3cretPw")); err == nil || toErr(err).Code != "SENSITIVE_FILE" || strings.Contains(text, "Sup3rS3cretPw") {
		t.Errorf("a binary object with a vault value: %q %v", text, err)
	}
	if text, err := agentStdout(tcl, "app.conf", []byte("pw = Sup3rS3cretPw\n")); err != nil || text != "pw = [secret:db-pass]\n" {
		t.Errorf("text: %q %v", text, err)
	}
	if text, err := agentStdout(tcl, "logo.png", []byte("\x00\x01\x02")); err != nil || text != "\x00\x01\x02" {
		t.Errorf("plain binary: %q %v", text, err)
	}
}

// mask_columns hides a MongoDB document's fields by name, at any depth,
// and a command that names a hidden field is refused like a SQL query.
func TestMongoHiddenFields(t *testing.T) {
	c := &store.Conn{Name: "m", Options: map[string]string{"mask_columns": "name address"}}
	p := &out.Printer{Mask: true, Personal: true}
	saved := tcl.out
	tcl.out = p
	t.Cleanup(func() { tcl.out = saved })
	res := &dbx.MongoResult{Documents: []any{
		map[string]any{"_id": 1, "name": "Ada Lovelace", "Address": map[string]any{"street": "12 St James's Sq"}, "orders": []any{map[string]any{"name": "Ada L", "sku": "x1"}}, "plan": "pro"},
	}, Reply: map[string]any{"users": []any{map[string]any{"name": "Ada Lovelace", "credentials": map[string]any{"SCRAM-SHA-256": map[string]any{"salt": "c2FsdHNhbHQ=", "storedKey": "U3RvcmVk"}}}}}}
	maskMongo(tcl, c, res)
	b, _ := json.Marshal(res)
	got := string(b)
	for _, leak := range []string{"Ada", "St James", "c2FsdHNhbHQ=", "U3RvcmVk"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q leaked: %s", leak, got)
		}
	}
	if !strings.Contains(got, `"name":"[hidden: column]"`) || !strings.Contains(got, `"Address":"[hidden: column]"`) || !strings.Contains(got, `"sku":"x1"`) || !strings.Contains(got, `"plan":"pro"`) {
		t.Errorf("masked: %s", got)
	}
	for _, cmd := range []string{`{"find":"users","filter":{"name":"Ada"}}`, `{"aggregate":"users","pipeline":[{"$project":{"n":"$name"}}],"cursor":{}}`} {
		if e := toErr(hiddenColumnUse(tcl, c, cmd)); e == nil || e.Code != "REVEAL_NEEDS_PERSON" {
			t.Errorf("%s: %+v", cmd, e)
		}
	}
	if err := hiddenColumnUse(tcl, c, `{"find":"users","filter":{"plan":"pro"}}`); err != nil {
		t.Errorf("a command that names no hidden field: %v", err)
	}
	// a person sees it all
	tcl.out = &out.Printer{}
	res = &dbx.MongoResult{Documents: []any{map[string]any{"name": "Ada Lovelace"}}}
	maskMongo(tcl, c, res)
	if b, _ := json.Marshal(res); !strings.Contains(string(b), "Ada Lovelace") {
		t.Errorf("a person: %s", b)
	}
}

// A queue message that is not text is shown as base64: what it holds is
// checked like any other value.
func TestQueueBinaryValuesAreChecked(t *testing.T) {
	p := &out.Printer{Mask: true, Personal: true, Secrets: func() map[string]string { return map[string]string{"db-pass": "Sup3rS3cretPw"} }}
	saved := tcl.out
	tcl.out = p
	t.Cleanup(func() { tcl.out = saved })
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	msgs := []queuex.Received{
		{Value: b64("\xff\x00 token Sup3rS3cretPw"), Encoding: "base64"},
		{Value: b64("\xff\x00 to alice@example.com"), Encoding: "base64"},
		{Value: b64("\xff\x00\x01\x02"), Encoding: "base64"},
		{Value: "plain text"},
	}
	hideBinaryMessages(tcl, msgs)
	if msgs[0].Value != out.Hidden || msgs[1].Value != out.Hidden || msgs[2].Value != b64("\xff\x00\x01\x02") || msgs[3].Value != "plain text" {
		t.Errorf("messages: %+v", msgs)
	}
}
