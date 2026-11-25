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

// The hiding a person set on a conn does not go away by replacing the
// conn, removing it or reaching the same database under another name.
func TestMaskingSurvivesOtherWaysToTheConn(t *testing.T) {
	personalDB(t)
	mustRun(t, "conn", "edit", "dev", "--option", "mask_columns=name card")
	d := mustRun(t, "conn", "show", "dev")
	url, _ := d["url"].(string)
	if url == "" {
		t.Fatalf("conn show: %v", d)
	}
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	wantCode(t, "SAFETY_SETTING", "conn", "add", "dev", url, "--overwrite")
	wantCode(t, "SAFETY_SETTING", "conn", "rm", "dev")
	// another name for the same database: the columns stay hidden
	mustRun(t, "conn", "add", "dev2", url)
	if got := strs(customer(t, "dev2")); got[1] != "[hidden: column]" || got[2] != "[hidden: email]" {
		t.Errorf("a second conn to the same database: %v", got)
	}
	wantCode(t, "REVEAL_NEEDS_PERSON", "db", "query", "dev2", "select name n from users")
	wantCode(t, "SENSITIVE_FILE", "db", "dump", "dev2", "--to", filepath.Join(t.TempDir(), "x.db"))
}

// A MongoDB command is searched as the server reads it: an escape in the
// text is the same field.
func TestMongoCommandIsSearchedDecoded(t *testing.T) {
	c := &store.Conn{Name: "m", URL: "mongodb://h/db", Options: map[string]string{"mask_columns": "name"}}
	saved := tcl.out
	tcl.out = &out.Printer{Mask: true, Personal: true}
	t.Cleanup(func() { tcl.out = saved })
	for _, cmd := range []string{
		`{"find":"users","projection":{"x":"$name"}}`,
		`{"aggregate":"users","pipeline":[{"$project":{"all":{"$objectToArray":"$$ROOT"}}}],"cursor":{}}`,
		`{"find":"users","filter":{"$where":"this.x == 1"}}`,
	} {
		if e := toErr(hiddenColumnUse(tcl, c, cmd)); e == nil || e.Code != "REVEAL_NEEDS_PERSON" {
			t.Errorf("%s: %+v", cmd, e)
		}
	}
	// SQL: an escaped identifier cannot be read by komando
	sql := &store.Conn{Name: "p", URL: "postgres://h/db", Options: map[string]string{"mask_columns": "name"}}
	if e := toErr(hiddenColumnUse(tcl, sql, `select U&"n\0061me" from users`)); e == nil || e.Code != "REVEAL_NEEDS_PERSON" {
		t.Errorf("U& escape: %+v", e)
	}
}

// Commands that show a file's content in a dry run or a diff hide
// personal data too.
func TestMoreCommandsHidePersonalData(t *testing.T) {
	for _, id := range []string{"fs write", "fs restore", "docker compose"} {
		if !personalCmds[id] {
			t.Errorf("%s shows a target's data, but personal data is never hidden for it", id)
		}
	}
}

// A binary cell is checked before any format shows it (-o text and csv
// print it as hex), and a cell that is JSON has its hidden fields masked
// (to_jsonb(row), row_to_json).
func TestQueryCellsAreChecked(t *testing.T) {
	saved := tcl.out
	tcl.out = &out.Printer{Mask: true, Personal: true, Secrets: func() map[string]string { return map[string]string{"db-pass": "Sup3rS3cretPw"} }}
	t.Cleanup(func() { tcl.out = saved })
	c := &store.Conn{Name: "p", Options: map[string]string{"mask_columns": "name"}}
	b64 := base64.StdEncoding.EncodeToString([]byte("\xff\x00 Sup3rS3cretPw"))
	res := &dbx.Result{Results: []dbx.StatementResult{{Columns: []dbx.Column{{Name: "blob"}, {Name: "row"}, {Name: "doc"}, {Name: "id"}},
		Rows: [][]any{{map[string]string{"base64": b64}, `{"id":1,"name":"Ada Lovelace"}`, map[string]any{"Name": "Ada L", "plan": "pro"}, int64(7)}}}}}
	maskColumns(tcl, c, res)
	b, _ := json.Marshal(res.Results[0].Rows[0])
	got := string(b)
	if strings.Contains(got, b64) || strings.Contains(got, "Ada") || !strings.Contains(got, `[hidden: column]`) || !strings.Contains(got, `pro`) || !strings.Contains(got, "7") {
		t.Errorf("cells: %s", got)
	}
	if s, ok := res.Results[0].Rows[0][0].(string); !ok || s != out.Hidden {
		t.Errorf("the binary cell is the text [hidden] for every format: %#v", res.Results[0].Rows[0][0])
	}
}

// An edit that takes away both kinds of hiding names both.
func TestLostMaskingNamesAll(t *testing.T) {
	old := &store.Conn{Name: "c", Options: map[string]string{"mask_personal": "on", "mask_columns": "name card"}}
	now := &store.Conn{Name: "c", Options: map[string]string{"mask_columns": "card"}}
	if got := lostMasking(old, now); !strings.Contains(got, "mask_personal") || !strings.Contains(got, "name") {
		t.Errorf("lostMasking: %q", got)
	}
}

// A queue message's key and headers that are not text are checked like
// its value.
func TestQueueKeysAndHeadersAreChecked(t *testing.T) {
	saved := tcl.out
	tcl.out = &out.Printer{Mask: true, Secrets: func() map[string]string { return map[string]string{"db-pass": "Sup3rS3cretPw"} }}
	t.Cleanup(func() { tcl.out = saved })
	hid := base64.StdEncoding.EncodeToString([]byte("\xff\x00 Sup3rS3cretPw"))
	key := hid
	msgs := []queuex.Received{{KafkaRecord: &queuex.KafkaRecord{Key: &key}, Value: "v", Headers: map[string]string{"trace": hid, "plain": "abc", "sqs": "base64:" + hid}}}
	hideBinaryMessages(tcl, msgs)
	if *msgs[0].Key != out.Hidden || msgs[0].Headers["trace"] != out.Hidden || msgs[0].Headers["sqs"] != out.Hidden || msgs[0].Headers["plain"] != "abc" {
		t.Errorf("message: key %q headers %v", *msgs[0].Key, msgs[0].Headers)
	}
}

// mask_columns takes plain column names, and the options are written in
// lower case: anything else would hide nothing.
func TestMaskOptionsAreChecked(t *testing.T) {
	personalDB(t)
	wantCode(t, "USAGE", "conn", "edit", "dev", "--option", "mask_columns=users.name")
	wantCode(t, "USAGE", "conn", "edit", "dev", "--option", "Mask_Columns=name")
}

// Round 2 of the review.

// A MongoDB command with a key twice is searched as it is sent: every
// copy, not only the last one.
func TestMongoDuplicateKeysAreSearched(t *testing.T) {
	c := &store.Conn{Name: "m", URL: "mongodb://h/db", Options: map[string]string{"mask_columns": "name"}}
	saved := tcl.out
	tcl.out = &out.Printer{Mask: true, Personal: true}
	t.Cleanup(func() { tcl.out = saved })
	cmd := `{"aggregate":"users","pipeline":[{"$project":{"x":"$name"}}],"pipeline":[],"cursor":{}}`
	if e := toErr(hiddenColumnUse(tcl, c, cmd)); e == nil || e.Code != "REVEAL_NEEDS_PERSON" {
		t.Errorf("%s: %+v", cmd, e)
	}
	// extended JSON MongoDB takes is read too, not refused
	if err := hiddenColumnUse(tcl, c, `{"find":"users","filter":{"_id":{"$oid":"5f1d7a1e2b3c4d5e6f708192"}}}`); err != nil {
		t.Errorf("extended JSON: %v", err)
	}
}

// The hiding of one database does not reach another database on the same
// server.
func TestTwinIsTheSameDatabase(t *testing.T) {
	shop := &store.Conn{Name: "shop", URL: "postgres://app@10.0.0.5/app", Options: map[string]string{"mask_columns": "name"}}
	billing := &store.Conn{Name: "billing", URL: "postgres://app@10.0.0.5/billing"}
	again := &store.Conn{Name: "again", URL: "postgres://other@10.0.0.5:5432/app"}
	st := &store.State{Conns: map[string]*store.Conn{"shop": shop, "billing": billing, "again": again}}
	if maskedTwin(st, billing) != nil {
		t.Error("another database on the same server")
	}
	if maskedTwin(st, again) == nil {
		t.Error("the same database under another conn")
	}
	// MySQL, SQL Server, ClickHouse, MongoDB ... read every database of
	// the server from any conn to it (select name from shop.users): there
	// the hiding covers the whole server
	for _, u := range []string{"mysql://app@10.0.0.6/shop", "sqlserver://app@10.0.0.6/shop", "clickhouse://app@10.0.0.6/shop", "mongodb://app@10.0.0.6/shop"} {
		masked := &store.Conn{Name: "m", URL: u, Options: map[string]string{"mask_columns": "name"}}
		other := &store.Conn{Name: "o", URL: strings.Replace(u, "/shop", "/mysql", 1)}
		st := &store.State{Conns: map[string]*store.Conn{"m": masked, "o": other}}
		if maskedTwin(st, other) == nil {
			t.Errorf("%s: a conn to another database of the same server reads this one", u)
		}
	}
}

// A JSON cell keeps its numbers exactly.
func TestJSONCellKeepsBigNumbers(t *testing.T) {
	saved := tcl.out
	tcl.out = &out.Printer{Mask: true, Personal: true}
	t.Cleanup(func() { tcl.out = saved })
	got := maskCell(tcl, map[string]any{"id": json.Number("9007199254740993"), "name": "Ada"}, map[string]bool{"name": true}, "[hidden: column]")
	b, _ := json.Marshal(got)
	if !strings.Contains(string(b), "9007199254740993") || strings.Contains(string(b), "Ada") {
		t.Errorf("cell: %s", b)
	}
}

// A server that a conn hiding personal data reaches through (its --via
// path) or points at (its URL's address or name) is a personal target
// too: what an AI agent reads there is hidden as the conn's data is,
// whatever the mask_personal setting says.
func TestHostOfAMaskingConnIsPersonal(t *testing.T) {
	web1 := &store.Host{Name: "web1", Address: "10.0.0.5"}
	jump := &store.Host{Name: "jump", Address: "10.0.0.1"}
	other := &store.Host{Name: "other", Address: "10.0.0.9"}
	on := map[string]string{"mask_personal": "on"}
	for _, tc := range []struct {
		name string
		conn *store.Conn
		host *store.Host
		want bool
	}{
		{"through the server", &store.Conn{Name: "pg", URL: "postgres://u@127.0.0.1:5432/app", Via: "web1", Options: on}, web1, true},
		{"a step on the via path", &store.Conn{Name: "pg", URL: "postgres://u@127.0.0.1:5432/app", Via: "jump,web1", Options: on}, jump, true},
		{"at the server's address", &store.Conn{Name: "pg", URL: "postgres://u@10.0.0.5:5432/app", Options: map[string]string{"mask_columns": "name"}}, web1, true},
		{"at the server's name", &store.Conn{Name: "pg", URL: "postgres://u@WEB1:5432/app", Options: on}, web1, true},
		{"another server", &store.Conn{Name: "pg", URL: "postgres://u@127.0.0.1:5432/app", Via: "web1", Options: on}, other, false},
		{"a conn that hides nothing", &store.Conn{Name: "pg", URL: "postgres://u@10.0.0.5:5432/app", Via: "web1"}, web1, false},
		{"a conn whose twin hides it", &store.Conn{Name: "pg", URL: "postgres://u@10.0.0.6:5432/app", Via: "web1"}, web1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &store.State{Settings: store.Settings{MaskPersonal: "off"},
				Hosts: map[string]*store.Host{"web1": web1, "jump": jump, "other": other},
				Conns: map[string]*store.Conn{tc.conn.Name: tc.conn}}
			if tc.name == "a conn whose twin hides it" { // the same database, reached directly, hides it
				st.Conns["pg-direct"] = &store.Conn{Name: "pg-direct", URL: "postgres://u@10.0.0.6:5432/app", Options: on}
				tc.host = web1
			}
			if got := personalTarget(st, []*store.Host{tc.host}, nil); got != tc.want {
				t.Fatalf("personalTarget(%s) = %v, want %v", tc.host.Name, got, tc.want)
			}
		})
	}
}

// What an AI agent's exec prints on a server that a masking conn reaches
// through shows personal data hidden; before that conn, it shows as sent.
func TestExecOnAMaskingConnsServerHidesPersonalData(t *testing.T) {
	srv := startFakeServer(t)
	srv.answer = func(string) (string, int) { return "id,email\n1,ann@example.com\n", 0 }
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["prod"].Protected = false // dev is the same server: neither is a personal target by the setting
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	if got := asJSON(mustRun(t, "exec", "dev", "--read-only", "--", "cat", "/tmp/x.csv")); !strings.Contains(got, "ann@example.com") {
		t.Fatalf("no masking conn yet: %s", got)
	}
	to := filepath.Join(t.TempDir(), "x.csv")
	if _, e := invRun(t, "download", "dev", "/tmp/x.csv", "--to", to, "--dry-run"); e != nil || tcl.out.Personal {
		t.Fatalf("a download from dev, no masking conn yet: hidden %v, %+v", tcl.out.Personal, e)
	}
	tcl.flags.dryRun = false
	os.Unsetenv("KOMANDO_AGENT")
	resetApproval()
	mustRun(t, "conn", "add", "pg", "postgres://u@127.0.0.1:5432/app", "--via", "dev", "--option", "mask_personal=on")
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	got := asJSON(mustRun(t, "exec", "dev", "--read-only", "--", "cat", "/tmp/x.csv"))
	if strings.Contains(got, "ann@example.com") || !strings.Contains(got, "[hidden: email]") {
		t.Fatalf("a masking conn reaches the database through dev: %s", got)
	}
	// a download from dev takes the same decision (runCp's selection)
	if _, e := invRun(t, "download", "dev", "/tmp/x.csv", "--to", to, "--dry-run"); e != nil || !tcl.out.Personal {
		t.Fatalf("a download from dev: hidden %v, %+v", tcl.out.Personal, e)
	}
	tcl.flags.dryRun = false
}
