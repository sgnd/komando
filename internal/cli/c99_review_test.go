package cli

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
	"github.com/sgnd/komando/internal/store"
)

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
	wantCode(t, "REVEAL_REQUIRED", "db", "query", "dev2", "select name n from users")
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
		if e := toErr(hiddenColumnUse(tcl, c, cmd)); e == nil || e.Code != "REVEAL_REQUIRED" {
			t.Errorf("%s: %+v", cmd, e)
		}
	}
	// SQL: an escaped identifier cannot be read by komando
	sql := &store.Conn{Name: "p", URL: "postgres://h/db", Options: map[string]string{"mask_columns": "name"}}
	if e := toErr(hiddenColumnUse(tcl, sql, `select U&"n\0061me" from users`)); e == nil || e.Code != "REVEAL_REQUIRED" {
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
	if e := toErr(hiddenColumnUse(tcl, c, cmd)); e == nil || e.Code != "REVEAL_REQUIRED" {
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
