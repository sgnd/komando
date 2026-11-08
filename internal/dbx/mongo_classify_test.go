package dbx

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/driver"
)

func TestClassifyMongo(t *testing.T) {
	for doc, want := range map[string]string{
		`{"find": "users", "filter": {"plan": "pro"}}`:                                               "read",
		`{"aggregate": "orders", "pipeline": [{"$match": {}}], "cursor": {}}`:                        "read",
		`{"aggregate": "orders", "pipeline": [{"$group": {"_id": 1}}, {"$out": "x"}], "cursor": {}}`: "write",
		`{"count": "users"}`:     "read",
		`{"listCollections": 1}`: "read",
		`{"explain": {"delete": "users", "deletes": [{"q": {}, "limit": 0}]}}`:                "read",
		`{"insert": "users", "documents": [{"a": 1}]}`:                                        "write",
		`{"update": "users", "updates": [{"q": {"_id": 1}, "u": {"$set": {"a": 2}}}]}`:        "write",
		`{"update": "users", "updates": [{"q": {}, "u": {"$set": {"a": 2}}}]}`:                "write", // one document
		`{"update": "users", "updates": [{"q": {}, "u": {"$set": {"a": 2}}, "multi": true}]}`: "destructive mongo-update-all",
		`{"delete": "users", "deletes": [{"q": {"_id": 1}, "limit": 1}]}`:                     "write",
		`{"delete": "users", "deletes": [{"q": {"_id": 1}, "limit": 0}]}`:                     "write",
		`{"delete": "users", "deletes": [{"q": {}, "limit": 0}]}`:                             "destructive mongo-delete-all",
		`{"delete": "users", "deletes": [{"q": {}, "limit": 1}]}`:                             "write",
		`{"drop": "users"}`:   "destructive mongo-drop",
		`{"dropDatabase": 1}`: "destructive mongo-drop",
		`{"renameCollection": "a.b", "to": "a.c", "dropTarget": true}`: "destructive mongo-drop",
		`{"renameCollection": "a.b", "to": "a.c"}`:                     "write",
		`{"createUser": "bob", "pwd": "x", "roles": []}`:               "destructive mongo-privileges",
		`{"shutdown": 1}`:            "destructive mongo-admin",
		`{"fsync": 1, "lock": true}`: "destructive mongo-admin",
		`{"someNewCommand": 1}`:      "write", // not known as a read
	} {
		cmd, _, err := ParseMongoCommand(doc)
		if err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		v := ClassifyMongo(cmd)
		got := v.Risk.String()
		if v.Risk == driver.RiskDestructive {
			got += " " + strings.Join(v.RuleIDs, ",")
		}
		if got != want {
			t.Errorf("%s: %s, want %s", doc, got, want)
		}
	}
}

func TestParseMongoCommand(t *testing.T) {
	cmd, db, err := ParseMongoCommand(`{"find": "orders", "$db": "shop", "filter": {"_id": {"$oid": "5f1d7f1b2c3a4b5c6d7e8f90"}}}`)
	if err != nil || db != "shop" || len(cmd) != 2 || cmd[0].Key != "find" {
		t.Errorf("$db is taken out: %v %q %v", cmd, db, err)
	}
	for _, bad := range []string{"", "select 1", `{"$db": "shop"}`, `[1,2]`} {
		if _, _, err := ParseMongoCommand(bad); err == nil {
			t.Errorf("%q: want an error", bad)
		}
	}
}
