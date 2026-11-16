package dbx

import "testing"

// profile and validate read only in one form each: profile with level -1
// reports the level, any other level sets it (and slowms, sampleRate);
// validate checks a collection, but repair and fixMetadata change it.
func TestClassifyMongoProfileValidate(t *testing.T) {
	for doc, want := range map[string]string{
		`{"profile": -1}`:                        "read",
		`{"profile": -1.0}`:                      "read",
		`{"profile": 2, "slowms": 0}`:            "write",
		`{"profile": 0}`:                         "write",
		`{"profile": 1, "sampleRate": 1.0}`:      "write",
		`{"profile": -1, "slowms": 5}`:           "write",
		`{"profile": "2"}`:                       "write",
		`{"validate": "c"}`:                      "read",
		`{"validate": "c", "full": true}`:        "read",
		`{"validate": "c", "repair": true}`:      "write",
		`{"validate": "c", "repair": 1}`:         "write",
		`{"validate": "c", "fixMetadata": true}`: "write",
		`{"validate": "c", "repair": false}`:     "read",
		`{"explain": {"profile": 2}}`:            "read",
	} {
		cmd, _, err := ParseMongoCommand(doc)
		if err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		if got := ClassifyMongo(cmd).Risk.String(); got != want {
			t.Errorf("%s: %s, want %s", doc, got, want)
		}
	}
}

// The bulkWrite command deletes or updates every document the same way
// delete and update do; aggregate with $out replaces a whole collection;
// killCursors ends another client's query. None is a plain read or write.
func TestClassifyMongoBulkOutKill(t *testing.T) {
	for doc, want := range map[string]string{
		`{"bulkWrite": 1, "ops": [{"delete": 0, "filter": {}, "multi": true}], "nsInfo": [{"ns": "a.b"}]}`:                                   "destructive mongo-delete-all",
		`{"bulkWrite": 1, "ops": [{"insert": 0, "document": {"a": 1}}, {"delete": 0, "multi": true}], "nsInfo": [{"ns": "a.b"}]}`:            "destructive mongo-delete-all",
		`{"bulkWrite": 1, "ops": [{"delete": 0, "filter": {}, "multi": false}], "nsInfo": [{"ns": "a.b"}]}`:                                  "write",
		`{"bulkWrite": 1, "ops": [{"delete": 0, "filter": {"_id": 1}, "multi": true}], "nsInfo": [{"ns": "a.b"}]}`:                           "write",
		`{"bulkWrite": 1, "ops": [{"update": 0, "filter": {}, "updateMods": {"$set": {"a": 1}}, "multi": true}], "nsInfo": [{"ns": "a.b"}]}`: "destructive mongo-update-all",
		`{"bulkWrite": 1, "ops": [{"update": 0, "filter": {}, "updateMods": {"$set": {"a": 1}}}], "nsInfo": [{"ns": "a.b"}]}`:                "write",
		`{"bulkWrite": 1, "ops": [{"insert": 0, "document": {"a": 1}}], "nsInfo": [{"ns": "a.b"}]}`:                                          "write",
		`{"aggregate": "orders", "pipeline": [{"$group": {"_id": 1}}, {"$out": "users"}], "cursor": {}}`:                                     "destructive mongo-drop",
		`{"aggregate": "orders", "pipeline": [{"$out": {"db": "x", "coll": "users"}}], "cursor": {}}`:                                        "destructive mongo-drop",
		`{"aggregate": "orders", "pipeline": [{"$merge": {"into": "totals"}}], "cursor": {}}`:                                                "write",
		`{"aggregate": "orders", "pipeline": [{"$match": {"a": "$out"}}], "cursor": {}}`:                                                     "read",
		`{"killCursors": "users", "cursors": [123]}`:                                                                                         "write",
	} {
		cmd, _, err := ParseMongoCommand(doc)
		if err != nil {
			t.Fatalf("%s: %v", doc, err)
		}
		v := ClassifyMongo(cmd)
		got := v.Risk.String()
		if len(v.RuleIDs) > 0 {
			got += " " + v.RuleIDs[0]
		}
		if got != want {
			t.Errorf("%s: %s, want %s", doc, got, want)
		}
	}
}
