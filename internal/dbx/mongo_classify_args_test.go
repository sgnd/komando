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
