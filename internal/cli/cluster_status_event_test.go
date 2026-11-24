package cli

import "testing"

// eventRow keeps what happened to which object, how often and when last.
// The "last" field falls back from lastTimestamp to eventTime, firstTimestamp
// and metadata.creationTimestamp, in that order. last_age depends on the
// clock, so the tests only check that it is set when the time parses.
func TestEventRow(t *testing.T) {
	obj := map[string]any{"kind": "Pod", "name": "web-1"}
	tests := []struct {
		name     string
		in       map[string]any
		wantLast string
		wantObj  string
		wantN    int
		wantAge  bool
	}{
		{
			name: "lastTimestamp wins",
			in: map[string]any{"type": "Warning", "reason": "BackOff", "message": "restarting", "count": float64(7),
				"involvedObject": obj, "lastTimestamp": "2020-01-02T03:04:05Z", "eventTime": "2020-01-01T00:00:00Z", "firstTimestamp": "2019-12-31T00:00:00Z"},
			wantLast: "2020-01-02T03:04:05Z", wantObj: "pod/web-1", wantN: 7, wantAge: true,
		},
		{
			name: "eventTime when there is no lastTimestamp",
			in: map[string]any{"type": "Normal", "reason": "Pulled", "message": "ok", "count": float64(1),
				"involvedObject": obj, "eventTime": "2020-01-01T00:00:00Z", "firstTimestamp": "2019-12-31T00:00:00Z"},
			wantLast: "2020-01-01T00:00:00Z", wantObj: "pod/web-1", wantN: 1, wantAge: true,
		},
		{
			name: "firstTimestamp as the next fallback",
			in: map[string]any{"type": "Normal", "reason": "Created", "involvedObject": obj,
				"firstTimestamp": "2019-12-31T00:00:00Z"},
			wantLast: "2019-12-31T00:00:00Z", wantObj: "pod/web-1", wantN: 0, wantAge: true,
		},
		{
			name: "creationTimestamp is the last resort",
			in: map[string]any{"type": "Normal", "reason": "Scheduled", "involvedObject": obj,
				"metadata": map[string]any{"creationTimestamp": "2018-05-06T07:08:09Z"}},
			wantLast: "2018-05-06T07:08:09Z", wantObj: "pod/web-1", wantN: 0, wantAge: true,
		},
		{
			name:     "no time at all leaves last and last_age empty",
			in:       map[string]any{"type": "Normal", "reason": "X", "involvedObject": obj},
			wantLast: "", wantObj: "pod/web-1", wantN: 0, wantAge: false,
		},
		{
			name:     "a time that does not parse keeps last and empties last_age",
			in:       map[string]any{"type": "Normal", "reason": "X", "involvedObject": obj, "lastTimestamp": "yesterday"},
			wantLast: "yesterday", wantObj: "pod/web-1", wantN: 0, wantAge: false,
		},
		{
			name:     "no involved object gives a bare slash",
			in:       map[string]any{"type": "Normal", "reason": "X"},
			wantLast: "", wantObj: "/", wantN: 0, wantAge: false,
		},
		{
			name:     "the kind is lower-cased",
			in:       map[string]any{"involvedObject": map[string]any{"kind": "StatefulSet", "name": "db"}},
			wantLast: "", wantObj: "statefulset/db", wantN: 0, wantAge: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := eventRow(tt.in)
			if got["last"] != tt.wantLast {
				t.Errorf("last = %v, want %q", got["last"], tt.wantLast)
			}
			if got["object"] != tt.wantObj {
				t.Errorf("object = %v, want %q", got["object"], tt.wantObj)
			}
			if got["count"] != tt.wantN {
				t.Errorf("count = %v (%T), want int %d", got["count"], got["count"], tt.wantN)
			}
			if age, _ := got["last_age"].(string); (age != "") != tt.wantAge {
				t.Errorf("last_age = %q, want set: %v", age, tt.wantAge)
			}
			for _, k := range []string{"type", "reason", "message"} {
				if got[k] != tt.in[k] {
					t.Errorf("%s = %v, want %v", k, got[k], tt.in[k])
				}
			}
			if len(got) != 8 {
				t.Errorf("a row has %d fields, want 8 (type, reason, message, count, object, last, last_age)", len(got))
			}
		})
	}
}
