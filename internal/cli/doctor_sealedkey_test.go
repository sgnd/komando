package cli

import "testing"

// doctor finds a key komando made in the store, where it lives, and says
// nothing about a missing file.
func TestDoctorSealedKey(t *testing.T) {
	invHome(t)
	mustRun(t, "key", "gen", "deploy")
	d, _ := invRun(t, "doctor")
	for _, c := range d["inventory"].([]any) {
		m := c.(map[string]any)
		if m["name"] == "key:deploy" && m["ok"] != true {
			t.Fatalf("doctor fails a key in the store: %v", m)
		}
	}
}
