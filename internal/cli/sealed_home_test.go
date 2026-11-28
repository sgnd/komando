package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// config show and doctor name the sealed store on a sealed home.
func TestSealedConfigAndDoctor(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "deploy@10.0.0.1")
	c := mustRun(t, "config", "show")
	files := c["files"].(map[string]any)
	for _, k := range []string{"state", "vault", "known_hosts", "audit"} {
		if files[k] != store.Path(store.StoreFile) {
			t.Errorf("files.%s = %v", k, files[k])
		}
	}
	d, _ := invRun(t, "doctor")
	found := false
	sec, _ := d["security"].([]any)
	for _, ch := range sec {
		m := ch.(map[string]any)
		if m["name"] == "security:vault" && strings.Contains(m["detail"].(string), store.StoreFile) {
			found = true
		}
	}
	if !found {
		t.Errorf("doctor does not name the store: %v", sec)
	}
}

// Accepting an old copy is for a person at a terminal.
func TestAcceptOldCopyNeedsAPerson(t *testing.T) {
	invHome(t)
	setCallerEnv(t, "KOMANDO_AGENT", "1")
	if _, e := invRun(t, "doctor", "--accept-old-copy"); e == nil || e.Code != "NEEDS_PERSON" {
		t.Fatalf("agent: %+v", e)
	}
}
