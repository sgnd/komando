package cli

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// On a sealed home the audit log lives in the store: listed and verified
// as before, unreadable in the file, and a record removed outside komando
// stops audit verify at its number.
func TestSealedAudit(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "audited-web", "deploy@10.0.0.1")
	mustRun(t, "host", "edit", "audited-web", "--add-tag", "x")
	mustRun(t, "host", "edit", "audited-web", "--add-tag", "y")
	if _, err := os.Stat(store.Path("audit.jsonl")); !os.IsNotExist(err) {
		t.Fatal("audit.jsonl written on a sealed home")
	}
	l := mustRun(t, "audit", "-n", "0", "--command", "host.")
	if l["count"].(float64) < 3 {
		t.Fatalf("audit list: %v", l)
	}
	v := mustRun(t, "audit", "verify")
	if v["ok"] != true || v["entries"].(float64) < 3 {
		t.Fatalf("verify: %v", v)
	}
	b, _ := os.ReadFile(store.Path(store.StoreFile))
	if strings.Contains(string(b), "audited-web") {
		t.Fatal("a host name is readable in store.db")
	}

	raw, err := sql.Open("sqlite", store.Path(store.StoreFile))
	if err != nil {
		t.Fatal(err)
	}
	_, err = raw.Exec(`DELETE FROM audit WHERE seq=2`)
	raw.Close()
	if err != nil {
		t.Fatal(err)
	}
	_, e := invRun(t, "audit", "verify")
	if e == nil || e.Code != "AUDIT_TAMPERED" || !strings.Contains(e.Message, "line 2") {
		t.Fatalf("tampered: %+v", e)
	}
}
