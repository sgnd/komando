package cli

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
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
	// the list still shows the records before the broken one, and says so
	d := mustRun(t, "audit", "-n", "0")
	if d["count"].(float64) != 1 {
		t.Fatalf("records before the break: %v", d)
	}
}

// Without a filter, `komando audit` reads only the newest records.
func TestAuditListNewest(t *testing.T) {
	invHome(t)
	for i := range 12 {
		audit(nil, fmt.Sprintf("test.c%02d", i), nil, "", true, nil)
	}
	d := mustRun(t, "audit", "-n", "3")
	es := d["entries"].([]any)
	if len(es) != 3 || es[2].(map[string]any)["command"] != "test.c11" || es[0].(map[string]any)["command"] != "test.c09" {
		t.Fatalf("newest 3: %v", es)
	}
	if n, err := newestAuditSeq(); err != nil || n != 12 {
		t.Fatalf("newest %d %v", n, err)
	}
}

// A store that cannot be written stops a change before it runs, and an
// audit record that cannot be written is a warning, never silence.
func TestAuditUnwritable(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web", "u@10.0.0.1")
	db := store.Path(store.StoreFile)
	if err := os.Chmod(db, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(db, 0o600) })
	if os.Getuid() == 0 {
		t.Skip("root writes any file")
	}
	wantCode(t, "AUDIT_UNAVAILABLE", "host", "add", "db", "u@10.0.0.2")
	mustRun(t, "host", "list") // reads still run
	// a folder where no store can be made: the record fails to write
	ro := t.TempDir()
	os.Chmod(ro, 0o500)
	t.Cleanup(func() { os.Chmod(ro, 0o700) })
	t.Setenv("KOMANDO_HOME", filepath.Join(ro, "home"))
	out.P.Reset()
	audit(nil, "test.unwritable", nil, "", true, nil)
	var buf bytes.Buffer
	w := out.P.W
	out.P.W = &buf
	out.P.Print("x", map[string]any{}, nil)
	out.P.W = w
	if !strings.Contains(buf.String(), "the audit log could not record test.unwritable") {
		t.Fatalf("no warning in meta: %s", buf.String())
	}
}
