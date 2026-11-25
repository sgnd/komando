package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// Cut step E1: the store moves to format 3 at the first open by a person
// at a terminal, or through komando's safety-tier approval window drawn by
// the signed bundled core; an AI agent or a script gets NEEDS_PERSON.
// Every store here is built by the test in a temporary KOMANDO_HOME.

// callerIs makes every open in this test come from c.
func callerIs(t *testing.T, c MigrateCall) {
	t.Helper()
	old := MigrateCaller
	MigrateCaller = func() MigrateCall { return c }
	t.Cleanup(func() { MigrateCaller = old })
}

func atTerminal() MigrateCall {
	return MigrateCall{Way: MigrateTerminal, Alive: func(int, string) bool { return false }}
}

// codeOf is the store error's code and exit, or "" for an error without one.
func codeOf(err error) (string, int) {
	var oe *out.Error
	if errors.As(err, &oe) {
		return oe.Code, oe.Exit
	}
	return "", 0
}

// T1: a person's first open migrates; the inventory then reads back from
// format 3, field by field, with every reference spelled credential:NAME.
func TestFormat3OpenMigratesForPerson(t *testing.T) {
	format2Store(t)
	Close()
	callerIs(t, atTerminal())
	said := notices(t)
	s, err := Load()
	if err != nil {
		t.Fatalf("the first open by a person: %v", err)
	}
	if f := formatNow(t); f != "3" {
		t.Fatalf("format %s after the first open", f)
	}
	if strings.Contains(said.String(), sentinel) {
		t.Fatal("the report holds a secret value")
	}
	for name, want := range map[string][2]string{"web1": {"root", "deploy-root"}, "db1": {"app", "deploy-app"}} {
		h := s.Hosts[name]
		if h == nil || h.User != want[0] || h.Key != want[1] {
			t.Errorf("%s: %+v", name, h)
		}
	}
	web1 := s.Hosts["web1"]
	if web1.Address != "10.0.0.1" || !web1.Protected || web1.SudoRef != "credential:sudo-pw" ||
		web1.Env["PG"] != "credential:pg-pass" || web1.Env["MODE"] != "live" || web1.Labels["note"] != "secret:not-a-ref" {
		t.Errorf("web1 %+v", web1)
	}
	if h := s.Hosts["h3"]; h.User != "alice" || h.PasswordRef != "credential:shared-pw-alice" || h.Env["TOKEN"] != "credential:shared-pw" {
		t.Errorf("h3 %+v", h)
	}
	if h := s.Hosts["h4"]; h.User != "bob" || h.PasswordRef != "credential:shared-pw-bob" {
		t.Errorf("h4 %+v", h)
	}
	if h := s.Hosts["win1"]; h.Transport != TransportWinRM || h.User != `DOMAIN\admin` || h.PasswordRef != "credential:win-pw" || h.WinRMOpts.CA != "credential:win-ca" {
		t.Errorf("win1 %+v", h)
	}
	if c := s.Conns["pg"]; c.PasswordRef != "credential:pg-pass" || !strings.Contains(c.URL, "ca=credential:pg-ca") || !c.Protected {
		t.Errorf("pg %+v", c)
	}
	if v := s.Vpns["wg"]; v.KeyRef != "credential:wg-key" || v.PSKRef != "credential:wg-psk" || !v.MFA {
		t.Errorf("wg %+v", v)
	}
	if r := s.Snippets["r1"]; r == nil || r.Command != "echo secret:abc" {
		t.Errorf("a snippet body is text, kept as it was: %+v", r)
	}
	if len(s.Settings.ExtraDenyPattern) != 1 || s.Settings.ExtraDenyPattern[0] != "rm -rf /srv" {
		t.Errorf("deny patterns %v", s.Settings.ExtraDenyPattern)
	}
	Close()
	// a second open has nothing to do
	before := fileSum(t)
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	if fileSum(t) != before {
		t.Error("a second open changed the store")
	}
}

// T3 and T4: an AI agent, a script and CI never migrate, and the file is
// left exactly as it was.
func TestFormat2CallerNeedsPerson(t *testing.T) {
	for _, why := range []string{"an AI agent (Claude Code)", "a script", "CI"} {
		t.Run(why, func(t *testing.T) {
			format2Store(t)
			Close()
			callerIs(t, MigrateCall{Way: MigrateRefuse, Why: why})
			before := fileSum(t)
			_, err := Load()
			if code, exit := codeOf(err); code != "NEEDS_PERSON" || exit != out.ExitPolicy {
				t.Fatalf("got %v (%s, %d)", err, code, exit)
			}
			if !strings.Contains(err.Error(), "komando doctor") {
				t.Errorf("no terminal command in %v", err)
			}
			if fileSum(t) != before || formatNow(t) != "2" {
				t.Error("a refused caller changed the store")
			}
		})
	}
}

// The window path: the window names the backup and the counts; a no
// writes nothing; a yes migrates and the audit entry says how.
func TestFormat2Window(t *testing.T) {
	t.Run("no", func(t *testing.T) {
		format2Store(t)
		Close()
		before := fileSum(t)
		var shown string
		callerIs(t, MigrateCall{Way: MigrateWindow, Alive: func(int, string) bool { return false },
			Ask: func(text string) bool { shown = text; return false }})
		_, err := Load()
		if code, _ := codeOf(err); code != "NEEDS_PERSON" && code != "CANCELLED" {
			t.Fatalf("a no: %v", err)
		}
		if !strings.Contains(shown, "store-v0-17-backup-") || !strings.Contains(shown, "12 servers") {
			t.Errorf("the window showed %q", shown)
		}
		if fileSum(t) != before {
			t.Error("a no changed the store")
		}
		if m, _ := os.ReadDir(Home()); hasBackup(m) {
			t.Error("a no left a backup")
		}
	})
	t.Run("yes", func(t *testing.T) {
		format2Store(t)
		Close()
		asked := 0
		callerIs(t, MigrateCall{Way: MigrateWindow, Alive: func(int, string) bool { return false },
			Ask: func(string) bool { asked++; return true }})
		if _, err := Load(); err != nil {
			t.Fatal(err)
		}
		if asked != 1 || formatNow(t) != "3" {
			t.Fatalf("asked %d, format %s", asked, formatNow(t))
		}
		entry := lastAudit(t)
		if !strings.Contains(entry, `"via":"window"`) || !strings.Contains(entry, "store-v0-17-backup-") {
			t.Errorf("audit entry %s", entry)
		}
	})
}

func hasBackup(es []os.DirEntry) bool {
	for _, e := range es {
		if strings.HasPrefix(e.Name(), "store-v0-17-backup-") {
			return true
		}
	}
	return false
}

func lastAudit(t *testing.T) string {
	t.Helper()
	d, err := DB(false)
	if err != nil {
		t.Fatal(err)
	}
	var last string
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		rows, err := tx.Audit(0, 1000)
		if len(rows) > 0 {
			last = string(rows[len(rows)-1].Data)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return last
}

// T7 (N2): a migration that waited for the lock while another finished
// finds format 3 under the lock and does nothing: no backup, no error.
func TestMigrate3SecondWaiterFindsFormat3(t *testing.T) {
	format2Store(t)
	Close()
	o := personOpts()
	o.beforeLock = func() {
		if _, err := migrateFormat3(context.Background(), personOpts()); err != nil {
			t.Errorf("the first migration: %v", err)
		}
		Close()
	}
	res, err := migrateFormat3(context.Background(), o)
	if err != nil {
		t.Fatalf("the waiter: %v", err)
	}
	if res.report.Backup != "" {
		t.Errorf("the waiter made a backup: %s", res.report.Backup)
	}
	es, _ := os.ReadDir(Home())
	n := 0
	for _, e := range es {
		if strings.HasPrefix(e.Name(), "store-v0-17-backup-") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d backups, want 1", n)
	}
}

// T10 (F10): a format-3 store that holds secret:NAME in a reference field
// stops the load and names the field, never the value.
func TestFormat3RefusesSecretRef(t *testing.T) {
	format2Store(t)
	if _, err := migrateFormat3(context.Background(), personOpts()); err != nil {
		t.Fatal(err)
	}
	format3Write(t, func(tx *sealdb.Tx) error {
		return editRecord(tx, KindHost, "web1", func(m map[string]any) {
			m["env"] = map[string]any{"PG": "secret:pg-pass", "MODE": "live"}
		})
	})
	callerIs(t, atTerminal())
	_, err := Load()
	code, exit := codeOf(err)
	if code != "STORE_REFERENCE_UNSUPPORTED" || exit != out.ExitUsage {
		t.Fatalf("got %v (%s, %d)", err, code, exit)
	}
	if msg := err.Error(); !strings.Contains(msg, "web1") || !strings.Contains(msg, "PG") || strings.Contains(msg, "pg-pass") {
		t.Errorf("message %q", msg)
	}
}

// T11: a format this komando does not know is refused with a code, and
// nothing is written.
func TestFormatUnknownRefused(t *testing.T) {
	for v, want := range map[string]string{"4": "STORE_NEWER", "x": "STATE_CORRUPT", "": "STATE_CORRUPT"} {
		t.Run("format "+v, func(t *testing.T) {
			format2Store(t)
			Close()
			if _, err := rawSQL(t).Exec(`UPDATE meta SET v=? WHERE k='format'`, v); err != nil {
				t.Fatal(err)
			}
			callerIs(t, atTerminal())
			before := fileSum(t)
			_, err := Load()
			if code, _ := codeOf(err); code != want {
				t.Fatalf("got %v (%s), want %s", err, code, want)
			}
			if fileSum(t) != before {
				t.Error("an unknown format was written to")
			}
		})
	}
}

// T12 (C395, C377): an exec session record, even one whose server is
// gone, and a job not marked ended are carried as data: they do not block
// the migration and read back after it.
func TestMigrate3CarriesRemoteWork(t *testing.T) {
	format2Store(t)
	format2Runtime(t, func(s *State) {
		s.ExecSessions["e1"] = &ExecSession{ID: "e1", Host: "gone-host", Command: "sleep 1", PID: 42}
		s.Jobs["j1"] = &Job{ID: "j1", Host: "web1", PID: 77}
	})
	if _, err := migrateFormat3(context.Background(), personOpts()); err != nil {
		t.Fatalf("remote work blocked the migration: %v", err)
	}
	rt, err := ReadRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if e := rt.ExecSessions["e1"]; e == nil || e.Host != "gone-host" {
		t.Errorf("exec session after the migration: %+v", e)
	}
	if j := rt.Jobs["j1"]; j == nil || j.Host != "web1" {
		t.Errorf("job after the migration: %+v", j)
	}
}

// format3Write changes a format-3 store past komando's own writer, with
// the store's keys, as a tool that holds the master key could.
func format3Write(t *testing.T, fn func(tx *sealdb.Tx) error) {
	t.Helper()
	Close()
	master, _, err := KeySource(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keysFor3(master)
	if err != nil {
		t.Fatal(err)
	}
	d, err := sealdb.Open(context.Background(), DBPath(), ks.row)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.SetPolicy(context.Background(), ks.policy); err != nil {
		t.Fatal(err)
	}
	if err := d.Update(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

// editRecord changes the JSON of the record of type typ named name.
func editRecord(tx *sealdb.Tx, typ, name string, fn func(map[string]any)) error {
	rows, err := tx.List(typ)
	if err != nil {
		return err
	}
	for _, r := range rows {
		var m map[string]any
		if err := json.Unmarshal(r.Data, &m); err != nil {
			return err
		}
		if m["name"] != name {
			continue
		}
		fn(m)
		b, err := json.Marshal(m)
		if err != nil {
			return err
		}
		_, err = tx.Put(typ, r.ID, b)
		return err
	}
	return fmt.Errorf("no %s record named %s", typ, name)
}
