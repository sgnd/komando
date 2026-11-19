package cli

import (
	"bytes"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/store"
)

// olderStore makes this home's store as a komando before the sealed
// settings row did.
func olderStore(t *testing.T) {
	t.Helper()
	sealdb.SealNewStores = false
	mustRun(t, "host", "add", "web1", "--address", "10.0.0.5", "--user", "u")
	sealdb.SealNewStores = true
	store.Close()
}

func storeMetaLine(t *testing.T) map[string]any {
	t.Helper()
	d, _ := invRun(t, "doctor")
	for _, c := range d["security"].([]any) {
		if m := c.(map[string]any); m["name"] == "security:store_meta" {
			return m
		}
	}
	return nil
}

// A script's or an agent's command never seals an older store's settings
// row; a person's does, once, with a line on stderr (C08).
func TestMetaSealCarryOverByAPerson(t *testing.T) {
	invHome(t)
	olderStore(t)
	mustRun(t, "list")
	carryMetaSeal(tcl)
	if have, _ := store.MetaSealed(); have {
		t.Fatal("a script's command sealed it")
	}
	if m := storeMetaLine(t); m == nil || m["warning"] != true || !strings.Contains(m["detail"].(string), "your own terminal") {
		t.Errorf("doctor: %v", m)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	saved, savedErr := tcl.terminal, tcl.out.Err
	t.Cleanup(func() { tcl.terminal, tcl.out.Err = saved, savedErr })
	tcl.terminal = true
	mustRun(t, "list")
	carryMetaSeal(tcl)
	if have, _ := store.MetaSealed(); have {
		t.Fatal("an agent's command sealed it")
	}
	setCallerEnv(t, "CLAUDECODE", "")
	noAgent(t)
	var errBuf bytes.Buffer
	tcl.out.Err = &errBuf
	mustRun(t, "list")
	carryMetaSeal(tcl)
	if have, _ := store.MetaSealed(); !have || !strings.Contains(errBuf.String(), "sealed the store's settings row") {
		t.Fatalf("a person's command did not seal it: %q", errBuf.String())
	}
	errBuf.Reset()
	mustRun(t, "list")
	carryMetaSeal(tcl)
	if errBuf.Len() != 0 {
		t.Errorf("said again: %q", errBuf.String())
	}
	tcl.terminal = saved
	if m := storeMetaLine(t); m == nil || m["ok"] != true || m["warning"] == true {
		t.Errorf("doctor after: %v", m)
	}
}

// A settings row changed outside komando stops every command with a hint
// naming doctor --reseal-meta, which only a person runs (C08).
func TestMetaTamperedNeedsAPerson(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "--address", "10.0.0.5", "--user", "u")
	store.Close()
	db, err := sql.Open("sqlite", "file:"+store.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO meta(k,v) VALUES('key_moving','x')`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, e := invRun(t, "list")
	if e == nil || e.Code != "STATE_CORRUPT" || !strings.Contains(e.Hint, "komando doctor --reseal-meta") {
		t.Fatalf("list: %+v", e)
	}
	if _, e := invRun(t, "doctor", "--reseal-meta"); e == nil || e.Code != "NEEDS_PERSON" {
		t.Fatalf("a script resealed: %+v", e)
	}
	saved, savedIn, savedErr := tcl.terminal, tcl.stdin, tcl.out.Err
	t.Cleanup(func() { tcl.terminal, tcl.stdin, tcl.out.Err = saved, savedIn, savedErr })
	var asked bytes.Buffer
	tcl.out.Err = &asked // the question, kept out of the test's output
	// an agent at a terminal is no person
	setCallerEnv(t, "CLAUDECODE", "1")
	tcl.terminal, tcl.stdin = true, strings.NewReader("y\n")
	if _, e := invRun(t, "doctor", "--reseal-meta"); e == nil || e.Code != "NEEDS_PERSON" {
		t.Fatalf("an agent resealed: %+v", e)
	}
	noAgent(t)
	// a no changes nothing
	tcl.terminal, tcl.stdin = true, strings.NewReader("n\n")
	if _, e := invRun(t, "doctor", "--reseal-meta"); e == nil || e.Code != "CANCELLED" || !strings.Contains(asked.String(), "seal its settings row") {
		t.Fatalf("a no: %+v, asked %q", e, asked.String())
	}
	tcl.terminal = saved
	if _, e := invRun(t, "list"); e == nil || e.Code != "STATE_CORRUPT" {
		t.Fatalf("list after a no: %+v", e)
	}
	// without the passphrase there is no key to check with: that is not
	// a damaged store
	t.Setenv("KOMANDO_VAULT_PASS", "")
	tcl.terminal, tcl.stdin = true, strings.NewReader("y\n")
	if _, e := invRun(t, "doctor", "--reseal-meta"); e == nil || e.Code != "VAULT_LOCKED" {
		t.Fatalf("reseal without the passphrase: %+v", e)
	}
	t.Setenv("KOMANDO_VAULT_PASS", "test-passphrase-long-enough") // invHome's
	tcl.terminal, tcl.stdin = true, strings.NewReader("y\n")
	d := mustRun(t, "doctor", "--reseal-meta")
	if d["resealed"] != true {
		t.Fatalf("reseal: %v", d)
	}
	tcl.terminal = saved
	if st, err := store.Load(); err != nil || st.Hosts["web1"] == nil {
		t.Errorf("after reseal: %v", err)
	}
}

// A faked scrypt cost no longer shows as doctor's vault strength: the
// store does not open with it, and doctor says so (C08).
func TestDoctorReportsOnlyAnOpenedStore(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "--address", "10.0.0.5", "--user", "u")
	store.Close()
	db, err := sql.Open("sqlite", "file:"+store.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE meta SET v='2048' WHERE k='scrypt_n'`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	d, e := invRun(t, "doctor")
	if e != nil {
		if e.Code != "STATE_CORRUPT" {
			t.Errorf("doctor: %+v", e)
		}
		return // doctor stops on the store, and shows no strength
	}
	for _, c := range d["security"].([]any) {
		m := c.(map[string]any)
		if m["name"] == "security:vault" && (m["ok"] == true || strings.Contains(m["detail"].(string), "scrypt")) {
			t.Errorf("doctor trusted the faked row: %v", m)
		}
	}
}

// A first seal that fails says so in one line on stderr and stops
// nothing (C08).
func TestMetaSealCarryOverFailureSaysSo(t *testing.T) {
	invHome(t)
	noAgent(t)
	savedSeal := sealMeta
	saved, savedErr := tcl.terminal, tcl.out.Err
	t.Cleanup(func() { sealMeta, tcl.terminal, tcl.out.Err = savedSeal, saved, savedErr })
	sealMeta = func() (bool, error) { return false, errors.New("disk full") }
	var errBuf bytes.Buffer
	tcl.terminal, tcl.out.Err = true, &errBuf
	carryMetaSeal(tcl)
	if got := errBuf.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, "disk full") {
		t.Fatalf("stderr: %q", got)
	}
}
