package driver

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"
)

// C113 (c): a pg_dump archive (made by pg_dump 16 and 17, testdata) is
// read like a plain dump: its SQL is checked and named in the approval.
func TestCheckRestoreArchive(t *testing.T) {
	for _, f := range []string{"testdata/pgdump16.custom", "testdata/pgdump17.custom"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		v, err := CheckRestoreArchive(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !slices.Contains(v.RuleIDs, "sql-privileges") {
			t.Errorf("%s: the GRANT is not named: %+v", f, v)
		}
		// the same bytes with the GRANT turned into COPY ... TO PROGRAM
		grant := "GRANT SELECT ON TABLE public.t TO helper;"
		evil := "COPY public.t TO PROGRAM 'id';"
		evil += strings.Repeat(" ", len(grant)-len(evil))
		v, err = CheckRestoreArchive(bytes.NewReader(bytes.Replace(b, []byte(grant), []byte(evil), 1)))
		if err != nil || !slices.Contains(v.RuleIDs, "sql-program") {
			t.Errorf("%s: COPY TO PROGRAM in an archive: %+v %v", f, v, err)
		}
		// a cut archive is not read as harmless
		if v, err := CheckRestoreArchive(bytes.NewReader(b[:len(b)/3])); err == nil && !slices.Contains(v.RuleIDs, "sql-opaque") {
			t.Errorf("%s: a cut archive: %+v", f, v)
		}
	}
	if v, err := CheckRestoreArchive(strings.NewReader("PGDMP\x09\x09\x09junk")); err == nil && !slices.Contains(v.RuleIDs, "sql-opaque") {
		t.Errorf("an unknown version: %+v", v)
	}
}

// Review: table data kept as SQL (--inserts, no COPY), a dropStmt that
// pg_restore copies into ALTER ... OWNER, and a COPY that is not FROM
// stdin are not passed as harmless.
func TestCheckRestoreArchiveReview(t *testing.T) {
	b, err := os.ReadFile("testdata/pgdump17.custom")
	if err != nil {
		t.Fatal(err)
	}
	same := func(old, new string) []byte {
		if len(new) > len(old) {
			t.Fatalf("%q longer than %q", new, old)
		}
		return bytes.Replace(b, []byte(old), []byte(new+strings.Repeat(" ", len(old)-len(new))), 1)
	}
	// the table's COPY gone: its data block is SQL komando does not read
	noCopy := bytes.Replace(b, []byte("\x00\x25\x00\x00\x00COPY public.t (id, note) FROM stdin;\n"), []byte("\x00\x00\x00\x00\x00"), 1)
	if bytes.Equal(noCopy, b) {
		t.Fatal("fixture: no COPY string found")
	}
	if v, _ := CheckRestoreArchive(bytes.NewReader(noCopy)); !slices.Contains(v.RuleIDs, "sql-opaque") {
		t.Errorf("table data without COPY: %+v", v)
	}
	if v, _ := CheckRestoreArchive(bytes.NewReader(same("DROP FUNCTION public.f();", "COPY t TO PROGRAM 'id';"))); !slices.Contains(v.RuleIDs, "sql-program") {
		t.Errorf("a dropStmt with COPY ... PROGRAM: %+v", v)
	}
	if v, err := CheckRestoreArchive(bytes.NewReader(same("COPY public.t (id, note) FROM stdin;", "COPY public.t FROM PROGRAM 'id';"))); err == nil && !slices.Contains(v.RuleIDs, "sql-opaque") && !slices.Contains(v.RuleIDs, "sql-program") {
		t.Errorf("a COPY that is not FROM stdin: %+v", v)
	}
}
