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
