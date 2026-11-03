package dbx

import (
	"strings"
	"testing"
)

// the restore scanner reads whatever file a person gives it
func FuzzSQLScanner(f *testing.F) {
	f.Add("postgres", "SELECT 1;\nCOPY t FROM stdin;\n1\n\\.\n$$ ; $$;")
	f.Add("mysql", "DELIMITER ;;\nSELECT 1;;\nDELIMITER ;\n/*! x */;")
	f.Fuzz(func(t *testing.T, kind, text string) {
		if kind != "postgres" && kind != "mysql" {
			return
		}
		sc := newSQLScanner(strings.NewReader(text), kind)
		for i := 0; i < 10000; i++ {
			if _, err := sc.next(); err != nil {
				return
			}
		}
		t.Fatal("the scanner did not end")
	})
}
