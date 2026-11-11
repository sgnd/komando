package dbx

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// A connection whose rules komando cannot check, and a statement that
// ended komando's transaction, are safety stops (exit 6): an agent stops
// and tells the user, and the stop is audited. SQL the user wrote that
// tries the same is a usage error (exit 2), found before anything runs.
func TestSafetyStopsExitPolicy(t *testing.T) {
	exit := func(err error) int {
		var oe *out.Error
		if !errors.As(err, &oe) {
			t.Fatalf("not an out.Error: %v", err)
		}
		return oe.Exit
	}
	if e := exit(txEscaped(2, driver.Statement{Keyword: "COMMIT"}, nil)); e != out.ExitPolicy {
		t.Errorf("escaped transaction: exit %d", e)
	}
	srv := httptest.NewServer(&fakeCH{readonly: "0", dialect: "kusto"})
	defer srv.Close()
	if _, err := openFake(t, srv, "", "", true, nil); errCode(err) != "SQL_STRING_RULES" || exit(err) != out.ExitPolicy {
		t.Errorf("kusto dialect: %v", err)
	}
	if _, err := driver.ClassifySQL("postgres", "SET standard_conforming_strings = off"); errCode(err) != "SQL_STRING_RULES" || exit(err) != out.ExitUsage {
		t.Errorf("SET in the SQL: %v", err)
	}
}
