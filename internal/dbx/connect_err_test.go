package dbx

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// The checks komando runs right after connecting can run out of time too
// (a slow VPN); the error still names the address, not "connecting to  timed out".
func TestStringRulesTimeoutNamesTheAddress(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	for _, kind := range []string{"postgres", "mysql"} {
		tg := driver.Target{Kind: driver.Kind{Name: kind}, Address: "10.0.0.5:5432"}
		var e *out.Error
		if err := checkStringRules(ctx, db, tg); !errors.As(err, &e) || e.Code != "TIMEOUT" || e.Message != "connecting to 10.0.0.5:5432 timed out" {
			t.Errorf("%s: %+v", kind, err)
		}
	}
}
