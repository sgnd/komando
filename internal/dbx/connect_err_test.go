package dbx

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

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

// When TLS stops the connection, the hint says how to fix it and names
// the URL settings that weaken it, with what they cost.
func TestTLSHint(t *testing.T) {
	for _, c := range []struct {
		kind string
		err  error
		want string
	}{
		{"postgres", errors.New("failed to connect: tls error: tls: failed to verify certificate: x509: certificate signed by unknown authority"), "?sslrootcert=/path/to/ca.pem"},
		{"postgres", errors.New("x509: certificate is valid for db1, not db.internal"), "?sslmode=require encrypts without checking"},
		{"postgres", errors.New("failed to connect: server refused TLS connection"), "?sslmode=disable sends the password"},
		{"mysql", errors.New("x509: certificate signed by unknown authority"), "?tls=skip-verify"},
		{"mysql", mysql.ErrNoTLS, "?tls=false sends the password"},
	} {
		if got := tlsHint(c.kind, c.err); !strings.Contains(got, c.want) || !strings.Contains(got, "--via") {
			t.Errorf("%s %v: %q", c.kind, c.err, got)
		}
	}
	if tlsHint("postgres", errors.New("connection refused")) != "" || tlsHint("sqlite", errors.New("x509: x")) != "" {
		t.Error("a hint for an error that is not about TLS")
	}
	e := connectErr(driver.Target{Kind: driver.Kind{Name: "mysql"}, Address: "db:3306"}, mysql.ErrNoTLS)
	var oe *out.Error
	if !errors.As(e, &oe) || oe.Code != "DB_CONNECT" || !strings.Contains(oe.Hint, "tls=false") {
		t.Errorf("connectErr: %+v", e)
	}
}
