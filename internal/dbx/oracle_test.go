package dbx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sijms/go-ora/v2/network"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

func TestOracleConfig(t *testing.T) {
	saved := driver.ResolveSecret
	defer func() { driver.ResolveSecret = saved }()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "corp CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	driver.ResolveSecret = func(string) (string, error) {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
	}
	for _, c := range []struct {
		url, service, sid string
		tcps, skip, ca    bool
	}{
		{"oracle://app@db.internal/ERP", "ERP", "", false, false, false},
		{"oracle://app@db.internal:2484/ERP?tls=true", "ERP", "", true, false, false},
		{"oracle://app@db.internal/ERP?tls=skip-verify", "ERP", "", true, true, false},
		{"oracle://app@db.internal/ERP?tls=true&ca=secret:corp-ca", "ERP", "", true, false, true},
		{"oracle://app@db.internal?sid=ORCL&tls=false", "", "ORCL", false, false, false},
	} {
		tg, err := driver.Parse(c.url)
		if err != nil {
			t.Fatal(err)
		}
		cfg, tc, err := oracleConfig(c.url, tg, `p@ss "word"&x=y`, "komando/test")
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		if cfg.ServiceName != c.service || cfg.SID != c.sid || cfg.UserID != "app" || cfg.Password != `p@ss "word"&x=y` || cfg.ProgramName != "komando/test" ||
			len(cfg.Servers) != 1 || cfg.Servers[0].Addr != "db.internal" {
			t.Errorf("%s: %+v", c.url, cfg)
		}
		if (cfg.Protocol == "tcps") != c.tcps || (tc != nil) != c.tcps {
			t.Errorf("%s: protocol %q tls %+v", c.url, cfg.Protocol, tc)
		}
		if tc != nil && (tc.InsecureSkipVerify != c.skip || (tc.RootCAs != nil) != c.ca || tc.ServerName != "db.internal") {
			t.Errorf("%s: tls %+v", c.url, tc)
		}
	}
}

func TestOracleValues(t *testing.T) {
	for _, c := range []struct {
		v    any
		typ  string
		want any
	}{
		{"42", "NUMBER", int64(42)},
		{"-3", "NUMBER", int64(-3)},
		{"12.25", "NUMBER", 12.25},
		{"0.1", "NUMBER", 0.1},
		{"12345678901234567890", "NUMBER", "12345678901234567890"},
		{"1.23456789012345678901", "NUMBER", "1.23456789012345678901"},
		{"x", "VARCHAR2", "x"},
		{[]byte("abc"), "RAW", map[string]string{"base64": "YWJj"}},
		{time.Date(2026, 11, 9, 13, 4, 5, 0, time.UTC), "DATE", "2026-11-09 13:04:05"},
		{time.Date(2026, 11, 9, 13, 4, 5, 120000000, time.FixedZone("x", 3600)), "TIMESTAMP WITH TIME ZONE", "2026-11-09T12:04:05.12Z"},
	} {
		if got := colValue("oracle", c.typ, c.v); fmt.Sprint(got) != fmt.Sprint(c.want) || fmt.Sprintf("%T", got) != fmt.Sprintf("%T", c.want) {
			t.Errorf("%v %s: %#v, want %#v", c.v, c.typ, got, c.want)
		}
	}
	if oracleTypeName("NCHAR") != "VARCHAR2" || oracleTypeName("TimeStampTZ_DTY") != "TIMESTAMP WITH TIME ZONE" || oracleTypeName("NUMBER") != "NUMBER" {
		t.Error("oracleTypeName")
	}
}

func TestOracleErrors(t *testing.T) {
	ctx := context.Background()
	for n, code := range map[int]string{1008: "USAGE", 1456: "WRITE_REQUIRES_FLAG", 1031: "DB_PRIVILEGE", 942: "DB_ERROR", 904: "DB_ERROR", 1013: "TIMEOUT"} {
		err := queryErr("oracle", ctx, &network.OracleError{ErrCode: n, ErrMsg: fmt.Sprintf("ORA-%05d: m", n)})
		if e, ok := err.(*out.Error); !ok || e.Code != code {
			t.Errorf("%d: %v, want %s", n, err, code)
		}
	}
	// a missing role, or a grant to oneself, is no missing right
	for n, hint := range map[int]string{1919: "db user list", 1749: "itself"} {
		e, _ := queryErr("oracle", ctx, &network.OracleError{ErrCode: n, ErrMsg: fmt.Sprintf("ORA-%05d: m", n)}).(*out.Error)
		if e == nil || e.Code != "DB_ERROR" || !strings.Contains(e.Hint, hint) {
			t.Errorf("%d: %v, want DB_ERROR with %q", n, e, hint)
		}
	}
	// ORA-01466 right after a table's DDL: only a read is tried again
	just := queryErr("oracle", ctx, &network.OracleError{ErrCode: 1466, ErrMsg: "ORA-01466: unable to read data - table definition has changed"})
	if e, _ := just.(*out.Error); e == nil || !strings.Contains(e.Hint, "again") {
		t.Errorf("1466: %v, want a hint to run it again", just)
	}
	other := queryErr("oracle", ctx, &network.OracleError{ErrCode: 942, ErrMsg: "ORA-00942: m"})
	for _, c := range []struct {
		kind string
		o    Options
		err  error
		want bool
	}{
		{"oracle", Options{}, just, true},
		{"oracle", Options{Write: true}, just, false},
		{"oracle", Options{Showplan: "text"}, just, false},
		{"oracle", Options{}, other, false},
		{"oracle", Options{}, nil, false},
		{"postgres", Options{}, just, false},
	} {
		if got := oraSnapshotTooOld(c.kind, c.o, c.err); got != c.want {
			t.Errorf("oraSnapshotTooOld(%s, %+v, %v) = %v, want %v", c.kind, c.o, c.err, got, c.want)
		}
	}
	tg, _ := driver.Parse("oracle://app@db/ERP")
	for n, code := range map[int]string{1017: "DB_AUTH", 28000: "DB_AUTH", 12514: "DB_NOT_FOUND"} {
		if e, ok := connectErr(tg, &network.OracleError{ErrCode: n, ErrMsg: fmt.Sprintf("ORA-%05d: m", n)}).(*out.Error); !ok || e.Code != code {
			t.Errorf("connect %d: %v, want %s", n, e, code)
		}
	}
	for _, msg := range []string{"tls: first record does not look like a TLS handshake", "x509: certificate signed by unknown authority"} {
		if h := tlsHint("oracle", errors.New(msg)); !strings.Contains(h, "tls=") {
			t.Errorf("tls hint for %q: %q", msg, h)
		}
	}
	if readOnlyTx("oracle", false) {
		t.Error("go-ora has no read-only BeginTx")
	}
}

func TestOracleUsers(t *testing.T) {
	ctx := context.Background()
	stmt, shown, err := userSQL(ctx, nil, "oracle", "add", UserSpec{Name: "app_ro", Password: "s3cr'et"})
	if err != nil || !strings.Contains(stmt, `create user "APP_RO" identified by "s3cr''et"`) || !strings.Contains(stmt, `grant create session to "APP_RO"`) ||
		!strings.Contains(stmt, `drop user "APP_RO" cascade`) || strings.Contains(shown, "s3cr") {
		t.Errorf("add: %q / %q %v", stmt, shown, err)
	}
	if stmt, _, _ := userSQL(ctx, nil, "oracle", "add", UserSpec{Name: "readers", NoLogin: true}); stmt != `create role "READERS"` {
		t.Errorf("role: %q", stmt)
	}
	if _, shown, _ := userSQL(ctx, nil, "oracle", "passwd", UserSpec{Name: "app", Password: "x"}); shown != `alter user "APP" identified by "[hidden]"` {
		t.Errorf("passwd: %q", shown)
	}
	if stmt, _, _ := userSQL(ctx, nil, "oracle", "rm", UserSpec{Name: "app"}); !strings.Contains(stmt, `drop user "APP"`) || strings.Contains(stmt, "cascade") {
		t.Errorf("rm: %q", stmt)
	}
	for _, u := range []UserSpec{{Name: "app", Host: "%", Password: "x"}, {Name: "app", Password: `a"b`}, {Name: "a.b", Password: "x"}, {Name: "app", Password: "a\nb"}} {
		if _, _, err := userSQL(ctx, nil, "oracle", "add", u); err == nil {
			t.Errorf("accepted %+v", u)
		}
	}
	for _, c := range []struct {
		g    Grant
		want string
	}{
		{Grant{User: "ro", Privs: []string{"select"}, On: "table:app.orders"}, `grant SELECT on "APP"."ORDERS" to "RO"`},
		{Grant{User: "ro", Privs: []string{"SELECT", "insert"}, On: "table:Orders", Revoke: true}, `revoke SELECT, INSERT on "Orders" from "RO"`},
		{Grant{User: "ro", Privs: []string{"create  table", "SELECT ANY TABLE"}, On: "database"}, `grant CREATE TABLE, SELECT ANY TABLE to "RO"`},
		{Grant{User: "ro", Privs: []string{"select"}, On: "schema:app"}, `grant SELECT ANY TABLE on schema "APP" to "RO"`},
		{Grant{User: "ana", Role: "select_catalog_role"}, `grant "SELECT_CATALOG_ROLE" to "ANA"`},
		{Grant{User: "ana", Role: "r1", Revoke: true}, `revoke "R1" from "ANA"`},
	} {
		if got, err := GrantSQL(ctx, nil, "oracle", c.g); err != nil || got != c.want {
			t.Errorf("%+v: %q %v", c.g, got, err)
		}
	}
	for _, g := range []Grant{
		{User: "ro", Privs: []string{"DBA"}, On: "database"},
		{User: "ro", Privs: []string{"SELECT"}, On: "table:a.b.c"},
		{User: "ro", Privs: []string{"SELECT"}, On: "table:a\"b"},
		{User: "ro", Privs: []string{"SELECT"}, On: "database:other"},
		{User: "ro", Privs: []string{"CREATE TABLE"}, On: "table:t"},
		{User: "ro", Host: "%", Role: "r"},
	} {
		if _, err := GrantSQL(ctx, nil, "oracle", g); err == nil {
			t.Errorf("accepted %+v", g)
		}
	}
}

// A conn with tls=true to a listener without TCPS says what to do.
func TestOracleLiveNoTCPS(t *testing.T) {
	u := os.Getenv("KOMANDO_ORATEST")
	if u == "" {
		t.Skip("set KOMANDO_ORATEST to run")
	}
	u += "?tls=true"
	tg, _ := driver.Parse(u)
	_, err := Open(context.Background(), u, tg, "x", nil, true, "k")
	if e, ok := err.(*out.Error); !ok || e.Code != "DB_CONNECT" || !strings.Contains(e.Hint, "tls=false") {
		t.Errorf("tcps to a plain listener: %#v", err)
	}
}

// LOB data sits in SYS_LOB segments of its own, which count for their table.
func TestOracleTableSizesCountLOBs(t *testing.T) {
	q := oracleTableSizes("user_segments")
	for _, want := range []string{"all_lobs", "s.segment_name IN (l.segment_name, l.index_name)", "segment_type LIKE 'LOB%'"} {
		if !strings.Contains(q, want) {
			t.Errorf("table sizes leave out LOB segments: no %q in\n%s", want, q)
		}
	}
}
