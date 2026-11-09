package dbx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

func TestSQLServerConfig(t *testing.T) {
	for _, c := range []struct {
		url        string
		encryption msdsn.Encryption
		trust      bool
	}{
		// no encrypt=: the driver's default, the login only, unchecked
		{"sqlserver://app@db.internal/sales", msdsn.EncryptionOff, true},
		{"sqlserver://app@db.internal/sales?encrypt=true", msdsn.EncryptionRequired, false},
		{"sqlserver://app@db.internal/sales?Encrypt=TRUE&tls=skip-verify", msdsn.EncryptionRequired, true},
		{"sqlserver://app@db.internal/sales?encrypt=strict", msdsn.EncryptionStrict, false},
		{"sqlserver://app@db.internal/sales?encrypt=false", msdsn.EncryptionOff, false},
		{"sqlserver://app@db.internal/sales?encrypt=disable", msdsn.EncryptionDisabled, false},
	} {
		tg, err := driver.Parse(c.url)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := sqlserverConfig(c.url, tg, "p@ss word&x=y", "komando/test")
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		if cfg.Encryption != c.encryption || cfg.TrustServerCertificate != c.trust || cfg.Host != "db.internal" || cfg.Port != 1433 ||
			cfg.Database != "sales" || cfg.User != "app" || cfg.Password != "p@ss word&x=y" || cfg.AppName != "komando/test" {
			t.Errorf("%s: %+v", c.url, cfg)
		}
		if c.encryption != msdsn.EncryptionDisabled && (cfg.TLSConfig == nil || cfg.TLSConfig.InsecureSkipVerify != c.trust) {
			t.Errorf("%s: TLS %+v", c.url, cfg.TLSConfig)
		}
	}
	tg, _ := driver.Parse("sqlserver://app@db?database=sales&applicationintent=readonly")
	if cfg, _ := sqlserverConfig("sqlserver://app@db?database=sales&applicationintent=readonly", tg, "", "k"); !cfg.ReadOnlyIntent || cfg.Database != "sales" {
		t.Errorf("read-only intent: %+v", cfg)
	}
}

func TestSQLServerCA(t *testing.T) {
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
	raw := "sqlserver://app@db.internal/sales?encrypt=true&ca=secret:corp-ca"
	tg, err := driver.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := sqlserverConfig(raw, tg, "pw", "k")
	if err != nil {
		t.Fatal(err)
	}
	if tc := cfg.TLSConfig; tc == nil || tc.RootCAs == nil || tc.InsecureSkipVerify || tc.ServerName != "db.internal" {
		t.Errorf("the CA is not checked: %+v", tc)
	}
}

func TestMSSQLValue(t *testing.T) {
	// 6F9619FF-8B86-D011-B42D-00C04FC964FF as SQL Server sends it
	guid := []byte{0xFF, 0x19, 0x96, 0x6F, 0x86, 0x8B, 0x11, 0xD0, 0xB4, 0x2D, 0x00, 0xC0, 0x4F, 0xC9, 0x64, 0xFF}
	if v := colValue("sqlserver", "UNIQUEIDENTIFIER", guid); v != "6F9619FF-8B86-D011-B42D-00C04FC964FF" {
		t.Errorf("guid %v", v)
	}
	if v := colValue("sqlserver", "VARBINARY", []byte("abc")); fmt.Sprint(v) != "map[base64:YWJj]" {
		t.Errorf("varbinary %v", v)
	}
	if v := colValue("sqlserver", "DECIMAL", []byte("12.3400")); v != "12.3400" {
		t.Errorf("decimal %v", v)
	}
	day := time.Date(2026, 11, 9, 13, 4, 5, 120000000, time.UTC)
	for typ, want := range map[string]string{"DATE": "2026-11-09", "DATETIME2": "2026-11-09 13:04:05.12", "TIME": "13:04:05.12",
		"DATETIMEOFFSET": "2026-11-09T13:04:05.12Z"} {
		if v := colValue("sqlserver", typ, day); v != want {
			t.Errorf("%s: %v, want %s", typ, v, want)
		}
	}
}

func TestMSSQLErrors(t *testing.T) {
	ctx := context.Background()
	for n, code := range map[int32]string{137: "USAGE", 8178: "USAGE", 229: "DB_PRIVILEGE", 300: "DB_PRIVILEGE", 208: "DB_ERROR", 3906: "DB_ERROR"} {
		err := queryErr("sqlserver", ctx, mssql.Error{Number: n, Message: "m"})
		if e, ok := err.(*out.Error); !ok || e.Code != code {
			t.Errorf("%d: %v, want %s", n, err, code)
		}
	}
	tg, _ := driver.Parse("sqlserver://app@db/sales")
	for n, code := range map[int32]string{18456: "DB_AUTH", 4060: "DB_NOT_FOUND"} {
		if e, ok := connectErr(tg, mssql.Error{Number: n, Message: "m"}).(*out.Error); !ok || e.Code != code {
			t.Errorf("connect %d: %v, want %s", n, e, code)
		}
	}
	if h := tlsHint("sqlserver", fmt.Errorf("TLS Handshake failed: tls: failed to verify certificate: x509: certificate signed by unknown authority")); !strings.Contains(h, "tls=skip-verify") || !strings.Contains(h, "ca=secret:NAME") {
		t.Errorf("tls hint %q", h)
	}
	if !readOnlyTx("postgres", false) || readOnlyTx("sqlserver", false) || readOnlyTx("sqlite", false) || readOnlyTx("mysql", true) {
		t.Error("readOnlyTx")
	}
	if e, ok := KillNeedsSession().(*out.Error); !ok || e.Code != "NOT_SUPPORTED" {
		t.Error("kill without --session")
	}
}

func TestMSSQLUsers(t *testing.T) {
	ctx := context.Background()
	stmt, shown, err := userSQL(ctx, nil, "sqlserver", "add", UserSpec{Name: "app_ro", Password: "s3cr'et"})
	if err != nil || !strings.Contains(stmt, "create login [app_ro] with password = N's3cr''et'; create user [app_ro] for login [app_ro]") ||
		!strings.HasPrefix(stmt, "set xact_abort on; begin transaction;") || strings.Contains(shown, "s3cr") {
		t.Errorf("add: %q / %q %v", stmt, shown, err)
	}
	if stmt, _, _ := userSQL(ctx, nil, "sqlserver", "add", UserSpec{Name: "readers", NoLogin: true}); stmt != "create role [readers]" {
		t.Errorf("role: %q", stmt)
	}
	if _, shown, _ := userSQL(ctx, nil, "sqlserver", "passwd", UserSpec{Name: "app", Password: "x"}); shown != "alter login [app] with password = '[hidden]'" {
		t.Errorf("passwd: %q", shown)
	}
	if stmt, _, _ := userSQL(ctx, nil, "sqlserver", "rm", UserSpec{Name: "app"}); !strings.Contains(stmt, "drop user [app]") || !strings.Contains(stmt, "drop login [app]") {
		t.Errorf("rm: %q", stmt)
	}
	if _, _, err := userSQL(ctx, nil, "sqlserver", "add", UserSpec{Name: "app", Host: "%", Password: "x"}); err == nil {
		t.Error("--from accepted")
	}
	for _, c := range []struct {
		g    Grant
		want string
	}{
		{Grant{User: "ro", Privs: []string{"select"}, On: "schema:dbo"}, "grant SELECT on schema::[dbo] to [ro]"},
		{Grant{User: "ro", Privs: []string{"select"}, On: "all-tables:sales"}, "grant SELECT on schema::[sales] to [ro]"},
		{Grant{User: "ro", Privs: []string{"SELECT", "view  definition"}, On: "table:dbo.orders", Revoke: true}, "revoke SELECT, VIEW DEFINITION on object::[dbo].[orders] from [ro]"},
		{Grant{User: "ro", Privs: []string{"SHOWPLAN"}, On: "database"}, "grant SHOWPLAN to [ro]"},
		{Grant{User: "ana", Role: "db_datareader"}, "alter role [db_datareader] add member [ana]"},
		{Grant{User: "ana", Role: "db_datareader", Revoke: true}, "alter role [db_datareader] drop member [ana]"},
	} {
		if got, err := GrantSQL(ctx, nil, "sqlserver", c.g); err != nil || got != c.want {
			t.Errorf("%+v: %q %v", c.g, got, err)
		}
	}
	for _, g := range []Grant{
		{User: "ro", Privs: []string{"ALL"}, On: "schema:dbo"},
		{User: "ro", Privs: []string{"SELECT"}, On: "table:a.b.c"},
		{User: "ro", Privs: []string{"SELECT"}, On: "schema:a]b"},
		{User: "ro", Privs: []string{"SELECT"}, On: "database:other"},
		{User: "ro", Privs: []string{"SELECT"}, On: "view:x"},
		{User: "ro", Host: "%", Role: "r"},
	} {
		if _, err := GrantSQL(ctx, nil, "sqlserver", g); err == nil {
			t.Errorf("accepted %+v", g)
		}
	}
}
