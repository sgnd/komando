package driver

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in, kind, where, user, db string
	}{
		{"postgres://app@db.internal/app", "postgres", "db.internal:5432", "app", "app"},
		{"postgresql://app@10.0.0.5:6543/app?sslmode=require", "postgres", "10.0.0.5:6543", "app", "app"},
		{"mysql://root@[::1]/shop", "mysql", "[::1]:3306", "root", "shop"},
		{"sqlite:///var/lib/app.db", "sqlite", "/var/lib/app.db", "", ""},
		{"sqlite:./local.db", "sqlite", "./local.db", "", ""},
	}
	for _, c := range cases {
		tg, err := Parse(c.in)
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if tg.Kind.Name != c.kind || tg.Where() != c.where || tg.User != c.user || tg.Database != c.db {
			t.Errorf("%s: got %+v", c.in, tg)
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"postgres://app:hunter2@db/app":    "URL_HAS_PASSWORD",
		"postgres://app@db/app?password=x": "URL_HAS_PASSWORD",
		"mysql://root@db/shop?PWD=x":       "URL_HAS_PASSWORD",
		"ftp://files:21":                   "USAGE",
		"redis://cache:6379/main":          "USAGE",
		"s3://KEY:secret@bucket":           "URL_HAS_PASSWORD",
		"s3://KEY@bucket?secret_key=x":     "URL_HAS_PASSWORD",
		"s3://KEY@bucket?endpoint=minio":   "USAGE",
		"s3://KEY@bucket?acl=public-read":  "USAGE",
		"s3:///nobucket":                   "USAGE",
		"db.internal:5432":                 "USAGE",
		"postgres:///app":                  "USAGE",
		"postgres://app@db:99999/app":      "USAGE",
		"sqlite:":                          "USAGE",
	}
	for in, code := range cases {
		_, err := Parse(in)
		e, ok := err.(*out.Error)
		if !ok || e.Code != code {
			t.Errorf("%s: want %s, got %v", in, code, err)
		}
	}
}

func TestParseRedisAndS3(t *testing.T) {
	r, err := Parse("rediss://default@cache.internal/2")
	if err != nil || r.Kind.Family != "cache" || r.Address != "cache.internal:6379" || r.Database != "2" || !r.Secure || r.User != "default" {
		t.Errorf("redis: %+v %v", r, err)
	}
	if r, _ := Parse("redis://cache"); r.Database != "0" || r.Secure {
		t.Errorf("redis defaults: %+v", r)
	}
	s, err := Parse("s3://AKIAEXAMPLE@backups/db/daily?endpoint=http://minio.lan:9000&region=us-east-1")
	if err != nil || s.Bucket != "backups" || s.Prefix != "db/daily/" || s.Address != "minio.lan:9000" || s.Secure || s.User != "AKIAEXAMPLE" || s.Region != "us-east-1" {
		t.Errorf("s3: %+v %v", s, err)
	}
	if s.Where() != "backups/db/daily @ minio.lan:9000" {
		t.Errorf("s3 where: %s", s.Where())
	}
	if s, _ := Parse("s3://KEY@logs?region=eu-west-1"); s.Address != "s3.eu-west-1.amazonaws.com:443" || !s.Secure || s.Prefix != "" {
		t.Errorf("s3 aws default: %+v", s)
	}
	if err := s.Need("db"); err == nil || err.(*out.Error).Code != "WRONG_KIND" {
		t.Errorf("Need: %v", err)
	}
}

func TestParseFileStores(t *testing.T) {
	cases := []struct{ in, kind, addr, prefix string }{
		{"ftps://deploy@files.example.com/public_html", "ftps", "files.example.com:21", "public_html/"},
		{"ftps://deploy@files.example.com:2121/?tls=skip-verify", "ftps", "files.example.com:2121", ""},
		{"ftp://deploy@10.0.0.9/www?insecure=1", "ftp", "10.0.0.9:21", "www/"},
		{"sftp://deploy@files.example.com/uploads/in", "sftp", "files.example.com:22", "uploads/in/"},
	}
	for _, c := range cases {
		tg, err := Parse(c.in)
		if err != nil || tg.Kind.Name != c.kind || tg.Kind.Family != "storage" || tg.Address != c.addr || tg.Prefix != c.prefix || tg.User != "deploy" {
			t.Errorf("%s: %+v %v", c.in, tg, err)
		}
	}
	for in, code := range map[string]string{
		"ftp://deploy@files.example.com/www":        "INSECURE_PROTOCOL",
		"ftps://files.example.com/":                 "USAGE",
		"sftp://deploy:pw@files.example.com/":       "URL_HAS_PASSWORD",
		"ftps://deploy@files.example.com/?tls=nope": "USAGE",
		"sftp://deploy@files.example.com/?x=1":      "USAGE",
	} {
		_, err := Parse(in)
		if e, ok := err.(*out.Error); !ok || e.Code != code {
			t.Errorf("%s: want %s, got %v", in, code, err)
		}
	}
}

func TestRiskJSON(t *testing.T) {
	b, _ := json.Marshal(Verdict{Risk: RiskDestructive})
	if string(b) != `{"risk":"destructive"}` {
		t.Errorf("got %s", b)
	}
}

func TestParseRegistryTLS(t *testing.T) {
	for raw, want := range map[string][2]string{
		"registry://me@ghcr.io":                       {"", ""},
		"registry://me@registry.lan:5000?tls=false":   {"false", ""},
		"oci://me@registry.lan?tls=skip-verify":       {"skip-verify", ""},
		"registry://me@registry.lan?ca=secret:lan-ca": {"", "secret:lan-ca"},
	} {
		tg, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if tg.TLS != want[0] || tg.CA != want[1] {
			t.Errorf("%s: tls=%q ca=%q, want %q %q", raw, tg.TLS, tg.CA, want[0], want[1])
		}
	}
	for _, raw := range []string{
		"registry://me@registry.lan?tls=insecure",                // a typo is not a silent default
		"registry://me@registry.lan?insecure=1",                  // unknown option
		"registry://me@registry.lan?ca=lan-ca",                   // ca= is a vault reference
		"registry://me@registry.lan?ca=",                         // empty
		"registry://me@registry.lan?ca=secret:x&tls=skip-verify", // ca= would be ignored
		"registry://me@registry.lan?ca=secret:x&tls=false",
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: accepted", raw)
		}
	}
}

// ?resolve= is where to connect, like curl --resolve. The port comes from
// the URL unless the option has its own; Address keeps the name.
func TestParseResolve(t *testing.T) {
	for raw, want := range map[string][2]string{
		"registry://me@registry.example.com?resolve=104.248.148.41":                 {"registry.example.com:443", "104.248.148.41:443"},
		"registry://me@registry.lan:5000?resolve=10.0.0.5":                          {"registry.lan:5000", "10.0.0.5:5000"},
		"registry://me@registry.lan?resolve=10.0.0.5:8443":                          {"registry.lan:443", "10.0.0.5:8443"},
		"registry://me@registry.lan?resolve=[2001:db8::1]:8443":                     {"registry.lan:443", "[2001:db8::1]:8443"},
		"registry://me@registry.lan?resolve=[2001:db8::1]":                          {"registry.lan:443", "[2001:db8::1]:443"},
		"registry://me@registry.lan?resolve=2001:db8::1":                            {"registry.lan:443", "[2001:db8::1]:443"},
		"registry://me@registry.lan?ca=secret:lan-ca&resolve=10.0.0.5":              {"registry.lan:443", "10.0.0.5:443"},
		"s3://KEY@backups?endpoint=https://minio.example.com:9000&resolve=10.0.0.9": {"minio.example.com:9000", "10.0.0.9:9000"},
		"registry://me@registry.lan":                                                {"registry.lan:443", ""},
		"s3://KEY@backups?endpoint=http://minio.lan&region=us-east-1":               {"minio.lan:80", ""},
		"registry://me@registry.lan:5000?tls=false&resolve=192.168.1.20":            {"registry.lan:5000", "192.168.1.20:5000"},
		"oci://me@Registry.Example.com?resolve=%5B2001%3Adb8%3A%3A1%5D%3A443":       {"Registry.Example.com:443", "[2001:db8::1]:443"},
	} {
		tg, err := Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		dial := want[1]
		if dial == "" {
			dial = want[0]
		}
		if tg.Address != want[0] || tg.Resolve != want[1] || tg.DialAddress() != dial {
			t.Errorf("%s: address %q resolve %q dial %q, want %q %q", raw, tg.Address, tg.Resolve, tg.DialAddress(), want[0], want[1])
		}
	}
	for _, raw := range []string{
		"registry://me@registry.lan?resolve=registry.example.com", // a name: that is what DNS is for
		"registry://me@registry.lan?resolve=",
		"registry://me@registry.lan?resolve=999.1.1.1",
		"registry://me@registry.lan?resolve=10.0.0.5:",
		"registry://me@registry.lan?resolve=10.0.0.5:0",
		"registry://me@registry.lan?resolve=10.0.0.5:70000",
		"registry://me@registry.lan?resolve=10.0.0.5:https",
		"registry://me@registry.lan?resolve=[2001:db8::1",
		"s3://KEY@backups?endpoint=https://minio.lan&resolve=minio.internal",
	} {
		_, err := Parse(raw)
		e, ok := err.(*out.Error)
		if !ok || e.Code != "USAGE" || e.Exit != out.ExitUsage || !strings.Contains(e.Hint, "?resolve=") {
			t.Errorf("%s: %v, want USAGE with a hint", raw, err)
		}
	}
}

// A Windows path after a file conn's scheme is the file: C: is not a host.
func TestParseWindowsPath(t *testing.T) {
	for raw, want := range map[string]string{
		`sqlite://C:\data\app.db`:     `C:\data\app.db`,
		`sqlite://c:/data/app.db`:     `c:/data/app.db`,
		`sqlite3://D:\x.db?mode=ro`:   `D:\x.db`,
		`SQLITE://C:\Users\me\a b.db`: `C:\Users\me\a b.db`,
	} {
		got, err := Parse(raw)
		if err != nil || got.Kind.Name != "sqlite" || got.Path != want {
			t.Errorf("Parse(%q) = %q %q %v, want %q", raw, got.Kind.Name, got.Path, err, want)
		}
	}
	// only a file conn: postgres://C:/x stays a URL (and fails as one)
	if got, err := Parse(`postgres://C:\x`); err == nil {
		t.Errorf("postgres with a drive: %+v", got)
	}
	// sqlite:///C:/data/app.db on Windows; the same URL is a Unix path elsewhere
	saved := goos
	t.Cleanup(func() { goos = saved })
	for sys, want := range map[string]string{"windows": "C:/data/app.db", "linux": "/C:/data/app.db"} {
		goos = sys
		if got, err := Parse("sqlite:///C:/data/app.db"); err != nil || got.Path != want {
			t.Errorf("%s: %q %v, want %q", sys, got.Path, err, want)
		}
	}
}
