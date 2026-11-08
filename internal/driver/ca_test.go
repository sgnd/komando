package driver

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

func TestParseCA(t *testing.T) {
	for raw, want := range map[string]string{
		"postgres://app@db.internal:5432/app?ca=secret:rds-ca":            "secret:rds-ca",
		"postgres://app@db.internal/app?sslmode=verify-full&ca=secret:x":  "secret:x",
		"mysql://shop@db.internal/shop?ca=secret:azure-ca":                "secret:azure-ca",
		"mysql://shop@db.internal/shop?tls=true&ca=secret:azure-ca":       "secret:azure-ca",
		"rediss://default@cache.internal:6380/0?ca=secret:elasticache-ca": "secret:elasticache-ca",
		"memcacheds://cache.internal:11211?ca=secret:ca":                  "secret:ca",
		"postgres://app@db.internal/app":                                  "",
	} {
		tg, err := Parse(raw)
		if err != nil || tg.CA != want {
			t.Errorf("%s: CA %q %v, want %q", raw, tg.CA, err, want)
		}
	}
	for _, raw := range []string{
		"postgres://app@db/app?ca=/etc/ssl/ca.pem", // a path, not a secret
		"postgres://app@db/app?ca=secret:",         // no name
		"postgres://app@db/app?sslmode=disable&ca=secret:x",
		"mysql://shop@db/shop?tls=skip-verify&ca=secret:x",
		"redis://cache:6379/0?ca=secret:x", // no TLS
		"memcached://cache:11211?ca=secret:x",
	} {
		_, err := Parse(raw)
		if oe, ok := err.(*out.Error); !ok || oe.Exit != out.ExitUsage {
			t.Errorf("%s: want a usage error, got %v", raw, err)
		}
	}
}

func TestWithoutCA(t *testing.T) {
	got := WithoutCA("postgres://app@db/app?sslmode=require&ca=secret:x&application_name=a")
	if strings.Contains(got, "ca=") || !strings.Contains(got, "sslmode=require") || !strings.Contains(got, "application_name=a") {
		t.Errorf("WithoutCA: %s", got)
	}
	if s := "postgres://app@db/app?sslmode=require"; WithoutCA(s) != s {
		t.Errorf("a URL without ca= stays as it is")
	}
}

func TestRootCAs(t *testing.T) {
	saved := ResolveSecret
	defer func() { ResolveSecret = saved }()
	tg, _ := Parse("rediss://cache:6380/0?ca=secret:ca")
	ResolveSecret = func(string) (string, error) { return "", ErrSecretNotFound }
	if _, err := tg.RootCAs(); err == nil || err.(*out.Error).Code != "SECRET_NOT_FOUND" {
		t.Errorf("missing secret: %v", err)
	}
	ResolveSecret = func(string) (string, error) { return "not a certificate", nil }
	if _, err := tg.RootCAs(); err == nil || err.(*out.Error).Code != "BAD_CA" {
		t.Errorf("not PEM: %v", err)
	}
	if p, err := (Target{}).RootCAs(); p != nil || err != nil {
		t.Errorf("no ca=: %v %v", p, err)
	}
}
