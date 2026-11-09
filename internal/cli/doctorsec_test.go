package cli

import (
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// doctor names the risk of a conn without verified TLS and the exact
// command that fixes it.
func TestPlainConnSaysHowToFix(t *testing.T) {
	for u, want := range map[string]string{
		"postgres://app@db.internal/app":                     "conn edit c --url 'postgres://app@db.internal/app?sslmode=verify-full'",
		"postgres://app@db.internal/app?sslmode=disable":     "sslmode=verify-full'",
		"postgres://app@db.internal/app?sslmode=require&x=1": "get the password",
		"mysql://app@db.internal/app":                        "conn edit c --url 'mysql://app@db.internal/app?tls=true'",
		"mysql://app@db.internal/app?tls=preferred":          "tls=preferred",
		"mysql://app@db.internal/app?tls=skip-verify":        "?tls=true'",
		"redis://default@cache.internal:6379/0":              "--url 'rediss://default@cache.internal:6379/0'",
		"memcached://cache.internal:11211":                   "--url 'memcacheds://cache.internal:11211'",
	} {
		if got := plainConn(&store.Conn{Name: "c", URL: u}); !strings.Contains(got, want) {
			t.Errorf("%s:\n got %q\nwant %q in it", u, got, want)
		}
	}
	for _, u := range []string{"mysql://app@db.internal/app?tls=preferred", "postgres://app@db.internal/app?sslmode=prefer"} {
		if !strings.Contains(plainConn(&store.Conn{Name: "c", URL: u}), "may travel unencrypted") {
			t.Errorf("%s may fall back to no TLS", u)
		}
	}
}

func TestVerifiedTLSURL(t *testing.T) {
	for in, want := range map[string]string{
		"postgres://app@db:5432/app?sslmode=require&application_name=x": "postgres://app@db:5432/app?application_name=x&sslmode=verify-full",
		"mysql://app@db/app?tls=false":                                  "mysql://app@db/app?tls=true",
		"rediss://cache:6379/0":                                         "rediss://cache:6379/0",
		// an option the URL did not have goes at the end, the rest as written
		"postgres://app@db/app?ca=secret:pg-ca":          "postgres://app@db/app?ca=secret:pg-ca&sslmode=verify-full",
		"mysql://app@db/app?charset=utf8mb4&ca=secret:x": "mysql://app@db/app?charset=utf8mb4&ca=secret:x&tls=true",
	} {
		kind := map[string]string{"postgres": "postgres", "mysql": "mysql", "rediss": "redis"}[strings.SplitN(in, ":", 2)[0]]
		if got := verifiedTLSURL(in, kind); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
	if verifiedTLSURL("ftp://x@h/p?insecure=1", "ftp") != "" {
		t.Error("ftp has no verified-TLS form of the same URL")
	}
}

// Cisco-style IPsec with a group name uses aggressive mode: doctor says so.
func TestWeakVpn(t *testing.T) {
	if weakVpn(&store.Vpn{Kind: "ipsec", LocalID: "staff"}) == "" {
		t.Error("aggressive mode is not reported")
	}
	if w := weakVpn(&store.Vpn{Name: "old", Kind: "l2tp", LegacyCrypto: true, AllowPAP: true}); !strings.Contains(w, "--legacy-crypto=false") || !strings.Contains(w, "--allow-pap=false") {
		t.Errorf("the opt-ins are not reported: %q", w)
	}
	for _, v := range []*store.Vpn{{Kind: "ipsec"}, {Kind: "ikev2", LocalID: "me"}, {Kind: "l2tp"}} {
		if weakVpn(v) != "" {
			t.Errorf("%+v reported", v)
		}
	}
	t.Setenv("KOMANDO_HOME", t.TempDir())
	st := &store.State{Conns: map[string]*store.Conn{}, Hosts: map[string]*store.Host{}, Vpns: map[string]*store.Vpn{"office": {Name: "office", Kind: "ipsec", LocalID: "staff"}}}
	found := false
	for _, c := range securityChecks(st) {
		found = found || c.Name == "security:vpn:office" && c.Warning
	}
	if !found {
		t.Error("doctor does not list the VPN")
	}
}
