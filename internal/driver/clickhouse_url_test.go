package driver

import (
	"strings"
	"testing"
)

func TestParseClickHouse(t *testing.T) {
	for raw, want := range map[string]Target{
		"clickhouse://app@ch.internal/analytics":                 {Address: "ch.internal:8123", User: "app", Database: "analytics"},
		"clickhouse://app@ch.internal/analytics?tls=true":        {Address: "ch.internal:8443", User: "app", Database: "analytics", TLS: "true", Secure: true},
		"clickhouse://app@ch.internal:9443/?tls=skip-verify":     {Address: "ch.internal:9443", User: "app", TLS: "skip-verify", Secure: true},
		"clickhouse://ch.internal:8123":                          {Address: "ch.internal:8123"},
		"clickhouse://app@[2001:db8::1]:8443/x?tls=TRUE":         {Address: "[2001:db8::1]:8443", User: "app", Database: "x", TLS: "true", Secure: true},
		"clickhouse://app@ch.internal/a?tls=true&ca=secret:chca": {Address: "ch.internal:8443", User: "app", Database: "a", TLS: "true", Secure: true, CA: "secret:chca"},
	} {
		got, err := Parse(raw)
		if err != nil {
			t.Errorf("%s: %v", raw, err)
			continue
		}
		if got.Kind.Name != "clickhouse" || got.Address != want.Address || got.User != want.User || got.Database != want.Database ||
			got.TLS != want.TLS || got.Secure != want.Secure || got.CA != want.CA {
			t.Errorf("%s: %+v", raw, got)
		}
	}
	for raw, msg := range map[string]string{
		"clickhouse://app@ch.internal:9000/db":                        "native protocol",
		"clickhouse://app@ch.internal:9440/db?tls=true":               "native protocol",
		"clickhouse://app@ch.internal:8123/db?tls=true":               "plain HTTP port",
		"clickhouse://app@ch.internal/db?tls=yes":                     "must be true",
		"clickhouse://app@ch.internal/db?secure=1":                    "unknown clickhouse URL option",
		"clickhouse://app@ch.internal/db?ca=secret:x":                 "with tls=true",
		"clickhouse://app@ch.internal/db?tls=skip-verify&ca=secret:x": "with tls=true",
		"clickhouse://app@ch.internal/db?ca=/tmp/ca.pem&tls=true":     "secret:NAME",
		"clickhouse://app@ch.internal/a/b":                            "one database name",
		"clickhouse:///db":                                            "needs a host",
		"clickhouse://app:pw@ch.internal/db":                          "must not contain a password",
	} {
		_, err := Parse(raw)
		if err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: %v, want %q", raw, err, msg)
		}
	}
	for raw, want := range map[string]string{
		"clickhouse://a@h/db":                "clickhouse://a@h/db?tls=true",
		"clickhouse://a@h:8123/db":           "clickhouse://a@h:8443/db?tls=true",
		"clickhouse://a@h:9443/db?tls=false": "clickhouse://a@h:9443/db?tls=true",
		"clickhouse://a@h/db?ca=secret:x":    "clickhouse://a@h/db?ca=secret:x&tls=true",
	} {
		if got := ClickHouseVerified(raw); got != want {
			t.Errorf("ClickHouseVerified(%s) = %s, want %s", raw, got, want)
		}
	}
}
