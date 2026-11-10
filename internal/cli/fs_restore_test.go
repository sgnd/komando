package cli

import (
	"testing"
	"time"
)

func TestNewestBackup(t *testing.T) {
	cases := []struct {
		names []string
		want  string
	}{
		{nil, ""},
		{[]string{"nginx.conf", "other.bak"}, ""},
		{[]string{"nginx.conf", "nginx.conf.bak"}, "nginx.conf.bak"},
		{[]string{"nginx.conf.bak", "nginx.conf.bak.20261101T100000Z", "nginx.conf.bak.20261102T090000Z"}, "nginx.conf.bak.20261102T090000Z"},
		{[]string{"nginx.conf.bak.20261102T090000Z-9", "nginx.conf.bak.20261102T090000Z-10", "nginx.conf.bak.20261102T090000Z"}, "nginx.conf.bak.20261102T090000Z-10"},
		{[]string{"nginx.conf.bakery", "nginx.conf.bak."}, ""},
	}
	for _, c := range cases {
		if got := newestBackup("nginx.conf", c.names); got != c.want {
			t.Errorf("newestBackup(%v) = %q, want %q", c.names, got, c.want)
		}
	}
}

func TestArgQ(t *testing.T) {
	for in, want := range map[string]string{
		"/etc/nginx/nginx.conf": "/etc/nginx/nginx.conf",
		"/srv/my file":          "'/srv/my file'",
		"a;rm":                  "'a;rm'",
		"":                      "''",
	} {
		if got := argQ(in); got != want {
			t.Errorf("argQ(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDefaultDumpFile(t *testing.T) {
	now := time.Date(2026, 11, 2, 15, 0, 0, 0, time.UTC)
	if got := defaultDumpFile("prod-db", "plain", now); got != "prod-db-2026-11-02.sql.gz" {
		t.Errorf("plain: %q", got)
	}
	if got := defaultDumpFile("prod-db", "custom", now); got != "prod-db-2026-11-02.dump" {
		t.Errorf("custom: %q", got)
	}
	if got := defaultDumpFile("../x/y", "plain", now); got != "..-x-y-2026-11-02.sql.gz" {
		t.Errorf("path chars: %q", got)
	}
}
