package driver

import (
	"encoding/json"
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
		"redis://cache:6379":               "USAGE",
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

func TestRiskJSON(t *testing.T) {
	b, _ := json.Marshal(Verdict{Risk: RiskDestructive})
	if string(b) != `{"risk":"destructive"}` {
		t.Errorf("got %s", b)
	}
}
