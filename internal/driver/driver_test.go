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

func TestRiskJSON(t *testing.T) {
	b, _ := json.Marshal(Verdict{Risk: RiskDestructive})
	if string(b) != `{"risk":"destructive"}` {
		t.Errorf("got %s", b)
	}
}
