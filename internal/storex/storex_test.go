package storex

import (
	"testing"

	"github.com/sgnd/komando/internal/driver"
)

func TestKeyStaysInsidePrefix(t *testing.T) {
	tg, err := driver.Parse("s3://KEY@bucket/team/a?endpoint=http://minio.lan:9000")
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenS3(tg, "secret", nil, 0)
	s := b.(*s3Bucket)
	if err != nil {
		t.Fatal(err)
	}
	for rel, want := range map[string]string{
		"x.txt":      "team/a/x.txt",
		"/x.txt":     "team/a/x.txt",
		"2026/x.sql": "team/a/2026/x.sql",
	} {
		if got, err := s.Key(rel); err != nil || got != want {
			t.Errorf("%s: %s %v", rel, got, err)
		}
	}
	for _, bad := range []string{"", "../b/secret", "x/../../y", ".."} {
		if _, err := s.Key(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if s.rel("team/a/2026/x.sql") != "2026/x.sql" {
		t.Error("rel")
	}
}
