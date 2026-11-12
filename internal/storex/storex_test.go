package storex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
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
	for _, bad := range []string{"", "../b/secret", "x/../../y", "..", `a\..\..\x`, `..\x`, `a/..\..`} {
		if _, err := s.Key(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if s.rel("team/a/2026/x.sql") != "2026/x.sql" {
		t.Error("rel")
	}
}

// A bucket in another region than the conn says is named, with the next
// step, instead of a bare "STORAGE_ERROR: AuthorizationHeaderMalformed".
func TestS3WrongRegionNamesTheRegion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("x-amz-bucket-region", "eu-west-1")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>AuthorizationHeaderMalformed</Code>` +
			`<Message>The authorization header is malformed; the region 'us-east-1' is wrong; expecting 'eu-west-1'</Message>` +
			`<Region>eu-west-1</Region></Error>`))
	}))
	defer srv.Close()
	tg, err := driver.Parse("s3://KEY@shop/db?region=us-east-1&endpoint=" + srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := OpenS3(tg, "secret", nil, 5*time.Second)
	_, statErr := b.Stat(context.Background(), "x.sql") // HEAD: no body, only the header
	var buf strings.Builder
	_, getErr := b.Get(context.Background(), "x.sql", &buf) // the XML answer
	for what, err := range map[string]error{"stat": statErr, "get": getErr} {
		oe, ok := err.(*out.Error)
		if !ok || oe.Code != "STORAGE_ERROR" || !strings.Contains(oe.Message, "region eu-west-1") || !strings.Contains(oe.Hint, "region=eu-west-1") {
			t.Errorf("%s in the wrong region: %#v", what, err)
		}
	}
}
