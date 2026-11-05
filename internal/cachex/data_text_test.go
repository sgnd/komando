package cachex

import (
	"strings"
	"testing"
)

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"plain":      "plain",
		"":           `""`,
		"two words":  `"two words"`,
		"a\nb":       `"a\nb"`,
		`say "hi"`:   `"say \"hi\""`,
		"日本":         "日本",
		"\x00\xff":   `"\x00\xff"`,
		"tab\there":  `"tab\there"`,
		`back\slash`: `"back\\slash"`,
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestReplyText(t *testing.T) {
	got := ReplyText([]any{"a", "b c", []any{"x", int64(2)}, nil})
	want := "1) a\n2) \"b c\"\n3) 1) x\n   2) (integer) 2\n4) (nil)\n"
	if got != want {
		t.Errorf("array:\n%s\nwant\n%s", got, want)
	}
	if got := ReplyText(map[string]any{"f2": "v 2", "f1": "v1"}); got != "1# f1: v1\n2# f2: \"v 2\"\n" {
		t.Errorf("map: %q", got)
	}
	if got := ReplyText(map[string]any{"flags": []any{"on", "off"}}); got != "1# flags: 1) on\n          2) off\n" {
		t.Errorf("nested map: %q", got)
	}
	if got := ReplyText([]any{}); got != "(empty array)\n" {
		t.Errorf("empty: %q", got)
	}
	if got := ReplyText(map[string]string{"base64": "AP8="}); got != "\"\\x00\\xff\"\n" {
		t.Errorf("binary: %q", got)
	}
}

func TestValueText(t *testing.T) {
	ttl := int64(60)
	v := &Value{Key: "k", Type: "string", TTL: &ttl, Size: 9, Value: "two\nlines"}
	if s := v.Text(); !strings.Contains(s, `value: "two\nlines"`) || !strings.Contains(s, "ttl:   60s") {
		t.Errorf("string:\n%s", s)
	}
	v = &Value{Key: "l", Type: "list", Size: 3, Value: []any{"a", "b c"}, Truncated: true}
	s := v.Text()
	if !strings.Contains(s, "  1) a\n  2) \"b c\"\n") || !strings.Contains(s, "showing 2 of 3") || !strings.Contains(s, "ttl:   none") {
		t.Errorf("list:\n%s", s)
	}
	v = &Value{Key: "z", Type: "zset", Size: 1, Value: []map[string]any{{"member": "m", "score": 1.5}}}
	if s := v.Text(); !strings.Contains(s, "1) m  (score 1.5)") {
		t.Errorf("zset:\n%s", s)
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize(map[string]map[string]string{
		"server":      {"redis_version": "8.0.0", "redis_mode": "standalone", "uptime_in_seconds": "3600"},
		"memory":      {"used_memory": "1048576", "maxmemory": "0", "maxmemory_policy": "noeviction"},
		"clients":     {"connected_clients": "3"},
		"replication": {"role": "master"},
		"stats":       {"keyspace_hits": "9", "keyspace_misses": "1"},
		"keyspace":    {"db0": "keys=12,expires=3,avg_ttl=0"},
	})
	if s.Version != "8.0.0" || s.Role != "master" || s.Keys["db0"] != 12 || s.Expires["db0"] != 3 || s.HitRate == nil || *s.HitRate != 0.9 || s.UsedMemory != 1048576 {
		t.Errorf("summary: %+v", s)
	}
	if s := Summarize(map[string]map[string]string{}); s.HitRate != nil {
		t.Errorf("hit rate without reads: %v", *s.HitRate)
	}
}
