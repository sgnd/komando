package cachex

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
)

func TestClassifyMemcache(t *testing.T) {
	for line, want := range map[string]driver.Risk{
		"get a": driver.RiskRead, "stats items": driver.RiskRead, "lru_crawler metadump all": driver.RiskRead, "mg a v t": driver.RiskRead,
		"mg a v T30": driver.RiskWrite, "touch a 10": driver.RiskWrite, "incr n 1": driver.RiskWrite,
		"stats reset": driver.RiskWrite, "stats detail on": driver.RiskWrite, "stats detail dump": driver.RiskRead, "stats slabs": driver.RiskRead,
		"delete a": driver.RiskDestructive, "flush_all": driver.RiskDestructive, "shutdown": driver.RiskDestructive, "lru_crawler disable": driver.RiskDestructive,
	} {
		if got := ClassifyMemcache(strings.Fields(line)).Risk; got != want {
			t.Errorf("%q = %v, want %v", line, got, want)
		}
	}
	for _, args := range [][]string{{"get", "a\r\nflush_all"}, {"get", "a\nb"}} {
		if v := ClassifyMemcache(args); v.Risk != driver.RiskDestructive || v.RuleIDs[0] != "memcached-line" {
			t.Errorf("%q = %+v", args, v)
		}
	}
	if v := ClassifyMemcache([]string{"mg", "a T30"}); v.Risk != driver.RiskWrite {
		t.Errorf("mg with the flag in one argument = %v", v.Risk)
	}
	if v := ClassifyMemcache([]string{" flush_all", "x"}); v.Risk != driver.RiskDestructive {
		t.Errorf("leading space = %v", v.Risk)
	}
	if validKey("has space") == nil || validKey(strings.Repeat("k", 251)) == nil || validKey("ok:1") != nil {
		t.Error("key checks")
	}
}

// TestMemcacheServer runs every Store call against a real memcached (make
// e2e starts one; set KOMANDO_E2E_MEMCACHED=host:port to run it by hand).
func TestMemcacheServer(t *testing.T) {
	addr := os.Getenv("KOMANDO_E2E_MEMCACHED")
	if addr == "" {
		t.Skip("set KOMANDO_E2E_MEMCACHED=host:port")
	}
	ctx := context.Background()
	tg, err := driver.Parse("memcached://" + addr)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(ctx, tg, "", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Set(ctx, "komando:a", "hello\r\nworld", time.Hour); err != nil {
		t.Fatal(err)
	}
	s.Set(ctx, "komando:b", "two", 0)
	v, err := s.Get(ctx, "komando:a", 0, 0)
	meta := s.(*memcache).meta // 1.6+: the time to live is known
	if err != nil || v.Value != "hello\r\nworld" || meta && (v.TTL == nil || *v.TTL < 3500) {
		t.Errorf("get %+v %v", v, err)
	}
	if v, err := s.Get(ctx, "komando:b", 0, 0); err != nil || v.TTL != nil {
		t.Errorf("no expiry %+v %v", v, err)
	}
	if _, err := s.Get(ctx, "komando:none", 0, 0); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing key: %v", err)
	}
	if ok, err := s.Exists(ctx, "komando:a"); !ok || err != nil {
		t.Errorf("exists %v %v", ok, err)
	}
	keys, _, err := s.Keys(ctx, "komando:*", 100)
	if err != nil || len(keys) != 2 {
		t.Errorf("keys %v %v", keys, err)
	}
	info, err := s.Info(ctx, "")
	sum := SummarizeFor("memcached", info)
	if err != nil || !strings.HasSuffix(sum.Version, "(memcached)") || sum.Keys["items"] < 2 {
		t.Errorf("info %+v %v", sum, err)
	}
	if r, err := s.Run(ctx, []string{"get", "komando:b"}); err != nil || !strings.Contains(strings.ToLower(fmtAny(r)), "two") {
		t.Errorf("run get %v %v", r, err)
	}
	if r, err := s.Run(ctx, []string{"version"}); err != nil || !strings.HasPrefix(fmtAny(r), "VERSION") {
		t.Errorf("run version %v %v", r, err)
	}
	if n, err := s.Del(ctx, "komando:a", "komando:b", "komando:none"); n != 2 || err != nil {
		t.Errorf("del %d %v", n, err)
	}
}

func fmtAny(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []any:
		var b strings.Builder
		for _, e := range x {
			b.WriteString(fmtAny(e))
		}
		return b.String()
	case map[string]any:
		return fmtAny(x["value"])
	}
	return ""
}

// TestMemcacheAuth: memcached -Y (text protocol login), with the right and
// a wrong password (KOMANDO_E2E_MEMCACHED_AUTH=host:port, user e2e / mcpass).
func TestMemcacheAuth(t *testing.T) {
	addr := os.Getenv("KOMANDO_E2E_MEMCACHED_AUTH")
	if addr == "" {
		t.Skip("set KOMANDO_E2E_MEMCACHED_AUTH=host:port (memcached -Y with e2e:mcpass)")
	}
	tg, _ := driver.Parse("memcached://e2e@" + addr)
	s, err := OpenStore(context.Background(), tg, "mcpass", nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := OpenStore(context.Background(), tg, "wrong", nil, 5*time.Second); err == nil || !strings.Contains(err.Error(), "refused the login") {
		t.Errorf("a wrong password: %v", err)
	}
}

// memcached reads an exptime over 30 days as a Unix time.
func TestMemcacheExptime(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, c := range []struct {
		ttl  time.Duration
		want int64
	}{
		{0, 0},
		{time.Millisecond, 1},
		{time.Hour, 3600},
		{30 * 24 * time.Hour, 2592000},
		{31 * 24 * time.Hour, 1_800_000_000 + 2678400},
	} {
		if got := mcExptime(c.ttl, now); got != c.want {
			t.Errorf("%v: %d, want %d", c.ttl, got, c.want)
		}
	}
}
