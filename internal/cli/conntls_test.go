package cli

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// A conn that crosses the network on its own gets TLS that checks the
// server's certificate when its URL does not say otherwise; plain redis://
// and memcached:// need ?insecure=1 there. Conns saved before keep working.
func TestNewConnsCheckTLS(t *testing.T) {
	invHome(t)
	url := func(name string) string {
		st, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		return st.Conns[name].URL
	}
	d := mustRun(t, "conn", "add", "pg", "postgres://app@db.example.com/app")
	if url("pg") != "postgres://app@db.example.com/app?sslmode=verify-full" || !strings.Contains(fmt.Sprint(d["warnings"]), "added sslmode=verify-full") {
		t.Errorf("postgres: %s, %v", url("pg"), d)
	}
	mustRun(t, "conn", "add", "shop", "mysql://shop@db.example.com/shop?charset=utf8mb4")
	if url("shop") != "mysql://shop@db.example.com/shop?charset=utf8mb4&tls=true" {
		t.Errorf("mysql: %s", url("shop"))
	}
	// what the URL says, a --via path and this computer stay as they are
	mustRun(t, "host", "add", "jump", "deploy@10.0.0.3")
	for name, raw := range map[string]string{
		"pg-plain": "postgres://app@db.example.com/app?sslmode=disable",
		"pg-local": "postgres://app@127.0.0.1/app",
		"my-local": "mysql://shop@localhost/shop",
		"lite":     "sqlite:///var/lib/app.db",
	} {
		mustRun(t, "conn", "add", name, raw)
		if url(name) != raw {
			t.Errorf("%s: saved %s", name, url(name))
		}
	}
	mustRun(t, "conn", "add", "pg-via", "postgres://app@10.0.0.5/app", "--via", "jump")
	mustRun(t, "conn", "add", "cache-via", "redis://default@10.0.0.7:6379/0", "--via", "jump")
	if url("pg-via") != "postgres://app@10.0.0.5/app" {
		t.Errorf("--via: %s", url("pg-via"))
	}

	for _, raw := range []string{"redis://default@cache.example.com:6379/0", "memcached://cache.example.com:11211"} {
		if e := wantCode(t, "INSECURE_PROTOCOL", "conn", "add", "c", raw); !strings.Contains(e.Hint, "?insecure=1") {
			t.Errorf("%s: hint %q", raw, e.Hint)
		}
	}
	mustRun(t, "conn", "add", "cache", "redis://default@cache.example.com:6379/0?insecure=1")
	mustRun(t, "conn", "add", "cache-tls", "rediss://default@cache.example.com:6379/0")
	mustRun(t, "conn", "add", "mc-local", "memcached://127.0.0.1:11211")

	// conn edit --url: a new URL gets the same default; other edits do not
	mustRun(t, "conn", "edit", "pg-plain", "--add-tag", "live")
	mustRun(t, "conn", "edit", "pg-plain", "--url", "postgres://app@db2.example.com/app")
	if url("pg-plain") != "postgres://app@db2.example.com/app?sslmode=verify-full" {
		t.Errorf("edit --url: %s", url("pg-plain"))
	}
	wantCode(t, "INSECURE_PROTOCOL", "conn", "edit", "cache-tls", "--url", "redis://default@cache.example.com:6379/0")

	// a conn saved before this default keeps its URL and stays usable
	now := time.Now().UTC()
	if err := store.Update(func(s *store.State) error {
		s.Conns["old-cache"] = &store.Conn{Name: "old-cache", Kind: "redis", URL: "redis://default@cache.example.com:6379/0", CreatedAt: now, UpdatedAt: now}
		s.Conns["old-pg"] = &store.Conn{Name: "old-pg", Kind: "postgres", URL: "postgres://app@db.example.com/app", CreatedAt: now, UpdatedAt: now}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "conn", "edit", "old-cache", "--add-tag", "legacy", "--notes", "saved before")
	mustRun(t, "conn", "edit", "old-pg", "--add-tag", "legacy")
	if url("old-cache") != "redis://default@cache.example.com:6379/0" || url("old-pg") != "postgres://app@db.example.com/app" {
		t.Errorf("an older conn's URL changed: %s, %s", url("old-cache"), url("old-pg"))
	}
	mustRun(t, "conn", "show", "old-cache")
}
