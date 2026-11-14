package cli

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
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
	if err := store.Update(store.Save, func(s *store.State) error {
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

// TestOverNetworkEveryHost: a kafka:// or nats:// URL that lists several
// servers crosses the network when any of them is not this computer, not
// only when the first one is not.
func TestOverNetworkEveryHost(t *testing.T) {
	for raw, want := range map[string]bool{
		"kafka://localhost:9092,127.0.0.1:9093":   false,
		"kafka://localhost:9092,remote:9092":      true,
		"kafka://remote:9092,localhost:9092":      true,
		"nats://app@127.0.0.1:4222,[::1]:4223":    false,
		"nats://app@127.0.0.1:4222,10.0.0.9:4222": true,
		"redis://default@localhost:6379/0":        false,
	} {
		tg, err := driver.Parse(raw)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if got := overNetwork(&store.Conn{URL: raw}, tg); got != want {
			t.Errorf("%s: overNetwork %v, want %v", raw, got, want)
		}
	}
	if overNetwork(&store.Conn{URL: "kafka://localhost:9092,remote:9092", Via: "jump"}, driver.Target{Address: "localhost:9092", Brokers: []string{"localhost:9092", "remote:9092"}}) {
		t.Error("--via protects every server")
	}
	invHome(t)
	wantCode(t, "INSECURE_PROTOCOL", "conn", "add", "k", "kafka://localhost:9092,kafka.example.com:9092")
}

// TestInsecureProtocolCatalogHint: many kinds give INSECURE_PROTOCOL, so
// the catalog's hint (`komando schema`) names the TLS form of each, while
// the error itself keeps its own kind's hint.
func TestInsecureProtocolCatalogHint(t *testing.T) {
	for _, c := range errorCodes {
		if c.Code != "INSECURE_PROTOCOL" {
			continue
		}
		for _, form := range []string{"rediss://", "amqps://", "tls://", "tls=true", "https://", "ftps://", "--via"} {
			if !strings.Contains(c.Hint, form) {
				t.Errorf("the catalog's hint does not name %s: %q", form, c.Hint)
			}
		}
	}
	invHome(t)
	if e := wantCode(t, "INSECURE_PROTOCOL", "conn", "add", "c", "memcached://cache.example.com:11211"); !strings.Contains(e.Hint, "memcacheds://") || strings.Contains(e.Hint, "amqps") {
		t.Errorf("memcached's own hint: %q", e.Hint)
	}
}
