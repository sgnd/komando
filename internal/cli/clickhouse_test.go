package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// A ClickHouse conn that crosses the network gets tls=true (HTTPS), and
// port 8123, ClickHouse's plain HTTP port, becomes 8443; --via and this
// computer stay as written.
func TestClickHouseConnsCheckTLS(t *testing.T) {
	invHome(t)
	url := func(name string) string {
		st, err := store.Load()
		if err != nil {
			t.Fatal(err)
		}
		return st.Conns[name].URL
	}
	for name, c := range map[string]struct{ raw, saved, note string }{
		"ch-a": {"clickhouse://app@ch.example.com/analytics", "clickhouse://app@ch.example.com/analytics?tls=true", "added tls=true and port 8443"},
		"ch-b": {"clickhouse://app@ch.example.com:8123/analytics", "clickhouse://app@ch.example.com:8443/analytics?tls=true", "added tls=true and port 8443"},
		"ch-c": {"clickhouse://app@ch.example.com:9443/analytics", "clickhouse://app@ch.example.com:9443/analytics?tls=true", "added tls=true:"},
	} {
		d := mustRun(t, "conn", "add", name, c.raw)
		if url(name) != c.saved || !strings.Contains(fmt.Sprint(d["warnings"]), c.note) {
			t.Errorf("%s: %s, %v", name, url(name), d["warnings"])
		}
	}
	mustRun(t, "host", "add", "jump", "deploy@10.0.0.3")
	for name, raw := range map[string]string{
		"c-plain": "clickhouse://app@ch.example.com/db?tls=false",
		"c-local": "clickhouse://app@127.0.0.1/default",
	} {
		mustRun(t, "conn", "add", name, raw)
		if url(name) != raw {
			t.Errorf("%s: saved %s", name, url(name))
		}
	}
	mustRun(t, "conn", "add", "c-via", "clickhouse://app@10.0.0.5:8123/db", "--via", "jump")
	if url("c-via") != "clickhouse://app@10.0.0.5:8123/db" {
		t.Errorf("--via: %s", url("c-via"))
	}
	for raw, want := range map[string]string{
		"clickhouse://app@ch.example.com/db":                 "plain HTTP",
		"clickhouse://app@ch.example.com/db?tls=false":       "plain HTTP",
		"clickhouse://app@ch.example.com/db?tls=skip-verify": "not checked",
		"clickhouse://app@ch.example.com/db?tls=true":        "",
	} {
		got := plainConn(&store.Conn{Name: "c", URL: raw})
		if want == "" && got != "" || !strings.Contains(got, want) {
			t.Errorf("plainConn(%s) = %q, want %q", raw, got, want)
		}
	}
	if got := verifiedTLSURL("clickhouse://app@db:8123/x?tls=false", "clickhouse"); got != "clickhouse://app@db:8443/x?tls=true" {
		t.Errorf("verifiedTLSURL: %s", got)
	}
	if w := weakTLS("", "clickhouse://app@db/x?tls=skip-verify"); len(w) != 1 || !strings.Contains(w[0], "skip-verify") {
		t.Errorf("weakTLS skip-verify: %v", w)
	}
	if w := weakTLS("", "clickhouse://app@db/x?tls=false"); len(w) != 1 || !strings.Contains(w[0], "tls=false") {
		t.Errorf("weakTLS false: %v", w)
	}
	// what ClickHouse cannot do says so before connecting
	wantCode(t, "NOT_SUPPORTED", "db", "dump", "c-local", "--to", t.TempDir()+"/c.sql")
	wantCode(t, "NOT_SUPPORTED", "db", "restore", "c-local", "--from", "x.sql", "--dry-run")
	wantCode(t, "NOT_SUPPORTED", "db", "explain", "c-local", "select 1", "--analyze")
	wantCode(t, "NOT_SUPPORTED", "db", "kill", "c-local", "42", "--session")
	wantCode(t, "USAGE", "conn", "add", "c-native", "clickhouse://app@ch.example.com:9000/db")
}

func TestClickHouseRedactAndImport(t *testing.T) {
	for in, want := range map[string]string{
		"create user bob identified with sha256_hash by 'abc123' salt 'f00'": "create user bob identified with sha256_hash by '***' salt 'f00'",
		"alter user bob identified by 'Secret1'":                             "alter user bob identified by '***'",
		"create user bob identified with plaintext_password by 'p'":          "create user bob identified with plaintext_password by '***'",
	} {
		if got := redactSQL(in); got != want {
			t.Errorf("redact %s: %s, want %s", in, got, want)
		}
	}
	p, err := importDBeaver(writeTemp(t, "data-sources.json", `{"connections":{
		"clickhouse-1":{"name":"Events","provider":"clickhouse","configuration":{"host":"ch.lan","port":"8123","database":"events","user":"app"}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Conns) != 1 || p.Conns[0].URL != "clickhouse://app@ch.lan:8123/events" {
		t.Errorf("dbeaver clickhouse: %+v", p.Conns)
	}
}
