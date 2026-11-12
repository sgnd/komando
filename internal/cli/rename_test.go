package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// shopInventory is a small project under the prefix shop-: a VPN, a
// protected bastion behind it, a server behind both (the bastion is in the
// middle of its --via path), a protected database, a bucket whose URL names
// look like the prefix, a registry with a secret in its URL, a managed key,
// groups shop and shop-stg, and a server outside the project that uses a
// shop secret.
func shopInventory(t *testing.T) {
	t.Helper()
	invHome(t)
	for _, n := range []string{"shop-pass", "shop-psk", "shop-ca", "other-pass"} {
		if err := vault.Set(n, "value of "+n); err != nil {
			t.Fatal(err)
		}
	}
	mustRun(t, "vpn", "add", "shop-vpn", "socks", "--address", "127.0.0.1:1080", "-g", "shop")
	mustRun(t, "host", "add", "shop-bastion", "u@10.0.0.1", "--via", "shop-vpn", "-g", "shop", "-g", "shop-stg",
		"--password-ref", "secret:shop-pass", "--protected", "--label", "dc=jkt", "--notes", "jump for shop-db; see shop-vpn.")
	mustRun(t, "key", "gen", "shop-key")
	mustRun(t, "host", "add", "shop-data-01", "u@10.0.0.2", "--via", "shop-vpn,shop-bastion", "-g", "shop",
		"--sudo-ref", "secret:shop-pass", "--key", "shop-key")
	mustRun(t, "host", "add", "web", "u@10.0.0.3", "--via", "shop-vpn,shop-bastion", "--env", "DB=secret:shop-pass", "--password-ref", "secret:other-pass")
	mustRun(t, "conn", "add", "shop-db", "postgres://shop@10.0.0.5/shop", "--via", "shop-vpn,shop-bastion",
		"--password-ref", "secret:shop-pass", "--protected", "-g", "shop")
	mustRun(t, "conn", "add", "bucket", "s3://shop-admin@shop-prod?region=eu-west-1", "--password-ref", "secret:shop-pass")
	mustRun(t, "conn", "add", "reg", "registry://u@reg.lan?ca=secret:shop-ca")
	if err := store.Update(func(s *store.State) error {
		s.Vpns["shop-vpn"].PSKRef = "secret:shop-psk"
		s.Keys["shop-key"].PassphraseRef = "secret:shop-pass"
		s.Jobs["j1"] = &store.Job{ID: "j1", Host: "shop-data-01", Command: "sleep 1"}
		s.Tunnels["t1"] = &store.Tunnel{ID: "t1", Host: "shop-bastion", Via: "shop-vpn,shop-bastion", Conn: "shop-db", Kind: "local"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// homeFiles is the store and runtime.json, to check that nothing changed.
func homeFiles(t *testing.T) string {
	t.Helper()
	db, _ := os.ReadFile(store.Path(store.StoreFile))
	rt, _ := os.ReadFile(store.Path("runtime.json"))
	return string(db) + "\n--runtime--\n" + string(rt)
}

func pairs(d map[string]any, kind string) map[string]string {
	m := map[string]string{}
	list, _ := d["renamed"].(map[string]any)[kind].([]any)
	for _, p := range list {
		p := p.(map[string]any)
		m[p["from"].(string)] = p["to"].(string)
	}
	return m
}

func updatedRef(d map[string]any, entry, field string) (from, to string, ok bool) {
	for _, u := range d["updated"].([]any) {
		u := u.(map[string]any)
		if u["entry"] == entry && u["field"] == field {
			return u["from"].(string), u["to"].(string), true
		}
	}
	return "", "", false
}

func TestRenamePrefix(t *testing.T) {
	shopInventory(t)
	stBefore, _ := store.Load()
	created := stBefore.Hosts["shop-bastion"].CreatedAt
	keep := homeFiles(t)

	// the dry run: the old -> new map per kind, every reference, and the stop
	d := mustRun(t, "rename", "--prefix", "shop-", "acme-shop-", "--dry-run")
	if d["action"] != "would_rename" || d["count"].(float64) != 10 {
		t.Fatalf("dry run: %v", d)
	}
	want := map[string]map[string]string{
		"host":   {"shop-bastion": "acme-shop-bastion", "shop-data-01": "acme-shop-data-01"},
		"conn":   {"shop-db": "acme-shop-db"},
		"vpn":    {"shop-vpn": "acme-shop-vpn"},
		"secret": {"shop-pass": "acme-shop-pass", "shop-psk": "acme-shop-psk", "shop-ca": "acme-shop-ca"},
		"key":    {"shop-key": "acme-shop-key"},
		"group":  {"shop": "acme-shop", "shop-stg": "acme-shop-stg"}, // shop: OLD without its -
	}
	for kind, m := range want {
		got := pairs(d, kind)
		if len(got) != len(m) {
			t.Errorf("%s: %v, want %v", kind, got, m)
		}
		for from, to := range m {
			if got[from] != to {
				t.Errorf("%s %s -> %q, want %q", kind, from, got[from], to)
			}
		}
	}
	for _, c := range []struct{ entry, field, from, to string }{
		// a server in the middle of a --via path
		{"host acme-shop-data-01", "via", "shop-vpn,shop-bastion", "acme-shop-vpn,acme-shop-bastion"},
		{"host web", "via", "shop-vpn,shop-bastion", "acme-shop-vpn,acme-shop-bastion"},
		{"host web", "env DB", "secret:shop-pass", "secret:acme-shop-pass"},
		{"host acme-shop-data-01", "key", "shop-key", "acme-shop-key"},
		{"host acme-shop-data-01", "sudo_ref", "secret:shop-pass", "secret:acme-shop-pass"},
		{"host acme-shop-bastion", "groups", "shop,shop-stg", "acme-shop,acme-shop-stg"},
		{"conn acme-shop-db", "via", "shop-vpn,shop-bastion", "acme-shop-vpn,acme-shop-bastion"},
		{"conn bucket", "password_ref", "secret:shop-pass", "secret:acme-shop-pass"},
		// secret: inside a conn URL
		{"conn reg", "url", "registry://u@reg.lan?ca=secret:shop-ca", "registry://u@reg.lan?ca=secret:acme-shop-ca"},
		{"vpn acme-shop-vpn", "psk_ref", "secret:shop-psk", "secret:acme-shop-psk"},
		{"vpn acme-shop-vpn", "groups", "shop", "acme-shop"},
		{"key acme-shop-key", "passphrase_ref", "secret:shop-pass", "secret:acme-shop-pass"},
		{"job j1", "host", "shop-data-01", "acme-shop-data-01"},
		{"tunnel t1", "conn", "shop-db", "acme-shop-db"},
		{"tunnel t1", "via", "shop-vpn,shop-bastion", "acme-shop-vpn,acme-shop-bastion"},
	} {
		if from, to, ok := updatedRef(d, c.entry, c.field); !ok || from != c.from || to != c.to {
			t.Errorf("%s %s: %q -> %q (%v), want %q -> %q", c.entry, c.field, from, to, ok, c.from, c.to)
		}
	}
	if _, _, ok := updatedRef(d, "conn bucket", "url"); ok {
		t.Error("names inside a URL are the resource's own: the bucket URL must not change")
	}
	if _, _, ok := updatedRef(d, "host acme-shop-bastion", "notes"); ok {
		t.Error("notes change only with --notes")
	}
	if w, _ := d["warnings"].([]any); len(w) != 1 || !strings.Contains(w[0].(string), "the notes of 1 entry name old entries") {
		t.Errorf("one warning counts the notes that stay: %v", d["warnings"])
	}
	if moved, _ := d["moved"].([]any); len(moved) != 0 {
		t.Errorf("a key in the store has no file to move: %v", d["moved"])
	}
	if b := d["_meta"].(map[string]any)["would_be_blocked"]; b == nil || b.(map[string]any)["code"] != "PROTECTED_HOST" {
		t.Errorf("the dry run shows the stop: %v", b)
	}
	if homeFiles(t) != keep {
		t.Fatal("a dry run changed something")
	}

	// a script without --yes: stopped, nothing changed
	wantCode(t, "PROTECTED_HOST", "rename", "--prefix", "shop-", "acme-shop-")
	if homeFiles(t) != keep {
		t.Fatal("a stopped rename changed something")
	}

	// an AI agent: one window for every protected entry, which says how many
	texts := windowText(t, true)
	d = mustRun(t, "rename", "--prefix", "shop-", "acme-shop-", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "2 protected entries (1 server, 1 conn)") ||
		!strings.Contains((*texts)[0], "shop-bastion, shop-db") {
		t.Errorf("one window that counts them: %q", *texts)
	}
	if d["action"] != "renamed" {
		t.Fatalf("rename: %v", d)
	}

	st, _ := store.Load()
	b, data, web := st.Hosts["acme-shop-bastion"], st.Hosts["acme-shop-data-01"], st.Hosts["web"]
	if st.Hosts["shop-bastion"] != nil || b == nil || data == nil {
		t.Fatalf("hosts: %v", mapKeys(st.Hosts))
	}
	if !b.Protected || b.Labels["dc"] != "jkt" || b.Notes != "jump for shop-db; see shop-vpn." || !b.CreatedAt.Equal(created) {
		t.Errorf("the protected mark, labels, notes and created_at stay: %+v", b)
	}
	if b.Via != "acme-shop-vpn" || b.PasswordRef != "secret:acme-shop-pass" || strings.Join(b.Groups, ",") != "acme-shop,acme-shop-stg" {
		t.Errorf("bastion refs: %+v", b)
	}
	if data.Via != "acme-shop-vpn,acme-shop-bastion" || data.Key != "acme-shop-key" || data.SudoRef != "secret:acme-shop-pass" {
		t.Errorf("data refs: %+v", data)
	}
	if web.Env["DB"] != "secret:acme-shop-pass" || web.PasswordRef != "secret:other-pass" {
		t.Errorf("web refs: %+v", web)
	}
	db := st.Conns["acme-shop-db"]
	if db == nil || !db.Protected || db.PasswordRef != "secret:acme-shop-pass" || db.Via != "acme-shop-vpn,acme-shop-bastion" {
		t.Errorf("conn: %+v", db)
	}
	if u := st.Conns["bucket"].URL; u != "s3://shop-admin@shop-prod?region=eu-west-1" {
		t.Errorf("bucket URL changed: %s", u)
	}
	if u := st.Conns["reg"].URL; u != "registry://u@reg.lan?ca=secret:acme-shop-ca" {
		t.Errorf("registry URL: %s", u)
	}
	if v := st.Vpns["acme-shop-vpn"]; v == nil || v.PSKRef != "secret:acme-shop-psk" {
		t.Errorf("vpn: %+v", v)
	}
	k := st.Keys["acme-shop-key"]
	if k == nil || !store.SealedKey(k) || k.PassphraseRef != "secret:acme-shop-pass" {
		t.Errorf("key: %+v", k)
	}
	if b, err := store.ReadPrivateKey(k); err != nil || len(b) == 0 {
		t.Errorf("the renamed key does not read: %v", err)
	}
	if st.Jobs["j1"].Host != "acme-shop-data-01" || st.Tunnels["t1"].Host != "acme-shop-bastion" || st.Tunnels["t1"].Conn != "acme-shop-db" {
		t.Errorf("jobs and tunnels: %+v %+v", st.Jobs["j1"], st.Tunnels["t1"])
	}
	for n, v := range map[string]string{"acme-shop-pass": "value of shop-pass", "acme-shop-psk": "value of shop-psk", "acme-shop-ca": "value of shop-ca", "other-pass": "value of other-pass"} {
		if got, err := vault.Get(n); err != nil || got != v {
			t.Errorf("secret %s = %q, %v", n, got, err)
		}
	}
	if _, err := vault.Get("shop-pass"); err != vault.ErrNotFound {
		t.Errorf("the old secret is still there: %v", err)
	}
	// nothing starts with shop- any more
	wantCode(t, "NOTHING_TO_RENAME", "rename", "--prefix", "shop-", "acme-shop-")
}

// When NEW starts with OLD, a second run changes nothing; OLD without its
// trailing - is renamed too (group team -> team-ops).
func TestRenamePrefixTwice(t *testing.T) {
	invHome(t)
	mustRun(t, "conn", "add", "team-registry", "registry://u@reg.lan", "-g", "team")
	mustRun(t, "host", "add", "team", "u@10.0.0.1")
	d := mustRun(t, "rename", "--prefix", "team-", "team-ops-")
	if pairs(d, "conn")["team-registry"] != "team-ops-registry" || pairs(d, "group")["team"] != "team-ops" ||
		pairs(d, "host")["team"] != "team-ops" {
		t.Fatalf("first run: %v", d)
	}
	keep := homeFiles(t)
	d = mustRun(t, "rename", "--prefix", "team-", "team-ops-")
	if d["action"] != "unchanged" || d["count"].(float64) != 0 || len(d["skipped"].([]any)) != 3 {
		t.Errorf("second run: %v", d)
	}
	if homeFiles(t) != keep {
		t.Error("the second run changed something")
	}
	// a bare name only counts when OLD ends in -
	mustRun(t, "host", "add", "lab", "u@10.0.0.2")
	mustRun(t, "host", "add", "lab2", "u@10.0.0.3")
	d = mustRun(t, "rename", "--prefix", "lab", "test", "--kind", "host")
	if h := pairs(d, "host"); len(h) != 2 || h["lab"] != "test" || h["lab2"] != "test2" {
		t.Errorf("no - : %v", h)
	}
}

// A clash anywhere stops the whole rename before anything is written: the
// inventory, the vault and the key folder stay exactly as they were.
func TestRenameClashChangesNothing(t *testing.T) {
	shopInventory(t)
	cases := []struct {
		name  string
		setup func()
	}{
		{"a new host name is taken by a conn", func() { mustRun(t, "conn", "add", "acme-shop-data-01", "postgres://a@10.0.0.9/x") }},
		{"a new secret name is taken", func() {
			if err := vault.Set("acme-shop-psk", "x"); err != nil {
				t.Fatal(err)
			}
		}},
		{"a new group name is taken", func() { mustRun(t, "host", "add", "z", "u@10.0.0.8", "-g", "ACME-shop-stg") }},
		{"a new key name is taken", func() { mustRun(t, "key", "gen", "acme-shop-key") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			shopInventory(t)
			c.setup()
			keep := homeFiles(t)
			e := wantCode(t, "NAME_TAKEN", "rename", "--prefix", "shop-", "acme-shop-", "--yes")
			if !strings.Contains(e.Message, "acme-shop-") {
				t.Errorf("the message names the clash: %s", e.Message)
			}
			if homeFiles(t) != keep {
				t.Fatal("a clash changed something")
			}
		})
	}

	// a connected VPN cannot be renamed: its background session runs under the old name
	shopInventory(t)
	if err := store.Update(func(s *store.State) error {
		s.Sessions["shop-vpn"] = &store.VpnSession{Vpn: "shop-vpn", PID: os.Getpid(), StartedAt: time.Now(), LastUsed: time.Now()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	keep := homeFiles(t)
	wantCode(t, "VPN_IN_USE", "rename", "--prefix", "shop-", "acme-shop-", "--yes")
	if homeFiles(t) != keep {
		t.Fatal("VPN_IN_USE changed something")
	}
}

func TestRenameUsage(t *testing.T) {
	shopInventory(t)
	wantCode(t, "USAGE", "rename", "shop-", "acme-shop-")
	wantCode(t, "USAGE", "rename", "--prefix", "shop-", "shop-")
	wantCode(t, "USAGE", "rename", "--prefix", "", "x-")
	wantCode(t, "USAGE", "rename", "--prefix", "shop-", "acme-shop-", "--kind", "bucket")
	wantCode(t, "USAGE", "rename", "--prefix", "shop-", "bad name-", "--yes")
	wantCode(t, "NOTHING_TO_RENAME", "rename", "--prefix", "nope-", "x-")
	// --kind: only secrets are renamed; references still follow
	d := mustRun(t, "rename", "--prefix", "shop-", "acme-shop-", "--kind", "secret")
	if len(pairs(d, "secret")) != 3 || len(pairs(d, "host")) != 0 || d["_meta"].(map[string]any)["would_be_blocked"] != nil {
		t.Errorf("--kind secret: %v", d)
	}
	st, _ := store.Load()
	if st.Hosts["shop-bastion"].PasswordRef != "secret:acme-shop-pass" {
		t.Errorf("references follow: %+v", st.Hosts["shop-bastion"])
	}
}

// keptReason is the reason a rename gives for an old name it left in a
// field of an entry ("" when it is not listed).
func keptReason(d map[string]any, entry, field, name string) string {
	list, _ := d["kept"].([]any)
	for _, k := range list {
		k := k.(map[string]any)
		if k["entry"] == entry && k["field"] == field && k["name"] == name {
			return k["reason"].(string)
		}
	}
	return ""
}

// --notes replaces the names that clearly mean an entry, and lists the old
// names it keeps: OLD without its - (here a database and a role), a key
// and group name that is also a bucket, a server name that is also the
// bucket of a conn, and a pattern that would no longer match the same
// entries.
func TestRenameNotes(t *testing.T) {
	shopInventory(t)
	mustRun(t, "key", "gen", "shop-dev")
	mustRun(t, "conn", "add", "shop-files", "s3://AKIAEXAMPLE@shop-dev/backups?region=eu-west-1", "-g", "shop-dev")
	mustRun(t, "host", "add", "shop-prod", "u@10.0.0.6") // also the bucket in conn bucket's URL
	mustRun(t, "host", "add", "shop-prod-db-01", "u@10.0.0.7")
	mustRun(t, "host", "add", "shop-prod-db-02", "u@10.0.0.8")
	mustRun(t, "host", "add", "shop-web-1", "u@10.0.0.9")
	mustRun(t, "host", "add", "acme-shop-web-9", "u@10.0.0.10") // in the way of acme-shop-web-*
	note := "db shop, role shop on shop-db; dump to bucket shop-dev. Copy to shop-prod, then shop-prod-db-* and shop-web-*. " +
		"Password: secret:shop-pass. Members: @shop and @shop-stg (shop-stg); ssh u@shop. Is it shop-vpn?"
	mustRun(t, "host", "add", "ops", "u@10.0.0.11", "--notes", note)

	d := mustRun(t, "rename", "--prefix", "shop-", "acme-shop-", "--notes", "--yes", "--dry-run")
	from, to, ok := updatedRef(d, "host ops", "notes")
	want := "db shop, role shop on acme-shop-db; dump to bucket shop-dev. Copy to shop-prod, then acme-shop-prod-db-* and shop-web-*. " +
		"Password: secret:acme-shop-pass. Members: @acme-shop and @acme-shop-stg (shop-stg); ssh u@shop. Is it acme-shop-vpn?"
	if !ok || from != note || to != want {
		t.Errorf("notes:\n got %q\nwant %q", to, want)
	}
	for name, why := range map[string]string{
		"shop":           "OLD without its -",
		"shop-dev":       "a key's name",
		"shop-prod":      "also in the URL of conn bucket",
		"shop-web-*":     "acme-shop-web-* would also match acme-shop-web-9",
		"shop-stg":       "a group's name, often a plain word too; @shop-stg follows the group",
		"shop-prod-db-*": "",
	} {
		if got := keptReason(d, "host ops", "notes", name); !strings.Contains(got, why) || (why == "") != (got == "") {
			t.Errorf("kept %s: %q, want %q", name, got, why)
		}
	}
	if !strings.Contains(keptReason(d, "host ops", "notes", "shop"), "@shop follows the group") {
		t.Errorf("the bare name is a group here: %v", d["kept"])
	}
	if from, to, _ := updatedRef(d, "host acme-shop-bastion", "notes"); from != "jump for shop-db; see shop-vpn." || to != "jump for acme-shop-db; see acme-shop-vpn." {
		t.Errorf("bastion notes: %q -> %q", from, to)
	}
	if d["warnings"] != nil {
		t.Errorf("no notes warning with --notes: %v", d["warnings"])
	}
	text := renameResultText(t, d)
	for _, s := range []string{"old names kept in notes and labels", "host ops notes: shop (OLD without its -"} {
		if !strings.Contains(text, s) {
			t.Errorf("the text lists what stays (%q):\n%s", s, text)
		}
	}

	mustRun(t, "rename", "--prefix", "shop-", "acme-shop-", "--notes", "--yes")
	st, _ := store.Load()
	if n := st.Hosts["ops"].Notes; n != want {
		t.Errorf("saved notes: %q", n)
	}
	if n := st.Hosts["acme-shop-bastion"].Notes; n != "jump for acme-shop-db; see acme-shop-vpn." {
		t.Errorf("notes: %q", n)
	}

	// --kind conn: the servers keep their names, so a pattern for them stays
	invHome(t)
	mustRun(t, "host", "add", "lab-db-1", "u@10.0.0.1", "--notes", "backups on lab-db-* via lab-gw")
	mustRun(t, "conn", "add", "lab-gw", "postgres://a@10.0.0.2/x")
	d = mustRun(t, "rename", "--prefix", "lab-", "test-", "--kind", "conn", "--notes")
	if _, to, _ := updatedRef(d, "host lab-db-1", "notes"); to != "backups on lab-db-* via test-gw" {
		t.Errorf("--kind conn notes: %q", to)
	}
	if r := keptReason(d, "host lab-db-1", "notes", "lab-db-*"); r != "a pattern that also matches lab-db-1, which keeps its name" {
		t.Errorf("--kind conn pattern: %q", r)
	}
}

// renameResultText is the text komando prints for a rename's JSON data.
func renameResultText(t *testing.T, d map[string]any) string {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var r renameResult
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r.Text()
}

func TestNameTextReplace(t *testing.T) {
	nt := &nameText{
		follow: map[string]string{"shop-db": "acme-shop-db", "shop-vpn": "acme-shop-vpn"},
		groups: map[string]string{"shop": "acme-shop"},
		left:   map[string]string{"shop": "OLD without its -"},
	}
	for in, want := range map[string]string{
		"shop-db":                     "acme-shop-db",
		"shop-db.":                    "acme-shop-db.",
		"shop-db?":                    "acme-shop-db?",
		"(shop-db, shop-vpn)":         "(acme-shop-db, acme-shop-vpn)",
		"**shop-db** and *shop-vpn*":  "**acme-shop-db** and *acme-shop-vpn*",
		"shop-db-replica":             "shop-db-replica",
		"my-shop-db":                  "my-shop-db",
		"shop-db.example.com":         "shop-db.example.com",
		"s3://shop-admin@shop-prod":   "s3://shop-admin@shop-prod",
		"@shop and tag:x":             "@acme-shop and tag:x",
		"u@shop, x@shop-db":           "u@shop, x@acme-shop-db",
		"Jakarta–shop-db ✓ ünïcode":   "Jakarta–acme-shop-db ✓ ünïcode",
		"":                            "",
		"shop shop- shop-db shopshop": "shop shop- acme-shop-db shopshop",
		"shop-db-* and *":             "shop-db-* and *", // no prefix: patterns stay
	} {
		if got, _ := nt.replace(in); got != want {
			t.Errorf("replace(%q) = %q, want %q", in, got, want)
		}
	}
	if _, kept := nt.replace("db shop, @shop, u@shop."); len(kept) != 2 || kept[0] != (keptWord{"shop", "OLD without its -"}) {
		t.Errorf("kept: %v", kept)
	}
}

// Labels are free text: without --labels each value that names an old
// entry stays and is listed with what it would become; --labels replaces
// it, by the same rules as --notes.
func TestRenameLabels(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "shop-web", "u@10.0.0.1", "-g", "shop")
	mustRun(t, "conn", "add", "shop-db", "postgres://app@10.0.0.2/app", "--label", "host=shop-web", "--label", "team=shop", "--label", "dc=eu")
	mustRun(t, "host", "add", "other", "u@10.0.0.3", "--label", "backup=shop-db")

	d := mustRun(t, "rename", "--prefix", "shop-", "acme-shop-", "--dry-run")
	for _, c := range []struct{ entry, field, name, to, why string }{
		{"conn acme-shop-db", "label host", "shop-web", "acme-shop-web", "labels change only with --in-labels"},
		{"host other", "label backup", "shop-db", "acme-shop-db", "labels change only with --in-labels"},
		{"conn acme-shop-db", "label team", "shop", "", "OLD without its -"},
	} {
		if r := keptReason(d, c.entry, c.field, c.name); !strings.HasPrefix(r, c.why) {
			t.Errorf("%s %s: %q, want %q", c.entry, c.field, r, c.why)
		}
	}
	if k := d["kept"].([]any); len(k) != 3 {
		t.Errorf("kept: %v", k)
	}
	if text := renameResultText(t, d); !strings.Contains(text, "conn acme-shop-db label host: shop-web (labels change only with --in-labels; it would become acme-shop-web)") {
		t.Errorf("text:\n%s", text)
	}
	mustRun(t, "rename", "--prefix", "shop-", "acme-shop-")
	st, _ := store.Load()
	if l := st.Conns["acme-shop-db"].Labels; l["host"] != "shop-web" || l["team"] != "shop" {
		t.Errorf("labels changed without --labels: %v", l)
	}

	// --labels: the values that name entries follow; the bare name stays
	invHome(t)
	mustRun(t, "host", "add", "shop-web", "u@10.0.0.1", "-g", "shop")
	mustRun(t, "conn", "add", "shop-db", "postgres://app@10.0.0.2/app", "--label", "host=shop-web", "--label", "team=shop", "--label", "dc=eu")
	d = mustRun(t, "rename", "--prefix", "shop-", "acme-shop-", "--labels")
	if from, to, ok := updatedRef(d, "conn acme-shop-db", "label host"); !ok || from != "shop-web" || to != "acme-shop-web" {
		t.Errorf("label host: %q -> %q", from, to)
	}
	st, _ = store.Load()
	if l := st.Conns["acme-shop-db"].Labels; l["host"] != "acme-shop-web" || l["team"] != "shop" || l["dc"] != "eu" {
		t.Errorf("labels: %v", l)
	}
	if !strings.HasPrefix(keptReason(d, "conn acme-shop-db", "label team", "shop"), "OLD without its -") {
		t.Errorf("kept: %v", d["kept"])
	}
}

// A rename points references at new names of the same secrets, keys and
// VPNs: the same values go to the same places, so an AI agent needs no
// person's yes when no protected entry changes, and no window opens
// (TestMain fails a test that opens one).
func TestRenameAgentNeedsNoWindow(t *testing.T) {
	invHome(t)
	if err := vault.Set("lab-pass", "v"); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "vpn", "add", "lab-vpn", "socks", "--address", "127.0.0.1:1080")
	mustRun(t, "host", "add", "lab-a", "u@10.0.0.1", "--via", "lab-vpn", "--password-ref", "secret:lab-pass", "--env", "P=secret:lab-pass")
	mustRun(t, "conn", "add", "lab-db", "postgres://a@10.0.0.2/x", "--via", "lab-vpn,lab-a", "--password-ref", "secret:lab-pass")
	t.Setenv("CLAUDECODE", "1")
	resetApproval()
	t.Cleanup(resetApproval)
	d := mustRun(t, "rename", "--prefix", "lab-", "test-")
	if d["action"] != "renamed" || d["count"].(float64) != 4 {
		t.Errorf("agent rename: %v", d)
	}
	// a protected entry still needs a person: no screen, so it is refused
	mustRun(t, "host", "add", "lab-p", "u@10.0.0.3", "--protected")
	saved := askOnScreen
	askOnScreen = func(string) (bool, bool) { return false, false } // no screen
	t.Cleanup(func() { askOnScreen = saved })
	keep := homeFiles(t)
	wantCode(t, "PROTECTED_HOST", "rename", "--prefix", "lab-", "test-", "--yes")
	if homeFiles(t) != keep {
		t.Fatal("a refused rename changed something")
	}
}

// The approval code's secret is never renamed: a prefix that matches it
// leaves it alone, and the vault refuses it whatever the caller asks.
func TestRenameReservedSecret(t *testing.T) {
	invHome(t)
	for _, n := range []string{approvalSecret, "komando-other"} {
		if err := vault.Set(n, "v"); err != nil {
			t.Fatal(err)
		}
	}
	d := mustRun(t, "rename", "--prefix", "komando-", "k-", "--kind", "secret")
	if s := pairs(d, "secret"); len(s) != 1 || s["komando-other"] != "k-other" {
		t.Errorf("renamed: %v", s)
	}
	if sk := d["skipped"].([]any); len(sk) != 1 || sk[0].(map[string]any)["name"] != approvalSecret {
		t.Errorf("skipped: %v", sk)
	}
	if _, err := vault.Get(approvalSecret); err != nil {
		t.Errorf("the approval code's secret moved: %v", err)
	}
	if err := vault.RenameMany(map[string]string{"k-other": approvalSecret}); err == nil {
		t.Error("the vault put a value under the approval code's name")
	}
	if err := vault.RenameMany(map[string]string{approvalSecret: "x"}); err == nil {
		t.Error("the vault moved the approval code's secret")
	}
}

func TestKeyMv(t *testing.T) {
	invHome(t)
	mustRun(t, "key", "gen", "deploy")
	mustRun(t, "host", "add", "web", "u@10.0.0.1", "--key", "deploy")
	mustRun(t, "host", "add", "db", "u@10.0.0.2", "--key", "deploy", "--protected")

	keep := homeFiles(t)
	d := mustRun(t, "key", "mv", "deploy", "deploy-2026", "--dry-run")
	if moved, _ := d["moved"].([]any); d["action"] != "would_rename" || len(moved) != 0 || len(d["updated"].([]any)) != 2 {
		t.Errorf("dry run: %v", d)
	}
	if homeFiles(t) != keep {
		t.Fatal("a dry run changed something")
	}

	d = mustRun(t, "key", "mv", "deploy", "deploy-2026") // the protected db keeps the same key: no --yes
	if d["action"] != "renamed" {
		t.Fatalf("key mv: %v", d)
	}
	st, _ := store.Load()
	k := st.Keys["deploy-2026"]
	if st.Keys["deploy"] != nil || k == nil || k.Name != "deploy-2026" || !store.SealedKey(k) || k.PublicKey == "" {
		t.Fatalf("key: %+v", k)
	}
	if st.Hosts["web"].Key != "deploy-2026" || st.Hosts["db"].Key != "deploy-2026" {
		t.Errorf("hosts follow: %+v %+v", st.Hosts["web"], st.Hosts["db"])
	}

	// a key added from elsewhere keeps its file where it is
	ext := filepath.Join(t.TempDir(), "id_ext")
	b, _ := store.ReadPrivateKey(k)
	if err := os.WriteFile(ext, b, 0o600); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "key", "add", "ext", ext)
	mustRun(t, "key", "mv", "ext", "external")
	st, _ = store.Load()
	if st.Keys["external"].Path != ext {
		t.Errorf("an added key's file moved: %+v", st.Keys["external"])
	}
	if _, err := os.Stat(ext); err != nil {
		t.Errorf("the added key's file is gone: %v", err)
	}

	wantCode(t, "KEY_NOT_FOUND", "key", "mv", "nosuch", "x")
	wantCode(t, "KEY_EXISTS", "key", "mv", "external", "deploy-2026")
	wantCode(t, "USAGE", "key", "mv", "external", "bad name")
	if d := mustRun(t, "key", "mv", "external", "external"); d["action"] != "unchanged" {
		t.Errorf("same name: %v", d)
	}
}

func TestGroupMv(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "a", "u@10.0.0.1", "-g", "web")
	mustRun(t, "host", "add", "b", "u@10.0.0.2", "-g", "Web", "--protected")
	mustRun(t, "conn", "add", "c", "postgres://a@10.0.0.3/x", "-g", "web", "-g", "db")
	mustRun(t, "vpn", "add", "v", "socks", "--address", "127.0.0.1:1080", "-g", "web")

	// a protected member: one yes
	wantCode(t, "PROTECTED_HOST", "group", "mv", "web", "frontend")
	d := mustRun(t, "group", "mv", "@web", "frontend", "--dry-run")
	if d["action"] != "would_rename" || len(d["updated"].([]any)) != 4 || d["_meta"].(map[string]any)["would_be_blocked"] == nil {
		t.Errorf("dry run: %v", d)
	}
	texts := windowText(t, true)
	mustRun(t, "group", "mv", "web", "frontend", "--yes")
	if len(*texts) != 1 || !strings.Contains((*texts)[0], "1 protected server") {
		t.Errorf("one window: %q", *texts)
	}
	st, _ := store.Load()
	if strings.Join(st.Hosts["a"].Groups, ",") != "frontend" || strings.Join(st.Hosts["b"].Groups, ",") != "frontend" ||
		strings.Join(st.Conns["c"].Groups, ",") != "db,frontend" || strings.Join(st.Vpns["v"].Groups, ",") != "frontend" {
		t.Errorf("members: %v %v %v %v", st.Hosts["a"].Groups, st.Hosts["b"].Groups, st.Conns["c"].Groups, st.Vpns["v"].Groups)
	}
	noAgent(t)
	wantCode(t, "GROUP_NOT_FOUND", "group", "mv", "web", "x")
	wantCode(t, "GROUP_EXISTS", "group", "mv", "db", "FRONTEND")
	wantCode(t, "USAGE", "group", "mv", "db", "a b")
	// no protected member: no yes needed
	if d := mustRun(t, "group", "mv", "db", "databases"); d["action"] != "renamed" {
		t.Errorf("group mv: %v", d)
	}
}

// A failure after the vault changed (a VPN folder that cannot move) puts
// the secrets back and leaves the store unchanged.
func TestRenameRollback(t *testing.T) {
	unixOnly(t, "a folder made read-only with chmod (Windows folders ignore it)")
	shopInventory(t)
	secretsNow := func() string {
		var b strings.Builder
		for _, n := range secretNames() {
			v, err := vault.Get(n)
			b.WriteString(n + "=" + v + ";")
			if err != nil {
				t.Fatal(err)
			}
		}
		return b.String()
	}
	if err := store.Update(func(s *store.State) error {
		s.Vpns["shop-ts"] = &store.Vpn{Name: "shop-ts", Kind: "tailscale"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	vpnDir := store.Path("vpn")
	if err := os.MkdirAll(filepath.Join(vpnDir, "shop-ts-tailscale"), 0o700); err != nil {
		t.Fatal(err)
	}
	s0, h0 := secretsNow(), homeFiles(t)
	if err := os.Chmod(vpnDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(vpnDir, 0o700) })
	wantCode(t, "RENAME_FAILED", "rename", "--prefix", "shop-", "acme-shop-", "--yes")
	_ = os.Chmod(vpnDir, 0o700)
	if secretsNow() != s0 || homeFiles(t) != h0 {
		t.Fatal("a vault that did not open left changes")
	}
}
