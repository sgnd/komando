package cli

import (
	"crypto/ed25519"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/sshx"
)

// goldenGateHome is a komando home with the gate rows' inventory, made
// once and copied into each run's own home.
var goldenGateHome string

// goldenGateSetup fills this run's home with the inventory the gate rows
// of TestAgentGolden run against: plain and protected servers and conns at
// addresses nothing answers on, so every row stops at a safety check
// before connecting.
func goldenGateSetup(t *testing.T) {
	t.Helper()
	home := os.Getenv("KOMANDO_HOME")
	if goldenGateHome == "" {
		noAgent(t)
		t.Setenv("GOLDEN_SECRET", "golden-value")
		for _, a := range [][]string{
			{"host", "add", "web1", "u@127.0.0.1:1"},
			{"host", "add", "prod1", "u@127.0.0.2:1", "--protected"},
			{"host", "add", "h1", "u@127.0.0.11:1", "-g", "big"},
			{"host", "add", "h2", "u@127.0.0.12:1", "-g", "big"},
			{"host", "add", "h3", "u@127.0.0.13:1", "-g", "big"},
			{"host", "add", "h4", "u@127.0.0.14:1", "-g", "big"},
			{"conn", "add", "cache1", "redis://127.0.0.1:1/0"},
			{"conn", "add", "pcache", "redis://127.0.0.3:1/1", "--protected"},
			{"conn", "add", "db1", "postgres://u@127.0.0.1:1/app"},
			{"conn", "add", "pdb", "postgres://u@127.0.0.3:1/prod", "--protected"},
			{"conn", "add", "q1", "kafka://127.0.0.1:1"},
			{"conn", "add", "st1", "sftp://u@127.0.0.1:1/up"},
			{"conn", "add", "reg1", "registry://u@127.0.0.1:1?tls=false"},
			{"policy", "deny", "foo.*bar"},
			{"vpn", "add", "pvpn", "socks", "--proxy-address", "127.0.0.1:1", "--protected", "--mfa"},
			{"secret", "set", "gsec", "--from-env", "GOLDEN_SECRET"},
			{"key", "gen", "gkey"},
		} {
			mustRun(t, a...)
		}
		// prod1 has a pinned host key, so `host trust prod1 --reset` would
		// replace one (a fixed key: the golden text stays the same)
		pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sshx.PinHostKey("127.0.0.2:1", pub, false); err != nil {
			t.Fatal(err)
		}
		goldenGateHome = filepath.Join(os.TempDir(), "komando-golden-gates-"+filepath.Base(home))
		if err := os.CopyFS(goldenGateHome, os.DirFS(home)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(goldenGateHome); goldenGateHome = "" })
		return
	}
	err := filepath.WalkDir(goldenGateHome, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(goldenGateHome, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		dst := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// goldenGates are the command lines that stop at a safety check today,
// one per gated command and flag combination komando can show without a
// server: changes.md C-C01 pins them before one rule table (riskOf)
// replaces the two lists, so no stop an agent gets today can be lost.
var goldenGates = [][]string{
	// POLICY_BLOCKED: cannot be undone, or a policy hit (--allow-dangerous)
	{"exec", "web1", "--", "rm", "-rf", "/"},
	{"exec", "web1", "--", "reboot"},
	{"exec", "web1", "--", "foo", "bar"}, // the deny rule foo.*bar
	{"job", "start", "web1", "--", "reboot"},
	{"reboot", "web1"},
	{"reboot", "prod1"},
	{"svc", "stop", "web1", "sshd"},
	{"user", "rm", "web1", "bob"},
	{"pkg", "rm", "web1", "openssh-server"},
	{"fs", "rm", "web1", "/tmp/x", "--recursive"},
	{"fs", "rm", "web1", "/"},
	{"sync", "testdata", "web1:/tmp/x", "--delete"},
	{"cache", "rm", "cache1", "k"},
	{"cache", "rm", "pcache", "k"},
	{"cache", "run", "cache1", "--write", "--", "FLUSHALL"},
	{"db", "query", "db1", "--write", "DROP TABLE x"},
	{"db", "query", "pdb", "--write", "UPDATE x SET a=1"},
	{"db", "user", "rm", "db1", "bob"},
	{"db", "restore", "db1", "--from", "testdata/golden_restore.sql"},
	{"queue", "purge", "q1", "t"},
	{"queue", "rm", "q1", "t"},
	{"storage", "rm", "st1", "k"},
	{"registry", "rm", "reg1", "a:1"},
	{"registry", "prune", "reg1", "a", "--keep", "5"},
	{"docker", "rm", "web1", "c1"},
	{"docker", "prune", "web1"},
	{"docker", "raw", "web1", "--", "system", "prune", "-af"},
	// PROTECTED_HOST: a change on a protected server (--yes)
	{"exec", "prod1", "--", "touch", "/tmp/x"},
	{"job", "start", "prod1", "--", "touch", "x"},
	{"svc", "restart", "prod1", "nginx"},
	{"user", "add", "prod1", "bob"},
	{"pkg", "install", "prod1", "vim"},
	{"fs", "write", "prod1", "/tmp/x", "--content", "hi"},
	{"fs", "rm", "prod1", "/tmp/x"},
	{"docker", "stop", "prod1", "c1"},
	{"cron", "rm", "prod1", "1"},
	{"upload", "prod1", "testdata/golden_restore.sql", "/tmp/h"},
	{"host", "rm", "prod1"},
	{"host", "edit", "prod1", "--protected=false"},
	// PROTECTED_TARGET: a change on a protected conn (--yes)
	{"cache", "set", "pcache", "k", "v"},
	{"cache", "run", "pcache", "--write", "--", "SET", "k", "v"},
	{"db", "kill", "pdb", "1"},
	{"conn", "rm", "pcache"},
	{"conn", "edit", "pcache", "--protected=false"},
	{"vpn", "rm", "pvpn"},
	{"vpn", "edit", "pvpn", "--notes", "x"},
	// SAFETY_SETTING: weakens komando's own checks (--yes)
	{"policy", "rm", "foo.*bar"},
	{"config", "set", "audit", "off"},
	{"vpn", "edit", "pvpn", "--protected=false"},
	{"vpn", "edit", "pvpn", "--mfa=false"},
	// WRITE_REQUIRES_FLAG: a read command asked to write
	{"cache", "run", "cache1", "--", "SET", "k", "v"},
	{"db", "query", "db1", "DELETE FROM x"},
	// CONFIRM_REQUIRED: a bulk change (group of more than 3 members)
	{"group", "rm", "big"},
	// NEEDS_PERSON: only a person at a terminal
	{"config", "approval-code"},
}

// goldenNotes are the command lines of the release notes' exit and error
// code changes (changes.md 11b) that need the gate inventory: each one
// stays as decided.
var goldenNotes = [][]string{
	// C-V16: update takes only a version; a server is a usage error
	{"update", "web1"},
	// C-V24: aws, gcp and azure are no new server's, conn's or VPN's name
	{"host", "add", "azure", "u@10.0.0.1"},
	{"conn", "add", "aws", "redis://127.0.0.1:1/0"},
	{"vpn", "add", "gcp", "socks", "--proxy-address", "127.0.0.1:1080"},
	// C-C03, C-C06 (OD-7): deletes that leave no copy are dangerous
	{"secret", "rm", "gsec"},
	{"key", "rm", "gkey", "--delete-file"},
	{"fs", "rm", "web1", "/tmp/x"},
	// C-C13 (OD-9): replacing a pinned host key is for a person only; with
	// a key pinned, the real run stops before it connects
	{"host", "trust", "prod1", "--reset", "--dry-run"},
	{"host", "trust", "prod1", "--reset"},
	// C-E11 (S-5.17): words from other tools get komando's command, a
	// typo the nearest name, as error.suggestion and in the hint
	{"ps"},
	{"get"},
	{"delete", "web1"},
	{"kubectl", "get", "pods"},
	{"psql"},
	{"exce", "web1", "--", "uptime"},
	{"svc", "restat", "web1", "nginx"},
}
