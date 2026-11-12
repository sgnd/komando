//go:build !windows

package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// t3Cases are the T3 rows of the rule table a person meets at the
// terminal, each typed in full: the one question is "Type <answer> to
// continue", the answer is the name of what goes, the count of several or
// the target for a whole-target step, and never yes (S-7.3, OD-8).
var t3Cases = []struct {
	id     string
	answer string // the shown answer: "the name k" or "2 (...)"
	args   []string
}{
	{"queue.purge", "the name t", []string{"queue", "purge", "q1", "t"}},
	{"queue.rm", "the name t", []string{"queue", "rm", "q1", "t"}},
	{"cache.rm", "the name k", []string{"cache", "rm", "cache1", "k"}},
	{"cache.rm", "2 (", []string{"cache", "rm", "cache1", "k", "k2"}},
	{"storage.rm", "the name k", []string{"storage", "rm", "st1", "k"}},
	{"cluster.rm", "the name web", []string{"cluster", "rm", "prod", "deployment", "web"}},
	{"cluster.scale", "the name web", []string{"cluster", "scale", "prod", "deploy/web", "0"}},
	{"registry.rm", "the name a:1", []string{"registry", "rm", "reg1", "a:1"}},
	{"registry.prune", "the name a", []string{"registry", "prune", "reg1", "a", "--keep", "5"}},
	{"db.restore", "the name db1", []string{"db", "restore", "db1", "--from", "testdata/golden_restore.sql"}},
	{"db.user.rm", "the name bob", []string{"db", "user", "rm", "db1", "bob"}},
	{"fs.rm", "the name /tmp/x", []string{"fs", "rm", "web1", "/tmp/x"}},
	{"fs.rm", "the name /tmp/x", []string{"fs", "rm", "web1", "/tmp/x", "--recursive"}},
	{"docker.rm", "the name c1", []string{"docker", "rm", "web1", "c1"}},
	{"docker.prune", "the name web1", []string{"docker", "prune", "web1"}},
	{"user.rm", "the name bob", []string{"user", "rm", "web1", "bob"}},
	{"user.rm", "the name bob", []string{"user", "rm", "web1", "bob", "--remove-home"}},
	{"secret.rm", "the name gsec", []string{"secret", "rm", "gsec"}},
	{"key.rm", "the name gkey", []string{"key", "rm", "gkey", "--delete-file"}},
	{"pkg.rm", "the name openssh-server", []string{"pkg", "rm", "web1", "openssh-server"}},
	{"reboot", "the name web1", []string{"reboot", "web1"}},
	{"svc.stop", "the name web1", []string{"svc", "stop", "web1", "sshd"}},
	{"svc.disable", "the name web1", []string{"svc", "disable", "web1", "sshd"}},
	{"sync", "the name web1", []string{"sync", "testdata", "web1:/tmp/x", "--delete"}},
}

// Every T3 row a command always has (not one decided at run time) asks a
// person at a real terminal one typed question that names what goes, and a
// wrong answer stops it with exit 6 and changes nothing (S-7.3, S-7.4). The
// targets are addresses nothing answers on: a command that got past the
// question would fail later with another code.
func TestT3AsksTheTypedName(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a process per command")
	}
	covered := map[string]bool{}
	for _, c := range t3Cases {
		covered[c.id] = true
	}
	for _, r := range riskRows {
		if r.tier == tierDangerous && r.dynamic == "" && !covered[r.id] {
			t.Errorf("the T3 row %s has no PTY case in t3Cases", r.id)
		}
	}
	invHome(t)
	t.Setenv("T3_SECRET", "t3-value")
	l := newLabCluster(t)
	for _, a := range [][]string{
		{"host", "add", "web1", "u@127.0.0.1:1"},
		{"conn", "add", "cache1", "redis://127.0.0.1:1/0"},
		{"conn", "add", "db1", "postgres://u@127.0.0.1:1/app"},
		{"conn", "add", "q1", "kafka://127.0.0.1:1"},
		{"conn", "add", "st1", "sftp://u@127.0.0.1:1/up"},
		{"conn", "add", "reg1", "registry://u@127.0.0.1:1?tls=false"},
		{"import", "kubeconfig", l.kubeconfigFile(t, "    token: test-token-abcdef")},
		{"secret", "set", "gsec", "--from-env", "T3_SECRET"},
		{"key", "gen", "gkey"},
	} {
		mustRun(t, a...)
	}
	for _, c := range t3Cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			p := startPTYEnv(t, []string{"KOMANDO_PTY_AS=person"}, c.args...)
			p.answer(" to continue: ", "wrong-answer\r")
			code := p.exit()
			shown := p.shown()
			if code != out.ExitPolicy || strings.Count(shown, "Type ") != 1 || strings.Contains(shown, "Type yes") ||
				!strings.Contains(shown, "Type "+c.answer) || strings.Contains(shown, "[y/N") {
				t.Errorf("exit %d, want %d with one typed question for %q; the screen:\n%s", code, out.ExitPolicy, c.answer, shown)
			}
		})
	}
	// nothing went: the secret and the key are still there
	if _, err := os.Stat(os.Getenv("KOMANDO_HOME")); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "secret", "show", "gsec")
	if st, _ := loadState(); st == nil || st.Keys["gkey"] == nil {
		t.Error("a wrong answer deleted the key")
	}
}
