package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/store"
)

// The tier table (internal/capability) describes what each command needs;
// what really stops a command is code in its handler (Guard, GuardConns,
// guardSafety, guardProtection, the person checks). TestTierMatchesRuntime
// is the proof that the two agree: every tier row above read, and the
// floor of every leaf that changes something, is run here as an AI agent
// through the real entry with --dry-run, and the stop it reports
// (meta.would_be_blocked, or the error a command gives even under
// --dry-run) must be the one its tier names.

// tierRun is one run. row names the tier row it proves (tierRowName), or
// "floor" for a leaf's plain run with no row applying.
type tierRun struct {
	row       string
	id        string   // today's command ID; its path is the ID's words
	args      []string // the words after the path
	protected bool     // the target is protected: change expects PROTECTED_TARGET
}

var tierRuns = []tierRun{
	// dangerous
	{"queue message delete --all dangerous", "queue.purge", []string{"q", "jobs"}, false},
	{"queue topic delete dangerous", "queue.rm", []string{"q", "jobs"}, false},
	{"storage object delete dangerous", "storage.rm", []string{"s3", "a.txt"}, false},
	{"registry image delete dangerous", "registry.rm", []string{"reg", "app:1"}, false},
	{"registry image prune dangerous", "registry.prune", []string{"reg", "app", "--keep", "1"}, false},
	{"database restore dangerous", "db.restore", []string{"pg", "--from", "dump.sql"}, false},
	{"credential key remove --delete-file dangerous", "key.rm", []string{"k1", "--delete-file"}, false},
	{"host exec dynamic dangerous", "exec", []string{"dev", "--", "rm -rf /"}, false},
	{"snippet exec dynamic dangerous", "recipe.run", []string{"wipe", "dev"}, false},
	{"cluster exec dynamic dangerous", "cluster.exec", []string{"k8s", "pod/a", "--", "rm -rf /"}, false},
	{"cluster raw dynamic dangerous", "cluster.run", []string{"k8s", "--write", "--", "delete", "pod", "a"}, false},
	{"cache raw dynamic dangerous", "cache.run", []string{"r", "--write", "--", "FLUSHALL"}, false},
	{"database query dynamic dangerous", "db.query", []string{"pg", "--write", "DROP TABLE t"}, false},
	{"host ssh add --proxy-command dynamic dangerous", "host.add", []string{"x", "--address", "10.0.0.9", "--proxy-command", "rm -rf /"}, false},
	{"host ssh edit --proxy-command dynamic dangerous", "host.edit", []string{"dev", "--proxy-command", "rm -rf /"}, false},
	// safety
	{"policy remove safety", "policy.rm", []string{"kubectl apply"}, false},
	{"policy edit --off safety", "policy.edit", []string{"docker-prune", "--off"}, false},
	{"policy edit --add-server safety", "policy.edit", []string{"docker-prune", "--off", "--add-server", "dev"}, false},
	{"policy edit --add-group safety", "policy.edit", []string{"docker-prune", "--off", "--add-group", "g1"}, false},
	{"floor", "policy.edit", []string{"docker-prune", "--rm-server", "dev"}, false},
	{"config set dynamic safety", "config.set", []string{"audit", "false"}, false},
	{"vpn edit --mfa=false safety", "vpn.edit", []string{"wg", "--mfa=false"}, false},
	{"host tunnel start dynamic safety", "tunnel.start", []string{"dev", "-L", "0.0.0.0:15432:localhost:5432"}, false},
	{"host ssh add --proxy-command dynamic safety", "host.add", []string{"y", "--address", "10.0.0.9", "--proxy-command", "nc %h %p"}, false},
	{"host ssh edit --proxy-command dynamic safety", "host.edit", []string{"dev", "--proxy-command", "nc %h %p"}, false},
	{"snippet create --overwrite --read-only dynamic safety", "recipe.add", []string{"r1", "--overwrite", "--read-only", "--", "uptime"}, false},
	{"host ssh trust dynamic safety", "host.trust", []string{"dev"}, false},
	{"agent skill uninstall dynamic safety", "guide.uninstall", []string{"--project"}, false},
	{"host edit --protected=false safety", "host.edit", []string{"prod", "--protected=false"}, false},
	{"database edit --protected=false safety", "conn.edit", []string{"pg-prot", "--protected=false"}, false},
	{"cache edit --protected=false safety", "conn.edit", []string{"r-prot", "--protected=false"}, false},
	{"queue edit --protected=false safety", "conn.edit", []string{"q-prot", "--protected=false"}, false},
	{"storage edit --protected=false safety", "conn.edit", []string{"s3-prot", "--protected=false"}, false},
	{"registry edit --protected=false safety", "conn.edit", []string{"reg-prot", "--protected=false"}, false},
	{"cluster edit --protected=false safety", "conn.edit", []string{"k8s-prot", "--protected=false"}, false},
	{"floor", "conn.edit", []string{"pg", "--notes", "x"}, false},
	{"floor", "conn.rm", []string{"pg"}, false},
	{"floor", "conn.rename", []string{"pg", "pg9"}, false},
	{"credential password remove dangerous", "secret.rm", []string{"pw"}, false},
	{"credential token remove dangerous", "secret.rm", []string{"pw"}, false},
	{"floor", "secret.rename", []string{"pw", "pw2"}, false},
	{"floor", "secret.set", []string{"pw3", "--from-env", "PW"}, false},
	{"copy --sync --delete dangerous", "sync", []string{"dev:/tmp/a", "b", "--delete"}, false},
	{"floor", "sync", []string{"dev:/tmp/a", "b"}, false},
	{"floor", "cp", []string{"dev:/tmp/a", "b"}, false},
	{"floor", "upload", []string{"dev", "a.txt", "/tmp/"}, false},
	{"floor", "download", []string{"dev", "/tmp/a", "--to", "."}, false},
	{"floor", "storage.upload", []string{"s3", "a.txt"}, false},
	{"floor", "storage.download", []string{"s3", "a.txt"}, false},
	{"vpn edit --protected=false safety", "vpn.edit", []string{"wg-prot", "--protected=false"}, false},
	// person
	{"config approval-code person", "config.approval-code", nil, false},
	{"config vault passphrase person", "secret.passphrase", nil, false},
	{"config vault keychain not --off person", "secret.keychain", nil, false},
	{"host shell person", "shell", []string{"dev"}, false},
	{"database shell person", "db.shell", []string{"pg"}, false},
	{"cluster shell person", "cluster.shell", []string{"k8s", "pod/a"}, false},
	{"credential certificate add person", "host.ca.add", []string{"ca1", "--key", "ca.pub", "--hosts", "*.corp.example"}, false},
	{"host ssh trust --reset person", "host.trust", []string{"prod", "--reset"}, false},
	{"export --sealed person", "export", []string{"--sealed", "--to", "out.kmd"}, false},
	{"export --for-phone person", "export", []string{"--for-phone", "--to", "out.kmd"}, false},
	// change rows
	{"group remove change", "group.rm", []string{"g1"}, false},
	// the floor: a leaf that changes something, run with no row applying
	{"floor", "cache.add", []string{"c2", "redis://127.0.0.1:1"}, false},
	{"floor", "cache.run", []string{"r", "--", "GET", "k"}, false},
	{"floor", "cluster.exec", []string{"k8s", "pod/a", "--", "ls"}, false},
	{"floor", "cluster.forward", []string{"k8s", "svc/a", "18080:80"}, false},
	{"floor", "cluster.run", []string{"k8s", "--", "get", "pods"}, false},
	{"floor", "config.set", []string{"parallel", "4"}, false},
	{"floor", "db.add", []string{"pg2", "postgres://u@127.0.0.1:1/app"}, false},
	{"floor", "db.query", []string{"pg", "SELECT 1"}, false},
	{"floor", "exec", []string{"dev", "--", "touch /tmp/x"}, false},
	{"floor", "exec", []string{"prod", "--", "touch /tmp/x"}, true},
	{"floor", "group.add", []string{"g2", "dev"}, false},
	{"floor", "group.rename", []string{"g1", "g3"}, false},
	{"floor", "guide.install", []string{"--project"}, false},
	{"floor", "guide.uninstall", nil, false},
	{"floor", "host.add", []string{"h2", "--address", "10.0.0.8"}, false},
	{"floor", "host.edit", []string{"dev", "--notes", "x"}, false},
	{"floor", "host.edit", []string{"prod", "--notes", "x"}, false}, // komando's own list: not stopped on a protected host
	{"floor", "host.rename", []string{"dev", "dev2"}, false},
	{"floor", "host.rm", []string{"dev"}, false},
	{"floor", "host.rm", []string{"prod"}, true},
	{"floor", "host.trust", []string{"prod"}, false},
	{"floor", "import", []string{"ssh-config", "ssh_config"}, false},
	{"floor", "key.deploy", []string{"k1", "dev"}, false},
	{"floor", "key.edit", []string{"k1", "--passphrase-ref", "secret:pw"}, false},
	{"floor", "key.gen", []string{"k3"}, false},
	{"floor", "key.rename", []string{"k1", "k4"}, false},
	{"floor", "key.revoke", []string{"k1", "dev"}, false},
	{"floor", "key.rm", []string{"k1"}, false},
	{"floor", "policy.deny", []string{"curl evil"}, false},
	{"floor", "queue.add", []string{"q2", "nats://127.0.0.1:1"}, false},
	{"floor", "queue.create", []string{"q", "t1"}, false},
	{"floor", "queue.send", []string{"q", "t1", "--value", "hello"}, false},
	{"floor", "recipe.add", []string{"r2", "uptime"}, false},
	{"floor", "recipe.rm", []string{"r1"}, false},
	{"floor", "recipe.run", []string{"r1", "dev"}, false},
	{"floor", "registry.add", []string{"reg2", "registry://127.0.0.1:1"}, false},
	{"registry add dynamic safety", "registry.add", []string{"reg3", "registry://127.0.0.1:1?tls=false"}, false},
	{"floor", "registry.copy", []string{"reg:app:1", "reg:app:2"}, false},
	{"credential run dynamic safety", "secret.run", []string{"--env", "X=secret:pw", "--", "true"}, false},
	{"floor", "ssh-gate.line", []string{"--name", "phone", "ca.pub"}, false},
	{"floor", "storage.add", []string{"s4", "s3://key@bucket/p?endpoint=http://127.0.0.1:1"}, false},
	{"storage object link dynamic safety", "storage.link", []string{"s3", "a.txt"}, false},
	{"floor", "storage.mkdir", []string{"s3", "dir/"}, false},
	{"floor", "storage.mv", []string{"s3", "a.txt", "b.txt"}, false},
	{"floor", "tunnel.start", []string{"dev", "-L", "15432:localhost:5432"}, false},
	{"floor", "vpn.add", []string{"v2", "socks", "--proxy-address", "127.0.0.1:1082"}, false},
	{"floor", "vpn.down", []string{"wg"}, false},
	{"floor", "vpn.edit", []string{"wg", "--notes", "x"}, false},
	{"floor", "vpn.rename", []string{"wg", "wg9"}, false},
	{"floor", "vpn.rm", []string{"wg"}, false},
	{"floor", "vpn.up", []string{"wg"}, false},
	{"floor", "key.add", []string{"k5", "id_k5"}, false},
	{"credential key uninstall dynamic dangerous", "key.revoke", []string{"k6", "kh"}, false},
	{"import dynamic dangerous", "import", []string{"ssh-config", "ssh_config_rm"}, false},
	{"import dynamic safety", "import", []string{"ssh-config", "ssh_config_nc"}, false},
}

// endNotYet: --end lands with #503 (C325), whose end of a session calls no
// guard yet (Audit A-503-4). tierRunsWhenBuilt holds its runs: they switch
// on by themselves once today's command has --end.
const endNotYet = "--end lands with #503; its runs wait in tierRunsWhenBuilt"

// tierRunsWhenBuilt are runs of a flag today's command does not have yet.
// Once the flag exists, each must run: the test fails until it moves to
// tierRuns and its tierUnreached line goes.
var tierRunsWhenBuilt = []tierRun{
	{"host ssh test --end change", "host.test", []string{"dev", "--end"}, false},
	{"test --end change", "test", []string{"--end"}, false},
}

// tierUnreached are the rows and floors this test cannot run, by name
// and today's ID, with the reason and where the stop is proved instead.
var tierUnreached = map[string]string{
	// leaves with no path today: C gives them one, and this test then runs them
	"floor | (no path today)": "no path today (credential token rename)",
	// only sync has --delete today; copy --sync --delete is run as sync above
	"copy --sync --delete dangerous | cp":               "only sync has --delete today (run as sync)",
	"copy --sync --delete dangerous | upload":           "only sync has --delete today (run as sync)",
	"copy --sync --delete dangerous | download":         "only sync has --delete today (run as sync)",
	"copy --sync --delete dangerous | storage.upload":   "only sync has --delete today (run as sync)",
	"copy --sync --delete dangerous | storage.download": "only sync has --delete today (run as sync)",
	// flags that arrive in the cut
	"host ssh exec --stop change | exec":     "--stop arrives with exec sessions (cut step D2); today it is job kill",
	"host ssh exec --remove change | exec":   "--remove arrives with exec sessions (cut step D2); today it is job rm",
	"host ssh test --end change | host.test": endNotYet,
	"test --end change | test":               endNotYet,
	// the condition needs what a unit run cannot give; the stop is proved there
	"host ssh test dynamic person | host.test":               "needs a server that asks a second factor",
	"import dynamic person | import":                         "needs a sealed file from export --sealed, which only a person makes",
	"ssh-gate person | ssh-gate":                             "sshd starts it for a key; an agent never runs ssh-gate itself",
	"update dynamic safety | update":                         "needs a release site",
	"floor | update":                                         "needs a release site",
	"config vault keychain dynamic safety | secret.keychain": "tests run with KOMANDO_KEYCHAIN=off",
	"floor | secret.keychain":                                "tests run with KOMANDO_KEYCHAIN=off; a plain run is the not --off person row",
	"floor | host.ca.rm":                                     "adding the CA it removes needs a person",
	"floor | tunnel.stop":                                    "no stop for an agent: change on an unprotected target",
	"floor | cluster.add":                                    "a Kubernetes conn comes only from import kubeconfig; a swarm is no conn kind",
	"floor | secret.run":                                     "an agent always meets the row: secret run always hands a secret on",
	"floor | storage.link":                                   "an agent always meets the row: a link is always --reveal for an agent",
	"floor | queue.purge":                                    "today's queue purge is v2.7's message delete --all: its run is that row",
}

// tierDisagree are the runs whose stop is not the one the tier names, with
// the stop they give. Each was sent to the CLI coordinator (C418 B4a); the
// stricter side holds until it is decided. A run that agrees again fails
// until its line goes.
var tierDisagree = map[string]string{
	// the same strength under another code (C429: one code later)
	"host.edit prod --protected=false":     "PROTECTED_TARGET", // vpn edit gives SAFETY_SETTING
	"conn.edit pg-prot --protected=false":  "PROTECTED_TARGET",
	"conn.edit r-prot --protected=false":   "PROTECTED_TARGET",
	"conn.edit q-prot --protected=false":   "PROTECTED_TARGET",
	"conn.edit s3-prot --protected=false":  "PROTECTED_TARGET",
	"conn.edit reg-prot --protected=false": "PROTECTED_TARGET",
	"conn.edit k8s-prot --protected=false": "PROTECTED_TARGET",
	// --dry-run shows no stop; the real run stops (its own test proves it)
	"host.ca.add ca1 --key ca.pub --hosts *.corp.example": "", // host_ca.go returns the preview before its NEEDS_PERSON
	"host.trust dev":                  "", // guardFirstPin runs after the dry run returned
	"import ssh-config ssh_config_rm": "", // the real run leaves the host out (IMPORT_INCOMPLETE)
	"import ssh-config ssh_config_nc": "", // the real run leaves the host out (IMPORT_INCOMPLETE)
}

// tierProof is the test that asserts a stop without --dry-run.
type tierProof struct {
	test string // the test function
	via  string // the table variable it runs, when the case sits there
	cmd  string // the command it runs, when not the one of the key
	stop string // the code it asserts, when not the one the tier names
}

// tierProvedBy names, for each run pinned with no stop under --dry-run and
// each unreached row whose stop a run can meet, the test that asserts that
// stop without --dry-run (Audit's lows on #550). tierProofsExist checks
// that the test exists and that its body (with the table it runs) names
// the command and the code.
var tierProvedBy = map[string]tierProof{
	"host.ca.add ca1 --key ca.pub --hosts *.corp.example": {test: "TestHostCAAddNeedsAPerson"},
	"host.trust dev":                                         {test: "TestStandardConfirmTable", via: "agentStops"},
	"import ssh-config ssh_config_rm":                        {test: "TestImportSSHConfigProxyCommandAgent", stop: "IMPORT_INCOMPLETE"}, // the host is left out
	"import ssh-config ssh_config_nc":                        {test: "TestImportSSHConfigProxyCommandAgent", stop: "IMPORT_INCOMPLETE"},
	"host ssh test dynamic person | host.test":               {test: "TestLoginKeepsATwoFactorLogin", cmd: "login"},
	"import dynamic person | import":                         {test: "TestSealedNeedsPerson"},
	"update dynamic safety | update":                         {test: "TestUpdateOlderAgentNeedsWindow"},
	"floor | update":                                         {test: "TestUpdateInstallsNewest"},
	"config vault keychain dynamic safety | secret.keychain": {test: "TestSecretKeychainOff"},
	"floor | secret.keychain":                                {test: "TestSecretKeychainNeedsPerson"},
	"floor | host.ca.rm":                                     {test: "TestHostCAPersonAddsAndAnyoneRemoves"},
	"floor | cluster.add":                                    {test: "TestClusterAddKind"},
}

func TestTierMatchesRuntime(t *testing.T) {
	if testing.Short() {
		t.Skip("runs every command above read")
	}
	covered := map[string]bool{}
	for _, r := range tierRuns {
		covered[r.row+" | "+r.id] = true
	}
	needed := tierNeeded()
	tierProofsExist(t)
	for _, r := range tierRuns {
		if _, ok := needed[r.row+" | "+r.id]; !ok {
			t.Errorf("run %q | %s proves no row the table has for that command: remove or rename it", r.row, r.id)
		}
	}
	for need := range tierUnreached {
		if _, ok := needed[need]; !ok {
			t.Errorf("tierUnreached %q names no row the table has: remove it", need)
		}
	}
	for need, why := range needed {
		if !covered[need] && tierUnreached[need] == "" {
			t.Errorf("%s (%s): no run and no reason in tierUnreached", need, why)
		}
	}
	root := newRoot(tcl)
	for _, r := range tierRunsWhenBuilt {
		c, _, err := root.Find(strings.Split(r.id, "."))
		flag := r.args[len(r.args)-1][2:]
		if err == nil && c.Flags().Lookup(flag) != nil {
			t.Errorf("%s now has --%s: move %q from tierRunsWhenBuilt to tierRuns and drop its tierUnreached line", r.id, flag, r.row)
		}
	}
	for _, r := range tierRuns {
		name := r.id + " " + strings.Join(r.args, " ")
		t.Run(name, func(t *testing.T) {
			want := tierStop(r)
			args := append([]string{"--dry-run", "-o", "json"}, strings.Split(r.id, ".")...)
			stdout, _, _ := goldenRunWith(t, true, append(args, r.args...), tierSeed)
			got := runStop(stdout)
			if slices.Contains(tierStopAlso[want], got) {
				got = want // the same stop under its handler's code
			}
			if e := runErr(stdout); e == "USAGE" || strings.HasSuffix(e, "_NOT_FOUND") {
				t.Fatalf("the command never reached its checks (%s):\n%s", e, stdout)
			}
			if d, ok := tierDisagree[name]; ok {
				if got == want {
					t.Errorf("the table and the handler agree now (%q): remove the tierDisagree line", got)
				} else if got != d {
					t.Errorf("stop %q, want %q (tierDisagree says %q)", got, want, d)
				}
				return
			}
			if got != want {
				t.Errorf("row %q: stop %q, want %q", r.row, got, want)
			}
		})
	}
}

// tierProofsExist: every run pinned with no stop has a named proof, no
// reason points at a file instead of a function, and every named test
// function exists.
func tierProofsExist(t *testing.T) {
	for run, code := range tierDisagree {
		if _, ok := tierProvedBy[run]; code == "" && !ok {
			t.Errorf("%q shows no stop under --dry-run: name the test that asserts its stop in tierProvedBy", run)
		}
	}
	for need, why := range tierUnreached {
		if strings.Contains(why, "_test.go") {
			t.Errorf("tierUnreached %q names a file: name the test function in tierProvedBy", need)
		}
	}
	files, _ := filepath.Glob("*_test.go")
	var src strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	for key, pr := range tierProvedBy {
		_, pinned := tierDisagree[key]
		if _, unreached := tierUnreached[key]; !pinned && !unreached {
			t.Errorf("tierProvedBy %q names no pinned run or unreached row: remove it", key)
		}
		body := goBlock(src.String(), "func "+pr.test+"(t *testing.T)")
		if body == "" {
			t.Errorf("tierProvedBy %q: no test function %s", key, pr.test)
			continue
		}
		cmd, stop := tierProofWant(key, pr)
		if pr.via != "" {
			table := goBlock(src.String(), "var "+pr.via+" = ")
			if table == "" || !strings.Contains(body, pr.via) {
				t.Errorf("tierProvedBy %q: %s does not run a table %s", key, pr.test, pr.via)
			}
			// the command and its code on one entry of the table
			if !tableHasCase(table, cmd, stop) {
				t.Errorf("tierProvedBy %q: no entry of %s runs %q and asserts %s", key, pr.via, cmd, stop)
			}
			continue
		}
		if !runsCmd(body, cmd) {
			t.Errorf("tierProvedBy %q: %s does not run %q", key, pr.test, cmd)
		}
		if stop != "" && !strings.Contains(body, `"`+stop+`"`) {
			t.Errorf("tierProvedBy %q: %s does not assert %s", key, pr.test, stop)
		}
	}
}

// runsCmd: text names every word of cmd quoted, or the whole phrase.
func runsCmd(text, cmd string) bool {
	if strings.Contains(text, cmd) {
		return true
	}
	for _, w := range strings.Fields(cmd) {
		if !strings.Contains(text, `"`+w+`"`) {
			return false
		}
	}
	return true
}

// tableHasCase: one entry of a table literal (a composite literal that
// starts a line at one tab) runs cmd and names stop.
func tableHasCase(table, cmd, stop string) bool {
	var entries []string
	for _, line := range strings.Split(table, "\n") {
		if strings.HasPrefix(line, "\t{") || len(entries) == 0 {
			entries = append(entries, line)
			continue
		}
		entries[len(entries)-1] += "\n" + line
	}
	for _, e := range entries[1:] {
		if runsCmd(e, cmd) && (stop == "" || strings.Contains(e, `"`+stop+`"`)) {
			return true
		}
	}
	return false
}

// TestTableHasCase: the command and its code must sit on the same entry.
func TestTableHasCase(t *testing.T) {
	table := "var cases = []c{\n" +
		"\t{args: []string{\"host\", \"trust\", \"web1\"}, code: \"POLICY_BLOCKED\"},\n" +
		"\t{args: []string{\"policy\", \"rm\", \"x\"},\n\t\tcode: \"SAFETY_SETTING\"},\n"
	tests := []struct {
		name, cmd, stop string
		want            bool
	}{
		{"code on another entry", "host trust", "SAFETY_SETTING", false},
		{"same entry", "host trust", "POLICY_BLOCKED", true},
		{"entry over two lines", "policy rm", "SAFETY_SETTING", true},
		{"no such command", "host shell", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tableHasCase(table, tt.cmd, tt.stop); got != tt.want {
				t.Errorf("tableHasCase(%q, %q) = %v, want %v", tt.cmd, tt.stop, got, tt.want)
			}
		})
	}
}

// tierProofWant is the command a proof must run and the code it must
// assert: from the key (a pinned run, or "row | ID") unless the proof says.
func tierProofWant(key string, pr tierProof) (cmd, stop string) {
	if row, id, ok := strings.Cut(key, " | "); ok {
		cmd, stop = strings.ReplaceAll(id, ".", " "), tierStop(tierRun{row: row})
	} else {
		id := strings.Fields(key)[0]
		cmd = strings.ReplaceAll(id, ".", " ")
		for _, r := range tierRuns {
			if r.id+" "+strings.Join(r.args, " ") == key {
				stop = tierStop(r)
			}
		}
	}
	if pr.cmd != "" {
		cmd = pr.cmd
	}
	if pr.stop != "" {
		stop = pr.stop
	}
	return cmd, stop
}

// goBlock is the Go source from head to the end of its block (a line that
// is only "}" or ")"), or "".
func goBlock(src, head string) string {
	i := strings.Index(src, head)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if j := strings.Index(rest, "\n}\n"); j >= 0 {
		return rest[:j]
	}
	return rest
}

// tierStopAlso are other codes that are the stop of a tier: the same stop
// under the code its handler gives (chief, 2026-11-25: C428 for
// NEEDS_TERMINAL and OPEN_BIND, C431 for SECRET_DESTINATION and
// SENSITIVE_FILE).
var tierStopAlso = map[string][]string{
	"NEEDS_PERSON":   {"NEEDS_TERMINAL"},
	"SAFETY_SETTING": {"OPEN_BIND", "SECRET_DESTINATION", "SENSITIVE_FILE"},
}

// tierStop is the stop a run's tier names.
func tierStop(r tierRun) string {
	words := strings.Fields(r.row)
	switch words[len(words)-1] {
	case "dangerous":
		return "POLICY_BLOCKED"
	case "safety":
		return "SAFETY_SETTING"
	case "person":
		return "NEEDS_PERSON"
	}
	if r.protected {
		return "PROTECTED_TARGET"
	}
	return ""
}

// tierNeeded is every (row or floor, today ID) the table says is above
// read, keyed as tierRuns and tierUnreached name it.
func tierNeeded() map[string]string {
	need := map[string]string{}
	for _, l := range capability.All() {
		if l.State != capability.Built || capability.Highest(l.Key) == capability.Read {
			continue
		}
		ids := l.Today // a leaf with no command of its own is run as the one it carries
		if len(ids) == 0 {
			ids = l.Carries
		}
		if len(ids) == 0 {
			ids = []string{"(no path today)"}
		}
		always := false // a row with no condition decides the base instead of the floor
		for _, r := range capability.Rows(l.Key) {
			always = always || (len(r.When.Flags) == 0 && len(r.When.Words) == 0 && !r.When.Not && r.Dynamic == "")
			if r.Tier == capability.Read {
				continue
			}
			for _, id := range ids {
				need[tierRowName(r)+" | "+id] = l.Key.String()
			}
		}
		if !always && capability.Base(l.Key) > capability.Read {
			for _, id := range ids {
				need["floor | "+id] = l.Key.String()
			}
		}
	}
	return need
}

// tierRowName names a row: its words, its condition and its tier.
func tierRowName(r capability.TierRow) string {
	n := r.Key.String()
	for i, f := range r.When.Flags {
		switch {
		case r.When.Not:
			n += " not --" + f
		case i == 0 && r.When.Value != "":
			n += " --" + f + "=" + r.When.Value
		default:
			n += " --" + f
		}
	}
	for _, w := range r.When.Words {
		n += " " + w
	}
	if r.Dynamic != "" {
		n += " dynamic"
	}
	return n + " " + [...]string{"read", "change", "protected", "dangerous", "safety", "person"}[r.Tier]
}

// runStop is the stop a run reports: meta.would_be_blocked's code, else
// the code of a policy error a command gives even under --dry-run.
func runStop(stdout string) string {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var env struct {
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
		Meta struct {
			Blocked *struct {
				Code string `json:"code"`
			} `json:"would_be_blocked"`
		} `json:"meta"`
	}
	_ = json.Unmarshal([]byte(lines[len(lines)-1]), &env)
	switch {
	case env.Meta.Blocked != nil:
		return env.Meta.Blocked.Code
	case env.Error != nil && slices.Contains(policyStopCodes, env.Error.Code):
		return env.Error.Code
	}
	return ""
}

// runErr is the code of the error a run ends with, or "".
func runErr(stdout string) string {
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var env struct {
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal([]byte(lines[len(lines)-1]), &env)
	if env.Error == nil {
		return ""
	}
	return env.Error.Code
}

// policyStopCodes are the codes of the stops a tier can name or meet.
var policyStopCodes = []string{"NEEDS_PERSON", "NEEDS_TERMINAL", "POLICY_BLOCKED", "SAFETY_SETTING",
	"PROTECTED_TARGET", "WRITE_REQUIRES_FLAG", "CONFIRM_REQUIRED", "OPEN_BIND", "SSH_GATE_REFUSED"}

// tierSeed fills the home: hosts dev and prod (protected, its key pinned)
// on a fake SSH server, one conn or VPN of each kind a run names, and the
// secret, key, snippets, group and deny rule the runs remove.
func tierSeed(t *testing.T) {
	t.Chdir(t.TempDir())
	startFakeServer(t)
	// prod on a server of its own: komando takes two names of one server
	// as one, so dev would be protected too
	prodPort := listenFakeSSH(t)
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["prod"].Port = prodPort
		st.Conns["pg"] = &store.Conn{Name: "pg", Kind: "postgres", URL: "postgres://u@127.0.0.1:1/app"}
		st.Conns["pg-prot"] = &store.Conn{Name: "pg-prot", Kind: "postgres", URL: "postgres://u@127.0.0.1:2/app", Protected: true}
		st.Conns["r-prot"] = &store.Conn{Name: "r-prot", Kind: "redis", URL: "redis://127.0.0.1:3", Protected: true}
		st.Conns["q-prot"] = &store.Conn{Name: "q-prot", Kind: "nats", URL: "nats://127.0.0.1:3", Protected: true}
		st.Conns["s3-prot"] = &store.Conn{Name: "s3-prot", Kind: "s3", URL: "s3://key@bucket2/p?endpoint=http://127.0.0.1:3", Protected: true}
		st.Conns["reg-prot"] = &store.Conn{Name: "reg-prot", Kind: "registry", URL: "registry://127.0.0.1:3?tls=false", Protected: true}
		st.Conns["k8s-prot"] = &store.Conn{Name: "k8s-prot", Kind: "k8s", URL: "k8s://127.0.0.1:3", Protected: true}
		st.Conns["r"] = &store.Conn{Name: "r", Kind: "redis", URL: "redis://127.0.0.1:1"}
		st.Conns["s3"] = &store.Conn{Name: "s3", Kind: "s3", URL: "s3://key@bucket/p?endpoint=http://127.0.0.1:1"}
		st.Conns["q"] = &store.Conn{Name: "q", Kind: "nats", URL: "nats://127.0.0.1:1"}
		st.Conns["reg"] = &store.Conn{Name: "reg", Kind: "registry", URL: "registry://127.0.0.1:1?tls=false"}
		st.Conns["k8s"] = &store.Conn{Name: "k8s", Kind: "k8s", URL: "k8s://127.0.0.1:1"}
		st.Vpns["wg"] = &store.Vpn{Name: "wg", Kind: "socks", Address: "127.0.0.1:1080", MFA: true}
		st.Vpns["wg-prot"] = &store.Vpn{Name: "wg-prot", Kind: "socks", Address: "127.0.0.1:1081", Protected: true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PW", "secret-value-1")
	mustRun(t, "secret", "set", "pw", "--from-env", "PW")
	mustRun(t, "key", "gen", "k1")
	mustRun(t, "key", "gen", "k6")
	mustRun(t, "recipe", "add", "wipe", "rm -rf /")
	mustRun(t, "recipe", "add", "r1", "uptime")
	mustRun(t, "group", "add", "g1", "dev")
	mustRun(t, "policy", "deny", "kubectl apply")
	mustRun(t, "guide", "install", "--project")
	mustRun(t, "host", "trust", "prod", "--yes")
	mustRun(t, "config", "set", "host_key_policy", "strict")
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	_ = os.WriteFile("ca.pub", ssh.MarshalAuthorizedKey(sp), 0o600)
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	_ = os.WriteFile("id_k5", pem.EncodeToMemory(blk), 0o600)
	_ = os.WriteFile("ssh_config", []byte("Host imp1\n  HostName 10.0.0.5\n"), 0o600)
	_ = os.WriteFile("ssh_config_rm", []byte("Host imp2\n  HostName 10.0.0.6\n  ProxyCommand rm -rf /\n"), 0o600)
	_ = os.WriteFile("ssh_config_nc", []byte("Host imp3\n  HostName 10.0.0.7\n  ProxyCommand nc %h %p\n"), 0o600)
	// kh logs in with k6: revoking k6 there locks komando out
	if err := store.Update(store.Save(), func(st *store.State) error {
		st.Hosts["kh"] = &store.Host{Name: "kh", Address: "127.0.0.1", Port: 1, User: "deploy", Key: "k6"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile("a.txt", []byte("a\n"), 0o600)
	_ = os.WriteFile("dump.sql", []byte("select 1;\n"), 0o600)
}

// listenFakeSSH starts one more fake SSH server and gives its port.
func listenFakeSSH(t *testing.T) int {
	t.Helper()
	_, hostKey, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &fakeServer{port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, cfg)
		}
	}()
	return s.port
}
