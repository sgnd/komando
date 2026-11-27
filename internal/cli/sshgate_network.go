package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/cli/kit/gatehere"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/version"
)

// gateKey is what an ssh-gate key may do, from its authorized_keys line,
// and whether sshd gave this call of it a terminal.
type gateKey struct {
	readOnly    bool // --read-only: only commands that read
	network     bool // reads that reach the network too (always, for a full key)
	shellAccess bool // --shell-access: also a login shell on one server (sshgate_shell.go)
	here        bool // --here: server mode, the key runs komando on this server itself
	tty         bool // the call has the terminal sshd gives a --shell-access line (gateTTY)
}

// A read key (--read-only) without --network runs only the reads that stay
// on the servers and conns a person put in the inventory. Reaching the
// network is no write, but it is a way out: `cert check
// https://HOST` (dialed from this computer) or `exec --read-only -- curl`
// carry what the key reads to any host, in a URL or a DNS name. So the rule
// fails closed: a read runs only when gateNoNetwork names it, and a command
// added later is refused until someone decides it reaches only known
// targets (TestGateNetworkClassified makes every reachable read be in one
// of the two lists). SQL and cache commands that reach another server
// (dblink, COPY TO PROGRAM, url(), MIGRATE ...) are writes already: db query
// and cache redis raw need --write for them, which no read key has.

// gateNoNetwork are the reads a no-network read key runs: komando's own
// reads of targets in the inventory (gateLocalTarget refuses a target not in
// it), or of komando's own records. A func says why the command as given
// reaches a place the key names, or "".
var gateNoNetwork = map[string]func(c *cobra.Command) string{
	"audit": nil, "audit.verify": nil, "version": nil, "status": nil, "schema": nil, "guide": nil, "doctor": nil,
	"list": nil, "test": nil, "logs": nil, "export": nil, "copy": nil, "ssh-gate.status": nil,
	"cache": nil, "cache.get": nil, "cache.info": nil, "cache.keys": nil, "cache.run": nil,
	"queue": nil, "queue.describe": nil, "queue.groups": nil, "queue.info": nil, "queue.lag": nil, "queue.list": nil, "queue.peek": nil,
	"cert": nil, "cert.check": gateCertURL,
	"cluster": nil, "cluster.describe": nil, "cluster.events": nil, "cluster.get": nil, "cluster.helm": nil,
	"cluster.helm.history": nil, "cluster.helm.list": nil, "cluster.helm.status": nil, "cluster.helm.values": nil,
	"cluster.history": nil, "cluster.list": nil, "cluster.logs": nil, "cluster.run": nil, "cluster.status": nil,
	"config": nil, "config.get": nil, "config.show": nil,
	"conn": nil, "conn.kinds": nil, "conn.list": nil, "conn.show": nil, "conn.test": nil,
	"db": nil, "db.activity": nil, "db.dump": nil, "db.explain": nil, "db.info": nil, "db.locks": nil, "db.query": nil,
	"db.schema": nil, "db.sizes": nil, "db.user": nil, "db.user.list": nil, "db.user.show": nil,
	"docker": nil, "docker.images": nil, "docker.inspect": nil, "docker.logs": nil, "docker.ps": nil, "docker.stats": nil,
	"fs": nil, "fs.cat": nil, "fs.list": nil, "fs.stat": nil,
	"group": nil, "group.list": nil, "group.show": nil,
	"host": nil, "host.ca": nil, "host.ca.list": nil, "host.list": nil, "host.show": nil, "host.ssh-command": nil, "host.test": nil,
	"key": nil, "key.list": nil, "key.show": nil,
	"pkg": nil, "pkg.installed": nil, "pkg.security": nil, "pkg.upgradable": nil,
	"policy": nil, "policy.check": nil, "policy.list": nil, "policy.show": nil,
	"snippet": nil, "recipe.list": nil, "snippet.show": nil,
	"registry": nil, "registry.inspect": nil, "registry.list": nil,
	"secret": nil, "secret.list": nil, "secret.show": nil,
	"storage": nil, "storage.cat": nil, "storage.list": nil,
	"tunnel": nil, "tunnel.list": nil,
	"vpn": nil, "vpn.list": nil, "vpn.show": nil, "vpn.status": nil, "vpn.test": nil,
}

// gateNetwork are the reads that may reach a place the key names, and why.
var gateNetwork = map[string]string{
	"exec":         "it runs a program of your choosing, which can connect anywhere",
	"docker.exec":  "it runs a program of your choosing in a container, which can connect anywhere",
	"cluster.exec": "it runs a program of your choosing in a pod, which can connect anywhere",
	"recipe.run":   "a recipe is a shell command with blanks you fill in, which can connect anywhere",
}

// gateEgress says why a read key without --network may not run c, or "".
func gateEgress(c *cobra.Command, name string) string {
	if top, _, _ := strings.Cut(name, "."); c == c.Root() || top == "help" || top == "completion" {
		return "" // first steps, help and shell completion scripts: printed
	}
	if f, ok := gateNoNetwork[name]; ok {
		if f != nil {
			return f(c)
		}
		return ""
	}
	if why := gateNetwork[name]; why != "" {
		return why
	}
	return "komando does not know that it stays on the servers and conns in your list"
}

// gateCertURL: cert check of a website (a URL or HOST:PORT that names no
// server or conn) connects from the komando computer to that place.
func gateCertURL(c *cobra.Command) string {
	st, err := store.Load()
	if err != nil {
		return "your list of servers and conns could not be read"
	}
	for _, a := range c.Flags().Args() {
		if addr, _, ok, _ := parseCertURL(st, a); ok {
			return "it connects from the komando computer to " + addr + ", which is no server or conn in your list"
		}
	}
	return ""
}

// gateStatus is what `ssh-gate status` prints: which key the caller holds
// and what it may do.
type gateStatus struct {
	Gate        bool   `json:"gate"`         // the command came through ssh-gate
	Name        string `json:"name"`         // the key's --name ("" when not through a key)
	ReadOnly    bool   `json:"read_only"`    // only commands that read
	Network     bool   `json:"network"`      // reads that reach the network too
	ShellAccess bool   `json:"shell_access"` // a login shell on one server too
	Here        bool   `json:"here"`         // server mode: komando acts on this server only
	Komando     string `json:"komando"`      // komando's version
}

func (s gateStatus) Text() string {
	if !s.Gate {
		return "not through ssh-gate: komando runs here as for anyone at this computer\n"
	}
	mode := "may change things"
	switch {
	case s.ReadOnly && s.Network:
		mode = "read only, network checks allowed"
	case s.ReadOnly:
		mode = "read only, no network"
	case s.ShellAccess:
		mode = "may change things and open a shell on a server"
	}
	if s.Here {
		mode += ", on this server only"
	}
	return "key " + s.Name + ": " + mode + " (komando " + s.Komando + ")\n"
}

func sshGateStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Say which ssh-gate key runs this, and what it may do",
		Long: `Through an SSH key that ssh-gate limits, prints the key's name and what it
may do: change things, or read only, whether its reads may reach the
network (--network on its line), and whether it may open a login shell on
a server (--shell-access on its line), and whether it acts on this server
only (here: a phone's key on a server, see credential key install --public-key-file).
ssh-gate answers it itself, so an app can check what its key is before it
sends anything else. Typed on the
komando computer, it says the command did not come through a key.`,
		Example: "  ssh HOST komando ssh-gate status -o json\n  komando ssh-gate status",
		Args:    cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			cl.out.Print("ssh-gate.status", gateStatus{Network: true, Komando: version.Version}, nil)
			return nil
		}),
	}
}

// The server mode (--here, U117) is the line `credential key install
// --public-key-file` writes for a phone's key on a server: komando there
// acts on that server itself, the one place the computer-side gate
// refuses (gateLocalTarget). Its rules, lettered as in the U107 note, are
// in internal/cli/kit/gatehere: (a) nothing through the gate writes the
// gate, the key files, a start file or komando's own files, by any name;
// (d) only readings and the typed service, package and file-read commands
// run, exec is a shell and the dangerous tier is refused; (e) the system
// log copy of each record; (f) nothing runs as root. Beside them, the read
// limit: no read of another user's home, of ~/.ssh or of komando's own
// folder. sshd, the line and parseGate give (b) and (c).

// gatePasswd is the user database the server mode reads other users'
// homes from; tests point it elsewhere.
var gatePasswd = "/etc/passwd"

// gateServerPaths are what the server mode protects, for the user the
// key logs in as.
func gateServerPaths() (gatehere.Paths, error) {
	home, err := store.AccountHome()
	if err != nil {
		return gatehere.Paths{}, err
	}
	self, err := os.Executable()
	if err != nil {
		return gatehere.Paths{}, err
	}
	if r, err := filepath.EvalSymlinks(self); err == nil {
		self = r
	}
	passwd, _ := os.ReadFile(gatePasswd) // none (macOS): the homes next to this one count
	homes := gatehere.NextTo(home)
	for n, h := range gatehere.OtherHomes(passwd, home) {
		homes[n] = h
	}
	return gatehere.Paths{Home: home, Komando: store.Home(), Self: self, Homes: homes}, nil
}

// gateServerRule is gateRule's answer in server mode, for a command c
// whose flags are read.
func gateServerRule(c *cobra.Command, name string, key gateKey) *out.Error {
	if top, _, _ := strings.Cut(name, "."); c == c.Root() || top == "help" || top == "completion" {
		return nil // first steps, help and shell completion scripts: printed
	}
	refuse := func(why string) *out.Error {
		return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person runs it on this server, or from the komando computer",
			"komando %s is refused for this server's key: %s", strings.ReplaceAll(name, ".", " "), why)
	}
	paths, err := gateServerPaths()
	if err != nil {
		return refuse("the gate cannot tell this user's home (" + err.Error() + ")")
	}
	k, _ := kindOf(c)
	writes := k.Kind != kindRead || gateSavesHere[cmdKeys[name]] != nil // a read that saves a file (download)
	for _, w := range gateServerWords(c) {
		if why := paths.WriteRefusal(w); why != "" && writes {
			// rule a, before the list: the phone's probe 5 expects this refusal
			return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person changes it on this server itself; `komando ssh-gate status` shows what this key may do",
				"komando %s is refused for this server's key: %s; no key changes it", strings.ReplaceAll(name, ".", " "), why)
		}
		if why := paths.ReadRefusal(w); why != "" {
			return refuse(why) // the read limit
		}
	}
	key3 := cmdKeys[name]
	if ok, why := gatehere.Runs(key3.typ, key3.area, key3.verb); !ok {
		return refuse(why) // rule d
	}
	for _, f := range []string{"sudo", "sudo-user"} {
		if fl := c.Flags().Lookup(f); fl != nil && fl.Changed {
			return refuse("--" + f + " is refused: a phone's key runs as the user it logs in as, never through sudo")
		}
	}
	if why := gateWrites(c, name); key.readOnly && why != "" {
		return out.Errf(out.ExitPolicy, "SSH_GATE_READ_ONLY", "this key was added with --read-only and runs only commands that read",
			"komando %s is refused for a read-only key: %s", strings.ReplaceAll(name, ".", " "), why)
	}
	for _, t := range gateUseTargets(c, c.Flags().Args()) {
		if why := gatehere.Target(t); why != "" {
			return refuse(why)
		}
	}
	if r := riskOf(c, gateRiskWords(c)); r.tier >= tierDangerous {
		return refuse("it is " + r.tier.String() + " (" + strings.TrimSpace(r.what+" "+r.dynamic) + "), and a phone's key runs no dangerous command")
	}
	return nil
}

// gateUID is the gate's own effective uid; tests set it.
var gateUID = os.Geteuid

// gateServerRoot refuses every command when the server mode runs as root
// (rule f), whatever the line says: a phone's line in root's
// authorized_keys runs nothing.
func gateServerRoot() *out.Error {
	if gateUID() != 0 {
		return nil
	}
	return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person removes this key's line from root's ~/.ssh/authorized_keys and pairs a user that is not root with `komando credential key install`",
		"this server's key logs in as root (uid 0), and the gate runs nothing as root")
}

// gateServerNotYet refuses a command the server mode allows but cannot
// run yet: komando acts on its own server only through the local
// transport (row C549), so until then the gate answers ssh-gate status
// and runs nothing else. No komando is started for the key meanwhile.
func gateServerNotYet(name string) *out.Error {
	return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "update komando on this server; this version answers `komando ssh-gate status` only",
		"komando %s is allowed for this server's key, but this komando does not run commands on its own server yet", strings.ReplaceAll(name, ".", " "))
}

// gateServerWords are the words rules a and f check as paths: every
// argument (and the PATH of TARGET:PATH) and every flag value.
func gateServerWords(c *cobra.Command) []string {
	var w []string
	for _, a := range c.Flags().Args() {
		w = append(w, a)
		if _, p, ok := strings.Cut(a, ":"); ok {
			w = append(w, p)
		}
	}
	c.Flags().Visit(func(f *pflag.Flag) {
		if s, ok := f.Value.(pflag.SliceValue); ok {
			w = append(w, s.GetSlice()...)
			return
		}
		w = append(w, f.Value.String())
	})
	return w
}

// gateRiskWords are c's words as the risk table reads them: the
// arguments, and each flag given as --name=value.
func gateRiskWords(c *cobra.Command) []string {
	w := slices.Clone(c.Flags().Args())
	c.Flags().Visit(func(f *pflag.Flag) {
		if s, ok := f.Value.(pflag.SliceValue); ok { // a list's text has brackets and quotes
			for _, v := range s.GetSlice() {
				w = append(w, "--"+f.Name+"="+v)
			}
			return
		}
		w = append(w, "--"+f.Name+"="+f.Value.String())
	})
	return w
}

// gateSystemLog sends a server-mode record to this server's system log
// too, which the paired user cannot change or remove (rule e). The
// record in komando's audit log is the one that counts: this copy is
// best effort.
var gateSystemLog = func(rec map[string]any) {
	if b, err := json.Marshal(rec); err == nil {
		_ = gatehere.SystemLog(string(b))
	}
}
