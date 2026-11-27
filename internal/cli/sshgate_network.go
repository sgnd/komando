package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/version"
)

// gateKey is what an ssh-gate key may do, from its authorized_keys line,
// and whether sshd gave this call of it a terminal.
type gateKey struct {
	readOnly    bool // --read-only: only commands that read
	network     bool // reads that reach the network too (always, for a full key)
	shellAccess bool // --shell-access: also a login shell on one server (sshgate_shell.go)
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
	"list": nil, "test": nil, "logs": nil, "export": nil, "download": nil, "ssh-gate.status": nil,
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
	"job": nil, "job.list": nil, "job.logs": nil, "job.status": nil, "job.wait": nil,
	"key": nil, "key.list": nil, "key.show": nil,
	"pkg": nil, "pkg.installed": nil, "pkg.security": nil, "pkg.upgradable": nil,
	"policy": nil, "policy.check": nil, "policy.list": nil, "policy.show": nil,
	"snippet": nil, "recipe.list": nil, "snippet.show": nil,
	"registry": nil, "registry.inspect": nil, "registry.list": nil,
	"secret": nil, "secret.list": nil, "secret.show": nil,
	"storage": nil, "storage.cat": nil, "storage.download": nil, "storage.list": nil,
	"tunnel": nil, "tunnel.list": nil,
	"vpn": nil, "vpn.list": nil, "vpn.show": nil, "vpn.status": nil, "vpn.test": nil,
}

// gateNetwork are the reads that may reach a place the key names, and why.
var gateNetwork = map[string]string{
	"exec":         "it runs a program of your choosing, which can connect anywhere",
	"job.start":    "it runs a program of your choosing, which can connect anywhere",
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
	return "key " + s.Name + ": " + mode + " (komando " + s.Komando + ")\n"
}

func sshGateStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Say which ssh-gate key runs this, and what it may do",
		Long: `Through an SSH key that ssh-gate limits, prints the key's name and what it
may do: change things, or read only, whether its reads may reach the
network (--network on its line), and whether it may open a login shell on
a server (--shell-access on its line). ssh-gate answers it itself, so an app
can check what its key is before it sends anything else. Typed on the
komando computer, it says the command did not come through a key.`,
		Example: "  ssh HOST komando ssh-gate status -o json\n  komando ssh-gate status",
		Args:    cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			cl.out.Print("ssh-gate.status", gateStatus{Network: true, Komando: version.Version}, nil)
			return nil
		}),
	}
}
