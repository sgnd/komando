package cli

import (
	"fmt"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// After a command a person ran at the terminal ends well, komando says on
// stderr what usually comes next (a formHint's next), and after a command
// it filled in, the line to type next time. `host show`, `conn show` and
// `vpn show` end with the commands that work on that item. Nothing of this
// is ever printed for an agent, a script or a pipe.

// fillInfo is what promptFill saw of this command.
type fillInfo struct {
	person   bool   // a person at a terminal (promptable)
	key      string // the command (db query)
	first    string // its first argument, usually the target
	prompted bool   // komando asked for something
	line     []string
}

var fillSeen fillInfo

// promptNext prints Next time: and Next: for a person, after a run that
// ended well.
func promptNext() {
	if !fillSeen.person || fillSeen.key == "" {
		return
	}
	if fillSeen.prompted {
		fmt.Fprintln(promptW, "Next time: komando "+menuCommandLine(fillSeen.line))
	}
	switch fillSeen.key {
	case "host show", "conn show", "vpn show":
		showCommands(fillSeen.first)
	}
	if next := formHints[fillSeen.key].next; len(next) > 0 && fillSeen.first != "" {
		lines := make([]string, len(next))
		for i, n := range next {
			lines[i] = "komando " + strings.ReplaceAll(n, "{}", fillSeen.first)
		}
		fmt.Fprintln(promptW, "Next: "+strings.Join(lines, " · "))
	}
}

// itemCommands are the commands that work on one item of a kind, {} the
// item; `host show`, `conn show` and `vpn show` list them for a person.
// They follow what the menu offered for each kind.
var itemCommands = map[string][]string{
	"server": {"facts {}", "logs {} --unit nginx --since 1h", "exec {} -- uptime", "shell {}", "svc list {}",
		"fs ls {} /etc", "docker ps {}", "pkg upgradable {}", "job start {} -- make", "host edit {}", "test {}"},
	"db": {"db info {}", "db query {} \"select 1\"", "db schema {}", "db sizes {}", "db dump {} --to backup.sql",
		"db shell {}", "db activity {}", "conn edit {}", "test {}"},
	"cache":    {"cache info {}", "cache keys {} 'user:*'", "cache get {} KEY", "cache run {} -- INFO", "conn edit {}", "test {}"},
	"queue":    {"queue info {}", "queue ls {}", "queue peek {} TOPIC", "queue lag {} GROUP", "queue send {} TOPIC --value hi", "conn edit {}", "test {}"},
	"storage":  {"storage ls {}", "storage download {} KEY", "storage upload {} FILE", "storage link {} KEY", "conn edit {}", "test {}"},
	"cluster":  {"cluster status {}", "cluster ls {} pods", "cluster logs {} POD", "cluster deploy {} deployment/NAME --image IMAGE", "cluster events {}", "conn edit {}", "test {}"},
	"registry": {"registry ls {}", "registry inspect {} REPO:TAG", "registry copy {}:REPO:TAG OTHER:REPO:TAG", "conn edit {}", "test {}"},
	"vpn":      {"vpn up {}", "vpn test {}", "vpn status", "vpn edit {}", "vpn down {}"},
}

// itemKind is the kind of a host, conn or VPN for itemCommands.
func itemKind(st *store.State, name string) string {
	if _, ok := st.Hosts[name]; ok {
		return "server"
	}
	if c, ok := st.Conns[name]; ok {
		return connFamily(c)
	}
	if _, ok := st.Vpns[name]; ok {
		return "vpn"
	}
	return ""
}

// showCommands prints the commands for one item after `host show` (conn,
// vpn) for a person at the terminal, on stderr.
func showCommands(name string) {
	st, err := loadState()
	if err != nil {
		return
	}
	cmds := itemCommands[itemKind(st, name)]
	if len(cmds) == 0 {
		return
	}
	fmt.Fprintln(promptW, "\nCOMMANDS")
	for _, c := range cmds {
		fmt.Fprintln(promptW, "  komando "+strings.ReplaceAll(c, "{}", name))
	}
}
