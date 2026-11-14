package cli

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/store"
)

// After a command a person ran at the terminal ends well, komando says on
// stderr what usually comes next (a formHint's next), and after a command
// it filled in, the line to type next time. `host show`, `conn show` and
// `vpn show` end with the commands that work on that item. Nothing of this
// is ever printed for an agent, a script or a pipe.

// fillInfo is what promptFill saw of this command.
type fillInfo struct {
	person   bool     // a person at a terminal (promptable)
	key      string   // the command (db query)
	first    string   // its first argument, usually the target
	args     []string // the positional arguments as given (rename's NEW)
	prompted bool     // komando asked for something
	line     []string
}

// sayNext sets the Next: lines a person sees after this command, each a
// whole `komando ...` line. Nothing next is ever printed on stdout (S-9.3).
func sayNext(cl *call, lines ...string) { cl.nextNow = lines }

// promptNext prints Next time: and Next: for a person, after a run that
// ended well. A Next: line with {} needs the command's first argument.
// Next: is one line on stderr, at most three commands (S-9.3).
func promptNext(cl *call) {
	if !cl.fillSeen.person || cl.fillSeen.key == "" {
		return
	}
	if cl.fillSeen.prompted {
		fmt.Fprintln(promptW(cl), "Next time: komando "+pickCommandLine(cl.fillSeen.line))
	}
	if kind, ok := showKinds[cl.fillSeen.key]; ok && cl.fillSeen.first != "" {
		showCommands(cl, kind, cl.fillSeen.first)
	}
	lines := cl.nextNow
	if len(lines) == 0 {
		lines = nextLines(cl.fillSeen.key, cl.fillSeen.first, cl.fillSeen.args)
	}
	if len(lines) > 3 {
		lines = lines[:3]
	}
	if len(lines) > 0 {
		fmt.Fprintln(promptW(cl), "Next: "+strings.Join(lines, " · "))
	}
}

// nextLines are the Next: lines of the command key, filled in: its
// formHint's list, or else the one its verb gives (verbNext). A line with
// {} needs first; one with NEW needs rename's second argument.
func nextLines(key, first string, args []string) []string {
	next := formHints[key].next
	if len(next) == 0 {
		next = verbNext(key)
	}
	newName := ""
	if len(args) > 1 {
		newName = args[1]
	}
	var lines []string
	for _, n := range next {
		if strings.Contains(n, "{}") && first == "" || strings.Contains(n, " NEW") && newName == "" {
			continue
		}
		n = strings.ReplaceAll(n, "{}", first)
		if newName != "" {
			n = strings.ReplaceAll(n, " NEW", " "+newName)
		}
		lines = append(lines, "komando "+n)
	}
	return lines
}

// verbNext is the Next: list every add, edit, rename and rm has when its
// formHint names none (S-9.4): add -> test and show, edit -> show and
// test, rename -> show NEW, rm -> list. A command of a noun without a
// show (user, cron, cache) gets the noun's list of the same target. The
// lines are written as formHint next lines are ({}, NEW).
func verbNext(key string) []string {
	w := strings.Fields(key)
	if len(w) < 2 {
		if key == "rename" {
			return []string{"list NEW"}
		}
		return nil
	}
	noun, verb := strings.Join(w[:len(w)-1], " "), w[len(w)-1]
	root := nextRoot()
	cmd := cmdByKey(root, key)
	if cmd == nil {
		return nil
	}
	show, list := cmdByKey(root, noun+" show"), cmdByKey(root, noun+" list")
	inventory := slices.Contains([]string{"host", "conn", "vpn"}, noun)
	// sameFirst: c takes the same first argument as cmd (user list TARGET
	// after user add TARGET USER), so {} fills it
	sameFirst := func(c *cobra.Command) bool {
		a, b := useArgs(cmd), useArgs(c)
		return len(a) > 0 && len(b) > 0 && a[0] == b[0] && !strings.HasPrefix(b[0], "[")
	}
	listLine := func() string {
		switch {
		case list == nil:
			return ""
		case sameFirst(list):
			return commandKey(list) + " {}"
		case len(useArgs(list)) > 0 && !strings.HasPrefix(useArgs(list)[0], "["):
			return "" // its list needs an argument rm does not have
		}
		return commandKey(list)
	}
	showLine := func(arg string) string {
		if show == nil || len(useArgs(show)) != 1 {
			return ""
		}
		return commandKey(show) + " " + arg
	}
	var next []string
	add := func(l ...string) {
		for _, s := range l {
			if s != "" {
				next = append(next, s)
			}
		}
	}
	switch verb {
	case "add":
		if inventory {
			add("test {}")
		}
		if s := showLine("{}"); s != "" && sameFirst(show) {
			add(s)
		} else {
			add(listLine())
		}
	case "edit":
		add(showLine("{}"))
		if inventory {
			add("test {}")
		}
	case "rename":
		if s := showLine("NEW"); s != "" {
			add(s)
		} else {
			add(listLine())
		}
	case "rm":
		add(listLine())
	}
	return next
}

// nextRoot is the command tree verbNext reads.
var nextRoot = sync.OnceValue(func() *cobra.Command { return newRoot(treeCall()) })

// cmdByKey is the command whose key is key, or nil (an alias does not count).
func cmdByKey(root *cobra.Command, key string) *cobra.Command {
	c, _, err := root.Find(strings.Fields(key))
	if err != nil || c == root || commandKey(c) != key {
		return nil
	}
	return c
}

// useArgs are the argument words of c's Use line, without [flags].
func useArgs(c *cobra.Command) []string {
	f := strings.Fields(c.Use)
	if len(f) > 0 {
		f = f[1:]
	}
	return slices.DeleteFunc(f, func(s string) bool { return s == "[flags]" })
}

// showKinds are the commands that show one item, and its kind for
// itemCommands; "" finds the kind in the inventory (a server, conn or VPN).
var showKinds = map[string]string{
	"host show": "", "conn show": "", "vpn show": "",
	"group list": "group", "key show": "key", "job status": "job", "secret show": "secret", "config get": "setting",
	"tunnel show": "tunnel", "recipe show": "recipe",
}

// itemCommands are the commands that work on one item of a kind, {} the
// item; the show commands in showKinds list them for a person. A conn
// gets its family's (or its kind's, db:sqlite) list, then the conn list.
var itemCommands = map[string][]string{
	"server": {"facts {}", "logs {} --since 30m", "exec {} -- uptime", "shell {}", "svc list {} --failed",
		"pkg upgradable {}", "docker ps {}", "fs list {} /etc", "upload {} ./FILE /tmp/FILE",
		"download {} /var/log/syslog --to ./", "job start {} -- make", "tunnel start {} -L 8080:localhost:80",
		"key deploy KEY {}", "audit --target {}", "host edit {}", "host rename {} NEW", "host rm {}", "test {}"},
	"server:windows": {"facts {}", "svc list {} --state running", "svc status {} NAME", "svc restart {} NAME --wait 10s",
		"exec {} -- Get-Date", "audit --target {}", "host edit {}", "host rename {} NEW", "host rm {}", "test {}"},
	// a server tagged swarm is also a Docker Swarm manager
	"swarm": {"cluster status {}", "cluster list {} services", "cluster logs {} service/NAME",
		"cluster deploy {} service/NAME --image IMAGE --wait", "cluster apply {} --file compose.yml --stack STACK"},
	"conn": {"conn edit {}", "conn rename {} NEW", "conn rm {}", "test {}"},
	"db": {"db query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}", "db dump {} --to backup.sql",
		"db user list {}", "db shell {}"},
	"db:sqlite":    {"db query {} \"select 1\"", "db schema {}", "db info {}", "db dump {} --to backup.sql", "db shell {}"},
	"db:snowflake": {"db query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}"},
	"db:bigquery":  {"db query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}"},
	"db:mongodb":   {"db query {} '{\"find\": \"COLLECTION\", \"limit\": 10}'", "db schema {}", "db info {}", "db shell {}"},
	"cache": {"cache info {}", "cache keys {} 'user:*'", "cache get {} KEY", "cache set {} KEY VALUE --dry-run",
		"cache rm {} KEY --dry-run", "cache run {} -- PING"},
	"cache:memcached": {"cache info {}", "cache keys {}", "cache get {} KEY", "cache set {} KEY VALUE --dry-run",
		"cache rm {} KEY --dry-run", "cache run {} -- stats"},
	"queue:kafka": {"queue info {}", "queue list {}", "queue groups {}", "queue peek {} TOPIC", "queue lag {} CONSUMER",
		"queue send {} TOPIC --value hi --dry-run"},
	"queue:nats": {"queue info {}", "queue list {}", "queue groups {}", "queue peek {} STREAM", "queue lag {} CONSUMER",
		"queue send {} SUBJECT --value hi --dry-run"},
	"queue:pubsub": {"queue info {}", "queue list {}", "queue groups {}", "queue peek {} SUBSCRIPTION",
		"queue send {} TOPIC --value hi --dry-run"},
	"queue": {"queue info {}", "queue list {}", "queue peek {} QUEUE", "queue send {} QUEUE --value hi --dry-run"},
	"storage": {"storage list {}", "storage cat {} OBJECT --tail 50", "download {} KEY --to ./", "upload {} FILE FOLDER/",
		"sync ./folder {}:FOLDER/ --dry-run", "storage rm {} --prefix FOLDER/ --older-than 30d --dry-run"},
	"storage:link": {"storage link {} OBJECT --expires 24h"},
	"cluster": {"cluster status {}", "cluster list {} pods", "cluster events {} --warnings", "cluster logs {} deploy/NAME",
		"cluster deploy {} deploy/NAME --image IMAGE --wait", "cluster apply {} --file app.yaml --dry-run",
		"cluster helm list {} -A", "cluster run {} -- get pods -A"},
	"registry": {"registry list {}", "registry list {} REPO", "registry inspect {} IMAGE", "registry copy {}:IMAGE DST_CONN",
		"registry prune {} REPO --keep 10 --dry-run", "registry rm {} IMAGE --dry-run"},
	"vpn": {"vpn up {}", "vpn test {}", "vpn down {}", "vpn edit {} --check HOST:PORT", "vpn rename {} NEW", "vpn rm {}",
		"host add NAME USER@ADDRESS --via {}"},
	"group": {"list @{}", "test @{}", "exec @{} -- uptime", "facts @{}", "pkg upgradable @{}", "recipe run health @{}",
		"group add {} TARGET", "group rm {} TARGET", "group rename {} NEW"},
	"key":     {"key deploy {} TARGET", "key revoke {} TARGET", "key edit {}", "key rename {} NEW", "key rm {}"},
	"job":     {"job logs {} --limit 50", "job wait {}", "job kill {}", "job rm {}"},
	"secret":  {"secret check {}", "secret set {}", "secret rename {} NEW", "secret cp {} NEW", "secret rm {}"},
	"setting": {"config set {} VALUE"},
	"tunnel":  {"tunnel stop {}", "tunnel list"},
	"recipe":  {"recipe run {} TARGET", "recipe add {} COMMAND --overwrite --dry-run", "recipe rm {}"},
}

// itemKinds are the itemCommands lists for name, shown by a command that
// shows kind ("" for host, conn and vpn show: found in the inventory).
func itemKinds(st *store.State, kind, name string) []string {
	if kind != "" {
		return []string{kind}
	}
	if h, ok := st.Hosts[name]; ok {
		if h.Windows() {
			return []string{"server:windows"}
		}
		if slices.Contains(h.Tags, "swarm") {
			return []string{"server", "swarm"}
		}
		return []string{"server"}
	}
	if c, ok := st.Conns[name]; ok {
		fam := connFamily(c)
		ks := []string{fam}
		if _, ok := itemCommands[fam+":"+c.Kind]; ok {
			ks = []string{fam + ":" + c.Kind}
		}
		if c.Kind == "s3" || c.Kind == "gcs" || c.Kind == "azblob" {
			ks = append(ks, "storage:link") // only these sign links
		}
		return append(ks, "conn")
	}
	if _, ok := st.Vpns[name]; ok {
		return []string{"vpn"}
	}
	return nil
}

// showCommands prints the commands for one item after a show command, for
// a person at the terminal, on stderr.
func showCommands(cl *call, kind, name string) {
	st, err := loadState()
	if err != nil {
		return
	}
	var cmds []string
	for _, k := range itemKinds(st, kind, name) {
		cmds = append(cmds, itemCommands[k]...)
	}
	if len(cmds) == 0 {
		return
	}
	fmt.Fprintln(promptW(cl), "\nCOMMANDS")
	for _, c := range cmds {
		fmt.Fprintln(promptW(cl), "  komando "+strings.ReplaceAll(c, "{}", name))
	}
}
