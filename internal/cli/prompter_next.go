package cli

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/store"
)

// After a command a person ran at the terminal ends well, komando says on
// stderr what usually comes next (a formHint's next), and after a command
// it filled in, the line to type next time. The show of a server, a conn and
// a VPN ends with the commands that work on that item. Nothing of this
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

// noLinkLeaf says whether the Next: line n suggests `storage PROVIDER object
// link` for a provider that has no such command.
func noLinkLeaf(n, provider string) bool {
	if !strings.Contains(n, "{P} object link") || provider == "PROVIDER" {
		return false
	}
	_, ok := capability.Find(capability.Key{Type: "storage", Provider: provider, Area: "object", Verb: "link"})
	return !ok
}

// nextLines are the Next: lines of the command key, filled in: its
// formHint's list, or else the one its verb gives (verbNext). A line with
// {} needs first; one with NEW needs rename's second argument.
func nextLines(key, first string, args []string) []string {
	h, _ := hintOf(key)
	next := h.next
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
		prov := providerOfEntry(first)
		if noLinkLeaf(n, prov) {
			continue
		}
		n = strings.ReplaceAll(n, "{}", first)
		n = strings.ReplaceAll(n, "{P}", prov)
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
	inventory := slices.Contains([]string{"host", "conn", "vpn"}, w[0]) || len(w) == 3 && slices.Contains(connTypes, w[0])
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
	case "rm", "remove":
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
// The show of every provider of a conn type joins it at start.
var showKinds = map[string]string{
	"host ssh show": "", "conn show": "",
	"group list": "group", "credential key show": "key", "credential password show": "secret",
	"credential token show": "secret", "config get": "setting",
	"snippet show": "recipe",
}

// itemCommands are the commands that work on one item of a kind, {} the
// item, {TP} its type and provider; the show commands in showKinds list
// them for a person. A conn gets its family's (or its kind's, db:sqlite)
// list, then the entry list.
var itemCommands = map[string][]string{
	"server": {"logs {} --since 30m", "host ssh exec {} -- uptime", "host ssh shell {}",
		"pkg upgradable {}", "docker ps {}", "fs list {} /etc", "copy ./FILE {}:/tmp/FILE",
		"copy {}:/var/log/syslog ./", "host ssh tunnel start {} -L 8080:localhost:80",
		"credential key install KEY {}", "audit list --target {}", "host ssh edit {}", "host ssh rename {} NEW", "host ssh remove {}", "test {}"},
	"server:windows": {"host winrm exec {} -- Get-Date", "audit list --target {}", "host winrm edit {}", "host winrm rename {} NEW", "host winrm remove {}", "test {}"},
	// a server tagged swarm is also a Docker Swarm manager
	"swarm": {"cluster swarm raw {} -- service ls", "cluster swarm raw {} -- service logs SERVICE",
		"cluster swarm raw {} --write -- service update --image IMAGE SERVICE"},
	"entry": {"{TP} edit {}", "{TP} rename {} NEW", "{TP} remove {}", "test {}"},
	"db:postgres": {"database postgres query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}",
		"database postgres backup {} --to backup.sql", "db user list {}", "database postgres shell {}"},
	"db:mysql": {"database mysql query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}",
		"database mysql backup {} --to backup.sql", "db user list {}", "database mysql shell {}"},
	"db:sqlserver": {"database sqlserver query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}",
		"db user list {}", "database sqlserver shell {}"},
	"db:oracle": {"database oracle query {} \"select 1 from dual\"", "db schema {}", "db info {}", "db activity {}",
		"db user list {}", "database oracle shell {}"},
	"db:clickhouse": {"database clickhouse query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}",
		"db user list {}", "database clickhouse shell {}"},
	"db:sqlite":    {"database sqlite query {} \"select 1\"", "db schema {}", "db info {}", "database sqlite backup {} --to backup.db", "database sqlite shell {}"},
	"db:snowflake": {"database snowflake query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}"},
	"db:bigquery":  {"database bigquery query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}"},
	"db:mongodb":   {"database mongodb query {} '{\"find\": \"COLLECTION\", \"limit\": 10}'", "db schema {}", "db info {}"},
	"cache": {"cache redis raw {} -- PING", "cache redis raw {} -- INFO", "cache redis raw {} -- SCAN 0 MATCH 'user:*'",
		"cache redis raw {} -- GET KEY", "cache redis raw {} --write -- SET KEY VALUE --dry-run", "cache redis raw {} --write -- DEL KEY --dry-run"},
	"cache:memcached": {"cache memcached raw {} -- stats", "cache memcached raw {} -- stats items", "cache memcached raw {} -- get KEY"},
	"queue:kafka": {"queue kafka info {}", "queue kafka topic list {}", "queue kafka consumer list {}", "queue kafka message list {} TOPIC", "queue kafka consumer show {} CONSUMER",
		"queue kafka message create {} TOPIC --value hi --dry-run"},
	"queue:rabbitmq": {"queue rabbitmq info {}", "queue rabbitmq topic list {}", "queue rabbitmq message list {} QUEUE", "queue rabbitmq message create {} QUEUE --value hi --dry-run"},
	"queue:nats": {"queue nats info {}", "queue nats topic list {}", "queue nats consumer list {}", "queue nats message list {} STREAM", "queue nats consumer show {} CONSUMER",
		"queue nats message create {} SUBJECT --value hi --dry-run"},
	"queue:sqs": {"queue sqs info {}", "queue sqs topic list {}", "queue sqs message list {} QUEUE", "queue sqs message create {} QUEUE --value hi --dry-run"},
	"queue:pubsub": {"queue pubsub info {}", "queue pubsub topic list {}", "queue pubsub consumer list {}", "queue pubsub message list {} SUBSCRIPTION",
		"queue pubsub message create {} TOPIC --value hi --dry-run"},
	"storage": {"storage {P} object list {}", "storage {P} object read {} OBJECT --tail 50", "copy {}:KEY ./", "copy ./FILE {}:FOLDER/",
		"copy ./folder {}:FOLDER/ --sync --dry-run", "storage {P} object delete {} --prefix FOLDER/ --older-than 30d --dry-run"},
	"storage:link": {"storage {P} object link {} OBJECT --expires 24h"},
	"cluster": {"cluster kubernetes raw {} -- get pods -A", "cluster kubernetes raw {} -- get events -A", "cluster kubernetes raw {} -- logs deploy/NAME",
		"cluster kubernetes raw {} --write -- apply -f app.yaml --dry-run"},
	"registry": {"registry oci image list {}", "registry oci image list {} REPO", "registry oci image show {} IMAGE", "registry oci image copy {}:IMAGE DST_CONN",
		"registry oci image prune {} REPO --keep 10 --dry-run", "registry oci image delete {} IMAGE --dry-run"},
	"vpn": {"vpn KIND start {}", "vpn KIND test {}", "vpn KIND stop {}", "vpn KIND edit {} --check HOST:PORT", "vpn KIND rename {} NEW", "vpn KIND remove {}",
		"host ssh add NAME ADDRESS --via {}"},
	"group": {"list @{}", "test @{}", "host ssh exec @{} -- uptime", "pkg upgradable @{}", "snippet exec health @{}",
		"group create {} TARGET", "group remove {} TARGET", "group rename {} NEW"},
	"key": {"credential key install {} TARGET", "credential key uninstall {} TARGET", "credential key edit {}",
		"credential key rename {} NEW", "credential key remove {}"},
	"secret": {"secret check {}", "credential password add {}", "credential password rename {} NEW", "secret cp {} NEW",
		"credential password remove {}"},
	"setting": {"config set {} VALUE"},
	"recipe":  {"snippet exec {} TARGET", "snippet create {} COMMAND --overwrite --dry-run", "snippet remove {}"},
}

func init() {
	for _, l := range capability.All() {
		if l.State == capability.Built && l.Key.Verb == "show" && l.Key.Area == "" && slices.Contains(connTypes, l.Key.Type) {
			showKinds[l.Key.String()] = ""
		}
	}
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
		if swarmOf(st, h) != nil {
			return []string{"server", "swarm"}
		}
		return []string{"server"}
	}
	if c, ok := st.Conns[name]; ok {
		if c.Kind == "swarm" { // its commands work on its manager
			return []string{"swarm"}
		}
		fam := inventory.ConnFamily(c)
		ks := []string{fam}
		if _, ok := itemCommands[fam+":"+c.Kind]; ok {
			ks = []string{fam + ":" + c.Kind}
		}
		if c.Kind == "s3" || c.Kind == "gcs" || c.Kind == "azblob" {
			ks = append(ks, "storage:link") // only these sign links
		}
		return append(ks, "entry")
	}
	if _, ok := st.Vpns[name]; ok {
		return []string{"vpn"}
	}
	return nil
}

// entryPathOfName is the type and provider words of the saved conn called
// name (database postgres); TYPE PROVIDER when there is none.
func entryPathOfName(st *store.State, name string) string {
	return strings.TrimPrefix(entryCmd(entryWords(st.Conns[name]), "", ""), "komando ")
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
		if v, ok := st.Vpns[name]; ok {
			c = strings.ReplaceAll(c, "vpn KIND ", "vpn "+v.Kind+" ")
		}
		c = strings.ReplaceAll(strings.ReplaceAll(c, "{}", name), "{P}", providerOfEntry(name))
		fmt.Fprintln(promptW(cl), "  komando "+strings.ReplaceAll(c, "{TP}", entryPathOfName(st, name)))
	}
}
