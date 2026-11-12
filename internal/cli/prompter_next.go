package cli

import (
	"fmt"
	"slices"
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
// ended well. A Next: line with {} needs the command's first argument.
func promptNext() {
	if !fillSeen.person || fillSeen.key == "" {
		return
	}
	if fillSeen.prompted {
		fmt.Fprintln(promptW, "Next time: komando "+menuCommandLine(fillSeen.line))
	}
	if kind, ok := showKinds[fillSeen.key]; ok && fillSeen.first != "" {
		showCommands(kind, fillSeen.first)
	}
	var lines []string
	for _, n := range formHints[fillSeen.key].next {
		if strings.Contains(n, "{}") && fillSeen.first == "" {
			continue
		}
		lines = append(lines, "komando "+strings.ReplaceAll(n, "{}", fillSeen.first))
	}
	if len(lines) > 0 {
		fmt.Fprintln(promptW, "Next: "+strings.Join(lines, " · "))
	}
}

// showKinds are the commands that show one item, and its kind for
// itemCommands; "" finds the kind in the inventory (a server, conn or VPN).
var showKinds = map[string]string{
	"host show": "", "conn show": "", "vpn show": "",
	"group list": "group", "key show": "key", "job status": "job", "secret get": "secret", "config get": "setting",
}

// itemCommands are the commands that work on one item of a kind, {} the
// item; the show commands in showKinds list them for a person. A conn
// gets its family's (or its kind's, db:sqlite) list, then the conn list.
var itemCommands = map[string][]string{
	"server": {"facts {}", "logs {} --since 30m", "exec {} -- uptime", "shell {}", "svc list {} --failed",
		"pkg upgradable {}", "docker ps {}", "fs ls {} /etc", "upload {} ./FILE /tmp/FILE",
		"download {} /var/log/syslog --to ./", "job start {} -- make", "tunnel start {} -L 8080:localhost:80",
		"key deploy KEY {}", "audit --target {}", "host edit {}", "host mv {} NEW", "host rm {}", "test {}"},
	"server:windows": {"facts {}", "svc list {} --state running", "svc status {} NAME", "svc restart {} NAME --wait 10s",
		"exec {} -- Get-Date", "audit --target {}", "host edit {}", "host mv {} NEW", "host rm {}", "test {}"},
	// a server tagged swarm is also a Docker Swarm manager
	"swarm": {"cluster status {}", "cluster ls {} services", "cluster logs {} service/NAME",
		"cluster deploy {} service/NAME --image IMAGE --wait", "cluster apply {} --file compose.yml --stack STACK"},
	"conn": {"conn edit {}", "conn mv {} NEW", "conn rm {}", "test {}"},
	"db": {"db query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}", "db dump {} --to backup.sql",
		"db user ls {}", "db shell {}"},
	"db:sqlite":    {"db query {} \"select 1\"", "db schema {}", "db info {}", "db dump {} --to backup.sql", "db shell {}"},
	"db:snowflake": {"db query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}"},
	"db:bigquery":  {"db query {} \"select 1\"", "db schema {}", "db info {}", "db activity {}"},
	"db:mongodb":   {"db query {} '{\"find\": \"COLLECTION\", \"limit\": 10}'", "db schema {}", "db info {}", "db shell {}"},
	"cache": {"cache info {}", "cache keys {} 'user:*'", "cache get {} KEY", "cache set {} KEY VALUE --dry-run",
		"cache rm {} KEY --dry-run", "cache run {} -- PING"},
	"cache:memcached": {"cache info {}", "cache keys {}", "cache get {} KEY", "cache set {} KEY VALUE --dry-run",
		"cache rm {} KEY --dry-run", "cache run {} -- stats"},
	"queue:kafka": {"queue info {}", "queue ls {}", "queue groups {}", "queue peek {} TOPIC", "queue lag {} GROUP",
		"queue send {} TOPIC --value hi --dry-run"},
	"queue:nats": {"queue info {}", "queue ls {}", "queue groups {}", "queue peek {} STREAM", "queue lag {} CONSUMER",
		"queue send {} SUBJECT --value hi --dry-run"},
	"queue:pubsub": {"queue info {}", "queue ls {}", "queue groups {}", "queue peek {} SUBSCRIPTION",
		"queue send {} TOPIC --value hi --dry-run"},
	"queue": {"queue info {}", "queue ls {}", "queue peek {} QUEUE", "queue send {} QUEUE --value hi --dry-run"},
	"storage": {"storage ls {}", "storage cat {} KEY --tail 50", "download {} KEY --to ./", "upload {} FILE FOLDER/",
		"sync ./folder {}:FOLDER/ --dry-run", "storage rm {} --prefix FOLDER/ --older-than 30d --dry-run"},
	"storage:link": {"storage link {} KEY --expires 24h"},
	"cluster": {"cluster status {}", "cluster ls {} pods", "cluster events {} --warnings", "cluster logs {} deploy/NAME",
		"cluster deploy {} deploy/NAME --image IMAGE --wait", "cluster apply {} --file app.yaml --dry-run",
		"cluster helm ls {} -A", "cluster run {} -- get pods -A"},
	"registry": {"registry ls {}", "registry ls {} REPO", "registry inspect {} REPO:TAG", "registry copy {}:REPO:TAG OTHER:",
		"registry prune {} REPO --keep 10 --dry-run", "registry rm {} REPO:TAG --dry-run"},
	"vpn": {"vpn up {}", "vpn test {}", "vpn down {}", "vpn edit {} --check HOST:PORT", "vpn mv {} NEW", "vpn rm {}",
		"host add NAME USER@ADDRESS --via {}"},
	"group": {"list @{}", "test @{}", "exec @{} -- uptime", "facts @{}", "pkg upgradable @{}", "recipe run health @{}",
		"group add {} TARGET", "group rm {} TARGET", "group mv {} NEW"},
	"key":     {"key deploy {} TARGET", "key revoke {} TARGET", "key edit {}", "key mv {} NEW", "key rm {}"},
	"job":     {"job logs {} --limit 50", "job wait {}", "job kill {}", "job rm {}"},
	"secret":  {"secret check {}", "secret set {}", "secret mv {} NEW", "secret cp {} NEW", "secret rm {}"},
	"setting": {"config set {} VALUE"},
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
func showCommands(kind, name string) {
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
	fmt.Fprintln(promptW, "\nCOMMANDS")
	for _, c := range cmds {
		fmt.Fprintln(promptW, "  komando "+strings.ReplaceAll(c, "{}", name))
	}
}
