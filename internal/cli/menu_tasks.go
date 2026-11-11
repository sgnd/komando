package cli

import (
	"context"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// menuItemTasks is what can be done with one item.
func menuItemTasks(st *store.State, item string) (string, []menuTask) {
	kind := menuItemKind(st, item)
	switch kind {
	case "server":
		return kind, serverTasks
	case "group":
		return kind, groupTasks()
	case "vpn":
		return kind, vpnTasks(st, item)
	case "db":
		return kind, dbTasks
	case "cache":
		return kind, cacheTasks
	case "queue":
		return kind, queueTasks
	case "storage":
		return kind, storageTasks
	case "cluster":
		return kind, clusterTasks
	case "registry":
		return kind, registryTasks
	}
	return kind, []menuTask{{label: "Test", cmd: "test"}, connChange}
}

var serverTasks = []menuTask{
	{label: "Open a shell", detail: "Log in and type commands yourself", line: [][]string{{"shell", "{}"}}, ownExit: true},
	{label: "Check health", detail: "What it runs, updates waiting, and a health check", line: [][]string{{"facts", "{}"}, {"recipe", "run", "health", "{}"}}},
	{label: "Read logs", detail: "The system log, or one service's", cmd: "logs"},
	{label: "Services", detail: "Start, stop or restart a service", sub: serviceTasks},
	{label: "Run a command", detail: "Run one command and see what it prints", sub: runTasks, title: "Keep it running if the connection drops?"},
	{label: "Files", detail: "Look, edit, copy, put a backup back", sub: fileTasks},
	{label: "Docker containers", detail: "See, restart and read logs of containers", sub: dockerTasks},
	{label: "Updates and packages", detail: "Updates waiting, security updates, install or remove", sub: pkgTasks},
	{label: "Reboot", detail: "Restart the server", line: [][]string{{"reboot", "{}"}},
		confirm: "Reboot {}? It is away for a minute or more while it starts again.", yes: "Reboot it"},
	{label: "Change this server", detail: "Address, user, production, group, name", sub: hostChangeTasks},
	{label: "Remove from list", detail: "komando forgets it; the server itself stays as it is", cmd: "host rm"},
	{label: "More", sub: serverMoreTasks},
}

var serviceTasks = []menuTask{
	{label: "List services", cmd: "svc list"},
	{label: "Is a service running?", cmd: "svc status"},
	{label: "Restart a service", cmd: "svc restart"},
	{label: "Start a service", cmd: "svc start"},
	{label: "Stop a service", cmd: "svc stop"},
	{label: "Reload its settings", detail: "Without stopping it", cmd: "svc reload"},
	{label: "Start it when the server starts", cmd: "svc enable"},
	{label: "Do not start it when the server starts", cmd: "svc disable"},
	{label: "Read a service's log", cmd: "svc logs"},
	{label: "Read changed service files", detail: "systemctl daemon-reload", cmd: "svc daemon-reload"},
}

var runTasks = []menuTask{
	{label: "No, run it now", detail: "See what it prints as it runs", cmd: "exec"},
	{label: "Yes, as a background job", detail: "It keeps going if the connection drops; Running now shows it", cmd: "job start"},
}

var fileTasks = []menuTask{
	{label: "Look in a folder", cmd: "fs ls"},
	{label: "Show a file", cmd: "fs cat"},
	{label: "Change text in a file", detail: "Keeps a backup you can put back", cmd: "fs replace"},
	{label: "Write a whole file", cmd: "fs write"},
	{label: "Put a backup back", detail: "After a change made with a backup", cmd: "fs restore"},
	{label: "Copy a file to it", cmd: "upload"},
	{label: "Copy a file from it", cmd: "download"},
	{label: "Copy a folder", detail: "To or from any server, file storage or here; only what changed", cmd: "sync", noItem: true},
	{label: "Copy between servers", cmd: "cp", noItem: true},
	{label: "File details", detail: "Size, owner, permissions", cmd: "fs stat"},
	{label: "Make a folder", cmd: "fs mkdir"},
	{label: "Move or rename", cmd: "fs mv"},
	{label: "Change permissions", cmd: "fs chmod"},
	{label: "Delete", cmd: "fs rm"},
}

var dockerTasks = []menuTask{
	{label: "Running containers", cmd: "docker ps"},
	{label: "A container's logs", cmd: "docker logs"},
	{label: "Restart a container", cmd: "docker restart"},
	{label: "Start a container", cmd: "docker start"},
	{label: "Stop a container", cmd: "docker stop"},
	{label: "How busy they are", detail: "CPU and memory", cmd: "docker stats"},
	{label: "Run a command in a container", cmd: "docker exec"},
	{label: "Container details", cmd: "docker inspect"},
	{label: "Images", cmd: "docker images"},
	{label: "Download an image", cmd: "docker pull"},
	{label: "Remove a container", cmd: "docker rm"},
	{label: "Clean up", detail: "Stopped containers and unused images", cmd: "docker prune"},
	{label: "Docker Compose", cmd: "docker compose"},
	{label: "Any docker command", detail: "For experts", cmd: "docker raw"},
}

var pkgTasks = []menuTask{
	{label: "Updates waiting", cmd: "pkg upgradable"},
	{label: "Security updates", cmd: "pkg security"},
	{label: "Install every update", cmd: "pkg upgrade"},
	{label: "Refresh the package list", cmd: "pkg update"},
	{label: "Install a package", cmd: "pkg install"},
	{label: "Is a package installed?", cmd: "pkg installed"},
	{label: "Remove a package", cmd: "pkg rm"},
}

var hostChangeTasks = []menuTask{
	{label: "Change address, user or login", detail: "Also: ask me before changes (production)", cmd: "host edit"},
	{label: "Test it", detail: "Can komando log in?", cmd: "host test"},
	{label: "Show its settings", cmd: "host show"},
	{label: "Put it in a group", cmd: "group add", fill: []string{"", "{}"}},
	{label: "Take it out of a group", cmd: "group rm", fill: []string{"", "{}"}},
	{label: "Rename", cmd: "host mv"},
	{label: "Show the ssh command for it", cmd: "host ssh-command"},
}

var serverMoreTasks = []menuTask{
	{label: "Run a script from this computer", cmd: "script"},
	{label: "Reach a port on this server from my computer", detail: "A tunnel; Running now stops it", cmd: "tunnel start"},
	{label: "My saved commands", detail: "Run a saved command (a recipe) here", cmd: "recipe run", fill: []string{"", "{}"}},
	{label: "Save a command", cmd: "recipe add", noItem: true},
	{label: "Saved commands", cmd: "recipe list", noItem: true},
	{label: "Delete a saved command", cmd: "recipe rm", noItem: true},
	{label: "Scheduled tasks", detail: "cron: list, add, remove", sub: []menuTask{
		{label: "List scheduled tasks", cmd: "cron list"},
		{label: "Add or change one", cmd: "cron set"},
		{label: "Remove one", cmd: "cron rm"},
	}},
	{label: "Users", sub: []menuTask{
		{label: "List users", cmd: "user list"},
		{label: "Add a user", cmd: "user add"},
		{label: "Lock a user", cmd: "user lock"},
		{label: "Unlock a user", cmd: "user unlock"},
		{label: "Remove a user", cmd: "user rm"},
	}},
	{label: "Network checks", sub: []menuTask{
		{label: "Can it reach an address?", cmd: "net check"},
		{label: "Look up a name", detail: "DNS", cmd: "net dns"},
		{label: "Open a web address from it", cmd: "net http"},
		{label: "Open ports", cmd: "net ports"},
	}},
	{label: "Check SSL certificates", detail: "Warns before they run out", cmd: "cert check"},
	{label: "Put an SSH key on it", detail: "No password next time", cmd: "key deploy", fill: []string{"", "{}"}},
	{label: "Take an SSH key off it", cmd: "key revoke", fill: []string{"", "{}"}},
	{label: "Log in with a code", detail: "For a server that asks for a two-factor code; your commands reuse it", cmd: "login"},
	{label: "Background jobs", sub: jobTasks},
}

var jobTasks = []menuTask{
	{label: "List background jobs", line: [][]string{{"job", "list"}}},
	{label: "Is a job done?", cmd: "job status", noItem: true},
	{label: "Read a job's output", cmd: "job logs", noItem: true},
	{label: "Wait for a job", cmd: "job wait", noItem: true},
	{label: "Stop a job", cmd: "job kill", noItem: true},
	{label: "Forget finished jobs", cmd: "job rm", noItem: true},
}

// groupTasks is what a server offers, run on every server of the group,
// and the group's own changes. Tasks for one server only are left out.
func groupTasks() []menuTask {
	var tasks []menuTask
	for _, tk := range menuManyServers(serverTasks) {
		switch tk.label {
		case "Change this server", "Remove from list":
			continue
		case "Reboot":
			tk.confirm = "Reboot every server in {}? They are away for a minute or more while they start again."
			tk.yes = "Reboot them"
		}
		tasks = append(tasks, tk)
	}
	return append(tasks, menuTask{label: "Edit members", sub: []menuTask{
		{label: "Who is in it", cmd: "group list", fill: []string{"{name}"}},
		{label: "Add a server", cmd: "group add", fill: []string{"{name}"}},
		{label: "Take a server out", cmd: "group rm", fill: []string{"{name}"}},
		{label: "Rename the group", cmd: "group mv", fill: []string{"{name}"}},
	}})
}

// menuManyServers is tasks without those that work on one server only: a
// shell, a file edit, a tunnel, a login.
func menuManyServers(tasks []menuTask) []menuTask {
	var keep []menuTask
	for _, tk := range tasks {
		if menuOneServer(tk) {
			continue
		}
		if tk.sub != nil {
			tk.sub = menuManyServers(tk.sub)
		}
		keep = append(keep, tk)
	}
	return keep
}

func menuOneServer(tk menuTask) bool {
	if tk.cmd == "tunnel start" || tk.cmd == "login" || slices.ContainsFunc(tk.line, func(l []string) bool { return l[0] == "shell" }) {
		return true
	}
	h := formHints[tk.cmd]
	return tk.cmd != "" && !tk.noItem && tk.fill == nil && len(h.args) > 0 && h.args[0].pick == "server"
}

// vpnTasks: Connect, or Disconnect when it is connected, after saying what
// stops answering.
func vpnTasks(st *store.State, name string) []menuTask {
	conn := menuTask{label: "Connect", detail: "Log in if it asks", line: [][]string{{"vpn", "up", "{}"}}}
	if menuVpnUp(st, name) {
		q := "Disconnect {}?"
		if n := menuBehind(st, name); n > 0 {
			q += " " + menuCount(n, "server or service") + " behind it stop answering."
			if n == 1 {
				q = "Disconnect {}? 1 server or service behind it stops answering."
			}
		}
		conn = menuTask{label: "Disconnect", line: [][]string{{"vpn", "down", "{}"}}, confirm: q, yes: "Disconnect"}
	}
	return []menuTask{conn,
		{label: "Test", detail: "Does it connect, and does the test address answer?", cmd: "vpn test"},
		{label: "Show its settings", cmd: "vpn show"},
		{label: "Change login or test address", cmd: "vpn edit"},
		{label: "Rename", cmd: "vpn mv"},
		{label: "Remove", cmd: "vpn rm"},
		{label: "Every VPN's state", line: [][]string{{"vpn", "status"}}},
	}
}

// menuBehind is how many servers and services reach their target through
// this VPN.
func menuBehind(st *store.State, vpn string) int {
	n := 0
	for _, h := range st.Hosts {
		if slices.Contains(strings.Split(h.Via, ","), vpn) {
			n++
		}
	}
	for _, c := range st.Conns {
		if slices.Contains(strings.Split(c.Via, ","), vpn) {
			n++
		}
	}
	return n
}

var connChange = menuTask{label: "Change or remove", sub: []menuTask{
	{label: "Show its settings", cmd: "conn show"},
	{label: "Change it", cmd: "conn edit"},
	{label: "Rename", cmd: "conn mv"},
	{label: "Remove from list", detail: "komando forgets it; the service itself stays as it is", cmd: "conn rm"},
}}

var connTest = menuTask{label: "Test", detail: "Does it answer?", cmd: "conn test"}

var dbTasks = []menuTask{
	{label: "Look around", detail: "Summary, tables, sizes", sub: []menuTask{
		{label: "Summary", cmd: "db info"},
		{label: "Tables", cmd: "db schema"},
		{label: "Sizes", cmd: "db sizes"},
		{label: "How a query would run", detail: "EXPLAIN", cmd: "db explain"},
	}},
	{label: "Run a query", detail: "Read only unless you say so", cmd: "db query"},
	{label: "Open a SQL shell", line: [][]string{{"db", "shell", "{}"}}, ownExit: true},
	{label: "Back up to a file", detail: "A copy on this computer", cmd: "db dump"},
	{label: "Load a backup", detail: "Replaces what is there", cmd: "db restore"},
	{label: "Who is running what", detail: "Activity, locks, stop a query", sub: []menuTask{
		{label: "What is running", cmd: "db activity"},
		{label: "Locks", cmd: "db locks"},
		{label: "Stop a query", cmd: "db kill"},
	}},
	{label: "Users and rights", sub: []menuTask{
		{label: "List users", cmd: "db user ls"},
		{label: "Add a user", cmd: "db user add"},
		{label: "Change a password", cmd: "db user passwd"},
		{label: "Remove a user", cmd: "db user rm"},
		{label: "What a user may do", cmd: "db grants"},
		{label: "Give rights", cmd: "db grant"},
		{label: "Take rights away", cmd: "db revoke"},
	}},
	connTest, connChange,
}

var cacheTasks = []menuTask{
	{label: "Summary", cmd: "cache info"},
	{label: "Find keys", cmd: "cache keys"},
	{label: "Show a key", cmd: "cache get"},
	{label: "Set a key", cmd: "cache set"},
	{label: "Delete keys", cmd: "cache rm"},
	{label: "Send a command", detail: "Read only unless you say so", cmd: "cache run"},
	connTest, connChange,
}

var queueTasks = []menuTask{
	{label: "Summary", cmd: "queue info"},
	{label: "List topics or queues", cmd: "queue ls"},
	{label: "Look at messages", detail: "Reads without taking them", cmd: "queue peek"},
	{label: "Details of one", cmd: "queue describe"},
	{label: "Readers", detail: "Consumer groups", cmd: "queue groups"},
	{label: "Is a reader behind?", cmd: "queue lag"},
	{label: "Send a message", cmd: "queue send"},
	{label: "Create a topic or queue", cmd: "queue create"},
	{label: "Empty one", detail: "Its messages are gone for good", cmd: "queue purge"},
	{label: "Delete one", cmd: "queue rm"},
	connTest, connChange,
}

var storageTasks = []menuTask{
	{label: "See files", cmd: "storage ls"},
	{label: "Download", cmd: "storage download"},
	{label: "Upload", cmd: "storage upload"},
	{label: "Share a link", detail: "A link that works for a while", cmd: "storage link"},
	{label: "More", sub: []menuTask{
		{label: "Show a text file", cmd: "storage cat"},
		{label: "Delete", cmd: "storage rm"},
	}},
	connTest, connChange,
}

var clusterTasks = []menuTask{
	{label: "Is it healthy?", cmd: "cluster status"},
	{label: "What is running?", cmd: "cluster ls"},
	{label: "Show logs", cmd: "cluster logs"},
	{label: "Roll out a new image", cmd: "cluster deploy"},
	{label: "Undo the last rollout", cmd: "cluster rollback"},
	{label: "Restart an app", cmd: "cluster restart"},
	{label: "Change the number of copies", cmd: "cluster scale"},
	{label: "More", sub: []menuTask{
		{label: "Recent events", cmd: "cluster events"},
		{label: "Describe something", cmd: "cluster describe"},
		{label: "Show one as YAML", cmd: "cluster get"},
		{label: "Rollout history", cmd: "cluster history"},
		{label: "Run a command in a pod", cmd: "cluster exec"},
		{label: "Open a shell in a pod", cmd: "cluster shell", ownExit: true},
		{label: "Reach an app from my computer", cmd: "cluster forward"},
		{label: "Apply a file", cmd: "cluster apply"},
		{label: "Helm releases", cmd: "cluster helm ls"},
		{label: "A Helm release's state", cmd: "cluster helm status"},
		{label: "A Helm release's history", cmd: "cluster helm history"},
		{label: "A Helm release's values", cmd: "cluster helm values"},
		{label: "Any kubectl or docker command", detail: "For experts", cmd: "cluster run"},
		{label: "Delete something", cmd: "cluster rm"},
	}},
	connTest, connChange,
}

var registryTasks = []menuTask{
	{label: "See images and tags", cmd: "registry ls"},
	{label: "Image details", cmd: "registry inspect"},
	{label: "Copy an image", detail: "To another registry or name", cmd: "registry copy", noItem: true},
	{label: "More", sub: []menuTask{
		{label: "Clean up old images", cmd: "registry prune"},
		{label: "Delete an image", cmd: "registry rm"},
	}},
	connTest, connChange,
}

var importTasks = []menuTask{
	{label: "My SSH servers", detail: "From ~/.ssh/config", line: [][]string{{"import", "ssh-config"}}},
	{label: "Another file", detail: ".pgpass, my.cnf, a .env file or another ssh config", cmd: "import", noItem: true},
	{label: "A list exported from komando", detail: "From another computer", cmd: "import", fill: []string{"komando"}},
}

var historyTasks = []menuTask{
	{label: "What changed lately", detail: "The last 20 changes and who asked for them", line: [][]string{{"audit", "--limit", "20"}}},
	{label: "Put a file back", detail: "From the backup a change kept", cmd: "fs restore", noItem: true},
	{label: "Undo a cluster rollout", cmd: "cluster rollback", noItem: true},
	{label: "Check the history is untouched", detail: "Nobody edited or cut it", line: [][]string{{"audit", "verify"}}},
}

func settingsTasks() []menuTask {
	return []menuTask{
		{label: "AI agent", detail: "Install, reinstall or remove komando's rules", sub: []menuTask{
			{label: "Install or reinstall", detail: "Claude Code, Codex, Cursor, Gemini CLI", line: [][]string{{"guide", "install"}}},
			{label: "Remove", line: [][]string{{"guide", "uninstall"}}},
		}},
		{label: "Saved passwords", sub: []menuTask{
			{label: "List them", line: [][]string{{"secret", "list"}}},
			{label: "Save a password", cmd: "secret set", noItem: true},
			{label: "Is a password saved?", cmd: "secret check", noItem: true},
			{label: "Rename one", cmd: "secret mv", noItem: true},
			{label: "Copy one", cmd: "secret cp", noItem: true},
			{label: "Delete one", cmd: "secret rm", noItem: true},
			{label: "Keep them in the system keychain", cmd: "secret keychain", noItem: true},
			{label: "Change the passphrase", cmd: "secret passphrase", noItem: true},
		}},
		{label: "Production servers", detail: "komando asks you before every change on them", sub: []menuTask{
			{label: "Protect or unprotect a server", cmd: "host edit", noItem: true, only: []string{"protected"}},
			{label: "Protect or unprotect a service", cmd: "conn edit", noItem: true, only: []string{"protected"}},
			{label: "Ask for a code in the approval window", cmd: "config approval-code", noItem: true},
		}},
		{label: "Blocked commands", sub: []menuTask{
			{label: "List them", line: [][]string{{"policy", "list"}}},
			{label: "Is a command blocked?", cmd: "policy check", noItem: true},
			{label: "Block a command", cmd: "policy deny", noItem: true},
			{label: "Unblock a command", cmd: "policy rm", noItem: true},
		}},
		{label: "SSH keys", sub: []menuTask{
			{label: "List them", line: [][]string{{"key", "list"}}},
			{label: "Make a new key", cmd: "key gen", noItem: true},
			{label: "Bring in a key file", cmd: "key add", noItem: true},
			{label: "Put a key on a server", cmd: "key deploy", noItem: true},
			{label: "Take a key off a server", cmd: "key revoke", noItem: true},
			{label: "Show a key", cmd: "key show", noItem: true},
			{label: "Change a key", cmd: "key edit", noItem: true},
			{label: "Rename a key", cmd: "key mv", noItem: true},
			{label: "Delete a key", cmd: "key rm", noItem: true},
		}},
		{label: "Cloud logins", sub: []menuTask{
			{label: "Log in to AWS", line: [][]string{{"login", "aws"}}},
		}},
		{label: "Rename several", detail: "Change the start of many names at once", cmd: "rename", noItem: true},
		{label: "Check my setup", detail: "This computer, your list and its safety", line: [][]string{{"doctor"}}},
		{label: "Export my list", detail: "To move it to another computer", cmd: "export", noItem: true},
		{label: "Settings", sub: []menuTask{
			{label: "Show them", line: [][]string{{"config", "show"}}},
			{label: "Read one", cmd: "config get", noItem: true},
			{label: "Change one", cmd: "config set", noItem: true},
		}},
		{label: "Update komando", cmd: "update", noItem: true},
		{label: "Version", line: [][]string{{"version"}}},
	}
}

// menuRunningRows is what komando left running, each with the command
// that stops it.
func menuRunningRows(st *store.State) []menuTask {
	var rows []menuTask
	for _, n := range sortedKeys(st.Sessions) {
		if menuVpnUp(st, n) && validName("vpn", n) == nil {
			rows = append(rows, menuTask{label: "VPN " + n, detail: "connected; choose to disconnect",
				line: [][]string{{"vpn", "down", n}}, confirm: "Disconnect " + n + "?", yes: "Disconnect"})
		}
	}
	for _, n := range sortedKeys(st.Logins) {
		if validName("host", n) == nil {
			rows = append(rows, menuTask{label: "Login to " + n, detail: "choose to log out", line: [][]string{{"logout", n}}})
		}
	}
	for _, id := range sortedKeys(st.Tunnels) {
		tn := st.Tunnels[id]
		rows = append(rows, menuTask{label: "Tunnel " + cleanText(id), detail: cleanText(tn.Host + " " + tn.Spec + "; choose to stop it"),
			line: [][]string{{"tunnel", "stop", id}}})
	}
	for _, id := range sortedKeys(st.Jobs) {
		j := st.Jobs[id]
		if !menuJobRunning(st, j) {
			continue
		}
		rows = append(rows, menuTask{label: "Job " + cleanText(id), detail: cleanText(j.Host + ": " + j.Command + "; choose to stop it"),
			line: [][]string{{"job", "kill", id}}, confirm: "Stop job " + cleanText(id) + " on " + cleanText(j.Host) + "?", yes: "Stop it"})
	}
	return rows
}

// menuJobRunning is whether a job may still run: its server is still on
// the list and no check has seen it end. The menu never connects to find
// out; `job list --refresh` (Check which jobs still run) does.
func menuJobRunning(st *store.State, j *store.Job) bool {
	_, ok := st.Hosts[j.Host]
	return ok && j.Ended == ""
}

// runningTasks come first on Running now.
var runningTasks = []menuTask{
	{label: "Show it all", detail: "VPNs, logins, tunnels and jobs", line: [][]string{{"status"}}},
	{label: "Port forwards", line: [][]string{{"tunnel", "list"}}},
	{label: "Check which jobs still run", detail: "Asks each server; finished jobs leave this list", line: [][]string{{"job", "list", "--refresh"}}},
	{label: "Background jobs", sub: jobTasks},
}

// menuRunning is the Running now screen: everything at once, then each
// thing with a way to stop it.
func menuRunning(ctx context.Context, t *menuTerm, st *store.State, mem *menuMemory, scr menuScreen, try formTry) (menuNext, error) {
	tasks := append(slices.Clone(runningTasks), menuRunningRows(st)...)
	return menuTaskList(ctx, t, st, mem, scr, "Running now: what do you want to stop?", "", tasks, menuHelpRunning, try)
}

// menuCLIOnly are the commands the menu has no row for, and why: they are
// for scripts, agents or shells, or the menu must never offer them.
var menuCLIOnly = map[string]string{
	"ssh-gate":              "sshd runs it",
	"ssh-gate line":         "set up once by hand",
	"prompt":                "for the shell prompt",
	"completion bash":       "for the shell",
	"completion fish":       "for the shell",
	"completion powershell": "for the shell",
	"completion zsh":        "for the shell",
	"schema":                "for scripts and agents",
	"guide":                 "for AI agents",
	"list":                  "the menu is the list",
	"host list":             "the menu is the list",
	"conn list":             "the menu is the list",
	"vpn list":              "the menu is the list",
	"conn kinds":            "Add something lists the kinds",
	"secret get":            "--reveal is for a person typing it",
	"host export":           "Export my list does the same",
	"host import":           "A list exported from komando reads the whole export; My SSH servers reads ~/.ssh/config",
	"host trust":            "a changed identity can be an attack; the menu never offers to trust it",
}
