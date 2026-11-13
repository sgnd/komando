package cli

// The questions for your list (servers, conns, groups, import, export,
// test), jobs and recipes, safety and audit, and setup. host add, conn add
// and vpn add have hand-made forms (form_kinds.go).

func init() {
	addFormHints(invHostHints)
	addFormHints(invConnHints)
	addFormHints(invListHints)
	addFormHints(invJobHints)
	addFormHints(invRecipeHints)
	addFormHints(invSafetyHints)
	addFormHints(invSetupHints)
}

// Answers several hints share.
var (
	invServer = formArg{ask: "Which server?", pick: "server",
		help: "Pick one from your list."}
	invServers = formArg{ask: "Which servers?", pick: "host", free: true,
		help: "Pick one from your list, or type @group, tag:prod or several names separated by spaces or commas."}
	invConn = formArg{ask: "Which conn?", pick: "conn",
		help: "A database, cache, queue, file storage, cluster or registry in your list."}
	invConns = formArg{ask: "Which conns?", pick: "conn", free: true,
		help: "Pick one from your list, or type @group, tag:prod or several names separated by commas."}
	invTargets = formArg{ask: "Which ones?", pick: "target", free: true,
		help: "A server, conn or VPN from your list, or @group, tag:prod, or several names separated by spaces or commas."}
	invTargetsAll = formArg{ask: "Which ones? (pick all for everything)", pick: "target", free: true,
		help: "A server, conn or VPN from your list, or @group, tag:prod, or several names separated by spaces or commas."}
	invNewName = formArg{ask: "What should the new name be?", example: "web2",
		help: "Letters, digits, dot, dash and underscore, starting with a letter or digit."}
	invJob = formArg{ask: "Which job?", pick: "job", free: true,
		help: "A job started with `komando job start`. `komando job list` shows them."}
	invJobs = formArg{ask: "Which jobs?", pick: "job", free: true,
		help: "Several: separate them with spaces. `komando job list` shows them."}
	invGroupNew = formArg{ask: "Which group?", pick: "group", free: true, example: "web",
		help: "Pick one, or type a new name to make a new group."}
	invGroup = formArg{ask: "Which group?", pick: "group",
		help: "A group is a name you give to several servers, conns and VPNs, like web or prod."}
	invRecipe = formArg{ask: "Which recipe?", example: "health",
		help: "Its name. `komando recipe list` shows the built-in ones (health, disk, memory ...) and yours."}
	invSudo = formFlag{name: "sudo", ask: "Run it with sudo (as root)?",
		help: "Say yes when it needs admin rights, like changing system files or services."}
	invReadOnly = formFlag{name: "read-only", ask: "Does it only look, without changing anything?",
		help: "Yes lets it run on a production server without asking you first. Say yes only when that is true."}
	invAddGroup = formFlag{name: "add-group", ask: "Add it to a group?", pick: "group",
		help: "A group lets you pick many at once with @name. Leave empty for none.", example: "web"}
	invNotes = formFlag{name: "notes", ask: "Any notes to keep with it?",
		help:    "Free text, like who owns it or what runs there. AI agents read it too. Leave empty to keep the old notes.",
		example: "main shop database"}
	invAskPassword = formFlag{name: "ask-password", ask: "Change the password?",
		help: "Yes makes the command ask for it, hidden, when it runs. It is saved as a saved password, never on the command line."}
	invProtected = formFlag{name: "protected", ask: "Can a mistake on it hurt real users or real data?", keep: true,
		help: "Yes means komando asks you before every change there, also changes an AI agent wants to make. No takes that away."}
	invVia = formFlag{name: "via", ask: "Reach it through which server or VPN?", example: "bastion",
		help: "The name of a server or VPN in your list, when it only answers inside that network. Leave empty to keep how it is reached now."}
	invWait = formFlag{name: "wait", ask: "Keep trying for how long?",
		help:    "Like 2m: it tests again every few seconds until everything answers, handy right after a server starts. Leave empty to test once.",
		example: "2m"}
	invOverwrite = formFlag{name: "overwrite", ask: "Replace entries that have the same name?",
		help: "No skips a name that is in your list already."}
	invImportGroup = formFlag{name: "group", ask: "Put everything it adds in a group?", pick: "group",
		help: "A group lets you pick them all later with @name. Leave empty for none.", example: "imported"}
	invProject = formFlag{name: "project", ask: "Only for the folder you are in now?",
		help: "No is for every project of your user (your home folder). Yes is for this folder only."}
)

var invHostHints = map[string]formHint{
	"host": {},
	"host edit": {
		args: []formArg{invServers},
		flags: []formFlag{
			{name: "address", ask: "New address?", example: "203.0.113.20",
				help: "The server's IP address or host name. Leave empty to keep it."},
			{name: "user", ask: "New login user?", example: "deploy",
				help: "The user name you log in with. Leave empty to keep it."},
			{name: "port", ask: "New SSH port?", example: "2222",
				help: "Usually 22. Leave empty to keep it."},
			invAskPassword,
			{name: "key", ask: "Log in with which key from komando's key list?", pick: "key",
				help: "`komando key list` shows them. Leave empty to keep how it logs in now."},
			invProtected, invVia, invAddGroup, invNotes,
		},
		hide: []string{"group", "tag"},
	},
	"host list": {args: []formArg{{ask: "Which servers? (pick all for every server)", pick: "host", free: true,
		help: "Pick one, or type @group, tag:prod or several names separated by spaces or commas."}}},
	"host rename": {args: []formArg{{ask: "Which server do you want to rename?", pick: "server",
		help: "Groups, notes and everything else that names it are changed too."}, invNewName}},
	"host rm": {args: []formArg{{ask: "Which servers should come off your list?", pick: "host", free: true,
		help: "Only komando's list changes; the servers themselves are not touched."}}},
	"host show":        {args: []formArg{invServer}},
	"host ssh-command": {args: []formArg{invServer}},
	"host test":        {args: []formArg{invServers}, flags: []formFlag{invWait}},
	"host trust": {
		args: []formArg{invServers},
		flags: []formFlag{{name: "reset", ask: "Replace a key komando saved before?",
			help: "Only after you rebuilt or reinstalled the server. A changed key can also mean someone pretends to be your server: ask its admin first."}},
	},
}

var invConnHints = map[string]formHint{
	"conn": {},
	"conn edit": {
		args: []formArg{invConn},
		flags: []formFlag{
			{name: "url", ask: "New address (URL)?", example: "postgres://app@10.0.0.5:5432/shop",
				help: "Like the one you added it with, without the password. Leave empty to keep it."},
			invAskPassword, invProtected,
			invVia, invAddGroup, invNotes,
		},
		hide: []string{"group", "tag"},
	},
	"conn kinds": {},
	"conn list": {args: []formArg{{ask: "Which conns? (leave empty for all)", pick: "conn", free: true,
		help: "Pick one, or type @group, kind:postgres or several names separated by commas."}}},
	"conn rename": {args: []formArg{{ask: "Which conn do you want to rename?", pick: "conn",
		help: "Groups, notes and everything else that names it are changed too."}, invNewName}},
	"conn rm": {args: []formArg{{ask: "Which conns should come off your list?", pick: "conn", free: true,
		help: "Only komando's list changes; the database, bucket or cluster itself is not touched."}}},
	"conn show": {args: []formArg{invConn}},
	"conn test": {args: []formArg{invConns}, flags: []formFlag{invWait}},
}

var invListHints = map[string]formHint{
	"list": {args: []formArg{invTargetsAll}},
	"test": {args: []formArg{invTargets}, flags: []formFlag{invWait}},
	"rename": {
		args: []formArg{
			{ask: "Which start of the names should change?", example: "shop-",
				help: "Every name that starts with it is renamed: shop-web and shop-db with shop-."},
			{ask: "What should they start with instead?", example: "acme-shop-",
				help: "shop-web becomes acme-shop-web."},
		},
		always: []string{"--starts-with"},
		hide:   []string{"starts-with"},
		flags: []formFlag{
			{name: "in-notes", ask: "Also change the old names in notes?",
				help: "Yes changes them in the notes of servers, conns, VPNs and secrets too."},
		},
	},
	"import": {
		args: []formArg{
			{ask: "What do you want to bring in?", example: "ssh-config", choices: importSourceNames(),
				help: "One of: ssh-config, pgpass, mycnf, env, kubeconfig, docker, filezilla, rclone, aws, dbeaver, komando (a file from komando export), csv."},
			{ask: "From which file? (leave empty for the usual place)", example: "./app/.env", local: true,
				help: "Empty reads the usual file, like ~/.ssh/config. komando and csv need a file."},
		},
		flags: []formFlag{invImportGroup, invOverwrite},
	},
	"export": {
		args: []formArg{invTargetsAll},
		flags: []formFlag{
			{name: "to", ask: "Save it to which file?", example: "komando-backup.json", local: true,
				help: "A file on this computer, only you may read it. Passwords are never in it. Leave empty to show it on screen."},
			{name: "overwrite", ask: "Replace that file if it is there already?"},
		},
	},
	"group": {},
	"group add": {args: []formArg{invGroupNew, {ask: "What goes in it?", pick: "target", free: true,
		help: "A server, conn or VPN, or tag:prod or several names separated by spaces or commas."}}},
	"group list": {args: []formArg{{ask: "Which group? (leave empty for all)", pick: "group", free: true,
		help: "Empty lists every group and tag with what is in it."}}},
	"group rename": {args: []formArg{invGroup, {ask: "What should the new name be?", example: "web-prod",
		help: "Letters, digits, dot, dash and underscore."}}},
	"group rm": {args: []formArg{invGroup, {ask: "What should come out of it? (leave empty to delete the group)",
		pick: "target", free: true,
		help: "Empty deletes the group itself; the servers, conns and VPNs in it stay in your list."}}},
}

var invJobHints = map[string]formHint{
	"job": {},
	"job start": {
		next: []string{"job list", "job status JOB"},
		args: []formArg{invServers, {ask: "What command should it run?", example: "apt-get -y upgrade",
			help: "A long task that keeps running when your connection drops. Type it as you would on the server."}},
		flags: []formFlag{invSudo, invReadOnly,
			{name: "dir", ask: "In which folder on the server should it run?",
				help: "Leave empty for the login user's home folder.", example: "/srv/app"}},
		hide: []string{"cmd"},
	},
	"job list": {flags: []formFlag{
		{name: "target", ask: "Only the jobs on which servers?", pick: "host",
			help: "Leave empty for every job komando knows."},
		{name: "refresh", ask: "Ask the servers whether each job still runs?",
			help: "No shows what komando saw last time, which is quicker."}}},
	"job status": {args: []formArg{invJob}, flags: []formFlag{
		{name: "tail", ask: "How many of its last output lines to show?", example: "20",
			help: "0 shows none."}}},
	"job logs": {args: []formArg{invJob}, flags: []formFlag{
		{name: "limit", ask: "Only the last how many lines?", example: "50",
			help: "Leave empty to read the output from the start."}}},
	"job wait": {args: []formArg{invJobs}},
	"job kill": {args: []formArg{invJob}, flags: []formFlag{
		{name: "signal", ask: "How should it stop?", choices: []string{"TERM", "INT", "HUP", "KILL"},
			help: "TERM asks it to stop and clean up. KILL stops it at once, use it when TERM did not work."},
		{name: "sudo", ask: "Was the job started with sudo?",
			help: "Then stopping it needs sudo too."}}},
	"job rm": {args: []formArg{invJobs}, flags: []formFlag{
		{name: "kill", ask: "Stop it first if it still runs?",
			help: "No refuses to remove a job that still runs."}}},
}

var invRecipeHints = map[string]formHint{
	"recipe":      {},
	"recipe list": {},
	"recipe run": {
		args: []formArg{invRecipe, invServers},
		flags: []formFlag{
			{name: "var", ask: "Fill in a blank?", example: "path=/var",
				help: "Some recipes have blanks, like path for big-dirs: NAME=VALUE. `komando recipe list` shows them. Leave empty for the defaults."},
			{name: "no-sudo", ask: "Run it without sudo?",
				help: "Yes when the recipe asks for sudo but you may not use it there."},
		},
	},
	"recipe add": {
		args: []formArg{
			{ask: "What do you want to call this recipe?", example: "app-logs",
				help: "A short name you run later, like komando recipe run app-logs web1."},
			{ask: "What command should it run?", example: "tail -n {{lines=100}} /srv/app/app.log",
				help: "Type it as you would on the server. {{name}} is a blank you fill in when you run it; {{name=100}} has a default."},
		},
		flags: []formFlag{
			{name: "desc", ask: "What does it do, in a few words?", example: "Last lines of the app log"},
			{name: "needs-sudo", ask: invSudo.ask, help: invSudo.help},
			{name: "read-only", ask: "Does it only look, without changing anything?",
				help: "Yes lets it run on a production server without asking you first. Say yes only when that is true."},
		},
	},
	"recipe rm": {args: []formArg{{ask: "Which of your saved recipes should go?", example: "app-logs",
		help: "Built-in recipes cannot be removed. `komando recipe list --category saved` shows yours."}}},
}

var invSafetyHints = map[string]formHint{
	"audit": {flags: []formFlag{
		{name: "since", ask: "From when?", example: "today",
			help: "Like 2h, 7d, today or 2026-11-07. Leave empty for the newest entries."},
		{name: "target", ask: "Only for which servers or conns?", pick: "target",
			help: "Leave empty for everything."},
		{name: "failed", ask: "Only what failed or was blocked?"},
		{name: "actor", ask: "Only what one person or AI agent did?", example: "claude",
			help: "Part of the name, like claude or codex. Leave empty for everyone."},
	}},
	"audit verify": {},
	"doctor":       {},
	"status":       {},
	"policy":       {},
	"policy list":  {},
	"policy check": {args: []formArg{{ask: "Which command do you want to check?", example: "rm -rf /",
		help: "komando says whether it would refuse to run it. Nothing runs."}}},
	"policy deny": {args: []formArg{{ask: "Which command should komando block?", example: `kubectl\s+delete`,
		help: `Like kubectl delete: write it as kubectl\s+delete (\s+ means spaces, .* means anything). Then check it with komando policy check "kubectl delete pod web".`}}},
	"policy rm": {args: []formArg{{ask: "Which of your own rules should go?", example: "custom-1a2b3c4d",
		help: "Its id (custom-1a2b3c4d ...) or the pattern as you wrote it. `komando policy list` shows them. Built-in rules always stay."}}},
	"config":      {},
	"config show": {},
	"config get": {args: []formArg{{ask: "Which setting?", example: "parallel", choices: settingKeys(),
		help: "`komando config show` lists them: parallel, default_timeout, host_key_policy, audit ..."}}},
	"config set": {args: []formArg{
		{ask: "Which setting?", example: "default_timeout", choices: settingKeys(),
			help: "`komando config show` lists them with the values each one takes."},
		{ask: "What should it be?", example: "10m",
			help: "Like 20 for parallel, 10m for default_timeout, strict for host_key_policy."}}},
	"config approval-code": {flags: []formFlag{{name: "off", ask: "Turn the approval code off?",
		help: "No sets it up: the approval window then also asks for a code from an authenticator app on your phone."}}},
	"ssh-gate": {skip: true}, // sshd runs it for a key; a person runs ssh-gate line
	"ssh-gate line": {
		args: []formArg{{ask: "Which public key?", example: "~/phone.pub", local: true,
			help: "The .pub file of the key (on this computer), or its line: ssh-ed25519 AAAA... phone. Never the private key."}},
		flags: []formFlag{
			{name: "name", ask: "What do you want to call this key?", example: "phone", required: true,
				help: "It shows in `komando audit` for every command the key runs. Letters, digits, dot, dash, underscore."},
			{name: "read-only", ask: "Should the key only run commands that look, without changing anything?",
				help: "Yes is safer for a phone or a shared key."},
		},
	},
}

var invSetupHints = map[string]formHint{
	"guide":                 {},
	"guide install":         {flags: []formFlag{invProject}, hide: []string{"no-guard"}},
	"guide uninstall":       {flags: []formFlag{invProject}},
	"version":               {},
	"update":                {args: []formArg{{ask: "Which version? (leave empty for the newest)", example: "v0.6.0", help: "Empty installs the newest release."}}},
	"schema":                {args: []formArg{{ask: "For which command? (leave empty for all)", example: "db query", help: "Its words, like db query. The list is for programs and AI agents."}}},
	"completion bash":       {},
	"completion fish":       {},
	"completion powershell": {},
	"completion zsh":        {},
}

// importSourceNames are the values import SOURCE takes, so a person picks
// one instead of typing it (config get/set KEY use settingKeys).
func importSourceNames() []string {
	var n []string
	for _, s := range importSources {
		n = append(n, s.Name)
	}
	return n
}

// Next: lines for your list, jobs, safety and setup (core, server and
// release areas): what a person usually runs after each command.
func init() {
	addFormHints(map[string]formHint{
		"host edit":    {next: []string{"host show {}", "test {}"}},
		"import":       {next: []string{"list", "test all"}},
		"group add":    {next: []string{"list @{}", "test @{}"}},
		"group rm":     {next: []string{"group add {} TARGET..."}}, // to put them back
		"job status":   {next: []string{"job logs {} --limit 50", "job wait {}", "job kill {}"}},
		"job wait":     {next: []string{"job logs {} --limit 50", "job rm {}"}},
		"job kill":     {next: []string{"job status {}", "job rm {}"}},
		"job list":     {next: []string{"job list --refresh", "job status JOB", "job rm JOB"}},
		"policy deny":  {next: []string{"policy check 'COMMAND'", "policy list", "policy rm RULE"}},
		"policy check": {next: []string{"policy list"}},
		"audit":        {next: []string{"audit verify", "audit --failed"}},
		"update":       {next: []string{"guide install", "version"}},
	})
}
