package cli

// The questions for the Servers area: commands, logs, packages, Docker and
// certificate checks.

func init() {
	addFormHints(srvRunHints)
	addFormHints(srvPkgHints)
	addFormHints(srvDockerHints)
	addFormHints(srvCertHints)
}

// Answers several hints share.
var (
	srvServers = formArg{ask: "Which server?", pick: "host", free: true,
		help: "Pick one from your list, or type @group, tag:prod or several names separated by spaces or commas."}
	srvSudo = formFlag{name: "sudo", ask: "Run it with sudo (as root)?",
		help: "Say yes when it needs admin rights, like changing system files or services."}
	srvReadOnly = formFlag{name: "read-only", ask: "Does it only look, and change nothing on the server?",
		help: "Not sure? Say no. Yes is only for commands that read, like df -h or cat."}
	srvDir = formFlag{name: "dir", ask: "In which folder on the server should it run?",
		help: "Leave empty for the login user's home folder.", example: "/srv/app"}
	// a time back from now is 1h for every source (komando writes -1h for
	// journalctl itself)
	srvSince = formFlag{name: "since", ask: "From how long ago?", example: "1h",
		help: "30m or 2h means that long ago; the journal (a service or the whole system) also takes today or 2026-01-02 10:00. Leave empty for the latest lines."}
	srvUntil = formFlag{name: "until", ask: "Up to when?", example: "10m",
		help: "Like 10m (ten minutes ago), or a time like 2026-01-02 11:00. Leave empty for up to now."}
	srvDockerSince = formFlag{name: "since", ask: "From how long ago?", example: "1h",
		help: "Like 30m or 2h (that long ago), or a time like 2026-01-02T10:00:00. Leave empty for the latest lines."}
	srvGrep = formFlag{name: "grep", ask: "Only lines that contain a word?",
		help: "Big and small letters count the same. Several words: error|fail. Leave empty for every line.", example: "error"}
	srvLogSudo = formFlag{name: "sudo", ask: "Read with sudo (as root)?",
		help: "Say yes for the whole system journal or a log file only root may read."}
	srvPkgs = formArg{ask: "Which packages?", example: "htop jq",
		help: "Their names as the server's package manager (apt, dnf, apk ...) knows them. Several: separate them with spaces."}
	srvPkgsAll = formArg{ask: "Which packages? (leave empty for all)", example: "nginx openssl",
		help: "Several: separate them with spaces."}
	srvDockerSudo = formFlag{name: "sudo", ask: "Run docker with sudo?",
		help: "Say yes when docker says permission denied (your login user is not in the docker group)."}
	srvContainer = formArg{ask: "Which container?", example: "api",
		help: "Its name or ID. `komando docker ps` shows them."}
	srvContainers = formArg{ask: "Which containers?", example: "api worker",
		help: "Their names or IDs. Several: separate them with spaces. `komando docker ps` shows them."}
)

// The logs command takes one source: the file and container questions
// come only while no source was given, and a file has no time to filter on.
func srvNoUnit(a formAnswers) bool     { return a["flag:unit"] == "" }
func srvNoUnitFile(a formAnswers) bool { return a["flag:unit"] == "" && a["flag:file"] == "" }
func srvNoFile(a formAnswers) bool     { return a["flag:file"] == "" }

// exec runs a command, or with no command a script file from here.
func srvNoCommand(a formAnswers) bool  { return a["arg1"] == "" }
func srvWithScript(a formAnswers) bool { return a["flag:script"] != "" }

// srvWithShow is f asked only while show says true.
func srvWithShow(f formFlag, show func(formAnswers) bool) formFlag {
	f.show = show
	return f
}

var srvRunHints = map[string]formHint{
	"exec": {
		args: []formArg{srvServers, {ask: "What command should it run?", example: "df -h /",
			help: "Type it as you would on the server itself, pipes and all. Leave it empty to run a script file from this computer instead.",
			need: func(a formAnswers) bool { return a["flag:script"] == "" }}},
		flags: []formFlag{
			{name: "script", ask: "Which script on this computer?", example: "./deploy.sh", local: true, show: srvNoCommand,
				help: "A file on this computer. komando sends it to the server and runs it there; nothing is left on disk."},
			{name: "arg", ask: "Anything to pass to the script?", example: "v1.2.3", show: srvWithScript,
				help: "One value the script gets as its first argument. Leave empty for none."},
			srvSudo, srvReadOnly, srvDir},
		hide: []string{"cmd"},
	},
	"shell": {
		args: []formArg{{ask: "Which server?", pick: "server",
			help: "One server. You type on it as if you were there; type exit to come back."}},
	},
	"logs": {
		args: []formArg{srvServers},
		flags: []formFlag{
			{name: "unit", ask: "Which service's log?", example: "nginx",
				help: "A systemd service, like nginx or ssh. Leave empty to read a file, a container or the whole system journal."},
			{name: "file", ask: "Or which log file?", example: "/var/log/nginx/error.log", show: srvNoUnit,
				help: "The full path of a log file on the server. Leave empty for the system journal or a container."},
			{name: "container", ask: "Or which Docker container?", example: "api", show: srvNoUnitFile,
				help: "Its name or ID. Leave empty for the whole system journal."},
			srvWithShow(srvSince, srvNoFile), srvWithShow(srvUntil, srvNoFile), srvGrep, srvLogSudo,
		},
	},
}

var srvPkgHints = map[string]formHint{
	"pkg install":   {args: []formArg{srvServers, srvPkgs}},
	"pkg installed": {args: []formArg{srvServers, srvPkgsAll}},
	"pkg rm":        {args: []formArg{srvServers, srvPkgs}},
	"pkg security": {args: []formArg{srvServers}, flags: []formFlag{
		{name: "refresh", ask: "Refresh the package list first?",
			help: "Yes asks the package sources what is new, so the list is current."}}},
	"pkg update": {args: []formArg{srvServers}},
	"pkg upgradable": {args: []formArg{srvServers, srvPkgsAll}, flags: []formFlag{
		{name: "refresh", ask: "Refresh the package list first?",
			help: "Yes asks the package sources what is new, so the list is current."}}},
	"pkg upgrade": {args: []formArg{srvServers, srvPkgsAll}, flags: []formFlag{
		{name: "security", ask: "Only the security updates, one server at a time?",
			help: "Yes installs only security fixes and stops when a server comes out of it different. Leave the packages empty then."}}},
}

var srvDockerHints = map[string]formHint{
	"docker compose": {
		args: []formArg{srvServers, {ask: "What should docker compose do?", example: "up -d",
			help: "ps lists the containers, pull gets new images, up -d starts them, logs --tail 50 shows recent output."}},
		flags: []formFlag{
			{name: "dir", ask: "In which folder is the project?", example: "/srv/shop",
				help: "The folder on the server that holds compose.yaml (or docker-compose.yml)."},
			{name: "file", ask: "Which compose file, if it has another name?", example: "compose.prod.yaml",
				help: "Leave empty for the usual compose.yaml in that folder."},
			srvDockerSudo,
		},
	},
	"docker exec": {
		args: []formArg{srvServers, srvContainer,
			{ask: "Which program should run inside it?", example: "php",
				help: "Only the program's name; its words come next. There is no shell: for a pipe, type sh here and -c 'ls | wc -l' next."},
			{ask: "Its words? (leave empty for none)", example: "artisan migrate:status",
				help: "Separate them with spaces. Quotes keep words together: -c 'ls | wc -l' is two words."}},
		flags: []formFlag{srvReadOnly, srvDockerSudo},
	},
	"docker images":  {args: []formArg{srvServers}, flags: []formFlag{srvDockerSudo}},
	"docker inspect": {args: []formArg{srvServers, {ask: "Which container or image?", example: "api", help: "Its name or ID."}}, flags: []formFlag{srvDockerSudo}},
	"docker logs":    {args: []formArg{srvServers, srvContainer}, flags: []formFlag{srvDockerSince, srvGrep}},
	"docker prune": {args: []formArg{srvServers}, flags: []formFlag{
		{name: "all", ask: "Also every image no container uses?",
			help: "No removes only stopped containers, leftover image layers and build cache."},
		{name: "older-than", ask: "Only what is older than?", example: "30d",
			help: "Like 30d or 12h. Leave empty for any age."},
		srvDockerSudo}},
	"docker ps": {args: []formArg{srvServers}, flags: []formFlag{
		{name: "all", ask: "Show stopped containers too?"}, srvDockerSudo}},
	"docker pull": {args: []formArg{srvServers, {ask: "Which images?", example: "nginx:1.27",
		help: "Name and tag, like nginx:1.27. Several: separate them with spaces."}}, flags: []formFlag{srvDockerSudo}},
	"docker raw": {args: []formArg{srvServers, {ask: "What should docker do?", example: "network ls",
		help: "The words after docker, as you would type them on the server."}}, flags: []formFlag{srvDockerSudo}},
	"docker restart": {args: []formArg{srvServers, srvContainers}, flags: []formFlag{srvDockerSudo}},
	"docker rm":      {args: []formArg{srvServers, srvContainers}, flags: []formFlag{srvDockerSudo}},
	"docker start":   {args: []formArg{srvServers, srvContainers}, flags: []formFlag{srvDockerSudo}},
	"docker stats":   {args: []formArg{srvServers}, flags: []formFlag{srvDockerSudo}},
	"docker stop":    {args: []formArg{srvServers, srvContainers}, flags: []formFlag{srvDockerSudo}},
}

var srvCertHints = map[string]formHint{
	"cert check": {
		args: []formArg{{ask: "Which servers or websites?", pick: "host", free: true, example: "https://shop.example.com",
			help: "Pick a server, or type a website. Several: separate them with spaces."}},
		flags: []formFlag{{name: "warn", ask: "Warn how long before a certificate ends?", example: "30d",
			help: "Warns 30 days before. Empty keeps that. Or type 14d or 72h."}},
	},
}

// Next: lines for the server commands (server and ops areas).
func init() {
	addFormHints(map[string]formHint{
		"docker rm":      {next: []string{"docker ps {} --all"}},
		"exec":           {next: []string{"job start {} -- COMMAND", "logs {}"}},
		"logs":           {next: []string{"logs {} --unit UNIT --follow"}},
		"pkg upgradable": {next: []string{"pkg upgrade {} --dry-run", "pkg security {}"}},
		"pkg security":   {next: []string{"pkg upgrade {} --security --dry-run"}},
		"pkg update":     {next: []string{"pkg upgradable {}"}},
		"pkg install":    {next: []string{"pkg installed {} PACKAGE"}},
		"pkg rm":         {next: []string{"pkg installed {} PACKAGE"}},
		"docker ps":      {next: []string{"docker logs {} CONTAINER --since 10m", "docker restart {} CONTAINER", "docker stats {}"}},
		"docker logs":    {next: []string{"docker restart {} CONTAINER", "docker inspect {} CONTAINER"}},
		"docker prune":   {next: []string{"snippet exec disk {}"}},
		"cert check":     {next: []string{"cert check {} --warn 14d"}},
		"snippet list":   {next: []string{"snippet exec NAME TARGET"}},
		"snippet create": {next: []string{"snippet exec {} TARGET --dry-run"}},
		"snippet exec":   {next: []string{"snippet list"}},
	})
}
