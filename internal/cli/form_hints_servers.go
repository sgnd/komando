package cli

// The questions for the Servers area: commands, logs, services, packages,
// users, cron, Docker, network and certificate checks.

func init() {
	addFormHints(srvRunHints)
	addFormHints(srvSvcHints)
	addFormHints(srvPkgHints)
	addFormHints(srvUserCronHints)
	addFormHints(srvDockerHints)
	addFormHints(srvNetHints)
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
	// journalctl takes -1h (or today), docker logs 1h; logs and docker logs
	// drop a leading -, so -1h works for both.
	srvSince = formFlag{name: "since", ask: "From how long ago?", example: "-1h",
		help: "-30m or -2h means that long ago; the journal (a service or the whole system) also takes today or 2026-01-02 10:00. Leave empty for the latest lines."}
	srvUntil = formFlag{name: "until", ask: "Up to when?", example: "-10m",
		help: "Like -10m (ten minutes ago), or a time like 2026-01-02 11:00. Leave empty for up to now."}
	srvJournalSince = formFlag{name: "since", ask: "From how long ago?", example: "-1h",
		help: "Like -30m, -2h, today, yesterday or 2026-01-02 10:00. Leave empty for the latest lines."}
	srvDockerSince = formFlag{name: "since", ask: "From how long ago?", example: "1h",
		help: "Like 30m or 2h (that long ago), or a time like 2026-01-02T10:00:00. Leave empty for the latest lines."}
	srvGrep = formFlag{name: "grep", ask: "Only lines that contain a word?",
		help: "Big and small letters count the same. Several words: error|fail. Leave empty for every line.", example: "error"}
	srvLogSudo = formFlag{name: "sudo", ask: "Read with sudo (as root)?",
		help: "Say yes for the whole system journal or a log file only root may read."}
	srvUnit = formArg{ask: "Which service?", example: "nginx",
		help: "Its name as systemd knows it, like nginx or ssh. `komando svc list` shows them."}
	srvUnits = formArg{ask: "Which services?", example: "nginx",
		help: "Their names as systemd knows them, like nginx or ssh. Several: separate them with spaces. `komando svc list` shows them."}
	srvWait = formFlag{name: "wait", ask: "How long to wait for them to be running?",
		help: "Like 10s or 2m. It fails when a service is not running by then. Leave empty to not wait.", example: "10s"}
	srvPkgs = formArg{ask: "Which packages?", example: "htop jq",
		help: "Their names as the server's package manager (apt, dnf, apk ...) knows them. Several: separate them with spaces."}
	srvPkgsAll = formArg{ask: "Which packages? (leave empty for all)", example: "nginx openssl",
		help: "Several: separate them with spaces."}
	srvUsername = formArg{ask: "Which user?", example: "alice",
		help: "The account name on the server. `komando user list` shows them."}
	srvCronUser = formFlag{name: "user", ask: "Whose crontab?",
		help: "Leave empty for the user komando logs in as. Another user's crontab is read with sudo.", example: "www-data"}
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

// srvWithShow is f asked only while show says true.
func srvWithShow(f formFlag, show func(formAnswers) bool) formFlag {
	f.show = show
	return f
}

var srvRunHints = map[string]formHint{
	"exec": {
		args: []formArg{srvServers, {ask: "What command should it run?", example: "df -h /",
			help: "Type it as you would on the server itself, pipes and all."}},
		flags: []formFlag{srvSudo, srvReadOnly, srvDir},
		hide:  []string{"cmd"},
	},
	"shell": {
		args: []formArg{{ask: "Which server?", pick: "server",
			help: "One server. You type on it as if you were there; type exit to come back."}},
	},
	"facts": {args: []formArg{srvServers}},
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
	"reboot": {args: []formArg{srvServers}},
	"script": {
		args: []formArg{srvServers, {ask: "Which script on this computer?", example: "./deploy.sh", local: true,
			help: "A file on this computer. komando sends it to the server and runs it there."}},
		flags: []formFlag{srvSudo, srvReadOnly,
			{name: "arg", ask: "Anything to pass to the script?", example: "v1.2.3",
				help: "One value the script gets as its first argument. Leave empty for none."}},
	},
}

var srvSvcHints = map[string]formHint{
	"svc daemon-reload": {args: []formArg{srvServers}},
	"svc disable": {args: []formArg{srvServers, srvUnits}, flags: []formFlag{
		{name: "now", ask: "Also stop them now?", help: "No only keeps them from starting at the next boot."}}},
	"svc enable": {args: []formArg{srvServers, srvUnits}, flags: []formFlag{
		{name: "now", ask: "Also start them now?", help: "No only makes them start at the next boot."}}},
	"svc list": {args: []formArg{srvServers}, flags: []formFlag{
		{name: "state", ask: "Only services in one state?", choices: []string{"running", "exited", "failed", "inactive"},
			help: "Running are up now, exited ran once and finished, inactive are stopped."}}},
	"svc logs": {args: []formArg{srvServers, srvUnit},
		flags: []formFlag{srvJournalSince, srvGrep, srvLogSudo}},
	"svc reload":  {args: []formArg{srvServers, srvUnits}, flags: []formFlag{srvWait}},
	"svc restart": {args: []formArg{srvServers, srvUnits}, flags: []formFlag{srvWait}},
	"svc start":   {args: []formArg{srvServers, srvUnits}, flags: []formFlag{srvWait}},
	"svc status":  {args: []formArg{srvServers, srvUnits}},
	"svc stop":    {args: []formArg{srvServers, srvUnits}},
}

var srvPkgHints = map[string]formHint{
	"pkg install":   {args: []formArg{srvServers, srvPkgs}},
	"pkg installed": {args: []formArg{srvServers, srvPkgsAll}},
	"pkg rm":        {args: []formArg{srvServers, srvPkgs}},
	"pkg security": {args: []formArg{srvServers}, flags: []formFlag{
		{name: "refresh", ask: "Refresh the package list first?",
			help: "Yes asks the package sources what is new, so the list is current."},
		{name: "apply", ask: "Install the security updates now?",
			help: "No only lists them. Yes installs them, one server at a time."}}},
	"pkg update": {args: []formArg{srvServers}},
	"pkg upgradable": {args: []formArg{srvServers, srvPkgsAll}, flags: []formFlag{
		{name: "refresh", ask: "Refresh the package list first?",
			help: "Yes asks the package sources what is new, so the list is current."}}},
	"pkg upgrade": {args: []formArg{srvServers, srvPkgsAll}},
}

var srvUserCronHints = map[string]formHint{
	"user add": {
		args: []formArg{srvServers, {ask: "What is the new user's name?", example: "deploy",
			help: "Small letters, digits, - and _. Nothing happens when the user is there already."}},
		flags: []formFlag{
			{name: "key", pick: "key", ask: "Which of your komando keys may log in as this user?",
				help: "Leave empty to add no key. `komando key list` shows your keys."},
			{name: "admin", ask: "Make this user an admin (allowed to use sudo)?"},
		},
	},
	"user list": {args: []formArg{srvServers}, flags: []formFlag{
		{name: "all", ask: "Include system accounts too?", help: "Accounts programs use, like www-data. No shows only people."}}},
	"user lock": {args: []formArg{srvServers, srvUsername}},
	"user rm": {args: []formArg{srvServers, srvUsername}, flags: []formFlag{
		{name: "remove-home", ask: "Also delete their home folder and files?", help: "Files deleted this way cannot be brought back."}}},
	"user unlock": {args: []formArg{srvServers, srvUsername}},
	"cron list":   {args: []formArg{srvServers}, flags: []formFlag{srvCronUser}},
	"cron rm": {args: []formArg{srvServers, {ask: "Which entry?", example: "nightly-backup",
		help: "Its ID: the last column of `komando cron list`."}}, flags: []formFlag{srvCronUser}},
	"cron set": {
		args: []formArg{srvServers,
			{ask: "What name should this entry have?", example: "nightly-backup",
				help: "A short name komando finds it by later. A name used before replaces that entry."},
			{ask: "What command should it run?", example: "/usr/local/bin/backup.sh",
				help: "Type it as you would on the server itself."}},
		flags: []formFlag{
			{name: "schedule", required: true, ask: "When should it run?", example: "0 2 * * *",
				help: "@hourly, @daily, @weekly, @monthly or @reboot, or five fields (minute hour day month weekday): 0 2 * * * is every night at 2:00."},
			srvCronUser,
		},
	},
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

var srvNetHints = map[string]formHint{
	"net check": {args: []formArg{srvServers, {ask: "Which address and port should it try to reach?", example: "db.internal:5432",
		help: "Tried from the server, not from this computer. Several: separate them with spaces."}}},
	"net dns": {args: []formArg{srvServers, {ask: "Which name should it look up?", example: "db.internal",
		help: "Looked up from the server, so you see what the server sees."}},
		flags: []formFlag{{name: "type", ask: "Which kind of record?", choices: []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "PTR", "CAA", "SOA"},
			help: "Leave empty for the addresses the server would connect to. MX is mail, TXT is text notes."}}},
	"net http": {args: []formArg{srvServers, {ask: "Which web address?", example: "http://localhost:8080/health",
		help: "Opened from the server, so localhost means the server itself."}},
		flags: []formFlag{{name: "expect", ask: "Which answer counts as good?", example: "200",
			help: "A status like 200, or 2xx for any success. Leave empty to only report it."}}},
	"net ports": {args: []formArg{srvServers}, flags: []formFlag{
		{name: "sudo", ask: "Use sudo to see which program owns each port?"}}},
	"cert check": {
		args: []formArg{{ask: "Which servers or websites?", pick: "host", free: true, example: "https://shop.example.com",
			help: "Pick a server, or type a website. Several: separate them with spaces."}},
		flags: []formFlag{{name: "warn", ask: "Warn how long before a certificate ends?", example: "30d",
			help: "Warns 30 days before. Empty keeps that. Or type 14d or 72h."}},
	},
}
