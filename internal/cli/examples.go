package cli

// examples gives a real example to the commands whose definition has
// none, so every command shows one in --help and in a usage error
// (docs/design/ux.md, section 10). A command that sets its own Example
// keeps it. TestConventions fails when a command has neither.
var examples = map[string]string{
	// the groups: the usual journey, in order
	"komando svc": "  komando svc list web1 --failed                    # what is broken?\n" +
		"  komando svc status web1 nginx\n" +
		"  komando logs web1 --unit nginx --since 30m        # why?\n" +
		"  komando svc restart web1 nginx --wait 10s --dry-run\n" +
		"  komando svc restart web1 nginx --wait 10s",
	"komando pkg": "  komando pkg upgradable @web --refresh\n" +
		"  komando pkg security @web --apply --dry-run\n" +
		"  komando pkg upgrade web1 --dry-run\n" +
		"  komando pkg install web1 htop jq\n" +
		"  komando pkg rm web1 telnet",
	"komando user": "  komando user list web1\n" +
		"  komando user add web1 alice --key alice --admin\n" +
		"  komando user lock web1 alice                      # keep the account, stop logins\n" +
		"  komando user rm web1 alice --remove-home --dry-run",
	"komando docker": "  komando docker ps web1 --all\n" +
		"  komando docker logs web1 api --since 10m\n" +
		"  komando docker restart web1 api\n" +
		"  komando docker compose web1 --dir /srv/shop -- up -d\n" +
		"  komando docker prune web1 --dry-run               # what would be freed",
	"komando cron": "  komando cron list web1\n" +
		"  komando cron set web1 nightly-backup '/usr/local/bin/backup.sh' --schedule '0 2 * * *'\n" +
		"  komando cron rm web1 nightly-backup",
	"komando net": "  komando net ports web1 --sudo                     # what listens, and which program\n" +
		"  komando net check @web db.internal:5432           # can the servers reach it?\n" +
		"  komando net dns web1 db.internal\n" +
		"  komando net http web1 http://localhost:8080/health --expect 200",
	"komando cert": "  komando cert check web1                           # certificates on the server\n" +
		"  komando cert check https://shop.example.com --warn 14d",
	"komando recipe": "  komando recipe list\n" +
		"  komando recipe run health @web\n" +
		"  komando recipe add app-logs 'tail -n 100 /srv/{{app}}/log/app.log' --read-only\n" +
		"  komando recipe run app-logs web1 --var app=shop\n" +
		"  komando recipe rm app-logs",

	"komando audit verify": "  komando audit verify",
	"komando config show":  "  komando config show",
	"komando conn kinds":   "  komando conn kinds",
	"komando conn list":    "  komando conn list\n  komando conn list @prod",
	"komando conn show":    "  komando conn show app-db",
	"komando conn test":    "  komando conn test app-db\n  komando conn test kind:postgres",
	"komando cron list":    "  komando cron list web1",
	"komando cron rm":      "  komando cron rm web1 nightly-backup",

	"komando docker images":  "  komando docker images web1",
	"komando docker inspect": "  komando docker inspect web1 api",
	"komando docker logs":    "  komando docker logs web1 api --since 10m\n  komando docker logs web1 api --follow",
	"komando docker ps":      "  komando docker ps web1\n  komando docker ps @web --all   # stopped containers too",
	"komando docker pull":    "  komando docker pull web1 nginx:1.27",
	"komando docker raw":     "  komando docker raw web1 -- network ls",
	"komando docker restart": "  komando docker restart web1 api worker",
	"komando docker rm":      "  komando docker rm web1 old-api --dry-run\n  komando docker rm web1 old-api --allow-dangerous",
	"komando docker start":   "  komando docker start web1 api",
	"komando docker stats":   "  komando docker stats @web",
	"komando docker stop":    "  komando docker stop web1 api",

	"komando doctor": "  komando doctor",

	"komando fs cat":   "  komando fs cat web1 /etc/nginx/nginx.conf\n  komando fs cat web1 /var/log/syslog --tail 50",
	"komando fs chmod": "  komando fs chmod web1 640 /etc/app/config.yml",
	"komando fs list":  "  komando fs list web1 /var/www\n  komando fs list web1 /etc/nginx --recursive",
	"komando fs mkdir": "  komando fs mkdir web1 /srv/app/releases",
	"komando fs mv":    "  komando fs mv web1 /srv/app/current /srv/app/previous",
	"komando fs rm":    "  komando fs rm web1 /tmp/upload.tar.gz\n  komando fs rm web1 /srv/app/releases/old --recursive --allow-dangerous",
	"komando fs stat":  "  komando fs stat web1 /etc/nginx/nginx.conf --sha256",

	"komando host list": "  komando host list\n  komando host list @web",
	"komando host show": "  komando host show web1",
	"komando host test": "  komando host test web1\n  komando host test @prod --wait 2m",

	"komando job kill":   "  komando job kill j1103-101500-ab12cd34\n  komando job kill j1103-101500-ab12cd34 --signal KILL",
	"komando job list":   "  komando job list\n  komando job list --refresh --target web1",
	"komando job logs":   "  komando job logs j1103-101500-ab12cd34 --limit 100\n  komando job logs j1103-101500-ab12cd34 --offset 4096   # only what is new since then",
	"komando job rm":     "  komando job rm j1103-101500-ab12cd34",
	"komando job status": "  komando job status j1103-101500-ab12cd34",

	"komando key list": "  komando key list",
	"komando key rm":   "  komando key rm old-deploy",
	"komando key show": "  komando key show deploy",

	"komando net http":  "  komando net http web1 http://localhost:8080/health --expect 200",
	"komando net ports": "  komando net ports web1",

	"komando pkg install":    "  komando pkg install web1 htop jq",
	"komando pkg installed":  "  komando pkg installed @web nginx openssl",
	"komando pkg rm":         "  komando pkg rm web1 telnet",
	"komando pkg update":     "  komando pkg update @web",
	"komando pkg upgradable": "  komando pkg upgradable @web\n  komando pkg upgradable web1 --refresh",
	"komando pkg upgrade":    "  komando pkg upgrade web1 --dry-run   # see what would change first\n  komando pkg upgrade web1 openssl",

	"komando policy list": "  komando policy list",
	"komando recipe list": "  komando recipe list\n  komando recipe list --category security",
	"komando recipe rm":   "  komando recipe rm du-srv",
	"komando secret list": "  komando secret list",
	"komando shell":       "  komando shell web1",

	"komando svc disable": "  komando svc disable web1 apache2 --now",
	"komando svc enable":  "  komando svc enable web1 nginx --now",
	"komando svc list":    "  komando svc list web1 --failed\n  komando svc list web1 --state running",
	"komando svc logs":    "  komando svc logs web1 nginx --since 30m --grep error",
	"komando svc stop":    "  komando svc stop web1 nginx",

	"komando tunnel list": "  komando tunnel list",
	"komando tunnel stop": "  komando tunnel stop t1102-101500-ab12cd34\n  komando tunnel stop --all",

	"komando user list":   "  komando user list web1",
	"komando user lock":   "  komando user lock web1 alice",
	"komando user rm":     "  komando user rm web1 alice --dry-run\n  komando user rm web1 alice --remove-home --allow-dangerous",
	"komando user unlock": "  komando user unlock web1 alice",

	"komando version": "  komando version",

	"komando vpn down":   "  komando vpn down office\n  komando vpn down --all",
	"komando vpn list":   "  komando vpn list",
	"komando vpn rm":     "  komando vpn rm old-office",
	"komando vpn show":   "  komando vpn show office",
	"komando vpn status": "  komando vpn status",
	"komando vpn test":   "  komando vpn test office",
	"komando vpn up":     "  komando vpn up office",
}

// details is the help text of commands whose one-line Short had to be
// cut to fit 80 columns: the full sentence stays in --help. A command that
// sets its own Long keeps it.
var details = map[string]string{
	"komando cluster describe":  "One object in short: state, images, conditions, its pods or tasks, and recent events.",
	"komando cluster events":    "Recent events, oldest first (--warnings for problems only, --for TYPE/NAME for one object).",
	"komando cluster list":      "List pods, deployments, services, nodes, ... (Swarm: services, tasks, nodes, stacks).",
	"komando cluster rm":        "Delete an object (Kubernetes) or a service or stack (Swarm); needs --allow-dangerous.",
	"komando db activity":       "Sessions running something now (pid, user, how long, what); --all includes idle ones.",
	"komando export":            "Save servers, conns, VPNs, recipes, your deny rules and settings to a file, to move them to another computer (no passwords).",
	"komando fs replace":        "Edit a file on a server by exact (or --regex) replacement. It fails when the text is not found, or matches more than once without --all.",
	"komando guide":             "Playbook for AI agents: workflow, safety rules, recipes (read this first).",
	"komando host rm":           "Remove servers from the inventory. The servers are not touched, and their pinned host keys stay.",
	"komando job kill":          "Send a signal to a job's process group (default TERM). A job that already ended is left as it is.",
	"komando job logs":          "Read a job's output piece by piece (--offset with the next_offset of the last call), or its last --limit N lines.",
	"komando job rm":            "Forget jobs and delete their log folders on the server (a running job needs `job kill` or --kill).",
	"komando list":              "List servers, databases, other services and VPNs together (everything, or what TARGET picks).",
	"komando logs":              "Read logs from journald (--unit), a file (--file) or a container (--container).",
	"komando net ports":         "Listening sockets as structured rows: proto, address, port, process, pid (read with ss or netstat).",
	"komando pkg":               "Packages on servers through apt, dnf, yum, apk, zypper or pacman (komando finds which one the server has).",
	"komando policy check":      "Test whether a shell command would be blocked (exit 6), or rate SQL, Redis or memcached commands with --conn-kind KIND.",
	"komando recipe":            "Ready-made and saved commands: health, disk, oom, ... plus your own ({{blank}} to fill in).",
	"komando schema":            "Machine-readable reference of every command, flag, exit code and selector.",
	"komando svc":               "Services on servers: systemd units on Linux, Windows services on Windows servers. status, list, start, stop, restart, enable and disable work on both; reload, daemon-reload and logs are for systemd.",
	"komando svc daemon-reload": "Reload systemd's unit files (after writing a unit), and say which units still need it.",
	"komando svc status":        "Structured unit status (active_state, sub_state, main_pid, n_restarts, memory ...).",
	"komando user lock":         "Lock an account (password + expire, so SSH keys stop working too) without deleting it.",
	"komando vpn rm":            "Remove VPNs from komando (their keys stay in the vault until `komando secret rm`).",
	"komando vpn up":            "Connect a VPN now and keep it up for later commands (a person logs in here, MFA included).",
}
