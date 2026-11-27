package cli

// examples gives a real example to the commands whose definition has
// none, so every command shows one in --help and in a usage error
// (docs/design/principles.md, section 11). A command that sets its own Example
// keeps it. TestConventions fails when a command has neither.
var examples = map[string]string{
	"komando registry oci": "  komando registry oci add ghcr registry://myuser@ghcr.io --ask-password --dry-run\n" +
		"  komando registry oci add ghcr registry://myuser@ghcr.io --ask-password\n" +
		"  komando registry oci test ghcr\n" +
		"  komando registry oci image list ghcr myorg/api\n" +
		"  komando registry oci image copy ghcr:myorg/api:1.4.2 harbor:prod/api:1.4.2 --dry-run",
	"komando registry oci image": "  komando registry oci image list ghcr\n" +
		"  komando registry oci image show ghcr myorg/api:1.4.2\n" +
		"  komando registry oci image copy ghcr:myorg/api:1.4.2 harbor:prod/api:1.4.2 --dry-run\n" +
		"  komando registry oci image prune harbor shop/api --keep 10 --dry-run",
	"komando cache redis": "  komando cache redis add prod-redis redis://default@10.0.0.7:6379/0 --via web1 --dry-run\n" +
		"  komando cache redis add prod-redis redis://default@10.0.0.7:6379/0 --via web1\n" +
		"  komando cache redis test prod-redis\n" +
		"  komando cache redis raw prod-redis -- HGETALL user:42\n" +
		"  komando cache redis raw prod-redis --write -- EXPIRE session:42 3600 --dry-run",
	"komando cache memcached": "  komando cache memcached add prod-mc memcached://cache.internal:11211 --via web1 --dry-run\n" +
		"  komando cache memcached add prod-mc memcached://cache.internal:11211 --via web1\n" +
		"  komando cache memcached test prod-mc\n" +
		"  komando cache memcached raw prod-mc -- stats\n" +
		"  komando cache memcached raw prod-mc --write -- flush_all --dry-run",
	"komando cluster kubernetes": "  komando cluster kubernetes add prod-k8s k8s://api.cluster.example:6443 --credential prod-kubeconfig --dry-run\n" +
		"  komando cluster kubernetes add prod-k8s k8s://api.cluster.example:6443 --credential prod-kubeconfig\n" +
		"  komando cluster kubernetes test prod-k8s\n" +
		"  komando cluster kubernetes raw prod-k8s -- get pods -A -o wide\n" +
		"  komando cluster kubernetes exec prod-k8s deploy/api --namespace shop --read-only -- cat /app/config.yml",
	"komando cluster swarm": "  komando cluster swarm raw swarm1 -- service ls\n" +
		"  komando cluster swarm raw swarm1 -- service ps web\n" +
		"  komando cluster swarm raw swarm1 --write -- service scale web=3 --dry-run",
	"komando cluster kubernetes tunnel": "  komando cluster kubernetes tunnel start prod-k8s svc/api 8080:80 --namespace shop --dry-run\n" +
		"  komando cluster kubernetes tunnel start prod-k8s svc/api 8080:80 --namespace shop\n" +
		"  komando cluster kubernetes tunnel start prod-k8s deploy/db 15432:5432 --namespace shop",
	// the groups: the usual journey, in order
	"komando pkg": "  komando pkg upgradable @web --refresh\n" +
		"  komando pkg upgrade @web --security --dry-run\n" +
		"  komando pkg upgrade web1 --dry-run\n" +
		"  komando pkg install web1 htop jq\n" +
		"  komando pkg rm web1 telnet",
	"komando docker": "  komando docker ps web1 --all\n" +
		"  komando docker logs web1 api --since 10m\n" +
		"  komando docker restart web1 api\n" +
		"  komando docker compose web1 --dir /srv/shop -- up -d\n" +
		"  komando docker prune web1 --dry-run               # what would be freed",
	"komando cluster helm": "  komando cluster helm list prod-k8s -A\n" +
		"  komando cluster helm status prod-k8s shop --namespace shop\n" +
		"  komando cluster helm history prod-k8s shop --namespace shop\n" +
		"  komando cluster helm values prod-k8s shop --namespace shop",
	"komando config": "  komando config show\n" +
		"  komando config get default_timeout\n" +
		"  komando config set default_timeout 10m --dry-run\n" +
		"  komando config set default_timeout 10m",
	"komando config vault": "  komando config vault keychain --dry-run\n" +
		"  komando config vault keychain\n" +
		"  komando config vault passphrase   # asks for the new passphrase twice, hidden",
	"komando conn": "  komando conn add prod-db postgres://app@10.0.0.9/shop --password-ref credential:prod-db-pass\n" +
		"  komando test prod-db                              # does it answer and let komando in?\n" +
		"  komando conn edit prod-db --via web1 --dry-run\n" +
		"  komando conn rm prod-db                           # from komando only",
	"komando db user": "  komando db user list prod-db\n" +
		"  komando db user show prod-db app\n" +
		"  komando db user add prod-db app --password-ref credential:app-pass --dry-run\n" +
		"  komando db user add prod-db app --password-ref credential:app-pass --allow-dangerous",
	"komando fs": "  komando fs list web1 /etc/nginx\n" +
		"  komando fs cat web1 /etc/nginx/nginx.conf\n" +
		"  komando fs replace web1 /etc/nginx/nginx.conf --old 'worker_connections 512' --new 'worker_connections 1024' --backup --dry-run\n" +
		"  komando fs replace web1 /etc/nginx/nginx.conf --old 'worker_connections 512' --new 'worker_connections 1024' --backup\n" +
		"  komando fs restore web1 /etc/nginx/nginx.conf     # undo the edit",
	"komando group": "  komando group list\n" +
		"  komando group create web web1,web2 --dry-run\n" +
		"  komando group create web web1,web2\n" +
		"  komando group remove web web2",
	"komando host": "  komando host ssh add web1 deploy@10.0.0.5\n" +
		"  komando host ssh test web1\n" +
		"  komando host ssh exec web1 -- uptime\n" +
		"  komando host winrm add win1 Administrator@10.0.0.9 --ask-password\n" +
		"  komando host ssh remove web1                      # from komando only",
	"komando host ssh": "  komando host ssh add web1 deploy@10.0.0.5 --dry-run\n" +
		"  komando host ssh add web1 deploy@10.0.0.5\n" +
		"  komando host ssh test web1\n" +
		"  komando host ssh exec web1 -- uptime\n" +
		"  komando host ssh tunnel start db1 -L 15432:localhost:5432",
	"komando host ssh tunnel": "  komando host ssh tunnel start db1 -L 15432:localhost:5432\n" +
		"  komando host ssh tunnel start bastion -D 1080\n" +
		"  komando host ssh tunnel list\n" +
		"  komando host ssh tunnel stop --all",
	"komando host winrm": "  komando host winrm add win1 Administrator@10.0.0.9 --ask-password --dry-run\n" +
		"  komando host winrm add win1 Administrator@10.0.0.9 --ask-password\n" +
		"  komando host winrm test win1\n" +
		"  komando host winrm exec win1 -- 'Get-Date'",
	"komando job": "  komando job start @web -- ./deploy.sh\n" +
		"  komando job list\n" +
		"  komando job wait j1103-101500-ab12cd34 --timeout 30m\n" +
		"  komando job logs j1103-101500-ab12cd34 --limit 50",
	"komando credential": "  komando credential password add web1-pass   # typed hidden\n" +
		"  komando credential list\n" +
		"  komando credential key create deploy\n" +
		"  komando credential run --env TOKEN=credential:gh-token -- ./deploy.sh",
	"komando credential key": "  komando credential key create deploy\n" +
		"  komando credential key install deploy @web --dry-run\n" +
		"  komando credential key install deploy @web\n" +
		"  komando credential key list",
	"komando credential password": "  komando credential password add web1-pass   # typed hidden\n" +
		"  komando credential password show web1-pass\n" +
		"  komando credential password rename web1-pass web1-pass-old --dry-run\n" +
		"  komando credential password remove web1-pass-old --dry-run",
	"komando credential token": "  komando credential token add gh-token   # typed hidden\n" +
		"  komando credential token add gh-token --from-env GH_TOKEN --dry-run\n" +
		"  komando credential token show gh-token\n" +
		"  komando credential token remove gh-token --dry-run",
	"komando credential certificate": "  komando credential certificate add corp --key ~/corp-ca.pub --hosts '*.corp.example' --dry-run\n" +
		"  komando credential certificate list\n" +
		"  komando credential certificate remove corp --dry-run",
	"komando policy": "  komando policy list\n" +
		"  komando policy check 'rm -rf /srv/app'\n" +
		"  komando policy create 'systemctl stop postgresql' --dry-run\n" +
		"  komando policy create 'systemctl stop postgresql'",
	"komando secret": "  komando secret check db-pass   # type the value to compare, hidden\n" +
		"  komando secret cp db-pass db-pass-old --dry-run\n" +
		"  komando secret cp db-pass db-pass-old",
	"komando vpn": "  komando vpn wireguard add office --config ~/Downloads/office.conf\n" +
		"  komando vpn wireguard test office\n" +
		"  komando host ssh edit db1 --via office --dry-run\n" +
		"  komando vpn wireguard start office",
	"komando cert": "  komando cert check web1                           # certificates on the server\n" +
		"  komando cert check @web --warn 30d\n" +
		"  komando cert check https://shop.example.com --warn 14d",
	"komando snippet": "  komando snippet list\n" +
		"  komando snippet exec health @web\n" +
		"  komando snippet create app-logs 'tail -n 100 /srv/{{app}}/log/app.log' --read-only\n" +
		"  komando snippet exec app-logs web1 --var app=shop\n" +
		"  komando snippet remove app-logs",

	"komando audit": "  komando audit list\n" +
		"  komando audit list --since 2h --failed\n" +
		"  komando audit list -n 0 --target @prod\n" +
		"  komando audit check",
	"komando agent": "  komando agent skill install --dry-run\n" +
		"  komando agent skill install\n" +
		"  komando agent skill install --project\n" +
		"  komando agent skill uninstall --dry-run",
	"komando agent skill": "  komando agent skill install --dry-run\n" +
		"  komando agent skill install\n" +
		"  komando agent skill uninstall --dry-run\n" +
		"  komando agent skill uninstall",
	"komando conn kinds": "  komando conn kinds",
	"komando conn list":  "  komando conn list\n  komando conn list @prod",
	"komando conn show":  "  komando conn show prod-db",
	"komando conn test":  "  komando conn test prod-db\n  komando conn test kind:postgres",

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

	"komando job kill":   "  komando job kill j1103-101500-ab12cd34\n  komando job kill j1103-101500-ab12cd34 --signal KILL",
	"komando job list":   "  komando job list\n  komando job list --refresh --target web1",
	"komando job logs":   "  komando job logs j1103-101500-ab12cd34 --limit 100\n  komando job logs j1103-101500-ab12cd34 --offset 4096   # only what is new since then",
	"komando job rm":     "  komando job rm j1103-101500-ab12cd34",
	"komando job status": "  komando job status j1103-101500-ab12cd34",

	"komando pkg install":    "  komando pkg install web1 htop jq",
	"komando pkg installed":  "  komando pkg installed @web nginx openssl",
	"komando pkg rm":         "  komando pkg rm web1 telnet",
	"komando pkg update":     "  komando pkg update @web",
	"komando pkg upgradable": "  komando pkg upgradable @web\n  komando pkg upgradable web1 --refresh",

	"komando version": "  komando version",
}

// details is the help text of commands whose one-line Short had to be
// cut to fit 80 columns: the full sentence stays in --help. A command that
// sets its own Long keeps it.
var details = map[string]string{
	"komando cluster describe": "One object in short: state, images, conditions, its pods or tasks, and recent events.",
	"komando cluster events":   "Recent events, oldest first (--warnings for problems only, --for TYPE/NAME for one object).",
	"komando cluster list":     "List pods, deployments, services, nodes, ... (Swarm: services, tasks, nodes, stacks).",
	"komando cluster rm":       "Delete an object (Kubernetes) or a service or stack (Swarm); needs --allow-dangerous.",
	"komando db activity":      "Sessions running something now (pid, user, how long, what); --all includes idle ones.",
	"komando export":           "Save servers, conns, VPNs, recipes, your deny rules and settings to a file, to move them to another computer (no passwords).",
	"komando fs replace":       "Edit a file on a server by exact (or --regex) replacement. It fails when the text is not found, or matches more than once without --all.",
	"komando guide":            "Playbook for AI agents: workflow, safety rules, recipes (read this first).",
	"komando host ssh remove":  "Remove servers from your list. The servers are not touched, and their pinned host keys stay.",
	"komando job kill":         "Send a signal to a job's process group (default TERM). A job that already ended is left as it is.",
	"komando job logs":         "Read a job's output piece by piece (--offset with the next_offset of the last call), or its last --limit N lines.",
	"komando job rm":           "Forget jobs and delete their log folders on the server (a running job needs `job kill` or --kill).",
	"komando list":             "List servers, conns (databases, caches, queues, storage, clusters and\nregistries) and VPNs together: everything, or what TARGET picks.",
	"komando logs":             "Read logs from journald (--unit), a file (--file) or a container (--container).",
	"komando pkg":              "Packages on servers through apt, dnf, yum, apk, zypper or pacman (komando finds which one the server has).",
	"komando policy check":     "Test whether a shell command would be blocked (exit 6), or rate SQL, Redis or memcached commands with --conn-kind KIND.",
	"komando snippet":          "Ready-made and saved commands: health, disk, oom, ... plus your own ({{blank}} to fill in).",
	"komando schema":           "Machine-readable reference of every command, flag, exit code and selector.",
}
