package cli

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// ---------------------------------------------------------------- facts ---

const factsScript = `export LC_ALL=C
echo "hostname=$(hostname 2>/dev/null)"
if [ -r /etc/os-release ]; then . /etc/os-release; echo "os=$ID"; echo "os_version=$VERSION_ID"; echo "os_pretty=$PRETTY_NAME"; else echo "os=$(uname -s | tr A-Z a-z)"; fi
echo "kernel=$(uname -r)"; echo "arch=$(uname -m)"
echo "cpus=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)"
[ -r /proc/meminfo ] && awk '/^MemTotal/{print "mem_total_mb="int($2/1024)}/^MemAvailable/{print "mem_available_mb="int($2/1024)}/^SwapTotal/{print "swap_total_mb="int($2/1024)}/^SwapFree/{print "swap_free_mb="int($2/1024)}' /proc/meminfo
[ -r /proc/loadavg ] && echo "load=$(cut -d' ' -f1-3 /proc/loadavg)"
[ -r /proc/uptime ] && echo "uptime_sec=$(cut -d. -f1 /proc/uptime)"
df -P -k / 2>/dev/null | awk 'NR==2{print "disk_root_total_gb="int($2/1048576); print "disk_root_used_pct="int($5)}'
echo "ips=$(hostname -I 2>/dev/null || ip -o -4 addr show 2>/dev/null | awk '{print $4}' | tr '\n' ' ')"
echo "init=$(ps -p 1 -o comm= 2>/dev/null)"
echo "virt=$(systemd-detect-virt 2>/dev/null || echo unknown)"
for m in apt-get dnf yum apk zypper pacman; do command -v $m >/dev/null 2>&1 && { echo "pkg_manager=${m%-get}"; break; }; done
for b in curl wget openssl docker podman kubectl k3s systemctl nginx apache2 httpd caddy haproxy mysql psql redis-cli mongosh node python3 java go git ufw firewall-cmd certbot; do command -v $b >/dev/null 2>&1 && printf 'tool=%s\n' $b; done
[ -f /var/run/reboot-required ] && echo "reboot_required=true" || echo "reboot_required=false"
command -v systemctl >/dev/null 2>&1 && echo "failed_units=$(systemctl --failed --no-legend --plain 2>/dev/null | wc -l)"
echo "users_logged_in=$(who 2>/dev/null | wc -l)"
echo "time_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "timezone=$(cat /etc/timezone 2>/dev/null || date +%Z)"
`

func parseFacts(_ *store.Host, s string) (any, error) {
	f := map[string]any{}
	tools := []string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch {
		case k == "tool":
			tools = append(tools, v)
		case k == "os_version" || k == "hostname" || k == "kernel":
			f[k] = v
		case k == "ips":
			f[k] = strings.Fields(v)
		case k == "load":
			var l []float64
			for _, x := range strings.Fields(v) {
				n, _ := strconv.ParseFloat(x, 64)
				l = append(l, n)
			}
			f[k] = l
		case v == "true" || v == "false":
			f[k] = v == "true"
		default:
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				f[k] = n
			} else {
				f[k] = v
			}
		}
	}
	sort.Strings(tools)
	f["tools"] = tools
	return f, nil
}

func factsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "facts TARGET",
		Aliases: []string{"info", "inspect"},
		Short:   "Gather structured system facts: OS, CPU, memory, disk, load, IPs, installed tools",
		Long:    "Run this first on unfamiliar hosts: it tells an agent which package manager, init system and tools exist so later commands fit the server.",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return probe(cmd.Context(), "facts", args[0], factsScript, false, parseFacts)
		},
	}
}

// -------------------------------------------------------------- recipes ---

type recipe struct {
	Name     string            `json:"name"`
	Category string            `json:"category"`
	Desc     string            `json:"description"`
	Cmd      string            `json:"command"`
	Sudo     bool              `json:"sudo,omitempty"`
	Mutating bool              `json:"mutating,omitempty"`
	Params   map[string]string `json:"params,omitempty"` // name -> default ("" = required)
}

// recipes is a curated library of read-mostly diagnostics that cover the
// daily questions of server operations.
var recipes = []recipe{
	{Name: "health", Category: "system", Desc: "One-shot health summary: uptime, load, memory, disk, failed units", Cmd: `uptime; echo; free -m 2>/dev/null; echo; df -hP -x tmpfs -x devtmpfs -x overlay 2>/dev/null; echo; systemctl --failed --no-legend 2>/dev/null | head -20`},
	{Name: "disk", Category: "system", Desc: "Filesystem usage", Cmd: `df -hP -x tmpfs -x devtmpfs -x overlay -x squashfs`},
	{Name: "inodes", Category: "system", Desc: "Inode usage", Cmd: `df -iP -x tmpfs -x devtmpfs -x overlay -x squashfs`},
	{Name: "big-dirs", Category: "system", Desc: "Largest directories under a path", Cmd: `du -xh --max-depth={{depth}} {{path}} 2>/dev/null | sort -rh | head -n {{limit}}`, Sudo: true, Params: map[string]string{"path": "/", "depth": "2", "limit": "20"}},
	{Name: "big-files", Category: "system", Desc: "Largest files under a path", Cmd: `find {{path}} -xdev -type f -size +{{min}} -printf '%s\t%p\n' 2>/dev/null | sort -rn | head -n {{limit}} | awk -F'\t' '{printf "%.1fM\t%s\n", $1/1048576, $2}'`, Sudo: true, Params: map[string]string{"path": "/", "min": "100M", "limit": "20"}},
	{Name: "memory", Category: "system", Desc: "Memory and swap", Cmd: `free -m; echo; vmstat 1 2 | tail -1`},
	{Name: "top-cpu", Category: "process", Desc: "Top processes by CPU", Cmd: `ps -eo pid,user,%cpu,%mem,etime,cmd --sort=-%cpu | head -n {{limit}}`, Params: map[string]string{"limit": "15"}},
	{Name: "top-mem", Category: "process", Desc: "Top processes by memory", Cmd: `ps -eo pid,user,%mem,rss,etime,cmd --sort=-rss | head -n {{limit}}`, Params: map[string]string{"limit": "15"}},
	{Name: "process", Category: "process", Desc: "Find processes by name pattern", Cmd: `ps -eo pid,ppid,user,%cpu,%mem,etime,cmd | grep -i -- {{pattern}} | grep -v grep`, Params: map[string]string{"pattern": ""}},
	{Name: "oom", Category: "process", Desc: "Recent out-of-memory kills", Cmd: `(journalctl -k --since {{since}} --no-pager 2>/dev/null || dmesg -T 2>/dev/null) | grep -iE 'out of memory|oom-kill|killed process' | tail -n 50`, Sudo: true, Params: map[string]string{"since": "-24h"}},
	{Name: "ports", Category: "network", Desc: "Listening TCP/UDP ports with processes", Cmd: `ss -tulpnH 2>/dev/null || netstat -tulpn`, Sudo: true},
	{Name: "connections", Category: "network", Desc: "TCP connection counts by state and top remote IPs", Cmd: `ss -Htan | awk '{print $1}' | sort | uniq -c | sort -rn; echo; ss -Htn state established | awk '{split($4,a,":"); print a[1]}' | sort | uniq -c | sort -rn | head -n 10`},
	{Name: "firewall", Category: "network", Desc: "Firewall status (ufw / firewalld / nftables / iptables)", Cmd: `if command -v ufw >/dev/null; then ufw status verbose; elif command -v firewall-cmd >/dev/null; then firewall-cmd --list-all; elif command -v nft >/dev/null; then nft list ruleset; else iptables -S; fi`, Sudo: true},
	{Name: "dns", Category: "network", Desc: "Resolver config and a lookup", Cmd: `cat /etc/resolv.conf | grep -v '^#'; echo; getent hosts {{name}} || echo "lookup failed"`, Params: map[string]string{"name": "example.com"}},
	{Name: "failed-units", Category: "service", Desc: "Failed systemd units", Cmd: `systemctl --failed --no-legend --plain`},
	{Name: "journal-errors", Category: "logs", Desc: "Error-level journal entries", Cmd: `journalctl -p err --since {{since}} --no-pager -o short-iso | tail -n {{limit}}`, Sudo: true, Params: map[string]string{"since": "-1h", "limit": "100"}},
	{Name: "auth-failures", Category: "security", Desc: "Failed SSH logins", Cmd: `(journalctl -u ssh -u sshd --since {{since}} --no-pager 2>/dev/null || cat /var/log/auth.log /var/log/secure 2>/dev/null) | grep -iE 'failed password|invalid user|authentication failure' | tail -n {{limit}}`, Sudo: true, Params: map[string]string{"since": "-24h", "limit": "50"}},
	{Name: "last-logins", Category: "security", Desc: "Recent logins", Cmd: `last -n {{limit}} -a 2>/dev/null || lastlog | head -n {{limit}}`, Params: map[string]string{"limit": "20"}},
	{Name: "sudoers", Category: "security", Desc: "Users with sudo/wheel and sudoers rules", Cmd: `getent group sudo wheel admin 2>/dev/null; echo; grep -rhv '^\s*#' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^\s*$'`, Sudo: true},
	{Name: "sshd-config", Category: "security", Desc: "Effective sshd security settings", Cmd: `sshd -T 2>/dev/null | grep -iE '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|x11forwarding|allowusers|allowgroups|maxauthtries) '`, Sudo: true},
	{Name: "updates", Category: "packages", Desc: "Pending package updates", Cmd: `if command -v apt >/dev/null; then apt list --upgradable 2>/dev/null | tail -n +2; elif command -v dnf >/dev/null; then dnf -q check-update; elif command -v yum >/dev/null; then yum -q check-update; elif command -v apk >/dev/null; then apk -u list; fi; [ -f /var/run/reboot-required ] && echo "*** reboot required ***"; true`},
	{Name: "security-updates", Category: "packages", Desc: "Pending security updates", Cmd: `if command -v apt >/dev/null; then apt list --upgradable 2>/dev/null | grep -i security; elif command -v dnf >/dev/null; then dnf -q updateinfo list security; fi; true`},
	{Name: "cert-expiry", Category: "tls", Desc: "TLS certificate expiry for host:port (from the server)", Cmd: `echo | openssl s_client -servername {{name}} -connect {{name}}:{{port}} 2>/dev/null | openssl x509 -noout -subject -issuer -dates`, Params: map[string]string{"name": "", "port": "443"}},
	{Name: "certbot-certs", Category: "tls", Desc: "Let's Encrypt certificates managed by certbot", Cmd: `certbot certificates 2>/dev/null`, Sudo: true},
	{Name: "nginx-test", Category: "web", Desc: "Validate nginx config", Cmd: `nginx -t 2>&1`, Sudo: true},
	{Name: "nginx-sites", Category: "web", Desc: "nginx server_names and listen directives", Cmd: `nginx -T 2>/dev/null | grep -E '^\s*(server_name|listen|root|proxy_pass)\s' | sed 's/^\s*//' | sort | uniq -c`, Sudo: true},
	{Name: "apache-test", Category: "web", Desc: "Validate apache config", Cmd: `(apachectl configtest || apache2ctl configtest) 2>&1`, Sudo: true},
	{Name: "http-check", Category: "web", Desc: "HTTP status/timing of a URL from the server", Cmd: `curl -sS -o /dev/null -m {{timeout}} -w 'code=%{http_code} time_total=%{time_total}s ip=%{remote_ip} size=%{size_download}\n' {{url}}`, Params: map[string]string{"url": "", "timeout": "10"}},
	{Name: "docker-overview", Category: "container", Desc: "Docker containers, disk usage and unhealthy containers", Cmd: `docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'; echo; docker system df; echo; docker ps --filter health=unhealthy --format '{{.Names}} UNHEALTHY'`, Sudo: true},
	{Name: "k8s-overview", Category: "container", Desc: "Kubernetes nodes and non-running pods", Cmd: `kubectl get nodes -o wide; echo; kubectl get pods -A --field-selector=status.phase!=Running,status.phase!=Succeeded`},
	{Name: "time-sync", Category: "system", Desc: "Clock / NTP sync status", Cmd: `timedatectl 2>/dev/null || date`},
	{Name: "cron-all", Category: "system", Desc: "All cron entries (system + users)", Cmd: `cat /etc/crontab 2>/dev/null; ls /etc/cron.d 2>/dev/null; for u in $(cut -d: -f1 /etc/passwd); do c=$(crontab -l -u $u 2>/dev/null | grep -v '^#'); [ -n "$c" ] && printf '## %s\n%s\n' "$u" "$c"; done; systemctl list-timers --no-pager 2>/dev/null | head -n 30`, Sudo: true},
	{Name: "mysql-status", Category: "database", Desc: "MySQL/MariaDB status and process list", Cmd: `mysqladmin status; mysql -e 'SHOW FULL PROCESSLIST' | head -n 30`, Sudo: true},
	{Name: "postgres-status", Category: "database", Desc: "PostgreSQL activity and DB sizes", Cmd: `sudo -u postgres psql -Atc "select datname, pg_size_pretty(pg_database_size(datname)) from pg_database" && sudo -u postgres psql -Atc "select state, count(*) from pg_stat_activity group by 1"`},
	{Name: "redis-info", Category: "database", Desc: "Redis memory/clients/keyspace", Cmd: `redis-cli info | grep -E '^(redis_version|connected_clients|used_memory_human|maxmemory_human|db[0-9]+|role):'`},
	{Name: "drop-caches", Category: "maintenance", Desc: "Free page cache (safe but causes I/O)", Cmd: `sync && echo 3 > /proc/sys/vm/drop_caches && free -m`, Sudo: true, Mutating: true},
	{Name: "journal-vacuum", Category: "maintenance", Desc: "Shrink systemd journal to a size", Cmd: `journalctl --vacuum-size={{size}}`, Sudo: true, Mutating: true, Params: map[string]string{"size": "500M"}},
	{Name: "docker-prune", Category: "maintenance", Desc: "Remove stopped containers, dangling images and build cache (keeps volumes)", Cmd: `docker system prune -f`, Sudo: true, Mutating: true},
	{Name: "apt-clean", Category: "maintenance", Desc: "Clean apt cache and autoremove", Cmd: `apt-get clean && apt-get -y autoremove`, Sudo: true, Mutating: true},
}

var tmplRe = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:=([^}]*))?\}\}`)

// render substitutes {{name}} (shell-quoted). Defaults come from params or
// inline {{name=default}}; missing required params are an error.
func render(tmpl string, defaults map[string]string, vars map[string]string) (string, error) {
	var missing []string
	res := tmplRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		sub := tmplRe.FindStringSubmatch(m)
		name := sub[1]
		if v, ok := vars[name]; ok {
			return sshx.Q(v)
		}
		if d, ok := defaults[name]; ok && d != "" {
			return sshx.Q(d)
		}
		if strings.Contains(m, "=") {
			return sshx.Q(sub[2])
		}
		missing = append(missing, name)
		return m
	})
	if len(missing) > 0 {
		return "", out.Usage("missing parameter(s): %s (pass --var NAME=VALUE)", strings.Join(dedupe(missing), ", "))
	}
	return res, nil
}

// --------------------------------------------------------------- recipe ---

// A recipe is a saved command with {{blanks}}. The built-in ones (health,
// disk, certs, ...) and the ones people save live in one list, under one
// command. `ops` and `snippet` are other names for it (docs/design/ux.md,
// section 11).

type recipeRow struct {
	Name     string            `json:"name"`
	Builtin  bool              `json:"builtin"`
	Category string            `json:"category,omitempty"`
	Desc     string            `json:"description,omitempty"`
	Command  string            `json:"command"`
	Sudo     bool              `json:"sudo,omitempty"`
	ReadOnly bool              `json:"read_only"`
	Params   map[string]string `json:"params,omitempty"`
}

func builtinRecipe(name string) *recipe {
	for i := range recipes {
		if recipes[i].Name == name {
			return &recipes[i]
		}
	}
	return nil
}

// findRecipe looks up a saved recipe first, then a built-in one.
func findRecipe(st *store.State, name string) (recipeRow, bool) {
	if s, ok := st.Snippets[name]; ok {
		return recipeRow{Name: s.Name, Desc: s.Description, Command: s.Command, Sudo: s.Sudo, ReadOnly: s.ReadOnly}, true
	}
	if r := builtinRecipe(name); r != nil {
		return recipeRow{Name: r.Name, Builtin: true, Category: r.Category, Desc: r.Desc, Command: r.Cmd, Sudo: r.Sudo, ReadOnly: !r.Mutating, Params: r.Params}, true
	}
	return recipeRow{}, false
}

func recipeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "recipe",
		Aliases: []string{"recipes", "ops", "snippet", "snippets", "diag"},
		Short:   "Ready-made and saved commands: health, disk, certs, ... plus your own ({{blank}} to fill in)",
	}
	c.AddCommand(recipeListCmd(), recipeAddCmd(), recipeRmCmd(), recipeRunCmd())
	return c
}

func recipeListCmd() *cobra.Command {
	var category string
	c := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List built-in and saved recipes (filter with --category)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			rows := []recipeRow{}
			for _, s := range st.Snippets {
				if r, _ := findRecipe(st, s.Name); category == "" || category == "saved" {
					rows = append(rows, r)
				}
			}
			for _, b := range recipes {
				if r, _ := findRecipe(st, b.Name); r.Builtin && (category == "" || category == b.Category) {
					rows = append(rows, r)
				}
			}
			sort.SliceStable(rows, func(i, j int) bool {
				if rows[i].Builtin != rows[j].Builtin {
					return !rows[i].Builtin // saved first
				}
				return rows[i].Name < rows[j].Name
			})
			out.P.Print("recipe.list", map[string]any{"count": len(rows), "recipes": rows}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&category, "category", "", "only this category (or \"saved\" for your own)")
	return c
}

func recipeAddCmd() *cobra.Command {
	var desc string
	var sudo, readOnly, mutating, overwrite bool
	c := &cobra.Command{
		Use:   "add NAME COMMAND",
		Short: "Save a recipe; {{name}} is a blank, {{name=default}} has a default",
		Example: `  komando recipe add deploy-app 'cd /srv/{{app}} && git pull && systemctl restart {{app}}' --sudo
  komando recipe add disk-usage 'df -h {{path=/}}' --read-only`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validName("recipe", args[0]); err != nil {
				return err
			}
			if builtinRecipe(args[0]) != nil {
				return out.Errf(out.ExitConflict, "RECIPE_BUILTIN", "pick another name; see `komando recipe list`", "%q is a built-in recipe", args[0])
			}
			s := &store.Snippet{Name: args[0], Command: args[1], Description: desc, Sudo: sudo, ReadOnly: readOnly && !mutating, CreatedAt: time.Now().UTC()}
			err := store.Update(func(st *store.State) error {
				old, ok := st.Snippets[s.Name]
				if ok && !overwrite {
					return out.Errf(out.ExitConflict, "RECIPE_EXISTS", "pass --overwrite to replace it", "recipe %q exists", s.Name)
				}
				// marking someone's recipe read-only lets it skip --yes on
				// protected servers, so replacing one that way needs --yes
				if ok && !old.ReadOnly && s.ReadOnly {
					if err := guardSafety("marking the existing recipe " + s.Name + " read-only"); err != nil {
						return err
					}
				}
				st.Snippets[s.Name] = s
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "recipe.add", nil, s.Command, true, map[string]any{"recipe": s.Name, "read_only": s.ReadOnly})
			out.P.Print("recipe.add", s, nil)
			return nil
		},
	}
	c.Flags().StringVar(&desc, "desc", "", "description")
	c.Flags().BoolVar(&sudo, "sudo", false, "run with sudo")
	c.Flags().BoolVar(&readOnly, "read-only", false, "the recipe only reads, so protected servers don't need --yes")
	c.Flags().BoolVar(&mutating, "mutating", false, "")
	_ = c.Flags().MarkDeprecated("mutating", "recipes count as changes unless saved with --read-only")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace a recipe with the same name")
	aliasFlag(c.Flags(), "force", "overwrite")
	return c
}

func recipeRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm NAME",
		Short: "Delete a saved recipe",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if builtinRecipe(args[0]) != nil {
				return out.Errf(out.ExitConflict, "RECIPE_BUILTIN", "built-in recipes cannot be removed", "%q is a built-in recipe", args[0])
			}
			err := store.Update(func(st *store.State) error {
				if _, ok := st.Snippets[args[0]]; !ok {
					return out.NotFound("recipe", args[0])
				}
				delete(st.Snippets, args[0])
				return nil
			})
			if err != nil {
				return err
			}
			out.P.Print("recipe.rm", map[string]any{"removed": args[0]}, nil)
			return nil
		},
	}
}

func recipeRunCmd() *cobra.Command {
	var vars []string
	var noSudo bool
	c := &cobra.Command{
		Use:     "run NAME TARGET",
		Short:   "Run a recipe on servers",
		Example: "  komando recipe run health @web\n  komando recipe run cert-expiry web1 --var name=example.com\n  komando recipe run deploy-app @web --var app=shop",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			r, ok := findRecipe(st, args[0])
			if !ok {
				return out.NotFound("recipe", args[0])
			}
			kv, err := parseKV(vars)
			if err != nil {
				return err
			}
			command, err := render(r.Command, r.Params, kv)
			if err != nil {
				return err
			}
			return runFleet(cmd.Context(), "recipe."+r.Name, args[1], command, nil, execOpts{sudo: r.Sudo && !noSudo}, !r.ReadOnly)
		},
	}
	c.Flags().StringArrayVar(&vars, "var", nil, "fill in a blank: NAME=VALUE (repeatable)")
	aliasFlag(c.Flags(), "param", "var")
	c.Flags().BoolVar(&noSudo, "no-sudo", false, "do not use sudo even if the recipe asks for it")
	return c
}
