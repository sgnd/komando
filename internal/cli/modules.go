package cli

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// ------------------------------------------------------------------ svc ---

func svcCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "svc",
		Aliases: []string{"service", "systemd"},
		Short:   "systemd services: status (structured), start/stop/restart/reload/enable/disable, list, logs",
	}
	c.AddCommand(svcStatusCmd(), svcListCmd(), svcLogsCmd())
	for _, a := range []string{"start", "stop", "restart", "reload", "enable", "disable"} {
		c.AddCommand(svcActionCmd(a))
	}
	return c
}

var svcProps = []string{"Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID", "ActiveEnterTimestamp", "NRestarts", "MemoryCurrent", "Result", "ExecMainStatus"}

func parseSvcShow(_ *store.Host, s string) (any, error) {
	var units []map[string]any
	for _, block := range strings.Split(strings.TrimSpace(s), "\n\n") {
		u := map[string]any{}
		for _, line := range strings.Split(block, "\n") {
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key := snake(k)
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && k != "Id" {
				u[key] = n
			} else if v == "[not set]" || v == "" {
				continue
			} else {
				u[key] = v
			}
		}
		if len(u) > 0 {
			u["healthy"] = u["active_state"] == "active"
			units = append(units, u)
		}
	}
	return units, nil
}

func snake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 && !(s[i-1] >= 'A' && s[i-1] <= 'Z') {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func svcStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "status TARGET UNIT...",
		Short:   "Structured unit status (active_state, sub_state, main_pid, n_restarts, memory ...)",
		Example: "  komando svc status @web nginx php8.2-fpm",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := "systemctl show --no-pager -p " + strings.Join(svcProps, ",") + " -- " + quoteAll(args[1:])
			return probe(cmd.Context(), "svc.status", args[0], command, false, parseSvcShow)
		},
	}
}

// guardDocker rates a docker command line the way `cluster run` rates one
// on a Swarm manager: reads stay reads, and deleting or running anything
// (rm, volume rm, prune, run, exec) needs --allow-dangerous.
func guardDocker(args []string) (mutating bool, err error) {
	if len(args) == 0 {
		return true, nil
	}
	risk := classifyDocker(args)
	if risk >= driver.RiskDestructive && !dangerOK() {
		st, err := loadState()
		if err != nil {
			return true, err
		}
		return true, guardConns(st, nil, driver.Verdict{Risk: risk, RuleIDs: []string{"docker"}, Reasons: []string{"docker " + strings.Join(args, " ")}})
	}
	return risk > driver.RiskRead, nil
}

func svcActionCmd(action string) *cobra.Command {
	var noSudo bool
	c := &cobra.Command{
		Use:   action + " TARGET UNIT...",
		Short: strings.ToUpper(action[:1]) + action[1:] + " unit(s) (sudo) and report the resulting state",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			units := quoteAll(args[1:])
			unitFlags := make([]string, 0, len(args)-1)
			for _, u := range args[1:] {
				unitFlags = append(unitFlags, "-u "+sshx.Q(u))
			}
			command := "systemctl " + action + " -- " + units + " && systemctl show --no-pager -p Id,ActiveState,SubState,UnitFileState -- " + units
			if action == "restart" || action == "start" || action == "reload" {
				// give units a moment and surface the failure reason
				command = "systemctl " + action + " -- " + units + "; rc=$?; sleep 1; systemctl show --no-pager -p Id,ActiveState,SubState,UnitFileState,Result -- " + units +
					"; if [ $rc -ne 0 ]; then journalctl -n 20 --no-pager -o cat " + strings.Join(unitFlags, " ") + " 2>/dev/null; fi; exit $rc"
			}
			return runOne(cmd.Context(), "svc."+action, args[0], command, !noSudo, true)
		},
	}
	c.Flags().BoolVar(&noSudo, "no-sudo", false, "do not use sudo (e.g. --user units or root login)")
	return c
}

func svcListCmd() *cobra.Command {
	var state string
	var failed bool
	c := &cobra.Command{
		Use:   "list TARGET",
		Short: "List service units (filter --state running|failed|...)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := "systemctl list-units --type=service --all --no-legend --plain --no-pager"
			if failed {
				state = "failed"
			}
			if state != "" {
				command += " --state=" + sshx.Q(state)
			}
			return probe(cmd.Context(), "svc.list", args[0], command, false, func(_ *store.Host, s string) (any, error) {
				rows := []map[string]string{}
				for _, line := range strings.Split(s, "\n") {
					f := strings.Fields(line)
					if len(f) < 4 {
						continue
					}
					rows = append(rows, map[string]string{"unit": f[0], "load": f[1], "active": f[2], "sub": f[3], "description": strings.Join(f[4:], " ")})
				}
				return rows, nil
			})
		},
	}
	c.Flags().StringVar(&state, "state", "", "unit state filter")
	c.Flags().BoolVar(&failed, "failed", false, "only failed units")
	return c
}

func svcLogsCmd() *cobra.Command {
	var lo logOpts
	c := &cobra.Command{
		Use:   "logs TARGET UNIT",
		Short: "Same as `komando logs TARGET --unit UNIT`",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			lo.unit = args[1]
			return runLogs(cmd.Context(), "svc.logs", args[0], &lo, lo.sudo)
		},
	}
	lo.bind(c, false)
	return c
}

// ----------------------------------------------------------------- logs ---

type logOpts struct {
	unit, file, container, since, until, grep, priority string
	lines                                               int
	sudo, follow                                        bool
}

func (o *logOpts) bind(c *cobra.Command, sources bool) {
	f := c.Flags()
	if sources {
		f.StringVarP(&o.unit, "unit", "u", "", "systemd unit (journalctl)")
		f.StringVar(&o.file, "file", "", "log file path")
		f.StringVar(&o.container, "container", "", "docker container name/id")
	}
	f.StringVar(&o.since, "since", "", "start time, e.g. -1h, '2026-01-02 10:00', today")
	f.StringVar(&o.until, "until", "", "end time (journal/docker)")
	f.StringVar(&o.grep, "grep", "", "only lines matching this extended regex (case-insensitive)")
	f.StringVarP(&o.priority, "priority", "p", "", "journal priority: emerg..debug, e.g. err")
	f.IntVarP(&o.lines, "limit", "n", 200, "max lines (from the end)")
	aliasFlag(f, "lines", "limit")
	f.BoolVarP(&o.sudo, "sudo", "s", false, "read via sudo")
	f.BoolVarP(&o.follow, "follow", "f", false, "keep printing new lines until Ctrl-C")
}

func (o *logOpts) build() (string, error) {
	n := strconv.Itoa(o.lines)
	grep := ""
	if o.grep != "" {
		grep = " | grep -iE -- " + sshx.Q(o.grep)
	}
	if o.follow {
		if grep != "" {
			grep = " | grep --line-buffered -iE -- " + sshx.Q(o.grep)
		}
		switch {
		case o.container != "":
			return "docker logs --timestamps --tail " + n + " -f " + sshx.Q(o.container) + " 2>&1" + grep, nil
		case o.file != "":
			return "tail -n " + n + " -F -- " + sshx.Q(o.file) + grep, nil
		}
		c := "journalctl --no-pager -o short-iso -n " + n + " -f"
		if o.unit != "" {
			c += " -u " + sshx.Q(o.unit)
		}
		if o.priority != "" {
			c += " -p " + sshx.Q(o.priority)
		}
		return c + grep, nil
	}
	switch {
	case o.container != "":
		c := "docker logs --timestamps --tail " + n
		if o.grep != "" {
			c = "docker logs --timestamps"
		}
		if o.since != "" {
			c += " --since " + sshx.Q(strings.TrimPrefix(o.since, "-"))
		}
		if o.until != "" {
			c += " --until " + sshx.Q(strings.TrimPrefix(o.until, "-"))
		}
		c += " " + sshx.Q(o.container) + " 2>&1"
		if grep != "" {
			c += grep + " | tail -n " + n
		}
		return c, nil
	case o.file != "":
		if grep != "" {
			return "grep -iE -- " + sshx.Q(o.grep) + " " + sshx.Q(o.file) + " | tail -n " + n, nil
		}
		return "tail -n " + n + " -- " + sshx.Q(o.file), nil
	default:
		c := "journalctl --no-pager -o short-iso"
		if o.unit != "" {
			c += " -u " + sshx.Q(o.unit)
		}
		if o.since != "" {
			c += " --since " + sshx.Q(o.since)
		}
		if o.until != "" {
			c += " --until " + sshx.Q(o.until)
		}
		if o.priority != "" {
			c += " -p " + sshx.Q(o.priority)
		}
		if grep != "" {
			return c + grep + " | tail -n " + n, nil
		}
		return c + " -n " + n, nil
	}
}

func logsCmd() *cobra.Command {
	var lo logOpts
	c := &cobra.Command{
		Use:   "logs TARGET",
		Short: "Read logs from journald (--unit), a file (--file) or a container (--container)",
		Example: `  komando logs web1 --unit nginx --since -30m --grep 'error|crit'
  komando logs @web --file /var/log/nginx/error.log -n 50 --sudo
  komando logs app1 --container api --since 10m`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogs(cmd.Context(), "logs", args[0], &lo, lo.sudo)
		},
	}
	lo.bind(c, true)
	return c
}

// runLogs reads logs once, or streams them with --follow. `svc logs` and
// `docker logs` go through here too, so -f behaves the same everywhere.
func runLogs(ctx context.Context, name, target string, lo *logOpts, sudo bool) error {
	command, err := lo.build()
	if err != nil {
		return err
	}
	if lo.follow {
		return followLogs(ctx, target, command, sudo)
	}
	return runOne(ctx, name, target, command, sudo, false)
}

// --------------------------------------------------------------- docker ---

func dockerCmd() *cobra.Command {
	var sudo bool
	c := &cobra.Command{
		Use:     "docker",
		Aliases: []string{"container", "ctr"},
		Short:   "Docker: ps/stats/images (structured), logs, start/stop/restart, exec, compose, raw",
	}
	c.PersistentFlags().BoolVarP(&sudo, "sudo", "s", false, "run docker via sudo")
	jsonLines := func(name, args string) *cobra.Command {
		return &cobra.Command{
			Use:   name + " TARGET",
			Short: "docker " + name + " as structured JSON",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, a []string) error {
				return probe(cmd.Context(), "docker."+name, a[0], "docker "+args+" --format '{{json .}}'", sudo, parseJSONLines)
			},
		}
	}
	ps := jsonLines("ps", "ps -a")
	c.AddCommand(ps, jsonLines("stats", "stats --no-stream"), jsonLines("images", "images"))
	for _, a := range []string{"start", "stop", "restart", "rm", "pull"} {
		action := a
		c.AddCommand(&cobra.Command{
			Use:   action + " TARGET NAME...",
			Short: "docker " + action,
			Args:  cobra.MinimumNArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				if _, err := guardDocker(append([]string{action}, args[1:]...)); err != nil {
					return err
				}
				return runOne(cmd.Context(), "docker."+action, args[0], "docker "+action+" "+quoteAll(args[1:]), sudo, true)
			},
		})
	}
	var lo logOpts
	logs := &cobra.Command{
		Use:   "logs TARGET CONTAINER",
		Short: "Same as `komando logs TARGET --container NAME`",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			lo.container = args[1]
			return runLogs(cmd.Context(), "docker.logs", args[0], &lo, sudo)
		},
	}
	lo.bind(logs, false)
	_ = logs.Flags().MarkHidden("sudo")
	inspect := &cobra.Command{
		Use:   "inspect TARGET NAME",
		Short: "docker inspect (JSON)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return probe(cmd.Context(), "docker.inspect", args[0], "docker inspect "+sshx.Q(args[1]), sudo, func(_ *store.Host, s string) (any, error) {
				var v any
				if err := json.Unmarshal([]byte(s), &v); err != nil {
					return s, nil
				}
				return v, nil
			})
		},
	}
	var readOnly bool
	execC := &cobra.Command{
		Use:     "exec TARGET CONTAINER -- COMMAND...",
		Short:   "Run a command inside a container",
		Example: "  komando docker exec app1 api -- php artisan migrate:status",
		Args:    cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			inner := strings.Join(args[2:], " ")
			st, err := loadState()
			if err == nil {
				if err := guard(st, nil, inner, false); err != nil {
					return err
				}
			}
			return runOne(cmd.Context(), "docker.exec", args[0], "docker exec -i "+sshx.Q(args[1])+" sh -c "+sshx.Q(inner), sudo, !readOnly)
		},
	}
	execC.Flags().BoolVar(&readOnly, "read-only", false, "declare read-only")
	var file, dir string
	compose := &cobra.Command{
		Use:     "compose TARGET -- ARGS...",
		Short:   "docker compose with -f/--project-dir (e.g. ps, up -d, pull, logs --tail 50)",
		Example: "  komando docker compose app1 --dir /srv/shop -- up -d --pull always",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := "docker compose"
			if dir != "" {
				c = "cd " + sshx.Q(dir) + " && " + c
			}
			if file != "" {
				c += " -f " + sshx.Q(file)
			}
			sub := strings.Join(args[1:], " ")
			c += " " + sub + " 2>&1"
			ro := strings.HasPrefix(sub, "ps") || strings.HasPrefix(sub, "logs") || strings.HasPrefix(sub, "config") || strings.HasPrefix(sub, "ls")
			// down with volumes or images deletes data; plain down only stops
			if args[1] == "down" && hasFlag(args[2:], "-v", "--volumes", "--rmi") {
				if _, err := guardDocker([]string{"volume", "rm"}); err != nil {
					return err
				}
			}
			return runOne(cmd.Context(), "docker.compose", args[0], c, sudo, !ro)
		},
	}
	compose.Flags().StringVarP(&file, "file", "f", "", "compose file")
	compose.Flags().StringVar(&dir, "dir", "", "project directory")
	raw := &cobra.Command{
		Use:   "raw TARGET -- DOCKER_ARGS...",
		Short: "Any docker subcommand (policy still applies)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mutating, err := guardDocker(args[1:])
			if err != nil {
				return err
			}
			return runOne(cmd.Context(), "docker.raw", args[0], "docker "+strings.Join(args[1:], " "), sudo, mutating)
		},
	}
	c.AddCommand(logs, inspect, execC, compose, raw)
	return c
}

func parseJSONLines(_ *store.Host, s string) (any, error) {
	rows := []any{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return s, nil
		}
		rows = append(rows, v)
	}
	return rows, nil
}

// ------------------------------------------------------------------ pkg ---

// pkgShell dispatches on the detected package manager. $ACTION and $PKGS
// are set by the caller.
const pkgShell = `export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf >/dev/null 2>&1; then PM=dnf
elif command -v yum >/dev/null 2>&1; then PM=yum
elif command -v apk >/dev/null 2>&1; then PM=apk
elif command -v zypper >/dev/null 2>&1; then PM=zypper
elif command -v pacman >/dev/null 2>&1; then PM=pacman
else echo "no supported package manager" >&2; exit 3; fi
echo "# package-manager: $PM" >&2
case "$PM:$ACTION" in
apt:install) apt-get install -y -q $PKGS || { echo "# retrying after apt-get update" >&2; apt-get update -q >&2 && apt-get install -y -q $PKGS; } ;;
apt:remove) apt-get remove -y -q $PKGS ;;
apt:update) apt-get update -q ;;
apt:upgrade) if [ -n "$PKGS" ]; then apt-get install -y -q --only-upgrade $PKGS; else apt-get upgrade -y -q; fi ;;
apt:upgradable) apt list --upgradable 2>/dev/null | tail -n +2 ;;
apt:installed) dpkg-query -W -f='${Package}\t${Version}\n' $PKGS ;;
dnf:install|yum:install) $PM install -y $PKGS ;;
dnf:remove|yum:remove) $PM remove -y $PKGS ;;
dnf:update|yum:update) $PM makecache -q ;;
dnf:upgrade|yum:upgrade) $PM upgrade -y $PKGS ;;
dnf:upgradable|yum:upgradable) $PM -q check-update; [ $? -eq 100 ] && exit 0 ;;
dnf:installed|yum:installed) rpm -q --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' $PKGS ;;
apk:install) apk add $PKGS ;;
apk:remove) apk del $PKGS ;;
apk:update) apk update ;;
apk:upgrade) apk upgrade $PKGS ;;
apk:upgradable) apk -u list ;;
apk:installed) apk info -v $PKGS ;;
zypper:install) zypper -n install $PKGS ;;
zypper:remove) zypper -n remove $PKGS ;;
zypper:update) zypper -n refresh ;;
zypper:upgrade) zypper -n update $PKGS ;;
zypper:upgradable) zypper -n list-updates ;;
zypper:installed) rpm -q $PKGS ;;
pacman:install) pacman -S --noconfirm $PKGS ;;
pacman:remove) pacman -R --noconfirm $PKGS ;;
pacman:update) pacman -Sy ;;
pacman:upgrade) pacman -Syu --noconfirm $PKGS ;;
pacman:upgradable) pacman -Qu ;;
pacman:installed) pacman -Q $PKGS ;;
esac`

func pkgCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "pkg",
		Aliases: []string{"package", "packages"},
		Short:   "Package management across apt/dnf/yum/apk/zypper/pacman (auto-detected)",
	}
	var noSudo bool
	c.PersistentFlags().BoolVar(&noSudo, "no-sudo", false, "do not use sudo (e.g. when logged in as root)")
	mk := func(action, short string, needPkgs, mutating, sudo bool) *cobra.Command {
		use := action + " TARGET"
		if needPkgs {
			use += " PACKAGE..."
		} else {
			use += " [PACKAGE...]"
		}
		return &cobra.Command{
			Use:   use,
			Short: short,
			Args: func(cmd *cobra.Command, args []string) error {
				if needPkgs && len(args) < 2 {
					return out.Usage("give TARGET and at least one package")
				}
				if len(args) < 1 {
					return out.Usage("give TARGET")
				}
				return nil
			},
			RunE: func(cmd *cobra.Command, args []string) error {
				for _, p := range args[1:] {
					if strings.ContainsAny(p, " ;&|$`'\"\\") {
						return out.Usage("invalid package name %q", p)
					}
				}
				command := "ACTION=" + action + " PKGS=" + sshx.Q(strings.Join(args[1:], " ")) + "; " + pkgShell
				return runOne(cmd.Context(), "pkg."+action, args[0], command, sudo && !noSudo, mutating)
			},
		}
	}
	pkgRm := mk("remove", "Remove packages", true, true, true) // "remove" is what the package managers call it
	pkgRm.Use = "rm TARGET PACKAGE..."
	c.AddCommand(
		mk("install", "Install packages", true, true, true),
		pkgRm,
		mk("update", "Refresh package index", false, true, true),
		mk("upgrade", "Upgrade all or the given packages", false, true, true),
		mk("upgradable", "List pending upgrades", false, false, false),
		mk("installed", "Show installed versions (all or given packages)", false, false, false),
	)
	return c
}

// ------------------------------------------------------------------ net ---

func netCmd() *cobra.Command {
	c := &cobra.Command{Use: "net", Aliases: []string{"network"}, Short: "Network checks run FROM the servers: port reachability, HTTP, DNS, listening ports"}
	check := &cobra.Command{
		Use:     "check TARGET HOST:PORT...",
		Short:   "Can each server open a TCP connection to HOST:PORT? (structured)",
		Example: "  komando net check @web db.internal:5432 redis.internal:6379",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var sb strings.Builder
			for _, hp := range args[1:] {
				h, p, ok := strings.Cut(hp, ":")
				if !ok {
					return out.Usage("expected HOST:PORT, got %q", hp)
				}
				if _, err := strconv.Atoi(p); err != nil {
					return out.Usage("invalid port in %q", hp)
				}
				sb.WriteString(`s=$(date +%s%N 2>/dev/null); if (command -v nc >/dev/null && nc -z -w 5 ` + sshx.Q(h) + ` ` + p + `) >/dev/null 2>&1 || timeout 5 bash -c 'exec 3<>/dev/tcp/'` + sshx.Q(h) + `'/` + p + `' 2>/dev/null; then r=open; else r=closed; fi; e=$(date +%s%N 2>/dev/null); echo "` + hp + ` $r $(( (e-s)/1000000 ))"` + "\n")
			}
			return probe(cmd.Context(), "net.check", args[0], sb.String(), false, func(_ *store.Host, s string) (any, error) {
				rows := []map[string]any{}
				for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
					f := strings.Fields(line)
					if len(f) < 2 {
						continue
					}
					r := map[string]any{"target": f[0], "open": f[1] == "open"}
					if len(f) > 2 {
						if ms, err := strconv.Atoi(f[2]); err == nil && ms >= 0 {
							r["ms"] = ms
						}
					}
					rows = append(rows, r)
				}
				return rows, nil
			})
		},
	}
	var sudo bool
	ports := &cobra.Command{
		Use:   "ports TARGET",
		Short: "Listening sockets (structured: proto, address, port, process)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return probe(cmd.Context(), "net.ports", args[0], "ss -tulpnH", sudo, func(_ *store.Host, s string) (any, error) {
				rows := []map[string]any{}
				for _, line := range strings.Split(s, "\n") {
					f := strings.Fields(line)
					if len(f) < 5 {
						continue
					}
					local := f[4]
					i := strings.LastIndex(local, ":")
					port, _ := strconv.Atoi(local[i+1:])
					r := map[string]any{"proto": f[0], "state": f[1], "address": strings.Trim(local[:i], "[]"), "port": port}
					if len(f) > 6 {
						r["process"] = strings.Join(f[6:], " ")
					}
					rows = append(rows, r)
				}
				return rows, nil
			})
		},
	}
	ports.Flags().BoolVarP(&sudo, "sudo", "s", false, "use sudo to see process names")
	httpC := &cobra.Command{
		Use:   "http TARGET URL",
		Short: "HTTP request from the server: status, timing, IP (structured)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := `curl -sS -o /dev/null -m 15 -w '{"code":%{http_code},"time_total":%{time_total},"time_connect":%{time_connect},"time_starttransfer":%{time_starttransfer},"remote_ip":"%{remote_ip}","size":%{size_download},"redirect":"%{redirect_url}"}' ` + sshx.Q(args[1])
			return probe(cmd.Context(), "net.http", args[0], command, false, func(_ *store.Host, s string) (any, error) {
				var v any
				if err := json.Unmarshal([]byte(s), &v); err != nil {
					return s, nil
				}
				return v, nil
			})
		},
	}
	dns := &cobra.Command{
		Use:   "dns TARGET NAME",
		Short: "Resolve NAME from each server",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return probe(cmd.Context(), "net.dns", args[0], "getent ahosts "+sshx.Q(args[1])+" | awk '{print $1}' | sort -u", false, func(_ *store.Host, s string) (any, error) {
				return map[string]any{"name": args[1], "addresses": strings.Fields(s)}, nil
			})
		},
	}
	c.AddCommand(check, ports, httpC, dns)
	return c
}

// ----------------------------------------------------------------- user ---

func userCmd() *cobra.Command {
	c := &cobra.Command{Use: "user", Aliases: []string{"users"}, Short: "Linux user accounts: list, add (with SSH key & sudo), lock, rm"}
	var noSudo bool
	c.PersistentFlags().BoolVar(&noSudo, "no-sudo", false, "do not use sudo (e.g. when logged in as root)")
	var all bool
	list := &cobra.Command{
		Use:   "list TARGET",
		Short: "List accounts (human users by default; --all for system users)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return probe(cmd.Context(), "user.list", args[0], `getent passwd; echo ---; getent group sudo wheel admin 2>/dev/null`, false, func(_ *store.Host, s string) (any, error) {
				pw, grp, _ := strings.Cut(s, "---\n")
				admins := map[string]bool{}
				for _, l := range strings.Split(grp, "\n") {
					f := strings.Split(l, ":")
					if len(f) == 4 {
						for _, u := range strings.Split(f[3], ",") {
							admins[u] = true
						}
					}
				}
				rows := []map[string]any{}
				for _, l := range strings.Split(pw, "\n") {
					f := strings.Split(l, ":")
					if len(f) < 7 {
						continue
					}
					uid, _ := strconv.Atoi(f[2])
					if !all && (uid < 1000 || uid >= 65534) && uid != 0 {
						continue
					}
					rows = append(rows, map[string]any{"name": f[0], "uid": uid, "home": f[5], "shell": f[6], "admin": admins[f[0]] || uid == 0})
				}
				return rows, nil
			})
		},
	}
	list.Flags().BoolVar(&all, "all", false, "include system accounts")
	var pubKey, keyName, shell string
	var admin bool
	add := &cobra.Command{
		Use:     "add TARGET USERNAME",
		Short:   "Create a user (idempotent), optionally authorize an SSH key and grant sudo",
		Example: "  komando user add @web deploy --key deploy --admin",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			u := args[1]
			if !nameRe.MatchString(u) {
				return out.Usage("invalid username")
			}
			if keyName != "" {
				st, err := loadState()
				if err != nil {
					return err
				}
				k, ok := st.Keys[keyName]
				if !ok {
					return out.NotFound("key", keyName)
				}
				pubKey = k.PublicKey
			}
			q := sshx.Q(u)
			sb := strings.Builder{}
			sb.WriteString("set -e; id " + q + " >/dev/null 2>&1 || useradd -m -s " + sshx.Q(shell) + " " + q + "; ")
			if admin {
				sb.WriteString("if getent group sudo >/dev/null; then usermod -aG sudo " + q + "; else usermod -aG wheel " + q + "; fi; ")
			}
			if pubKey != "" {
				sb.WriteString("h=$(getent passwd " + q + " | cut -d: -f6); install -d -m 700 -o " + q + " -g $(id -gn " + q + ") \"$h/.ssh\"; touch \"$h/.ssh/authorized_keys\"; " +
					"grep -qF " + sshx.Q(pubKey) + " \"$h/.ssh/authorized_keys\" || printf '%s\\n' " + sshx.Q(pubKey) + " >> \"$h/.ssh/authorized_keys\"; " +
					"chown " + q + ": \"$h/.ssh/authorized_keys\"; chmod 600 \"$h/.ssh/authorized_keys\"; ")
			}
			sb.WriteString("id " + q)
			return runOne(cmd.Context(), "user.add", args[0], sb.String(), !noSudo, true)
		},
	}
	add.Flags().StringVar(&pubKey, "pubkey", "", "public key line to authorize")
	add.Flags().StringVar(&keyName, "key", "", "authorize this keychain key")
	add.Flags().StringVar(&shell, "shell", "/bin/bash", "login shell")
	add.Flags().BoolVar(&admin, "admin", false, "add to sudo/wheel group")
	lock := &cobra.Command{
		Use:   "lock TARGET USERNAME",
		Short: "Lock an account (password + expire) without deleting it",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			q := sshx.Q(args[1])
			return runOne(cmd.Context(), "user.lock", args[0], "usermod -L -e 1 "+q+" && echo locked "+q, !noSudo, true)
		},
	}
	var removeHome bool
	del := &cobra.Command{
		Use:   "rm TARGET USERNAME",
		Short: "Delete a user (dangerous: requires --allow-dangerous)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := "userdel "
			if removeHome {
				c += "-r "
			}
			return runOne(cmd.Context(), "user.rm", args[0], c+sshx.Q(args[1]), !noSudo, true)
		},
	}
	del.Flags().BoolVar(&removeHome, "remove-home", false, "also delete home directory")
	c.AddCommand(list, add, lock, del)
	return c
}

// ----------------------------------------------------------------- cron ---

func cronCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "cron",
		Short: "Idempotent crontab entries managed by ID (list, set, rm)",
		Long:  "Entries are tagged with '# komando:<id>' so 'cron set' replaces instead of duplicating.",
	}
	var user string
	var sudo bool
	c.PersistentFlags().StringVar(&user, "user", "", "crontab of this user (needs --sudo)")
	c.PersistentFlags().BoolVarP(&sudo, "sudo", "s", false, "use sudo")
	ct := func() string {
		if user != "" {
			return "crontab -u " + sshx.Q(user)
		}
		return "crontab"
	}
	list := &cobra.Command{
		Use:   "list TARGET",
		Short: "Show crontab entries",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return probe(cmd.Context(), "cron.list", args[0], ct()+" -l 2>/dev/null; true", sudo, func(_ *store.Host, s string) (any, error) {
				rows := []map[string]any{}
				for _, l := range strings.Split(s, "\n") {
					t := strings.TrimSpace(l)
					if t == "" || strings.HasPrefix(t, "#") {
						continue
					}
					r := map[string]any{"line": t}
					if _, id, ok := strings.Cut(t, "# komando:"); ok {
						r["id"] = strings.TrimSpace(id)
					}
					rows = append(rows, r)
				}
				return rows, nil
			})
		},
	}
	var schedule string
	set := &cobra.Command{
		Use:     "set TARGET ID COMMAND",
		Short:   "Create or replace the entry with this ID",
		Example: `  komando cron set db1 nightly-backup '/usr/local/bin/backup.sh >> /var/log/backup.log 2>&1' --schedule '0 2 * * *'`,
		Args:    cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(strings.Fields(schedule)) != 5 && !strings.HasPrefix(schedule, "@") {
				return out.Usage("--schedule must be 5 cron fields or @daily/@hourly/...")
			}
			if !nameRe.MatchString(args[1]) {
				return out.Usage("invalid id")
			}
			line := schedule + " " + args[2] + " # komando:" + args[1]
			command := "(" + ct() + " -l 2>/dev/null | grep -v " + sshx.Q("# komando:"+args[1]+"$") + "; printf '%s\\n' " + sshx.Q(line) + ") | " + ct() + " - && echo " + sshx.Q(line)
			return runOne(cmd.Context(), "cron.set", args[0], command, sudo, true)
		},
	}
	set.Flags().StringVar(&schedule, "schedule", "", "cron schedule, e.g. '*/5 * * * *'")
	rm := &cobra.Command{
		Use:   "rm TARGET ID",
		Short: "Remove the entry with this ID",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := ct() + " -l 2>/dev/null | grep -v " + sshx.Q("# komando:"+args[1]+"$") + " | " + ct() + " -"
			return runOne(cmd.Context(), "cron.rm", args[0], command, sudo, true)
		},
	}
	c.AddCommand(list, set, rm)
	return c
}

// followLogs streams a log command until Ctrl-C (or --timeout, if given).
func followLogs(ctx context.Context, target, command string, sudo bool) error {
	if g.timeout == 0 {
		g.timeout = 24 * time.Hour // the person stops it with Ctrl-C
	}
	return runFleet(ctx, "logs", target, command, nil, execOpts{sudo: sudo, stream: true}, false)
}
