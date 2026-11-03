package cli

import (
	"context"
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

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
dnf:install|yum:install) $PM install -y $PKGS ;;
dnf:remove|yum:remove) $PM remove -y $PKGS ;;
dnf:update|yum:update) $PM makecache -q ;;
dnf:upgrade|yum:upgrade) $PM upgrade -y $PKGS ;;
dnf:upgradable|yum:upgradable) $PM -q check-update; rc=$?; [ $rc -eq 100 ] && exit 0; exit $rc ;;
apk:install) apk add $PKGS ;;
apk:remove) apk del $PKGS ;;
apk:update) apk update ;;
apk:upgrade) apk upgrade $PKGS ;;
apk:upgradable) apk -u list ;;
zypper:install) zypper -n install $PKGS ;;
zypper:remove) zypper -n remove $PKGS ;;
zypper:update) zypper -n refresh ;;
zypper:upgrade) zypper -n update $PKGS ;;
zypper:upgradable) zypper -n list-updates ;;
pacman:install) pacman -S --noconfirm $PKGS ;;
pacman:remove) pacman -R --noconfirm $PKGS ;;
pacman:update) pacman -Sy ;;
pacman:upgrade) pacman -Syu --noconfirm $PKGS ;;
pacman:upgradable) pacman -Qu ;;
*:installed)
  case "$PM" in
  apt) ALL=$(dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n' | awk -F'\t' '$1 ~ /^ii/ {print $2"\t"$3}') ;;
  dnf|yum|zypper) ALL=$(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n') ;;
  apk) ALL=$(apk list -I 2>/dev/null | awk '{print $1}' | sed -E 's/^(.*)-([^-]+-r[0-9]+)$/\1\t\2/') ;;
  pacman) ALL=$(pacman -Q | tr ' ' '\t') ;;
  esac
  if [ -z "$PKGS" ]; then printf '%s\n' "$ALL"; exit 0; fi
  for p in $PKGS; do
    v=$(printf '%s\n' "$ALL" | awk -F'\t' -v p="$p" '$1 == p {print $2; exit}')
    printf '%s\t%s\n' "$p" "${v:--}"
  done ;;
esac`

// essentialPkgs are packages whose removal can lock you out of a server or
// break it; removing them needs --allow-dangerous.
var essentialPkgs = regexp.MustCompile(`^(openssh-server|openssh|ssh|sudo|systemd|systemd-sysv|init|libc6|glibc|libc|musl|bash|coreutils|util-linux|apt|dpkg|rpm|dnf|yum|apk-tools|busybox|base-files|login|passwd|linux-image.*|kernel.*|linux)$`)

// parseInstalled reads "name<TAB>version" lines ("-" when not installed).
func parseInstalled(_ *store.Host, s string) (any, error) {
	rows := []map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		name, ver, ok := strings.Cut(l, "\t")
		if !ok || name == "" {
			continue
		}
		r := map[string]any{"name": name, "installed": ver != "-"}
		if ver != "-" {
			r["version"] = ver
		}
		rows = append(rows, r)
	}
	return rows, nil
}

func pkgCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "pkg",
		Aliases: []string{"package", "packages"},
		Short:   "Package management across apt/dnf/yum/apk/zypper/pacman (auto-detected)",
	}
	var noSudo, refresh bool
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
					// a name starting with - would be read as an option, and a
					// glob can pick hundreds of packages
					if p == "" || strings.HasPrefix(p, "-") || strings.ContainsAny(p, " ;&|$`'\"\\*?[]{}()<>") {
						return out.Usage("invalid package name %q (give exact names, no options or patterns)", p)
					}
				}
				pkgs := strings.Join(args[1:], " ")
				command := "ACTION=" + action + " PKGS=" + sshx.Q(pkgs) + "; " + pkgShell
				if action == "installed" {
					return probe(cmd.Context(), "pkg.installed", args[0], command, false, parseInstalled)
				}
				if refresh && action == "upgradable" {
					command = "ACTION=update PKGS=''; (" + pkgShell + ") >/dev/null; " + command
				}
				if action == "remove" {
					for _, p := range args[1:] {
						if essentialPkgs.MatchString(p) && !dangerOK() {
							return out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "if this is truly intended, confirm with the user and re-run with --allow-dangerous",
								"removing %s can lock you out of the server or break it", p)
						}
					}
				}
				o := execOpts{sudo: (sudo || action == "upgradable" && refresh) && !noSudo, display: strings.TrimSpace("pkg " + action + " " + pkgs)}
				return runFleet(cmd.Context(), "pkg."+action, args[0], command, nil, o, mutating)
			},
		}
	}
	upgradable := mk("upgradable", "List pending upgrades", false, false, false)
	upgradable.Flags().BoolVar(&refresh, "refresh", false, "refresh the package index first (like apt-get update), so the list is current")
	pkgRm := mk("remove", "Remove packages", true, true, true) // "remove" is what the package managers call it
	pkgRm.Use = "rm TARGET PACKAGE..."
	c.AddCommand(
		mk("install", "Install packages", true, true, true),
		pkgRm,
		mk("update", "Refresh package index", false, true, true),
		mk("upgrade", "Upgrade all or the given packages", false, true, true),
		upgradable,
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
				h, p, err := net.SplitHostPort(hp)
				if err != nil {
					return out.Usage("expected HOST:PORT (or [IPv6]:PORT), got %q", hp)
				}
				if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
					return out.Usage("invalid port in %q (1-65535)", hp)
				}
				if h == "" || strings.ContainsAny(h, " \t'\"$`;&|") {
					return out.Usage("invalid host in %q", hp)
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
				// like nc -z: a closed port fails, so `net check ... && deploy` works
				var closed []string
				for _, r := range rows {
					if r["open"] != true {
						closed = append(closed, r["target"].(string))
					}
				}
				if len(closed) > 0 {
					return rows, out.Errf(out.ExitRemote, "PORT_CLOSED", "check the address, firewall or service on the other side", "cannot connect to %s", strings.Join(closed, ", "))
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
	var expect string
	httpC := &cobra.Command{
		Use:   "http TARGET URL",
		Short: "HTTP request from the server: status, timing, IP (structured)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			command := `curl -sS -o /dev/null -m 15 -w '{"code":%{http_code},"time_total":%{time_total},"time_connect":%{time_connect},"time_starttransfer":%{time_starttransfer},"remote_ip":"%{remote_ip}","size":%{size_download},"redirect":"%{redirect_url}"}' ` + sshx.Q(args[1])
			return probe(cmd.Context(), "net.http", args[0], command, false, func(_ *store.Host, s string) (any, error) {
				s = strings.Replace(s, `"code":000`, `"code":0`, 1) // curl writes 000 when nothing answered
				var v map[string]any
				if err := json.Unmarshal([]byte(s), &v); err != nil {
					return s, nil
				}
				code, _ := v["code"].(float64)
				switch {
				case code == 0:
					return v, out.Errf(out.ExitConnect, "NO_RESPONSE", "check the URL, and that the server can reach it (`komando net check`)", "no HTTP answer from %s", args[1])
				case expect != "" && !statusMatches(int(code), expect):
					return v, out.Errf(out.ExitRemote, "UNEXPECTED_STATUS", "", "HTTP %d, expected %s", int(code), expect)
				}
				return v, nil
			})
		},
	}
	httpC.Flags().StringVar(&expect, "expect", "", "fail unless the status matches, e.g. 200 or 2xx (like curl -f)")
	dns := &cobra.Command{
		Use:   "dns TARGET NAME",
		Short: "Resolve NAME from each server",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return probe(cmd.Context(), "net.dns", args[0], "getent ahosts "+sshx.Q(args[1])+" | awk '{print $1}' | sort -u", false, func(_ *store.Host, s string) (any, error) {
				res := map[string]any{"name": args[1], "addresses": strings.Fields(s)}
				if len(strings.Fields(s)) == 0 {
					return res, out.Errf(out.ExitNotFound, "NXDOMAIN", "check the name, and the server's DNS (/etc/resolv.conf)", "%s does not resolve from this server", args[1])
				}
				return res, nil
			})
		},
	}
	c.AddCommand(check, ports, httpC, dns)
	return c
}

// statusMatches: 200 matches 200, 2xx matches 200-299.
func statusMatches(code int, want string) bool {
	if len(want) == 3 && strings.HasSuffix(want, "xx") {
		return strconv.Itoa(code)[:1] == want[:1]
	}
	return strconv.Itoa(code) == want
}

// ----------------------------------------------------------------- user ---

func userCmd() *cobra.Command {
	c := &cobra.Command{Use: "user", Aliases: []string{"users"}, Short: "Linux user accounts: list, add (with SSH key & sudo), lock, unlock, rm"}
	var noSudo bool
	c.PersistentFlags().BoolVar(&noSudo, "no-sudo", false, "do not use sudo (e.g. when logged in as root)")
	var all bool
	list := &cobra.Command{
		Use:   "list TARGET",
		Short: "List accounts (human users by default; --all for system users)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return probe(cmd.Context(), "user.list", args[0], `getent passwd; echo ---; for g in sudo wheel admin; do getent group $g; done; true`, false, func(_ *store.Host, s string) (any, error) {
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
			if pubKey != "" {
				if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey)); err != nil {
					return out.Usage("--pubkey is not an SSH public key line (ssh-ed25519 AAAA... comment): %v", err)
				}
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
			sb.WriteString("set -e; if id " + q + " >/dev/null 2>&1; then echo 'exists' >&2; else useradd -m -s " + sshx.Q(shell) + " " + q + "; echo 'created' >&2; fi; ")
			if cmd.Flags().Changed("shell") {
				// an existing user gets the shell asked for, too
				sb.WriteString("[ \"$(getent passwd " + q + " | cut -d: -f7)\" = " + sshx.Q(shell) + " ] || usermod -s " + sshx.Q(shell) + " " + q + "; ")
			}
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
	unlock := &cobra.Command{
		Use:   "unlock TARGET USERNAME",
		Short: "Unlock an account locked with `user lock`",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			q := sshx.Q(args[1])
			return runOne(cmd.Context(), "user.unlock", args[0], "usermod -U -e '' "+q+" && echo unlocked "+q, !noSudo, true)
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
	c.AddCommand(list, add, lock, unlock, del)
	return c
}

// ----------------------------------------------------------------- cron ---

func cronCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "cron",
		Short: "Idempotent crontab entries managed by ID (list, set, rm)",
		Long: `Entries are tagged with '# komando:<id>', so 'cron set' replaces the
entry with the same ID instead of adding a second one, and 'cron rm' removes
only that entry. Other lines of the crontab are kept as they are.`,
	}
	var user string
	var sudo bool
	c.PersistentFlags().StringVar(&user, "user", "", "crontab of this user (uses sudo)")
	c.PersistentFlags().BoolVarP(&sudo, "sudo", "s", false, "use sudo")
	ct := func() string {
		if user != "" {
			return "crontab -u " + sshx.Q(user)
		}
		return "crontab"
	}
	useSudo := func() bool { return sudo || user != "" }
	// readCron puts the current crontab in $cur; "no crontab" is empty, any
	// other error (no permission, busybox not suid) stops before a write
	// could replace the whole crontab
	readCron := func() string {
		return "cur=$(" + ct() + ` -l 2>&1); rc=$?
if [ $rc -ne 0 ]; then case "$cur" in *"no crontab"*) cur="" ;; *) printf '%s\n' "$cur" >&2; exit $rc ;; esac; fi
`
	}
	// without keeps the lines that do not end in the exact tag
	without := func(id string) string {
		return `new=$(printf '%s\n' "$cur" | awk -v t=` + sshx.Q("# komando:"+id) + ` '{ n = length(t); if (length($0) >= n && substr($0, length($0) - n + 1) == t) next; print }')
`
	}
	list := &cobra.Command{
		Use:   "list TARGET",
		Short: "Show crontab entries",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return probe(cmd.Context(), "cron.list", args[0], readCron()+`printf '%s\n' "$cur"`, useSudo(), func(_ *store.Host, s string) (any, error) {
				rows := []map[string]any{}
				for _, l := range strings.Split(s, "\n") {
					t := strings.TrimSpace(l)
					if t == "" || strings.HasPrefix(t, "#") {
						continue
					}
					rows = append(rows, parseCronLine(t))
				}
				return rows, nil
			})
		},
	}
	var schedule string
	set := &cobra.Command{
		Use:   "set TARGET ID COMMAND",
		Short: "Create or replace the entry with this ID",
		Example: `  komando cron set db1 nightly-backup '/usr/local/bin/backup.sh >> /var/log/backup.log 2>&1' --schedule '0 2 * * *'
  komando cron set @web clean-tmp 'find /tmp -mtime +7 -delete' --schedule @daily`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkCronSchedule(schedule); err != nil {
				return err
			}
			if !cronID.MatchString(args[1]) {
				return out.Usage("invalid ID %q: use letters, digits, - and _", args[1])
			}
			if strings.ContainsAny(args[2], "\r\n") {
				return out.Usage("COMMAND must be one line (cron runs one line per entry)")
			}
			if strings.TrimSpace(args[2]) == "" {
				return out.Usage("COMMAND is empty")
			}
			// cron reads an unescaped % as a newline: date +%F would break
			line := schedule + " " + escapeCronPercent(args[2]) + " # komando:" + args[1]
			command := readCron() + without(args[1]) + `{ [ -n "$new" ] && printf '%s\n' "$new"; printf '%s\n' ` + sshx.Q(line) + "; } | " + ct() + " - && echo " + sshx.Q(line)
			return runFleet(cmd.Context(), "cron.set", args[0], command, nil, execOpts{sudo: useSudo(), display: "cron set " + args[1] + ": " + line}, true)
		},
	}
	set.Flags().StringVar(&schedule, "schedule", "", "cron schedule: 5 fields like '*/5 * * * *', or @hourly, @daily, @weekly, @monthly, @yearly, @reboot")
	_ = set.MarkFlagRequired("schedule")
	rm := &cobra.Command{
		Use:   "rm TARGET ID",
		Short: "Remove the entry with this ID",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !cronID.MatchString(args[1]) {
				return out.Usage("invalid ID %q: use letters, digits, - and _", args[1])
			}
			command := readCron() + without(args[1]) + `n=$(( $(printf '%s\n' "$cur" | grep -c .) - $(printf '%s\n' "$new" | grep -c .) ))
if [ "$n" -gt 0 ]; then { [ -n "$new" ] && printf '%s\n' "$new"; } | ` + ct() + ` - || exit $?; fi
echo "removed $n"`
			return runFleet(cmd.Context(), "cron.rm", args[0], command, nil, execOpts{sudo: useSudo(), display: "cron rm " + args[1]}, true)
		},
	}
	c.AddCommand(list, set, rm)
	return c
}

// cronID: no dots or other characters a pattern would read specially.
var cronID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

var cronMacros = map[string]bool{"@reboot": true, "@yearly": true, "@annually": true, "@monthly": true, "@weekly": true, "@daily": true, "@midnight": true, "@hourly": true}

// checkCronSchedule checks a schedule here, so a typo is a usage error and
// not a crontab that the server refuses.
func checkCronSchedule(s string) error {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "@") {
		if !cronMacros[s] {
			return out.Usage("unknown schedule %q: use @hourly, @daily, @weekly, @monthly, @yearly or @reboot, or 5 fields", s)
		}
		return nil
	}
	f := strings.Fields(s)
	if len(f) != 5 {
		return out.Usage("--schedule needs 5 fields (minute hour day month weekday), e.g. '0 2 * * *', or @daily")
	}
	limits := [5][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	names := [5]string{"minute", "hour", "day of month", "month", "day of week"}
	for i, field := range f {
		for _, part := range strings.Split(field, ",") {
			rng, step, hasStep := strings.Cut(part, "/")
			if hasStep {
				if n, err := strconv.Atoi(step); err != nil || n < 1 {
					return out.Usage("invalid step %q in the %s field", step, names[i])
				}
			}
			if rng == "*" {
				continue
			}
			lo, hi, isRange := strings.Cut(rng, "-")
			for _, v := range []string{lo, hi} {
				if v == "" && !isRange {
					continue
				}
				n, err := strconv.Atoi(v)
				if err != nil && (i == 3 || i == 4) && len(v) == 3 {
					continue // jan, mon ...
				}
				if err != nil || n < limits[i][0] || n > limits[i][1] {
					return out.Usage("%q is not a valid %s (%d-%d)", v, names[i], limits[i][0], limits[i][1])
				}
			}
		}
	}
	return nil
}

// escapeCronPercent escapes the % signs cron would turn into newlines.
func escapeCronPercent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && (i == 0 || s[i-1] != '\\') {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseCronLine splits a crontab line into schedule, command and ID.
func parseCronLine(t string) map[string]any {
	r := map[string]any{"line": t}
	body := t
	if b, id, ok := strings.Cut(t, " # komando:"); ok {
		r["id"] = strings.TrimSpace(id)
		body = b
	}
	f := strings.Fields(body)
	n := 5
	if len(f) > 0 && strings.HasPrefix(f[0], "@") {
		n = 1
	}
	if len(f) > n {
		r["schedule"] = strings.Join(f[:n], " ")
		r["command"] = strings.TrimSpace(strings.SplitN(body, f[n-1], 2)[1])
	}
	return r
}

// followLogs streams a log command until Ctrl-C (or --timeout, if given).
func followLogs(ctx context.Context, target, command string, sudo bool) error {
	if g.timeout == 0 {
		g.timeout = 24 * time.Hour // the person stops it with Ctrl-C
	}
	return runFleet(ctx, "logs", target, command, nil, execOpts{sudo: sudo, stream: true}, false)
}
