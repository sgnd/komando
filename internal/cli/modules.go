package cli

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

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
			return svcStatus(cmd.Context(), args[0], args[1:])
		},
	}
}

func svcActionCmd(action string) *cobra.Command {
	var noSudo, now bool
	var wait int
	c := &cobra.Command{
		Use:   action + " TARGET UNIT...",
		Short: strings.ToUpper(action[:1]) + action[1:] + " unit(s) (sudo) and report the resulting state",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if wait < 0 {
				return out.Usage("--wait must be 0 or more seconds")
			}
			return svcAction(cmd.Context(), action, args[0], args[1:], !noSudo, now, wait)
		},
	}
	c.Flags().BoolVar(&noSudo, "no-sudo", false, "do not use sudo (e.g. --user units or root login)")
	switch action {
	case "start", "restart", "reload":
		c.Example = "  komando svc " + action + " @web nginx --wait 10   # fails unless nginx is active within 10s"
		c.Flags().IntVar(&wait, "wait", 0, "wait up to N seconds for the units to be active; fail if they are not")
	case "enable", "disable":
		verb := map[string]string{"enable": "start", "disable": "stop"}[action]
		c.Flags().BoolVar(&now, "now", false, "also "+verb+" the units now (systemctl "+action+" --now)")
	}
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
			command := noSystemd + "systemctl list-units --type=service --all --no-legend --plain --no-pager"
			if failed {
				state = "failed"
			}
			if state != "" {
				command += " --state=" + sshx.Q(state)
			}
			return runOps(cmd.Context(), opsSpec{name: "svc.list", target: args[0], command: command,
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return svcListResult(rr) }, text: svcListTable})
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
	f.StringVar(&o.since, "since", "", "start time, e.g. -1h, '2026-01-02 10:00', today (journal and containers)")
	f.StringVar(&o.until, "until", "", "end time (journal and containers)")
	f.StringVar(&o.grep, "grep", "", "only lines matching this extended regex (case-insensitive)")
	f.StringVarP(&o.priority, "priority", "p", "", "journal priority and worse: emerg, alert, crit, err, warning, notice, info, debug (or 0-7)")
	f.IntVarP(&o.lines, "limit", "n", 200, "max lines (from the end)")
	aliasFlag(f, "lines", "limit")
	f.BoolVarP(&o.sudo, "sudo", "s", false, "read via sudo (the whole journal, protected files)")
	f.BoolVarP(&o.follow, "follow", "f", false, "keep printing new lines until Ctrl-C")
}

func (o *logOpts) build() (string, error) {
	if err := o.check(); err != nil {
		return "", err
	}
	c, err := o.source()
	if o.follow {
		return c, err // followCheck checks the source before streaming
	}
	return o.preflight() + c, err
}

func (o *logOpts) source() (string, error) {
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
			c := "docker logs --timestamps --tail " + n + " -f"
			if o.since != "" {
				c += " --since " + sshx.Q(strings.TrimPrefix(o.since, "-"))
			}
			return c + " " + sshx.Q(o.container) + " 2>&1" + grep, nil
		case o.file != "":
			return "tail -n " + n + " -F -- " + sshx.Q(o.file) + grep, nil
		}
		c := "journalctl --no-pager -o short-iso -n " + n + " -f"
		if o.unit != "" {
			c += " -u " + sshx.Q(o.unit)
		}
		if o.since != "" {
			c += " --since " + sshx.Q(o.since)
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
		if !g.dryRun {
			if err := lo.followCheck(ctx, target, sudo); err != nil {
				return err
			}
		}
		return followLogs(ctx, target, command, sudo)
	}
	shown, _ := lo.source()
	return runOps(ctx, opsSpec{name: name, target: target, command: command, display: shown, sudo: sudo, raw: true,
		parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return lo.result(rr) }})
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
apt:upgradable) t=$(stat -c %Y /var/lib/apt/lists/*Release 2>/dev/null | sort -n | tail -n 1); echo "# index-age: $([ -n "$t" ] && echo $(( $(date +%s) - t )) || echo never)" >&2
  apt list --upgradable 2>/dev/null | tail -n +2 ;;
apt:simulate) s=$(if [ -n "$PKGS" ]; then apt-get -s install --only-upgrade $PKGS; else apt-get -s upgrade; fi) || exit $?; printf '%s\n' "$s" | grep '^Inst ' || true ;;
dnf:install|yum:install) $PM install -y $PKGS ;;
dnf:remove|yum:remove) $PM remove -y $PKGS ;;
dnf:update|yum:update) $PM makecache -q ;;
dnf:upgrade|yum:upgrade) $PM upgrade -y $PKGS ;;
dnf:upgradable|yum:upgradable|dnf:simulate|yum:simulate) $PM -q check-update $PKGS; rc=$?; [ $rc -eq 100 ] && exit 0; exit $rc ;;
apk:install) apk add $PKGS ;;
apk:remove) apk del $PKGS ;;
apk:update) apk update ;;
apk:upgrade) apk upgrade $PKGS ;;
apk:upgradable) t=$(stat -c %Y /var/cache/apk/APKINDEX* 2>/dev/null | sort -n | tail -n 1); echo "# index-age: $([ -n "$t" ] && echo $(( $(date +%s) - t )) || echo never)" >&2
  apk -u list ;;
apk:simulate) apk upgrade --simulate $PKGS ;;
zypper:install) zypper -n install $PKGS ;;
zypper:remove) zypper -n remove $PKGS ;;
zypper:update) zypper -n refresh ;;
zypper:upgrade) zypper -n update $PKGS ;;
zypper:upgradable|zypper:simulate) zypper -n list-updates ;;
pacman:install) pacman -S --noconfirm $PKGS ;;
pacman:remove) pacman -R --noconfirm $PKGS ;;
pacman:update) pacman -Sy ;;
pacman:upgrade) pacman -Syu --noconfirm $PKGS ;;
pacman:upgradable|pacman:simulate) pacman -Qu $PKGS ;;
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
				if action == "remove" {
					for _, p := range args[1:] {
						if essentialPkgs.MatchString(p) && !dangerOK() {
							return policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "if this is truly intended, confirm with the user and re-run with --allow-dangerous",
								"removing %s can lock you out of the server or break it", p))
						}
					}
				}
				useSudo := (sudo || action == "upgradable" && refresh) && !noSudo
				if action != "update" {
					return runPkg(cmd.Context(), action, args[0], args[1:], useSudo, refresh)
				}
				command := "ACTION=" + action + " PKGS=" + sshx.Q(pkgs) + "; " + pkgShell
				o := execOpts{sudo: useSudo, display: strings.TrimSpace("pkg " + action + " " + pkgs)}
				return runFleet(cmd.Context(), "pkg."+action, args[0], command, nil, o, mutating)
			},
		}
	}
	upgradable := mk("upgradable", "List pending upgrades (from the server's package index; --refresh updates it first)", false, false, false)
	upgradable.Flags().BoolVar(&refresh, "refresh", false, "refresh the package index first (like apt-get update), so the list is current")
	pkgRm := mk("remove", "Remove packages (ones not installed are skipped; reports what changed)", true, true, true) // "remove" is what the package managers call it
	pkgRm.Use = "rm TARGET PACKAGE..."
	c.AddCommand(
		mk("install", "Install packages (already installed ones are left as they are; reports what changed)", true, true, true),
		pkgRm,
		mk("update", "Refresh package index", false, true, true),
		mk("upgrade", "Upgrade all or the given packages (--dry-run lists what would be upgraded)", false, true, true),
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
		RunE:    netCheckRun,
	}
	var sudo bool
	ports := &cobra.Command{
		Use:   "ports TARGET",
		Short: "Listening sockets (structured: proto, address, port, process, pid; ss or netstat)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return netPortsRun(cmd, args[0], sudo)
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
			return runOps(cmd.Context(), opsSpec{name: "net.http", target: args[0], command: command, display: "net http " + args[1], parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) {
				s := strings.Replace(rr.Stdout, `"code":000`, `"code":0`, 1) // curl writes 000 when nothing answered
				var v map[string]any
				if err := json.Unmarshal([]byte(s), &v); err != nil {
					if rr.ExitCode == 127 {
						return nil, out.Errf(out.ExitNotFound, "TOOL_MISSING", "install curl on the server", "curl is not installed")
					}
					return s, nil
				}
				code, _ := v["code"].(float64)
				switch {
				case code == 0:
					return v, out.Errf(out.ExitConnect, "NO_RESPONSE", "check the URL, and that the server can reach it (`komando net check`)", "no HTTP answer from %s", args[1])
				case expect != "" && !statusMatches(int(code), expect):
					return v, out.Errf(out.ExitRemote, "UNEXPECTED_STATUS", "check the URL and the service behind it", "HTTP %d, expected %s", int(code), expect)
				}
				return v, nil
			}, text: func(data any) string {
				v, _ := data.(map[string]any)
				if v == nil {
					return ""
				}
				if v["code"] == float64(0) {
					return "" // the error says it
				}
				t := "HTTP " + cell(v["code"])
				if ip, _ := v["remote_ip"].(string); ip != "" {
					t += " from " + ip
				}
				if total, ok := v["time_total"].(float64); ok {
					t += " in " + strconv.Itoa(int(total*1000)) + " ms"
				}
				if r, _ := v["redirect"].(string); r != "" {
					t += " (redirects to " + r + ")"
				}
				return t + "\n"
			}})
		},
	}
	httpC.Flags().StringVar(&expect, "expect", "", "fail unless the status matches, e.g. 200 or 2xx (like curl -f)")
	var rrType string
	dns := &cobra.Command{
		Use:     "dns TARGET NAME",
		Short:   "Resolve NAME from each server (--type MX, TXT, CNAME, NS ... needs dig there)",
		Example: "  komando net dns @web db.internal\n  komando net dns web1 example.com --type MX",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			command, err := dnsCommand(args[1], rrType)
			if err != nil {
				return err
			}
			return runOps(cmd.Context(), opsSpec{name: "net.dns", target: args[0], command: command, display: strings.TrimSpace("net dns " + args[1] + " " + strings.ToUpper(rrType)),
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) {
					return dnsResult(args[1], rrType, rr.Stdout)
				},
				text: dnsText})
		},
	}
	dns.Flags().StringVar(&rrType, "type", "", "record type: A, AAAA, CNAME, MX, NS, TXT, SOA, SRV, PTR, CAA (default: the addresses the server would connect to)")
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
		Short: "List accounts (human users by default; --all for system users), with admin group and lock state",
		Long: `Lists accounts with their uid, home, shell, whether they are in the sudo,
wheel or admin group (admin_group; rules in sudoers.d are not read) and
whether the account is locked (expired, as ` + "`komando user lock`" + ` does). The lock
state is read through sudo; with --no-sudo it is left out.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOps(cmd.Context(), opsSpec{name: "user.list", target: args[0], command: userListScript, display: "user list", sudo: !noSudo,
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return parseUsers(rr.Stdout, all), nil },
				text:  usersText})
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
	add.Flags().BoolVar(&admin, "admin", false, "add to the sudo (Debian) or wheel (RHEL, Alpine) group")
	lock := &cobra.Command{
		Use:   "lock TARGET USERNAME",
		Short: "Lock an account (password + expire, so SSH keys stop working too) without deleting it",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOps(cmd.Context(), opsSpec{name: "user.lock", target: args[0], command: userExists(args[1]) + "usermod -L -e 1 " + sshx.Q(args[1]),
				display: "user lock " + args[1], sudo: !noSudo, mutating: true,
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return userResult(args[1], "locked", rr) }})
		},
	}
	unlock := &cobra.Command{
		Use:   "unlock TARGET USERNAME",
		Short: "Unlock an account locked with `user lock`",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOps(cmd.Context(), opsSpec{name: "user.unlock", target: args[0], command: userExists(args[1]) + "usermod -U -e '' " + sshx.Q(args[1]),
				display: "user unlock " + args[1], sudo: !noSudo, mutating: true,
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return userResult(args[1], "unlocked", rr) }})
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
			return runOps(cmd.Context(), opsSpec{name: "cron.list", target: args[0], command: readCron() + `printf '%s\n' "$cur"`, display: "cron list", sudo: useSudo(),
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) {
					if rr.ExitCode != 0 {
						return nil, out.Errf(out.ExitRemote, "CRONTAB_UNREADABLE", "check the user name; reading another user's crontab needs sudo", "cannot read the crontab (exit %d)", rr.ExitCode)
					}
					rows := []map[string]any{}
					for _, l := range strings.Split(rr.Stdout, "\n") {
						t := strings.TrimSpace(l)
						if t == "" || strings.HasPrefix(t, "#") {
							continue
						}
						rows = append(rows, parseCronLine(t))
					}
					return rows, nil
				},
				text: func(data any) string {
					rows := [][]string{}
					for _, r := range data.([]map[string]any) {
						cmdText := cell(r["command"])
						if r["schedule"] == nil {
							cmdText = cell(r["line"])
						}
						rows = append(rows, []string{cell(r["schedule"]), cmdText, cell(r["id"])})
					}
					return textTable([]string{"schedule", "command", "id"}, rows)
				}})
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
			return runOps(cmd.Context(), opsSpec{name: "cron.rm", target: args[0], command: command, display: "cron rm " + args[1], sudo: useSudo(), mutating: true,
				parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return cronRemoved(rr) },
				text: func(data any) string {
					if n, _ := data.(map[string]any)["removed"].(int); n > 0 {
						return "removed " + strconv.Itoa(n) + " entry\n"
					}
					return "no entry with ID " + args[1] + "\n"
				}})
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
		rest := strings.TrimSpace(body)
		for i := 0; i < n; i++ { // skip the schedule fields, whatever they contain
			rest = strings.TrimLeft(strings.TrimLeft(rest, " \t")[len(f[i]):], " \t")
		}
		r["command"] = rest
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
