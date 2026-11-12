package cli

import (
	"context"
	"encoding/json"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// svc.

func svcCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "svc",
		Aliases: []string{"service"},
		Short:   "Services (systemd, Windows): status, start, stop, restart, logs",
	}
	c.AddCommand(svcStatusCmd(), svcListCmd(), svcLogsCmd(), svcDaemonReloadCmd())
	for _, a := range []string{"start", "stop", "restart", "reload", "enable", "disable"} {
		c.AddCommand(svcActionCmd(a))
	}
	return c
}

var svcProps = []string{"Id", "Description", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID", "ActiveEnterTimestamp", "NRestarts", "MemoryCurrent", "Result", "ExecMainStatus"}

func parseSvcShow(_ *store.Host, s string) any {
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
	return units
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
		Short:   "Unit status: state, main pid, restarts, memory",
		Example: "  komando svc status @web nginx php8.2-fpm",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return svcStatus(cmd.Context(), args[0], args[1:])
		},
	}
}

func svcActionCmd(action string) *cobra.Command {
	var noSudo, now bool
	var wait time.Duration
	c := &cobra.Command{
		Use:   action + " TARGET UNIT...",
		Short: strings.ToUpper(action[:1]) + action[1:] + " units (sudo) and report the resulting state",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return svcAction(cmd.Context(), action, args[0], args[1:], !noSudo, now, int(math.Ceil(wait.Seconds())))
		},
	}
	c.Flags().BoolVar(&noSudo, "no-sudo", false, "do not use sudo (when you log in as root)")
	switch action {
	case "start", "restart", "reload":
		c.Example = "  komando svc " + action + " @web nginx --wait 10s   # fails unless nginx is active within 10 seconds"
		c.Flags().Var(&durFlag{d: &wait, seconds: true, name: "wait"}, "wait", "wait up to this long (e.g. 10s, 2m) for the units to be active; fail if they are not")
	case "enable", "disable":
		verb := map[string]string{"enable": "start", "disable": "stop"}[action]
		c.Flags().BoolVar(&now, "now", false, "also "+verb+" the units now (systemctl "+action+" --now)")
	}
	return c
}

func svcLogsCmd() *cobra.Command {
	return logsAlias("logs TARGET UNIT", "svc.logs", "unit")
}

// logs.

func (o *logOpts) source() string {
	n := strconv.Itoa(o.lines)
	since, until, _ := o.times() // check() has refused a bad one
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
			c := o.dockerLogs() + " --tail " + n + " -f"
			if since != "" {
				c += " --since " + sshx.Q(since)
			}
			return c + " " + sshx.Q(o.container) + " 2>&1" + grep
		case o.file != "":
			return "tail -n " + n + " -F -- " + sshx.Q(o.file) + grep
		}
		c := "journalctl --no-pager -o short-iso -n " + n + " -f"
		if o.unit != "" {
			c += " -u " + sshx.Q(o.unit)
		}
		if since != "" {
			c += " --since " + sshx.Q(since)
		}
		if o.priority != "" {
			c += " -p " + sshx.Q(o.priority)
		}
		return c + grep
	}
	switch {
	case o.container != "":
		c := o.dockerLogs() + " --tail " + n
		if o.grep != "" {
			c = o.dockerLogs()
		}
		if since != "" {
			c += " --since " + sshx.Q(since)
		}
		if until != "" {
			c += " --until " + sshx.Q(until)
		}
		c += " " + sshx.Q(o.container) + " 2>&1"
		if grep != "" {
			c += grep + " | tail -n " + n
		}
		return c
	case o.file != "":
		if grep != "" {
			return "grep -iE -- " + sshx.Q(o.grep) + " " + sshx.Q(o.file) + " | tail -n " + n
		}
		return "tail -n " + n + " -- " + sshx.Q(o.file)
	default:
		c := "journalctl --no-pager -o short-iso"
		if o.unit != "" {
			c += " -u " + sshx.Q(o.unit)
		}
		if since != "" {
			c += " --since " + sshx.Q(since)
		}
		if until != "" {
			c += " --until " + sshx.Q(until)
		}
		if o.priority != "" {
			c += " -p " + sshx.Q(o.priority)
		}
		if grep != "" {
			return c + grep + " | tail -n " + n
		}
		return c + " -n " + n
	}
}

func logsCmd() *cobra.Command {
	var lo logOpts
	c := &cobra.Command{
		Use:   "logs TARGET",
		Short: "Read logs from journald, a file or a container",
		Example: `  komando logs web1 --unit nginx --since 30m --grep 'error|crit'
  komando logs @web --file /var/log/nginx/error.log -n 50 --sudo
  komando logs app1 --container api --since 10m`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLogs(cmd.Context(), "logs", args[0], &lo, lo.sudo)
		},
	}
	lo.bind(c)
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
	shown := lo.source()
	return runOps(ctx, opsSpec{name: name, target: target, command: command, display: shown, sudo: sudo, raw: true,
		parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return lo.result(rr) }})
}

// pkg.

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
apt:simulate-remove) apt-get -s remove $PKGS | awk '$1 == "Remv" {sub(/:.*/, "", $2); print $2}' ;;
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

// essentialSamples are names essentialPkgs matches, one per entry, for
// testing a name that apt would read as a pattern.
var essentialSamples = strings.Fields(`openssh-server openssh ssh sudo systemd systemd-sysv init libc6 glibc libc musl bash
coreutils util-linux apt dpkg rpm dnf yum apk-tools busybox base-files login passwd linux-image-generic kernel-core linux`)

// pkgNameRe is what a package name may look like: letters and digits, and
// . _ + - with :arch, =version, /release or @repo. Nothing else gets to the
// server's shell, which splits the list on any space, tab or newline. The
// last character is a letter, a digit or + (libstdc++): apt reads a name
// ending in - as "remove this package", even for install.
var pkgNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._+:~@/=-]{0,198}[A-Za-z0-9+])?$`)

// pkgVersionRe is the -1.2.3 that dnf and yum allow after a name.
var pkgVersionRe = regexp.MustCompile(`-[0-9].*$`)

// pkgArchRe is the .x86_64 that dnf, yum and zypper allow after a name.
var pkgArchRe = regexp.MustCompile(`\.(x86_64|i386|i586|i686|aarch64|armv7hl|armhfp|ppc64le|ppc64|s390x|noarch|src|amd64|arm64)$`)

// essentialPkg reports whether name, written any way a package manager
// takes it (OpenSSH-Server, openssh-server:amd64, sudo=1.9.15,
// systemd/bookworm, openssh-server-8.0p1, sudo.x86_64), is one of
// essentialPkgs. A name with a dot that is no package of its own is a
// regular expression to apt ("openssh.server", "sud."): it counts as
// essential when it would pick an essential package.
func essentialPkg(name string) bool {
	n := strings.ToLower(name)
	if i := strings.IndexAny(n, ":=/@"); i >= 0 {
		n = n[:i]
	}
	noArch := pkgArchRe.ReplaceAllString(n, "")
	for _, c := range []string{n, noArch, pkgVersionRe.ReplaceAllString(n, ""), pkgVersionRe.ReplaceAllString(noArch, ""),
		pkgArchRe.ReplaceAllString(pkgVersionRe.ReplaceAllString(n, ""), "")} {
		if essentialPkgs.MatchString(c) {
			return true
		}
	}
	if strings.Contains(n, ".") {
		re, err := regexp.Compile(strings.ReplaceAll(regexp.QuoteMeta(n), `\.`, "."))
		if err != nil {
			return true
		}
		for _, e := range essentialSamples {
			if re.MatchString(e) {
				return true
			}
		}
	}
	return false
}

// pkgFileRe is a local package file, which `pkg` does not install.
var pkgFileRe = regexp.MustCompile(`(^\.{0,2}/)|\.(deb|rpm|apk)$|\.pkg\.tar\.`)

// parseInstalled reads "name<TAB>version" lines ("-" when not installed).
func parseInstalled(_ *store.Host, s string) any {
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
	return rows
}

func pkgCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "pkg",
		Aliases: []string{"package", "packages"},
		Short:   "Packages on servers (apt, dnf, yum, apk, zypper, pacman)",
	}
	var noSudo, refresh bool
	var limit int
	c.PersistentFlags().BoolVar(&noSudo, "no-sudo", false, "do not use sudo (e.g. when logged in as root)")
	mk := func(action, short string, needPkgs, mutating, sudo bool) *cobra.Command {
		use := action + " TARGET"
		switch {
		case needPkgs:
			use += " PACKAGE..."
		case action != "update":
			use += " [PACKAGE...]"
		}
		return &cobra.Command{
			Use:   use,
			Short: short,
			Args: func(cmd *cobra.Command, args []string) error {
				// the usual missing-arguments error, which names the Use line
				n := 1
				if needPkgs {
					n = 2
				}
				if err := cobra.MinimumNArgs(n)(cmd, args); err != nil {
					return usageErr(cmd, err)
				}
				if action == "update" && len(args) > 1 {
					return out.Errf(out.ExitUsage, "USAGE", "to upgrade packages: komando pkg upgrade "+args[0]+" "+strings.Join(args[1:], " "),
						"pkg update only refreshes the package index; it takes no package names")
				}
				return nil
			},
			RunE: func(cmd *cobra.Command, args []string) error {
				for _, p := range args[1:] {
					// an allowlist: a name starting with - would be read as an
					// option, a glob can pick hundreds of packages, and a tab or
					// newline would split one name into two on the server
					if !pkgNameRe.MatchString(p) || pkgFileRe.MatchString(p) {
						if pkgFileRe.MatchString(p) {
							return out.Usage("%q looks like a package file: pkg installs packages by name from the server's repositories; for a local file, copy it with `komando upload` and install it with `komando exec`", p)
						}
						return out.Usage("invalid package name %q (give exact names, no options or patterns)", p)
					}
				}
				pkgs := strings.Join(args[1:], " ")
				if action == "remove" {
					for _, p := range args[1:] {
						if essentialPkg(p) {
							askTypes([]string{p}, "packages on "+args[0])
						}
						if essentialPkg(p) && !dangerOK() && !confirmDangerous(args[:1], "removing "+p+" can lock you out of the server or break it") {
							if err := policyStop(approvalErr("POLICY_BLOCKED",
								"removing "+p+" can lock you out of the server or break it")); err != nil {
								return err
							}
							break // --dry-run: show the plan, marked would_be_blocked
						}
					}
				}
				useSudo := (sudo || action == "upgradable" && refresh) && !noSudo
				if action != "update" {
					return runPkg(cmd.Context(), action, args[0], args[1:], useSudo, refresh, limit)
				}
				command := "ACTION=" + action + " PKGS=" + sshx.Q(pkgs) + "; " + pkgShell
				o := execOpts{sudo: useSudo, display: strings.TrimSpace("pkg " + action + " " + pkgs), exitMap: orSudo(soleHost(args[0]), nil)}
				return runFleet(cmd.Context(), "pkg."+action, args[0], command, nil, o, mutating)
			},
		}
	}
	upgradable := mk("upgradable", "Pending upgrades (--refresh updates the package index first)", false, false, false)
	upgradable.Flags().BoolVar(&refresh, "refresh", false, "refresh the package index first (like apt-get update), so the list is current")
	limitFlag(upgradable, &limit, 0, "packages per server")
	installed := mk("installed", "Show installed versions (all or given packages)", false, false, false)
	limitFlag(installed, &limit, 0, "packages per server")
	pkgRm := mk("remove", "Remove packages and report what changed (skips uninstalled)", true, true, true) // "remove" is what the package managers call it
	pkgRm.Use = "rm TARGET PACKAGE..."
	c.AddCommand(
		mk("install", "Install packages and report what changed (installed ones stay)", true, true, true),
		pkgRm,
		mk("update", "Refresh the package index", false, true, true),
		pkgUpgradeSecurity(mk("upgrade", "Upgrade all or the given packages (--dry-run lists them)", false, true, true), &noSudo),
		upgradable,
		installed,
		pkgSecurityCmd(&noSudo),
	)
	return c
}

// net.

func netCmd() *cobra.Command {
	c := &cobra.Command{Use: "net", Aliases: []string{"network"}, Short: "Network checks from the servers: ports, HTTP, DNS"}
	check := &cobra.Command{
		Use:     "check TARGET HOST:PORT...",
		Short:   "Check that each server can open a TCP connection to HOST:PORT",
		Example: "  komando net check @web db.internal:5432 redis.internal:6379",
		Args:    cobra.MinimumNArgs(2),
		RunE:    netCheckRun,
	}
	var sudo bool
	var portsLimit int
	ports := &cobra.Command{
		Use:   "ports TARGET",
		Short: "Listening sockets: protocol, address, port, process",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return netPortsRun(cmd, args[0], sudo, portsLimit)
		},
	}
	ports.Flags().BoolVarP(&sudo, "sudo", "s", false, "use sudo to see process names")
	limitFlag(ports, &portsLimit, 0, "sockets per server")
	var expect string
	httpC := &cobra.Command{
		Use:   "http TARGET URL",
		Short: "Send an HTTP request from each server: status, timing, IP",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkHTTPURL(args[1]); err != nil {
				return err
			}
			expect = strings.ToLower(expect)
			if expect != "" && !expectRe.MatchString(expect) {
				return out.Usage("--expect takes a status like 200 or a class like 2xx (got %q)", expect)
			}
			command := `curl -sS -o /dev/null -m ` + strconv.Itoa(curlSeconds()) + ` --proto =http,https -w '{"code":%{http_code},"time_total":%{time_total},"time_connect":%{time_connect},"time_starttransfer":%{time_starttransfer},"remote_ip":"%{remote_ip}","size":%{size_download},"redirect":"%{redirect_url}"}' --url ` + sshx.Q(args[1])
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
					return v, out.Errf(out.ExitConnect, "NO_RESPONSE", "check the URL, and that the server can reach it: `komando net check "+args[0]+" HOST:443`", "no HTTP answer from %s", args[1])
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
		Short:   "Resolve NAME from each server (--type MX etc. needs dig there)",
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

// checkHTTPURL takes only http:// and https:// URLs: anything else would
// reach curl as another protocol, or as an option when it starts with -.
func checkHTTPURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return out.Usage("give the URL with http:// or https:// in front, like https://example.com/health (got %q)", s)
	}
	return nil
}

var expectRe = regexp.MustCompile(`^[1-5]([0-9]{2}|xx)$`)

// curlSeconds is curl's own time limit: 15 seconds, or a moment less than
// --timeout, so curl reports the timeout before the connection is cut.
func curlSeconds() int {
	if g.timeout <= 0 {
		return 15
	}
	return max(1, int(g.timeout.Seconds())-1)
}

// statusMatches: 200 matches 200, 2xx matches 200-299.
func statusMatches(code int, want string) bool {
	want = strings.ToLower(want)
	if len(want) == 3 && strings.HasSuffix(want, "xx") {
		return strconv.Itoa(code)[:1] == want[:1]
	}
	return strconv.Itoa(code) == want
}

// cron.

const cronLong = `Cron runs commands on a schedule (every night at 2, every 5 minutes ...).
komando manages crontab entries by ID: each is tagged with '# komando:<id>',
so 'cron set' replaces the entry with the same ID instead of adding a second
one, and 'cron rm' removes only that entry. Other lines of the crontab are
kept as they are.`

func cronCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "cron",
		Short: "Manage crontab entries by ID (set replaces, never duplicates)",
		Long:  cronLong,
	}
	var user string
	var sudo bool
	c.PersistentFlags().StringVar(&user, "user", "", "crontab of this user (uses sudo)")
	c.PersistentFlags().BoolVarP(&sudo, "sudo", "s", false, "use root's crontab (through sudo)")
	_ = c.PersistentFlags().MarkHidden("sudo") // retired: --user root is the same
	noted := false
	ct := func() string {
		if user != "" {
			return "crontab -u " + sshx.Q(user)
		}
		return "crontab"
	}
	useSudo := func() bool {
		if sudo && !noted {
			noted = true
			retiredName("--sudo", "--user root")
		}
		return sudo || user != ""
	}
	// readCron puts the current crontab in $cur; "no crontab" (busybox: "can't
	// open ...: No such file") is empty, any other error (no permission,
	// busybox not suid) stops before a write could replace the whole crontab
	readCron := func() string {
		return "cur=$(" + ct() + ` -l 2>&1); rc=$?
if [ $rc -ne 0 ]; then case "$cur" in *"no crontab"*|*"can't open"*"No such file"*) cur="" ;; *) printf '%s\n' "$cur" >&2; exit $rc ;; esac; fi
`
	}
	// without keeps the lines that do not end in the exact tag
	without := func(id string) string {
		return `new=$(printf '%s\n' "$cur" | awk -v t=` + sshx.Q("# komando:"+id) + ` '{ n = length(t); if (length($0) >= n && substr($0, length($0) - n + 1) == t) next; print }')
`
	}
	list := cronListCmd(readCron, useSudo)
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
			return runFleet(cmd.Context(), "cron.set", args[0], command, nil, execOpts{sudo: useSudo(), display: "cron set " + args[1] + ": " + line, exitMap: orSudo(soleHost(args[0]), nil)}, true)
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
