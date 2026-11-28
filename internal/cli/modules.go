package cli

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// svc.

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
				c += " --since " + dockerTimeArg(since)
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
			c += " --since " + dockerTimeArg(since)
		}
		if until != "" {
			c += " --until " + dockerTimeArg(until)
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
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			return runLogs(cl, cmd.Context(), "logs", args[0], &lo, lo.sudo)
		}),
	}
	lo.bind(c)
	return c
}

// runLogs reads logs once, or streams them with --follow. `docker logs`
// goes through here too, so -f behaves the same everywhere.
func runLogs(cl *call, ctx context.Context, name, target string, lo *logOpts, sudo bool) error {
	command, err := lo.build()
	if err != nil {
		return err
	}
	if lo.follow {
		if !cl.dryRun() {
			if err := lo.followCheck(cl, ctx, target, sudo); err != nil {
				return err
			}
		}
		return followLogs(cl, ctx, target, command, sudo)
	}
	shown := lo.source()
	return runOps(cl, ctx, opsSpec{name: name, target: target, command: command, display: shown, sudo: sudo, raw: true,
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

// pkgNameRe is what a package name may look like: letters and digits, and
// . _ + - with :arch, =version, /release or @repo. Nothing else gets to the
// server's shell, which splits the list on any space, tab or newline. The
// last character is a letter, a digit or + (libstdc++): apt reads a name
// ending in - as "remove this package", even for install.
var pkgNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._+:~@/=-]{0,198}[A-Za-z0-9+])?$`)

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
		Short:   "Packages on servers: install, update, remove, check for updates",
	}
	var noSudo, refresh bool
	var limit int
	c.PersistentFlags().BoolVar(&noSudo, "no-sudo", false, "do not use sudo (like when logged in as root)")
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
				cl := callOf(cmd)
				// the usual missing-arguments error, which names the Use line
				n := 1
				if needPkgs {
					n = 2
				}
				if err := cobra.MinimumNArgs(n)(cmd, args); err != nil {
					return usageErr(cl, cmd, err)
				}
				if action == "update" && len(args) > 1 {
					return out.Errf(out.ExitUsage, "USAGE", "to upgrade packages: komando pkg upgrade "+args[0]+" "+strings.Join(args[1:], " "),
						"pkg update only refreshes the package index; it takes no package names")
				}
				return nil
			},
			RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
				for _, p := range args[1:] {
					// an allowlist: a name starting with - would be read as an
					// option, a glob can pick hundreds of packages, and a tab or
					// newline would split one name into two on the server
					if !pkgNameRe.MatchString(p) || pkgFileRe.MatchString(p) {
						if pkgFileRe.MatchString(p) {
							return out.Usage("%q looks like a package file: pkg installs packages by name from the server's repositories; for a local file, copy it with `komando copy` and install it with `komando host ssh exec`", p)
						}
						return out.Usage("%q is not a package name: give exact names, no options or patterns", p)
					}
				}
				pkgs := strings.Join(args[1:], " ")
				if action == "remove" {
					for _, p := range args[1:] {
						if policy.EssentialPackage(p) {
							askTypes(cl, []string{p}, "packages on "+args[0])
						}
						if policy.EssentialPackage(p) && !cl.dangerOK() && !confirmDangerous(cl, args[:1], "removes "+p+", which can lock you out of the server or break it") {
							if err := cl.policyStop(approvalErr(cl, "POLICY_BLOCKED",
								"removing "+p+" can lock you out of the server or break it")); err != nil {
								return err
							}
							break // --dry-run: show the plan, marked would_be_blocked
						}
					}
				}
				useSudo := (sudo || action == "upgradable" && refresh) && !noSudo
				if action != "update" {
					return runPkg(cl, cmd.Context(), action, args[0], args[1:], useSudo, refresh, limit)
				}
				command := "ACTION=" + action + " PKGS=" + sshx.Q(pkgs) + "; " + pkgShell
				o := execOpts{sudo: useSudo, display: strings.TrimSpace("pkg " + action + " " + pkgs), exitMap: orSudo(soleHost(cl, args[0]), nil)}
				return runFleet(cl, cmd.Context(), "pkg."+action, args[0], command, nil, o, mutating)
			}),
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

// cron.
