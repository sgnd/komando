package cli

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
)

// `pkg security` lists, and `pkg upgrade --security` installs, only the security
// updates of apt and dnf/yum servers, one server at a time, with a look at
// the server before and after (running containers, failed units, pending
// updates, reboot and service restarts). What a patch round by hand needs:
// unattended-upgrade's choice of packages, needrestart kept quiet, and a
// stop when a server came out of it different.

// snapshotShell prints what a server looks like as key=value lines:
// containers=N (only when docker answers), pending=N, security=N and
// hoststate's lines (failed units, reboot, services running old code). It
// needs $PM, the secpkgs function and hoststate's settings; read it with
// parseSnapshot.
const snapshotShell = hostStateShell + `snap() {
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then echo "containers=$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')"; fi
  hoststate
  case $PM in
  apt) echo "pending=$(apt list --upgradable 2>/dev/null | grep -c /)" ;;
  *) echo "pending=$($PM -q check-update 2>/dev/null | awk '/^Obsoleting/{exit} NF == 3 && $1 ~ /\./' | wc -l | tr -d ' ')" ;;
  esac
  echo "security=$(secpkgs | wc -l | tr -d ' ')"
}
`

// pkgSecShell is the whole remote script. $ACTION (list or apply),
// $REFRESH (1: refresh the package index first) and $GUARD (1: stop before
// an upgrade that would remove an essential package) are set in front of
// it. It always exits 0 once it has started: what happened is in its
// #komando: sections.
//
// The upgrade itself runs detached (setsid nohup) and the script waits for
// it, so a dropped connection or komando's --timeout does not kill dpkg
// halfway. NEEDRESTART_SUSPEND keeps needrestart from restarting services
// during the run; the "after" snapshot then says which ones still run old
// code.
const pkgSecShell = `export LC_ALL=C DEBIAN_FRONTEND=noninteractive
unset NEEDRESTART_SUSPEND NEEDRESTART_MODE
if command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf >/dev/null 2>&1; then PM=dnf
elif command -v yum >/dev/null 2>&1; then PM=yum
else PM=none; for m in apk zypper pacman; do command -v $m >/dev/null 2>&1 && { PM=$m; break; }; done
  echo '#komando:unsupported'; echo $PM; exit 0; fi
echo "# package-manager: $PM" >&2
echo '#komando:pm'; echo $PM
T=""; T20=""; command -v timeout >/dev/null 2>&1 && { T="timeout 60"; T20="timeout 20"; }
S=""; HS_ROOT=""; [ "$(id -u)" = 0 ] && HS_ROOT=1
echo '#komando:os'
` + osShell + `if [ "$REFRESH" = 1 ]; then case $PM in apt) apt-get update -q >&2 ;; *) $PM -q makecache >&2 ;; esac; fi
if [ $PM = apt ]; then t=$(stat -c %Y /var/lib/apt/lists/*Release 2>/dev/null | sort -n | tail -n 1)
  echo '#komando:index-age'; if [ -n "$t" ]; then echo $(( $(date +%s) - t )); else echo never; fi; fi
secpkgs() { case $PM in
  apt) apt list --upgradable 2>/dev/null | awk -F'[/ ]' '$2 ~ /-security/' ;;
  *) $PM -q check-update --security 2>/dev/null | awk '/^Obsoleting/{exit} NF == 3 && $1 ~ /\./' ;;
  esac; }
inst() { case $PM in
  apt) dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\t${Version}\n' 2>/dev/null | awk -F'\t' '$1 ~ /^ii/ {print $2"\t"$3}' ;;
  *) rpm -qa --qf '%{NAME}.%{ARCH}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n' 2>/dev/null | sed 's/\t0:/\t/' ;;
  esac | sort; }
` + snapshotShell + `B=$(snap)
echo '#komando:before'; printf '%s\n' "$B"
echo '#komando:security'; secpkgs
names=
if [ $PM = apt ]; then
  names=$(secpkgs | cut -d/ -f1 | grep -E '^[a-z0-9][a-z0-9.+-]*$' | tr '\n' ' ')
  gone=
  if [ -n "$names" ]; then gone=$(apt-get -s install --only-upgrade $names 2>/dev/null | awk '$1 == "Remv" {sub(/:.*/, "", $2); print $2}'); fi
  echo '#komando:removes'; printf '%s\n' "$gone"
fi
[ "$ACTION" = apply ] || exit 0
if [ -z "$(secpkgs | head -n 1)" ]; then echo '#komando:nothing'; exit 0; fi
if [ "$GUARD" = 1 ] && [ -n "$gone" ]; then
  hit=$(printf '%s\n' "$gone" | grep -E "$ESSENTIAL")
  if [ -n "$hit" ]; then echo '#komando:essential'; printf '%s\n' "$hit"; exit 0; fi
fi
case $PM in
apt) if command -v unattended-upgrade >/dev/null 2>&1 && ! apt-config dump Unattended-Upgrade::Automatic-Reboot 2>/dev/null | grep -qiE '"(true|yes|on|1)"'; then
    method=unattended-upgrade; run='unattended-upgrade -v'
  else method=apt-get
    run="apt-get install -y -q --only-upgrade -o DPkg::Lock::Timeout=300 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold $names"; fi ;;
*) method=$PM; run="$PM upgrade --security -y" ;;
esac
echo '#komando:method'; echo $method
d=$(mktemp -d /var/tmp/komando-pkgsec.XXXXXX) || { echo '#komando:rc'; echo 1; exit 0; }
inst > "$d/before"
printf 'export LC_ALL=C DEBIAN_FRONTEND=noninteractive NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l\n%s\necho $? > %s/rc\n' "$run" "$d" > "$d/run.sh"
S=$(command -v setsid)
$S nohup sh "$d/run.sh" > "$d/log" 2>&1 < /dev/null &
wait $!
rc=$(cat "$d/rc" 2>/dev/null || echo 1)
tail -n 80 "$d/log" >&2
echo '#komando:rc'; echo "$rc"
bc=$(printf '%s\n' "$B" | sed -n 's/^containers=//p')
i=0; while [ -n "$bc" ] && [ $i -lt 12 ] && [ "$(docker ps -q 2>/dev/null | wc -l)" -lt "$bc" ]; do sleep 5; i=$((i+1)); done
echo '#komando:after'; snap
inst > "$d/after"
echo '#komando:changed'
awk -F'\t' 'NR == FNR {b[$1] = $2; next} b[$1] != $2 {print $1"\t"(($1 in b) ? b[$1] : "-")"\t"$2}' "$d/before" "$d/after"
awk -F'\t' 'NR == FNR {a[$1] = 1; next} !($1 in a) {print $1"\t"$2"\t-"}' "$d/after" "$d/before"
rm -f "$d"/*; rmdir "$d"
exit 0`

// pkgSecScript is the script with its settings in front.
func pkgSecScript(apply, refresh, guardEssential bool) string {
	b := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	action := "list"
	if apply {
		action = "apply"
	}
	return "ACTION=" + action + " REFRESH=" + b(refresh) + " GUARD=" + b(guardEssential) +
		" ESSENTIAL=" + sshx.Q(essentialPkgs.String()) + "\n" + pkgSecShell
}

// hostSnapshot is what a server looked like at one moment.
type hostSnapshot struct {
	ContainersRunning *int     `json:"containers_running"` // null: no docker, or no access to it
	FailedUnits       []string `json:"failed_units"`
	PendingUpdates    int      `json:"pending_updates"`
	PendingSecurity   int      `json:"pending_security"`
	RebootRequired    bool     `json:"reboot_required"`
	RebootPackages    []string `json:"reboot_packages,omitempty"`
	NeedRestart       []string `json:"services_need_restart"`
}

// parseSnapshot reads snapshotShell's key=value lines.
func parseSnapshot(s string) hostSnapshot {
	snap := hostSnapshot{}
	var hs hostState
	for _, l := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if hs.line(k, v) {
			continue
		}
		switch k {
		case "containers":
			if n, err := strconv.Atoi(v); err == nil {
				snap.ContainersRunning = &n
			}
		case "pending":
			snap.PendingUpdates, _ = strconv.Atoi(v)
		case "security":
			snap.PendingSecurity, _ = strconv.Atoi(v)
		}
	}
	snap.FailedUnits = nonNil(hs.Failed)
	snap.RebootRequired = hs.Reboot != nil && *hs.Reboot
	snap.RebootPackages = hs.RebootPackages
	snap.NeedRestart = nonNil(hs.NeedRestart)
	return snap
}

// diffSnapshots says what changed between two snapshots. unexpected are
// the changes a patch should not cause: fewer running containers and units
// that failed since.
func diffSnapshots(b, a hostSnapshot) (changes, unexpected []string) {
	if b.ContainersRunning != nil && a.ContainersRunning != nil && *a.ContainersRunning != *b.ContainersRunning {
		c := fmt.Sprintf("running containers %d -> %d", *b.ContainersRunning, *a.ContainersRunning)
		changes = append(changes, c)
		if *a.ContainersRunning < *b.ContainersRunning {
			unexpected = append(unexpected, c)
		}
	} else if b.ContainersRunning != nil && a.ContainersRunning == nil {
		c := "docker no longer answers"
		changes, unexpected = append(changes, c), append(unexpected, c)
	}
	for _, u := range a.FailedUnits {
		if !slices.Contains(b.FailedUnits, u) {
			c := "unit failed: " + u
			changes, unexpected = append(changes, c), append(unexpected, c)
		}
	}
	for _, u := range b.FailedUnits {
		if !slices.Contains(a.FailedUnits, u) {
			changes = append(changes, "unit no longer failed: "+u)
		}
	}
	if a.PendingUpdates != b.PendingUpdates {
		changes = append(changes, fmt.Sprintf("pending updates %d -> %d", b.PendingUpdates, a.PendingUpdates))
	}
	if a.PendingSecurity != b.PendingSecurity {
		changes = append(changes, fmt.Sprintf("pending security updates %d -> %d", b.PendingSecurity, a.PendingSecurity))
	}
	if a.RebootRequired && !b.RebootRequired {
		changes = append(changes, "a reboot is now required")
	}
	var restart []string
	for _, s := range a.NeedRestart {
		if !slices.Contains(b.NeedRestart, s) {
			restart = append(restart, s)
		}
	}
	if len(restart) > 0 {
		changes = append(changes, "now need a restart: "+strings.Join(restart, ", "))
	}
	return changes, unexpected
}

type pkgSecRow struct {
	Host           string        `json:"host"`
	OK             bool          `json:"ok"`
	PackageManager string        `json:"package_manager,omitempty"`
	IndexAge       string        `json:"index_age,omitempty"`
	OSSupport      *osSupport    `json:"os_support,omitempty"`
	Security       []pkgUpgrade  `json:"security_updates"`
	Count          int           `json:"count"`
	WouldRemove    []string      `json:"would_remove,omitempty"`
	State          *hostSnapshot `json:"state,omitempty"` // without --apply
	Method         string        `json:"method,omitempty"`
	Upgraded       []pkgUpgrade  `json:"upgraded,omitempty"`
	Removed        []pkgUpgrade  `json:"removed,omitempty"`
	Before         *hostSnapshot `json:"before,omitempty"`
	After          *hostSnapshot `json:"after,omitempty"`
	Changes        []string      `json:"changes,omitempty"`
	Unexpected     []string      `json:"unexpected,omitempty"`
	RebootRequired bool          `json:"reboot_required"`
	Warnings       []string      `json:"warnings,omitempty"`
	Stderr         string        `json:"stderr,omitempty"`
	DurationMS     int64         `json:"duration_ms,omitempty"`
	Error          *out.Error    `json:"error,omitempty"`
	unsupported    string        // the package manager komando does not pick security updates on
}

type pkgSecData struct {
	Applied bool         `json:"applied"`
	Order   string       `json:"order,omitempty"`
	Results []pkgSecRow  `json:"results"`
	NotRun  []string     `json:"not_run,omitempty"` // stopped before these servers
	Summary fleetSummary `json:"summary"`
}

// pkgSecLists fills in what the script found before any change: the
// package manager, the OS's support, the security updates, what they would
// remove and how old the package index is.
func pkgSecLists(r *pkgSecRow, sec map[string]string, refreshed bool) {
	r.PackageManager = strings.TrimSpace(sec["pm"])
	if o, ok := sec["os"]; ok {
		sup, w := pkgSecSupport(o, time.Now())
		r.OSSupport = &sup
		if w != "" {
			r.Warnings = append(r.Warnings, w)
		}
	}
	r.Security = parseUpgrades(r.PackageManager, sec["security"])
	r.Count = len(r.Security)
	r.WouldRemove = strings.Fields(sec["removes"])
	switch age := strings.TrimSpace(sec["index-age"]); {
	case age == "never":
		r.IndexAge = "never"
		r.Warnings = append(r.Warnings, "the package index was never refreshed on this server; add --refresh")
	case age != "":
		if n, err := strconv.ParseInt(age, 10, 64); err == nil {
			r.IndexAge = humanAge(time.Duration(n) * time.Second)
			if time.Duration(n)*time.Second > staleIndex && !refreshed {
				r.Warnings = append(r.Warnings, "the package index is "+r.IndexAge+" old, so new security updates may be missing; add --refresh")
			}
		}
	}
}

// pkgSecParse reads one server's script output. apply says whether the
// script was asked to change anything.
func pkgSecParse(host string, rr *sshx.RunResult, apply, refreshed bool) pkgSecRow {
	r := pkgSecRow{Host: host, Security: []pkgUpgrade{}, DurationMS: rr.DurationMS}
	sec := sections(rr.Stdout)
	fail := func(e *out.Error) pkgSecRow {
		r.Error, r.Stderr = e, strings.TrimSpace(rr.Stderr)
		return r
	}
	if pm, ok := sec["unsupported"]; ok {
		r.unsupported = strings.TrimSpace(pm)
		return r
	}
	if _, ok := sec["pm"]; !ok {
		if rr.TimedOut {
			return fail(out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout", "pkg security timed out before it started"))
		}
		return fail(out.Errf(out.ExitRemote, "PKG_FAILED", "read stderr for the reason", "pkg security failed (exit %d)", rr.ExitCode))
	}
	pkgSecLists(&r, sec, refreshed)
	var ess []string
	for _, p := range r.WouldRemove {
		if essentialPkg(p) {
			ess = append(ess, p)
		}
	}
	before := parseSnapshot(sec["before"])
	if !apply {
		r.State = &before
		r.RebootRequired = before.RebootRequired
		if len(ess) > 0 {
			r.Warnings = append(r.Warnings, "these updates would remove "+strings.Join(ess, ", ")+"; `pkg upgrade --security` stops unless --allow-dangerous")
		}
		r.OK = true
		return r
	}
	r.Before = &before
	r.RebootRequired = before.RebootRequired
	if e, ok := sec["essential"]; ok {
		return fail(approvalErr("POLICY_BLOCKED",
			"the security updates would remove "+strings.Join(strings.Fields(e), ", ")+", which can lock you out of the server or break it; nothing was changed"))
	}
	if _, ok := sec["nothing"]; ok {
		r.After = &before
		r.OK = true
		return r
	}
	r.Method = strings.TrimSpace(sec["method"])
	for _, l := range strings.Split(sec["changed"], "\n") {
		f := strings.Split(strings.TrimSpace(l), "\t")
		if len(f) != 3 {
			continue
		}
		switch {
		case f[2] == "-":
			r.Removed = append(r.Removed, pkgUpgrade{Name: f[0], From: f[1]})
		case f[1] == "-":
			r.Upgraded = append(r.Upgraded, pkgUpgrade{Name: f[0], Version: f[2]}) // newly installed (a new kernel)
		default:
			r.Upgraded = append(r.Upgraded, pkgUpgrade{Name: f[0], From: f[1], Version: f[2]})
		}
	}
	if a, ok := sec["after"]; ok {
		after := parseSnapshot(a)
		r.After = &after
		r.RebootRequired = after.RebootRequired
		r.Changes, r.Unexpected = diffSnapshots(before, after)
	}
	for _, p := range r.Removed {
		if essentialPkg(p.Name) {
			r.Unexpected = append(r.Unexpected, "essential package removed: "+p.Name)
		}
	}
	rc := strings.TrimSpace(sec["rc"])
	switch {
	case rr.TimedOut:
		return fail(out.Errf(out.ExitTimeout, "TIMEOUT", "the upgrade keeps running on the server; see what is left with `komando pkg security "+host+"` in a few minutes, and give more time with --timeout",
			"komando stopped waiting for the upgrade"))
	case rc == "":
		return fail(out.Errf(out.ExitRemote, "PKG_FAILED", "read stderr; check the server with `komando pkg security "+host+"`", "the upgrade ended before it reported back"))
	case rc != "0":
		return fail(out.Errf(out.ExitRemote, "PKG_FAILED", "read stderr for the package manager's message", "the security upgrade failed (exit %s)", rc))
	case len(r.Unexpected) > 0:
		return fail(out.Errf(out.ExitConflict, "UNEXPECTED_CHANGE", "check the server (`komando docker ps "+host+"`, `komando svc list "+host+" --failed`); servers after it were not patched: run it again with --keep-going to patch them anyway",
			"%s changed after patching: %s", host, strings.Join(r.Unexpected, "; ")))
	}
	r.OK = true
	return r
}

// pkgSecSupport judges the OS support from the script's os section, and
// the warning when the OS gets no (or maybe no) security updates: then an
// empty list does not mean the server is safe.
func pkgSecSupport(section string, now time.Time) (osSupport, string) {
	set := map[string]string{}
	var pro *string
	for _, l := range strings.Split(section, "\n") {
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if k == "pro_json" {
			pro = &v
		}
		set[k] = v
	}
	sup := osSupportFrom(set["os"], set["os_version"], set["os_pretty"], pro, now)
	w, unknown := supportWarning(osName(set["os"], set["os_version"], set["os_pretty"]), sup, now)
	if unknown {
		w += "; the repositories publish no new security fixes for it, so an empty list does not mean the server is safe: upgrade the OS"
	}
	return sup, w
}

func (d pkgSecData) Text() string {
	var sb strings.Builder
	for _, r := range d.Results {
		switch {
		case r.Error != nil && r.Before == nil && r.State == nil:
			fmt.Fprintf(&sb, "● %s  FAILED: %s\n", r.Host, r.Error.Message)
			continue
		case !d.Applied:
			fmt.Fprintf(&sb, "● %s  %s (%s)\n", r.Host, countOf(r.Count, "security update"), r.PackageManager)
			if r.Count > 0 {
				sb.WriteString(indentLines(pkgUpgradesText(r.Security), "  "))
			}
		case r.Method == "" && r.Error == nil:
			fmt.Fprintf(&sb, "● %s  nothing to patch\n", r.Host)
		default:
			status := "patched"
			if r.Error != nil {
				status = "FAILED: " + r.Error.Message
			}
			fmt.Fprintf(&sb, "● %s  %s, %s changed (%s)\n", r.Host, status, countOf(len(r.Upgraded)+len(r.Removed), "package"), r.Method)
			for _, c := range r.Changes {
				fmt.Fprintf(&sb, "  %s\n", c)
			}
		}
		snap := r.State
		if r.After != nil {
			snap = r.After
		}
		if snap != nil {
			c := "-"
			if snap.ContainersRunning != nil {
				c = strconv.Itoa(*snap.ContainersRunning)
			}
			fmt.Fprintf(&sb, "  containers running: %s, failed units: %d, pending updates: %d\n", c, len(snap.FailedUnits), snap.PendingUpdates)
			if len(snap.NeedRestart) > 0 {
				fmt.Fprintf(&sb, "  need a restart: %s\n", strings.Join(snap.NeedRestart, ", "))
			}
		}
		if r.RebootRequired {
			fmt.Fprintf(&sb, "  reboot required: komando reboot %s --allow-dangerous\n", r.Host)
		}
		for _, w := range r.Warnings {
			fmt.Fprintf(&sb, "  warning: %s\n", w)
		}
	}
	if len(d.NotRun) > 0 {
		fmt.Fprintf(&sb, "not patched (stopped): %s\n", strings.Join(d.NotRun, ", "))
	}
	return sb.String()
}

// pkgSecTimeout is how long --apply waits for each server by default: a
// patch round with a new kernel takes minutes, more than the usual 5m
// command timeout allows on a slow mirror.
const pkgSecTimeout = 30 * time.Minute

// pkgSecRollout is how `pkg upgrade --security` (and the retired
// `pkg security --apply`) installs the updates.
const pkgSecRollout = `--security installs only the security updates, one server at a time. On
apt servers komando uses unattended-upgrade when it is installed (it picks
security origins only and follows the server's own settings), otherwise
apt-get --only-upgrade of the listed packages, keeping changed config
files. On dnf/yum it runs "upgrade --security". needrestart is kept from
restarting services during the run; the result lists the services that
need it.

After each server komando compares the state with the one before. When
fewer containers run or a unit has failed, it stops and leaves the other
servers as they are (--keep-going patches them anyway). It never reboots:
reboot_required says when a server needs one, use ` + "`komando reboot`" + `.

The upgrade runs detached on the server, so a dropped connection does not
break it. It waits up to 30 minutes per server (--timeout changes it).
Other package managers (apk, zypper, pacman) are listed in meta.skipped:
use ` + "`komando pkg upgrade`" + ` without --security there.`

func pkgSecurityCmd(noSudo *bool) *cobra.Command {
	var apply, refresh, keepGoing bool
	c := &cobra.Command{
		Use:   "security TARGET",
		Short: "Pending security updates and the state of each server",
		Long: `This only looks: the pending security updates of each server (apt:
packages from the -security pocket; dnf/yum: updates with a security
notice), and the server's state: running containers, failed units,
pending updates, whether a reboot is required, and services that run old
code.

To install them: ` + "`komando pkg upgrade TARGET --security`" + `, one server at a
time with a check before and after each. --apply here is the old way to
say that; it still works in this release.`,
		Example: "  komando pkg security @swarm --refresh\n  komando pkg upgrade @swarm --security --dry-run\n  komando pkg upgrade @swarm --security",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if keepGoing && !apply {
				return out.Usage("--keep-going goes with `komando pkg upgrade TARGET --security`")
			}
			if apply {
				retiredName("komando pkg security --apply", "komando pkg upgrade TARGET --security")
			}
			return pkgSecurity(cmd.Context(), args[0], apply, refresh, keepGoing, !*noSudo)
		},
	}
	c.Flags().BoolVar(&apply, "apply", false, "old way to install them: use komando pkg upgrade TARGET --security")
	c.Flags().BoolVar(&refresh, "refresh", false, "refresh the package index first (like apt-get update)")
	c.Flags().BoolVar(&keepGoing, "keep-going", false, "with --apply: go on to the next server after a failure or an unexpected change")
	_ = c.Flags().MarkHidden("apply")
	_ = c.Flags().MarkHidden("keep-going")
	return c
}

// pkgUpgradeSecurity gives `pkg upgrade` (made by pkgCmd) --security: it
// installs only the security updates through the same rollout as
// `pkg security --apply` did, and keeps that command's ID, pkg.security,
// in the envelope and the audit log (C-V18).
func pkgUpgradeSecurity(c *cobra.Command, noSudo *bool) *cobra.Command {
	var security, refresh, keepGoing bool
	plain := c.RunE
	c.Long = "Without --security: upgrades every package, or the given ones (--dry-run\nlists what would change).\n\n" + pkgSecRollout
	c.Example = "  komando pkg upgrade web1 --dry-run   # see what would change first\n  komando pkg upgrade web1 openssl\n  komando pkg upgrade @web --security --dry-run\n  komando pkg upgrade @web --security"
	c.RunE = func(cmd *cobra.Command, args []string) error {
		if !security {
			if refresh || keepGoing {
				return out.Usage("--refresh and --keep-going go with --security")
			}
			return plain(cmd, args)
		}
		if len(args) > 1 {
			return out.Usage("--security installs every pending security update; it takes no package names (see them with `komando pkg security %s`)", args[0])
		}
		withID(cmd, "pkg.security") // the same command as pkg security --apply was
		return pkgSecurity(cmd.Context(), args[0], true, refresh, keepGoing, !*noSudo)
	}
	c.Flags().BoolVar(&security, "security", false, "install only the security updates, one server at a time")
	c.Flags().BoolVar(&refresh, "refresh", false, "with --security: refresh the package index first")
	c.Flags().BoolVar(&keepGoing, "keep-going", false, "with --security: go on to the next server after a failure or an unexpected change")
	return c
}

func pkgSecurity(ctx context.Context, target string, apply, refresh, keepGoing, sudo bool) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return err
	}
	display := "pkg security"
	if apply {
		display += " --apply"
	}
	change := apply && !g.dryRun
	// an essential package may go only with --allow-dangerous, asked before
	// anything runs (the script stops on the server when it would happen)
	guardEssential := !g.allowDangerous || (change && !dangerOK("the security updates may remove a package the server needs", targetsWhy(st, hosts)))
	script := pkgSecScript(change, refresh, guardEssential)
	if apply {
		// protected servers need --yes; a dry run records the stop as would_be_blocked
		if gerr := guard(st, hosts, script, true); gerr != nil {
			audit(st, "pkg.security", hostNames(hosts), display, false, map[string]any{"blocked": toErr(gerr).Code})
			return gerr
		}
	}
	timeout := cmdTimeout(st)
	if change && g.timeout == 0 {
		timeout = max(timeout, pkgSecTimeout)
	}
	run := func(ctx context.Context, c *sshx.Client) (*sshx.RunResult, error) {
		return sshx.Run(ctx, c, sshx.RunRequest{Command: script, Sudo: sudo, Timeout: timeout, MaxOutput: maxOutput(st)})
	}
	data := pkgSecData{Applied: change, Results: []pkgSecRow{}}
	if apply {
		data.Order = "one server at a time, stopping at a failure or an unexpected change"
		if keepGoing {
			data.Order = "one server at a time"
		}
	}
	var rows []pkgSecRow
	var notRun []string
	if !change {
		for _, o := range fanout(ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) { return run(ctx, c) }) {
			if o.Err != nil {
				rows = append(rows, pkgSecRow{Host: o.Host.Name, Security: []pkgUpgrade{}, Error: toErr(o.Err)})
				continue
			}
			rows = append(rows, pkgSecParse(o.Host.Name, o.Value.(*sshx.RunResult), false, refresh))
		}
	} else {
		for i, h := range hosts {
			var r pkgSecRow
			err := withClient(ctx, st, h, func(c *sshx.Client) error {
				rr, err := run(ctx, c)
				if err == nil {
					r = pkgSecParse(h.Name, rr, true, refresh)
				}
				return err
			})
			if err != nil {
				r = pkgSecRow{Host: h.Name, Security: []pkgUpgrade{}, Error: toErr(err)}
			}
			rows = append(rows, r)
			if r.unsupported != "" {
				continue
			}
			audit(st, "pkg.security", []string{h.Name}, display, r.OK, map[string]any{"upgraded": len(r.Upgraded), "unexpected": r.Unexpected})
			if !r.OK && !keepGoing {
				for _, rest := range hosts[i+1:] {
					notRun = append(notRun, rest.Name)
				}
				break
			}
		}
	}
	worst := 0
	var fails []hostFail
	for _, r := range rows {
		if r.unsupported != "" {
			out.P.Skip(out.Skipped{Name: r.Host, Kind: "host", Reason: r.unsupported + ": komando picks security updates on apt and dnf/yum servers only; use `komando pkg upgrade` here"})
			continue
		}
		if apply && g.dryRun && r.Error == nil && !g.allowDangerous {
			for _, p := range r.WouldRemove {
				if essentialPkg(p) {
					out.P.WouldBlock(approvalErr("POLICY_BLOCKED",
						"on "+r.Host+" the security updates would remove "+p+", which can lock you out of the server or break it"))
					break
				}
			}
		}
		if r.Error != nil {
			r.Error.Exit = max(r.Error.Exit, 1)
			data.Summary.Failed++
			data.Summary.FailedHosts = append(data.Summary.FailedHosts, r.Host)
			worst = worse(worst, r.Error.Exit)
			fails = append(fails, hostFail{host: r.Host, reason: failReason(0, r.Error), err: r.Error})
		} else {
			data.Summary.OK++
		}
		data.Results = append(data.Results, r)
	}
	data.NotRun = notRun
	data.Summary.Total = len(data.Results)
	if len(data.Results) == 0 && len(rows) > 0 {
		return out.Errf(out.ExitNotFound, "SECURITY_UNSUPPORTED", "use `komando pkg upgrade TARGET` on these servers",
			"komando picks security updates on apt and dnf/yum servers only; %s uses %s", rows[0].Host, rows[0].unsupported)
	}
	if !change && !g.dryRun {
		audit(st, "pkg.security", hostNames(hosts), display, len(fails) == 0, nil)
	}
	return finishFleet("pkg.security", data, runSummary{fleetSummary: data.Summary}, worst, fails)
}
