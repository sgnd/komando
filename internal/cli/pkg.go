package cli

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// sections splits a script's stdout at komando's "#komando:NAME" lines.
func sections(stdout string) map[string]string {
	res := map[string]string{}
	cur := ""
	for _, l := range strings.Split(stdout, "\n") {
		if name, ok := strings.CutPrefix(strings.TrimSpace(l), "#komando:"); ok {
			cur = name
			res[cur] = ""
			continue
		}
		if cur != "" {
			res[cur] += l + "\n"
		}
	}
	return res
}

// pkgVersions reads "name<TAB>version" lines ("-" = not installed).
func pkgVersions(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		name, ver, ok := strings.Cut(strings.TrimSpace(l), "\t")
		if ok && name != "" {
			m[name] = ver
		}
	}
	return m
}

// pkgChangeScript runs ACTION for PKGS between two `installed` listings,
// so the result says what changed. install skips packages already there
// and remove skips packages that are not, like apt does, so both are safe
// to repeat. With guard, a removal that would take an essential package
// with it (libssl3 takes openssh-server) stops before anything changes and
// names them in a #komando:essential section; apt is asked with a
// simulated run, the other package managers are not checked this way.
func pkgChangeScript(action string, pkgs []string, guard bool) string {
	q := sshx.Q(strings.Join(pkgs, " "))
	listed := q
	if action == "upgrade" && len(pkgs) == 0 {
		listed = "''" // every package
	}
	var sb strings.Builder
	sb.WriteString("ACTION=installed PKGS=" + listed + "; before=$( (" + pkgShell + ") 2>/dev/null )\n")
	switch action {
	case "install":
		sb.WriteString(`todo=$(printf '%s\n' "$before" | awk -F'\t' '$2 == "-" {print $1}' | tr '\n' ' ')` + "\n")
	case "remove":
		sb.WriteString(`todo=$(printf '%s\n' "$before" | awk -F'\t' '$2 != "-" && $1 != "" {print $1}' | tr '\n' ' ')` + "\n")
	default:
		sb.WriteString("todo=" + q + "\n")
	}
	if action == "remove" && guard {
		sb.WriteString("if [ -n \"$(echo $todo)\" ]; then gone=$(ACTION=simulate-remove PKGS=\"$todo\"; (" + pkgShell + ") 2>/dev/null)\n" +
			"hit=$(printf '%s\\n' \"$gone\" | grep -E " + sshx.Q(essentialPkgs.String()) + " | tr '\\n' ' ')\n" +
			"if [ -n \"$(echo $hit)\" ]; then echo '#komando:essential'; printf '%s\\n' $hit; exit 0; fi; fi\n")
	}
	sb.WriteString("rc=0\n")
	run := "ACTION=" + action + " PKGS=\"$todo\"; (" + pkgShell + ") >&2; rc=$?"
	if action == "upgrade" {
		sb.WriteString(run + "\n")
	} else {
		sb.WriteString("if [ -n \"$(echo $todo)\" ]; then " + run + "; fi\n")
	}
	sb.WriteString("ACTION=installed PKGS=" + listed + "; after=$( (" + pkgShell + ") 2>/dev/null )\n")
	sb.WriteString(`echo '#komando:before'; printf '%s\n' "$before"; echo '#komando:after'; printf '%s\n' "$after"; exit $rc`)
	return sb.String()
}

// pkgNotFound matches what the package managers say about a name they do
// not know.
var pkgNotFound = regexp.MustCompile(`(?i)unable to locate package|no match for argument|unable to find a match|no such package|not found in package names|target not found|no provider of|package '[^']*' not found`)

func pkgFailure(action string, rr *sshx.RunResult, missing []string) *out.Error {
	switch {
	case strings.Contains(rr.Stderr, "no supported package manager"):
		return out.Errf(out.ExitNotFound, "NO_PACKAGE_MANAGER", "komando knows apt, dnf, yum, apk, zypper and pacman", "no supported package manager on this server")
	case pkgNotFound.MatchString(rr.Stderr):
		what := "a package"
		if len(missing) > 0 {
			what = strings.Join(missing, ", ")
		}
		return out.Errf(out.ExitNotFound, "PACKAGE_NOT_FOUND", "check the name; refresh the index with `komando pkg update TARGET` if the package is new",
			"%s: no such package in the server's package index", what)
	}
	return out.Errf(out.ExitRemote, "PKG_FAILED", "read the error output (stderr) for the package manager's message", "pkg %s failed (exit %d)", action, rr.ExitCode)
}

type pkgRow struct {
	Name    string `json:"name"`
	State   string `json:"state"` // installed, removed, upgraded, already installed, not installed
	Version string `json:"version,omitempty"`
	From    string `json:"from,omitempty"`
	Changed bool   `json:"changed"`
}

type pkgChange struct {
	Changed  bool     `json:"changed"`
	Packages []pkgRow `json:"packages"`
}

// pkgChangeResult compares the listings before and after the action.
func pkgChangeResult(cl *call, action string, pkgs []string, rr *sshx.RunResult) (any, *out.Error) {
	sec := sections(rr.Stdout)
	if ess, ok := sec["essential"]; ok {
		return pkgChange{Packages: []pkgRow{}}, approvalErr(cl, "POLICY_BLOCKED",
			fmt.Sprintf("removing %s would also remove %s, which can lock you out of the server or break it; nothing was removed", strings.Join(pkgs, " "), strings.Join(strings.Fields(ess), ", ")))
	}
	before, after := pkgVersions(sec["before"]), pkgVersions(sec["after"])
	res := pkgChange{Packages: []pkgRow{}}
	names := pkgs
	if action == "upgrade" && len(pkgs) == 0 {
		names = nil
		for n := range after {
			names = append(names, n)
		}
		slices.Sort(names)
	}
	var missing []string
	for _, n := range names {
		b, a := before[n], after[n]
		r := pkgRow{Name: n, Version: a, Changed: b != a}
		if a == "-" {
			r.Version = ""
		}
		switch {
		case action == "install" && a == "-":
			r.State = "not installed"
			missing = append(missing, n)
		case action == "install" && b == "-":
			r.State = "installed"
		case action == "install":
			r.State = "already installed"
		case action == "remove" && a != "-" && a != "":
			r.State = "still installed"
		case action == "remove" && b != "-" && b != "":
			r.State, r.From = "removed", b
		case action == "remove":
			r.State = "not installed"
		case a == "-" || a == "":
			r.State = "not installed"
			missing = append(missing, n)
		case b != a:
			r.State, r.From = "upgraded", b
		default:
			r.State = "up to date"
		}
		if action == "upgrade" && len(pkgs) == 0 && !r.Changed {
			continue // only what the upgrade changed
		}
		res.Changed = res.Changed || r.Changed
		res.Packages = append(res.Packages, r)
	}
	if rr.ExitCode != 0 {
		return res, pkgFailure(action, rr, missing)
	}
	if len(missing) > 0 {
		return res, out.Errf(out.ExitNotFound, "PACKAGE_NOT_FOUND", "check the name", "%s: not installed after pkg %s", strings.Join(missing, ", "), action)
	}
	return res, nil
}

func pkgChangeText(data any) string {
	d, _ := data.(pkgChange)
	if len(d.Packages) == 0 {
		return "nothing changed\n"
	}
	rows := [][]string{}
	for _, p := range d.Packages {
		rows = append(rows, []string{p.Name, p.State, p.From, p.Version})
	}
	return textTable([]string{"package", "state", "from", "version"}, rows)
}

type pkgUpgrade struct {
	Name    string `json:"name"`
	From    string `json:"from,omitempty"`
	Version string `json:"version,omitempty"`
}

var (
	reAptList  = regexp.MustCompile(`^(\S+?)/\S+\s+(\S+)\s+\S+(?:\s+\[upgradable from: ([^\]]+)\])?`)
	reAptSim   = regexp.MustCompile(`^Inst (\S+)(?: \[([^\]]+)\])? \((\S+)`)
	reApkList  = regexp.MustCompile(`^(\S+)\s.*\[upgradable from: ([^\]]+)\]`)
	reApkSim   = regexp.MustCompile(`Upgrading (\S+) \((\S+) -> (\S+)\)`)
	rePacman   = regexp.MustCompile(`^(\S+) (\S+) -> (\S+)$`)
	reApkNameV = regexp.MustCompile(`^(.*)-([^-]+-r[0-9]+)$`)
)

// parseUpgrades reads the pending upgrades out of whatever the package
// manager printed (list, check-update or a simulated upgrade).
func parseUpgrades(pm, s string) []pkgUpgrade {
	rows := []pkgUpgrade{}
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		switch pm {
		case "apt":
			if m := reAptSim.FindStringSubmatch(l); m != nil {
				rows = append(rows, pkgUpgrade{Name: m[1], From: m[2], Version: m[3]})
			} else if m := reAptList.FindStringSubmatch(l); m != nil {
				rows = append(rows, pkgUpgrade{Name: m[1], Version: m[2], From: m[3]})
			}
		case "apk":
			if m := reApkSim.FindStringSubmatch(l); m != nil {
				rows = append(rows, pkgUpgrade{Name: m[1], From: m[2], Version: m[3]})
			} else if m := reApkList.FindStringSubmatch(l); m != nil {
				r := pkgUpgrade{Name: m[1]}
				if nv := reApkNameV.FindStringSubmatch(m[1]); nv != nil {
					r.Name, r.Version = nv[1], nv[2]
				}
				if nv := reApkNameV.FindStringSubmatch(m[2]); nv != nil {
					r.From = nv[2]
				}
				rows = append(rows, r)
			}
		case "dnf", "yum":
			f := strings.Fields(l)
			if len(f) == 3 && strings.Contains(f[0], ".") && !strings.HasSuffix(f[0], ":") {
				rows = append(rows, pkgUpgrade{Name: f[0][:strings.LastIndex(f[0], ".")], Version: f[1]})
			}
			if strings.HasPrefix(l, "Obsoleting") {
				return rows
			}
		case "zypper":
			f := strings.Split(l, "|")
			if len(f) >= 6 && strings.TrimSpace(f[0]) == "v" {
				rows = append(rows, pkgUpgrade{Name: strings.TrimSpace(f[2]), From: strings.TrimSpace(f[3]), Version: strings.TrimSpace(f[4])})
			}
		case "pacman":
			if m := rePacman.FindStringSubmatch(l); m != nil {
				rows = append(rows, pkgUpgrade{Name: m[1], From: m[2], Version: m[3]})
			}
		}
	}
	return rows
}

// stderrValue reads a "# key: value" line komando's script writes to stderr.
func stderrValue(stderr, key string) string {
	for _, l := range strings.Split(stderr, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(l), "# "+key+": "); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

type pkgUpgradable struct {
	PackageManager string       `json:"package_manager,omitempty"`
	IndexAge       string       `json:"index_age,omitempty"` // age of the newest package list: "3d", or "never" (never refreshed)
	IndexAgeS      *int64       `json:"index_age_s,omitempty"`
	Count          int          `json:"count"`
	Packages       []pkgUpgrade `json:"packages"`
}

// staleIndex is when `pkg upgradable` suggests --refresh.
const staleIndex = 24 * time.Hour

// cutTo cuts the package list (limiter).
func (d pkgUpgradable) cutTo(cl *call, n int) any {
	d.Packages = cutRows(cl, d.Packages, n)
	d.Count = len(d.Packages)
	return d
}

func pkgUpgradableResult(rr *sshx.RunResult, refreshed bool) (any, *out.Error) {
	pm := stderrValue(rr.Stderr, "package-manager")
	if rr.ExitCode != 0 {
		return nil, pkgFailure("upgradable", rr, nil)
	}
	d := pkgUpgradable{PackageManager: pm, Packages: parseUpgrades(pm, rr.Stdout)}
	d.Count = len(d.Packages)
	var warn []string
	switch age := stderrValue(rr.Stderr, "index-age"); {
	case age == "never":
		d.IndexAge = "never"
		warn = append(warn, "the package index was never refreshed on this server; add --refresh for a current list")
	case age != "":
		if n, err := strconv.ParseInt(age, 10, 64); err == nil {
			d.IndexAgeS, d.IndexAge = &n, humanAge(time.Duration(n)*time.Second)
			if time.Duration(n)*time.Second > staleIndex && !refreshed {
				warn = append(warn, "the package index is "+d.IndexAge+" old; add --refresh for a current list")
			}
		}
	}
	if len(warn) > 0 {
		return opsWarnings{data: d, warnings: warn}, nil
	}
	return d, nil
}

func pkgUpgradesText(rows []pkgUpgrade) string {
	if len(rows) == 0 {
		return "everything is up to date\n"
	}
	t := [][]string{}
	for _, r := range rows {
		t = append(t, []string{r.Name, r.From, r.Version})
	}
	return textTable([]string{"package", "from", "to"}, t)
}

func pkgUpgradableText(data any) string {
	d, _ := data.(pkgUpgradable)
	s := pkgUpgradesText(d.Packages)
	if d.IndexAge != "" && d.IndexAge != "never" {
		s += "(newest package list is " + d.IndexAge + " old)\n"
	}
	return s
}

type pkgWouldUpgrade struct {
	WouldUpgrade []pkgUpgrade `json:"would_upgrade"`
	Count        int          `json:"count"`
}

func pkgSimulateResult(rr *sshx.RunResult) (any, *out.Error) {
	if rr.ExitCode != 0 {
		return nil, pkgFailure("upgrade", rr, nil)
	}
	rows := parseUpgrades(stderrValue(rr.Stderr, "package-manager"), rr.Stdout)
	return pkgWouldUpgrade{WouldUpgrade: rows, Count: len(rows)}, nil
}

// runPkg runs the pkg actions komando reads the result of.
func runPkg(cl *call, ctx context.Context, action, target string, pkgs []string, sudo, refresh bool, limit int) error {
	// the package managers call it remove; the command is pkg rm
	verb := map[string]string{"remove": "rm"}[action]
	if verb == "" {
		verb = action
	}
	display := strings.TrimSpace("pkg " + verb + " " + strings.Join(pkgs, " "))
	q := sshx.Q(strings.Join(pkgs, " "))
	switch action {
	case "installed":
		return runOps(cl, ctx, opsSpec{name: "pkg.installed", target: target, command: "ACTION=installed PKGS=" + q + "; " + pkgShell, display: display, limit: limit,
			parse: func(h *store.Host, rr *sshx.RunResult) (any, *out.Error) {
				if rr.ExitCode != 0 {
					return nil, pkgFailure(action, rr, nil)
				}
				v := parseInstalled(h, rr.Stdout)
				return v, nil
			},
			text: func(data any) string {
				rows := [][]string{}
				for _, r := range data.([]map[string]any) {
					inst := "no"
					if r["installed"] == true {
						inst = "yes"
					}
					rows = append(rows, []string{cell(r["name"]), inst, cell(r["version"])})
				}
				return textTable([]string{"package", "installed", "version"}, rows)
			}})
	case "upgradable":
		command := "ACTION=upgradable PKGS=" + q + "; " + pkgShell
		if !sudo {
			// as root when sudo needs no password, like facts and pkg
			// security: dnf and yum keep a cache per user, and the login
			// user's own can list other updates than the system's
			command = `if [ "$(id -u)" != 0 ] && sudo -n true 2>/dev/null; then exec sudo -n sh -c ` + sshx.Q(command) + "; fi\n" + command
		}
		if refresh {
			command = "ACTION=update PKGS=''; (" + pkgShell + ") >/dev/null; " + command
		}
		return runOps(cl, ctx, opsSpec{name: "pkg.upgradable", target: target, command: command, display: display, sudo: sudo, limit: limit,
			parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return pkgUpgradableResult(rr, refresh) },
			text:  pkgUpgradableText})
	}
	spec := opsSpec{name: "pkg." + verb, target: target, command: pkgChangeScript(action, pkgs, action == "remove" && !cl.dangerOK()), display: display, sudo: sudo, mutating: true,
		parse: func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) {
			return pkgChangeResult(cl, action, pkgs, rr)
		},
		text: pkgChangeText}
	if action == "upgrade" && cl.flags.dryRun {
		// a dry run asks the package manager what it would upgrade
		spec.preview = "ACTION=simulate PKGS=" + q + "; " + pkgShell
		spec.parse = func(_ *store.Host, rr *sshx.RunResult) (any, *out.Error) { return pkgSimulateResult(rr) }
		spec.text = func(data any) string { return pkgUpgradesText(data.(pkgWouldUpgrade).WouldUpgrade) }
	}
	return runOps(cl, ctx, spec)
}
