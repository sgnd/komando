package cli

import (
	"strings"
)

// Counting pending updates from what the package manager already knows,
// without refreshing its index (that would change the server). Shared by
// `komando facts`; other commands that count security updates can use the
// same helpers.

// aptSimCommand lists what an upgrade would install, without root and
// without changing anything: apt-get simulates and prints one "Inst" line
// per package, with the archives the new version comes from.
const aptSimCommand = `apt-get -s -o Debug::NoLocking=1 dist-upgrade`

// aptSimCounts counts the packages in `apt-get -s` output and how many of
// them come from a security archive (focal-security, bookworm-security,
// the ESM archives focal-infra-security and focal-apps-security).
func aptSimCounts(sim string) (total, security int) {
	for _, line := range strings.Split(sim, "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		total++
		if aptSecurityOrigin(line) {
			security++
		}
	}
	return total, security
}

// aptSecurityOrigin reports whether an "Inst" line's new version comes from
// a security archive. Only the part in parentheses names archives, so a
// package called python3-security does not count.
//
//	Inst openssl [1.1.1f-1ubuntu2.19] (1.1.1f-1ubuntu2.20 Ubuntu:20.04/focal-updates, Ubuntu:20.04/focal-security [amd64])
func aptSecurityOrigin(line string) bool {
	i := strings.Index(line, " (")
	if i < 0 {
		return false
	}
	o := line[i:]
	return strings.Contains(o, "-security") || strings.Contains(o, "Debian-Security:")
}

// dnfCheckUpdateCount counts the packages in `dnf -q check-update` (or
// yum's) output: "name.arch  version  repo" lines, up to the "Obsoleting
// Packages" list.
func dnfCheckUpdateCount(o string) int {
	n := 0
	for _, line := range strings.Split(o, "\n") {
		if strings.HasPrefix(line, "Obsoleting") {
			break
		}
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		if f := strings.Fields(line); len(f) == 3 && strings.Contains(f[0], ".") {
			n++
		}
	}
	return n
}

// dnfSecurityCount counts the packages (not advisories) in `dnf -q
// updateinfo list --security` output: "ADVISORY  SEVERITY/Sec.  package"
// lines; one package fixed by two advisories counts once.
func dnfSecurityCount(o string) int {
	seen := map[string]bool{}
	for _, line := range strings.Split(o, "\n") {
		if f := strings.Fields(line); len(f) == 3 {
			seen[f[2]] = true
		}
	}
	return len(seen)
}
