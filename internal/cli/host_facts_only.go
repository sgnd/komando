package cli

import (
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/snippet"
)

// facts --only runs the probes of a few sections, for an app that polls a
// server (the phone's load, memory and disk readings, the OS name and the
// time it has been up): no package index,
// Docker, ports, units or sudo, so it answers in about a second. The keys
// are those of the full facts; a section not asked for leaves its keys out.
type factsSection struct {
	script string
	keys   []string
}

var factsSections = map[string]factsSection{
	"load": {`[ -r /proc/loadavg ] && echo "load=$(cut -d' ' -f1-3 /proc/loadavg)"
echo "cpus=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null)"
`, []string{"load", "cpus"}},
	"mem":    {factsMemLine, []string{"mem_total_mb", "mem_available_mb", "swap_total_mb", "swap_free_mb"}},
	"disks":  {factsDiskLines, []string{"disks", "disk_root_total_gb", "disk_root_used_pct"}},
	"system": {factsSystemLines, []string{"os", "os_version", "os_pretty", "uptime_sec"}},
}

// factsSystemLines print os=, os_version=, os_pretty= and uptime_sec=. The
// os-release file is read in a subshell: a broken one, or a variable it
// sets (PATH), stays out of the other sections. printf, not echo, so a
// backslash in a name is not read as a line break. A server without
// /etc/os-release or /proc/uptime (macOS, BSD) answers from uname, sw_vers
// and the boot time.
const factsSystemLines = `( if [ -r /etc/os-release ]; then . /etc/os-release; printf 'os=%s\nos_version=%s\nos_pretty=%s\n' "$ID" "$VERSION_ID" "$PRETTY_NAME"
else echo "os=$(uname -s | tr A-Z a-z)"; echo "os_version=$(uname -r)"; if command -v sw_vers >/dev/null 2>&1; then echo "os_pretty=$(sw_vers -productName) $(sw_vers -productVersion)"; fi; fi ) 2>/dev/null || echo "os=$(uname -s | tr A-Z a-z)"
if [ -r /proc/uptime ]; then echo "uptime_sec=$(cut -d. -f1 /proc/uptime)"
else b=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/^{ sec = \([0-9]*\),.*/\1/p'); if [ -n "$b" ]; then echo "uptime_sec=$(( $(date +%s) - b ))"; fi; fi
`

// factsSectionNames are the values --only takes, sorted.
func factsSectionNames() []string {
	names := make([]string, 0, len(factsSections))
	for n := range factsSections {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// factsOnly is the script for the sections named and the keys they give.
func factsOnly(sections []string) (script string, keys []string, err error) {
	var b strings.Builder
	b.WriteString("export LC_ALL=C\n")
	seen := map[string]bool{}
	for _, s := range sections {
		s = strings.ToLower(strings.TrimSpace(s))
		sec, ok := factsSections[s]
		if !ok {
			return "", nil, out.Errf(out.ExitUsage, "USAGE", "--only takes: "+strings.Join(factsSectionNames(), ", ")+" (comma-separated), for example --only load,mem,disks",
				"facts has no section %q", s)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		b.WriteString(sec.script)
		keys = append(keys, sec.keys...)
	}
	b.WriteString(":\n") // a probe a server lacks is null, not a failed run
	return b.String(), keys, nil
}

// factsKeep keeps the keys asked for; one komando cannot read is null.
func factsKeep(f map[string]any, keys []string) map[string]any {
	res := map[string]any{}
	for _, k := range keys {
		res[k] = f[k]
	}
	return res
}

// factsOnlyAll is every section, in the order the apps' quick reads ask
// for them (the S0 golden's `--only load,mem,disks,system`).
var factsOnlyAll = []string{"load", "mem", "disks", "system"}

// factsOnlySnippets are the ready-made snippets of facts --only (design
// 2.1). They move with the host commands' package (M11). The snippet runs
// every section: it has no variable, so the closed set of sections is the
// set it runs, and its keys are only theirs.
func factsOnlySnippets() []snippet.Builtin {
	script, keys, err := factsOnly(factsOnlyAll)
	if err != nil {
		panic(err) // the section names are factsSections' own
	}
	return []snippet.Builtin{{
		Name: "facts-only", Type: "host", Replaces: "facts --only " + strings.Join(factsOnlyAll, ","), Reader: "KomandoCall+ReadKey.swift (quick reads)",
		Tier: capability.Read, Shape: "facts-only/1",
		Checks: []string{"TestFactsOnly", "TestFactsOnlySystem", "TestSnippetResultIsMaskedForAnAgent", "TestSnippetSamplesMatchGoldens/facts-only"},
		Text:   map[snippet.Family]string{snippet.Unix: script, snippet.Windows: winFactsScript},
		Parse: func(o snippet.Output, f snippet.Family) (any, error) {
			return factsKeep(factsOf(o.Stdout, f), keys), nil
		},
	}}
}
