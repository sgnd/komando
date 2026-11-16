package cli

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
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

// factsOnlyParse reads the script's lines as facts does and keeps the keys
// asked for; one komando cannot read is null, as in facts.
func factsOnlyParse(keys []string) func(h *store.Host, s string) (any, error) {
	return func(h *store.Host, s string) (any, error) {
		all, err := parseFacts(h, s)
		if err != nil {
			return nil, err
		}
		f, _ := all.(map[string]any)
		res := map[string]any{}
		for _, k := range keys {
			res[k] = f[k]
		}
		return res, nil
	}
}

// factsOnlyText is the -o text view of facts --only: one line per server.
func factsOnlyText(d probeData) string {
	var b strings.Builder
	for _, r := range d.Results {
		f, _ := r.Data.(map[string]any)
		if !r.OK || f == nil {
			msg := "failed"
			if r.Error != nil {
				msg = r.Error.Message
			}
			fmt.Fprintf(&b, "● %s  failed: %s\n", r.Host, msg)
			continue
		}
		var parts []string
		if p, ok := f["os_pretty"].(string); ok {
			parts = append(parts, p)
		} else if o, ok := f["os"].(string); ok {
			v, _ := f["os_version"].(string)
			parts = append(parts, strings.TrimSpace(o+" "+v))
		}
		if n, ok := f["uptime_sec"].(int64); ok {
			parts = append(parts, "up "+humanAge(time.Duration(n)*time.Second))
		}
		if l, ok := f["load"].([]float64); ok && len(l) == 3 {
			parts = append(parts, fmt.Sprintf("load %.2f %.2f %.2f", l[0], l[1], l[2]))
		}
		if n, ok := f["cpus"].(int64); ok {
			parts = append(parts, fmt.Sprintf("%d cpu", n))
		}
		if t, ok := f["mem_total_mb"].(int64); ok {
			if a, ok := f["mem_available_mb"].(int64); ok {
				parts = append(parts, fmt.Sprintf("mem %d of %d MB free", a, t))
			}
		}
		if ds, ok := f["disks"].([]diskFacts); ok {
			for _, x := range ds {
				parts = append(parts, fmt.Sprintf("%s %d%%", x.Mount, x.UsedPct))
			}
		}
		fmt.Fprintf(&b, "● %s  %s\n", r.Host, strings.Join(slices.DeleteFunc(parts, func(s string) bool { return s == "" }), ", "))
	}
	return b.String()
}
