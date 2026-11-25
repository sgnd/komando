package store

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// text is the report the person reads after the migration: names and
// counts only, never a value (design note section 5, step 14).
func (r migration3Report) text() string {
	var b strings.Builder
	b.WriteString("komando moved its store to format 3.\n")
	for _, typ := range slices.Sorted(maps.Keys(r.Counts)) {
		if c := r.Counts[typ]; c[0] != 0 || c[1] != 0 {
			fmt.Fprintf(&b, "  %s: %d before, %d after\n", typ, c[0], c[1])
		}
	}
	for _, n := range r.Names {
		fmt.Fprintf(&b, "  %s %s is now %s\n", n.Kind, n.Old, strings.Join(n.New, ", "))
	}
	for _, h := range r.KeyAndPassword {
		fmt.Fprintf(&b, "  %s logs in with its key; its saved password is kept unused: run `komando host ssh test %s`\n", h, h)
	}
	for _, s := range r.SnippetsWithOldRef {
		fmt.Fprintf(&b, "  snippet %s holds the text secret: (sent to the server as it is)\n", s)
	}
	fmt.Fprintf(&b, "Backup: %s\n", r.Backup)
	if r.BackupNote != "" {
		b.WriteString("  " + r.BackupNote + "\n")
	}
	b.WriteString("It opens only with komando v0.17.0 and holds every secret as it was: remove it once this komando works for you.")
	return b.String()
}
