package cli

import (
	"time"

	"github.com/sgnd/komando/internal/out"
)

// parseAge reads a positive span (parseSpan: 30d, 12h, 90m); flag names
// the flag in the error.
func parseAge(s, flag string) (time.Duration, error) {
	if d, err := parseSpan(s); err == nil && d > 0 {
		return d, nil
	}
	return 0, out.Errf(out.ExitUsage, "USAGE", "write a number and a unit: 90m, 12h or 30d",
		"%s takes a positive duration like 30d, 12h or 90m (got %q)", flag, s)
}
