package cli

import (
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// parseAge reads a positive duration with days (30d) as well as Go units
// (12h, 90m); flag names the flag in the error.
func parseAge(s, flag string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		if n, err := strconv.Atoi(d); err == nil && n > 0 {
			return time.Duration(n) * 24 * time.Hour, nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return d, nil
	}
	return 0, out.Errf(out.ExitUsage, "USAGE", "write a number and a unit: 90m, 12h or 30d",
		"%s takes a positive duration like 30d, 12h or 90m (got %q)", flag, s)
}

// ageFlag is a duration flag that also takes days (7d), like parseAge.
type ageFlag struct {
	d    *time.Duration
	name string
}

func (a ageFlag) String() string { return a.d.String() }
func (a ageFlag) Type() string   { return "duration" }
func (a ageFlag) Set(s string) error {
	d, err := parseAge(s, a.name)
	if err == nil {
		*a.d = d
	}
	return err
}
