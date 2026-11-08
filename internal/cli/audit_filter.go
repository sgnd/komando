package cli

import (
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// auditFilter picks the entries `komando audit` shows.
type auditFilter struct {
	command  string          // command prefix, "" for all
	failed   bool            // only failed or blocked actions
	byTarget bool            // only entries naming one of names
	names    map[string]bool // servers and conns picked by --target
	since    time.Time       // zero: no lower bound (inclusive)
	until    time.Time       // zero: no upper bound (exclusive)
}

func (f auditFilter) keep(e map[string]any) bool {
	if c, _ := e["command"].(string); f.command != "" && !strings.HasPrefix(c, f.command) {
		return false
	}
	if f.failed && e["ok"] == true {
		return false
	}
	if f.byTarget && !auditNames(e, f.names) {
		return false
	}
	if f.since.IsZero() && f.until.IsZero() {
		return true
	}
	ts, _ := e["ts"].(string)
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return false // without a time it cannot be in the window
	}
	return (f.since.IsZero() || !t.Before(f.since)) && (f.until.IsZero() || t.Before(f.until))
}

// auditNames reports whether the entry names one of the servers or conns.
func auditNames(e map[string]any, names map[string]bool) bool {
	hs, _ := e["hosts"].([]any)
	cs, _ := e["conns"].([]any)
	for _, h := range append(hs, cs...) {
		if n, ok := h.(string); ok && names[n] {
			return true
		}
	}
	return false
}

// setWindow reads --since and --until into the filter.
func (f *auditFilter) setWindow(since, until string, now time.Time) error {
	var err error
	if since != "" {
		if f.since, err = parseWhen(since, "--since", now); err != nil {
			return err
		}
	}
	if until != "" {
		if f.until, err = parseWhen(until, "--until", now); err != nil {
			return err
		}
	}
	if !f.since.IsZero() && !f.until.IsZero() && !f.since.Before(f.until) {
		return out.Usage("--since (%s) must be before --until (%s)", f.since.Local().Format(time.DateTime), f.until.Local().Format(time.DateTime))
	}
	return nil
}

// whenLayouts are the times parseWhen reads in this computer's time zone.
var whenLayouts = []string{"2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"}

// parseWhen reads a point in time: how long ago (30m, 12h, 7d, also
// written -2h), today or yesterday (from midnight), a time in this
// computer's time zone (2026-11-07, 2026-11-07 14:30), or one with its own
// zone (2026-11-07T14:30:00Z). flag names the flag in the error.
func parseWhen(s, flag string, now time.Time) (time.Time, error) {
	v := strings.TrimSpace(s)
	y, m, d := now.Date()
	midnight := time.Date(y, m, d, 0, 0, 0, 0, now.Location())
	switch strings.ToLower(v) {
	case "today":
		return midnight, nil
	case "yesterday":
		return midnight.AddDate(0, 0, -1), nil
	}
	ago := strings.TrimPrefix(v, "-")
	if n, ok := strings.CutSuffix(ago, "d"); ok {
		if k, err := strconv.Atoi(n); err == nil && k > 0 {
			return now.Add(-time.Duration(k) * 24 * time.Hour), nil
		}
	}
	if dur, err := time.ParseDuration(ago); err == nil && dur > 0 {
		return now.Add(-dur), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t, nil
	}
	for _, layout := range whenLayouts {
		if t, err := time.ParseInLocation(layout, v, now.Location()); err == nil {
			return t, nil
		}
	}
	return time.Time{}, out.Usage("%s takes how long ago (30m, 12h, 7d), today, yesterday, or a time like 2026-11-07, '2026-11-07 14:30' or 2026-11-07T14:30:00Z (got %q)", flag, s)
}
