package cli

import (
	"strconv"
	"time"
)

// Shared pieces for -o text output, so every list reads like the familiar
// tools (kubectl get, docker ps, ls -l): a header row and aligned columns.

// textTable is dataTable, kept as the short name the Text methods use.
func textTable(headers []string, rows [][]string) string { return dataTable(headers, rows) }

// The cells every table shares (S-9.6), so a person reads one form:

// yesCell is a boolean: "yes", or "-" so the few that say yes stand out.
func yesCell(b bool) string {
	if b {
		return "yes"
	}
	return "-"
}

// timeCell is a moment: this computer's time with its zone
// (2026-11-07 14:30 WIB), "-" for none.
func timeCell(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04 MST")
}

// ageCell is how long ago t was (3h), for an AGE or SINCE column; "-" for
// none.
func ageCell(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return humanAge(time.Since(t))
}

// humanAge is a duration the way kubectl shows ages: 40s, 5m, 3h, 12d.
func humanAge(d time.Duration) string {
	switch {
	case d < 0:
		return "-"
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + "m"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + "h"
	}
	return strconv.Itoa(int(d.Hours()/24)) + "d"
}
