package cli

import (
	"strconv"
	"time"
)

// Shared pieces for -o text output, so every list reads like the familiar
// tools (kubectl get, docker ps, ls -l): a header row and aligned columns.

// textTable is dataTable, kept as the short name the Text methods use.
func textTable(headers []string, rows [][]string) string { return dataTable(headers, rows) }

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
