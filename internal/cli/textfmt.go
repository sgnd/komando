package cli

import (
	"strconv"
	"strings"
	"time"
)

// Shared pieces for -o text output, so every list reads like the familiar
// tools (kubectl get, docker ps, ls -l): a header row and aligned columns.

// textTable lays out rows (wide characters such as CJK and emoji count as
// two cells, see displayWidth) under upper-case headers, two spaces apart. Empty
// cells show as "-".
func textTable(headers []string, rows [][]string) string {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = displayWidth(h)
	}
	for _, r := range rows {
		for i := range headers {
			if i < len(r) {
				if r[i] == "" {
					r[i] = "-"
				}
				if n := displayWidth(r[i]); n > w[i] {
					w[i] = n
				}
			}
		}
	}
	var b strings.Builder
	line := func(cells []string) {
		for i := range headers {
			c := ""
			if i < len(cells) {
				c = cells[i]
			}
			if i == len(headers)-1 {
				b.WriteString(c)
				break
			}
			b.WriteString(c + strings.Repeat(" ", w[i]-displayWidth(c)+2))
		}
		b.WriteString("\n")
	}
	up := make([]string, len(headers))
	for i, h := range headers {
		up[i] = strings.ToUpper(h)
	}
	line(up)
	for _, r := range rows {
		line(r)
	}
	return b.String()
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
