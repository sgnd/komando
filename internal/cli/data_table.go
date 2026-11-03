package cli

import (
	"strings"
	"unicode"

	"golang.org/x/text/width"
)

// Text tables for data commands (db, cache, storage). Cells are measured in
// terminal columns, not bytes or runes: CJK characters and emoji take two
// columns, combining marks none, so columns line up as in psql.

// displayWidth is how many terminal columns s takes.
func displayWidth(s string) int {
	n := 0
	for _, r := range s {
		n += runeWidth(r)
	}
	return n
}

func runeWidth(r rune) int {
	switch {
	case r == 0 || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r):
		return 0
	case r < 0x20 || r == 0x7f:
		return 0
	}
	switch width.LookupRune(r).Kind() {
	case width.EastAsianWide, width.EastAsianFullwidth:
		return 2
	}
	if r >= 0x1F300 && r <= 0x1FAFF { // emoji and pictographs
		return 2
	}
	return 1
}

// truncateWidth cuts s to at most w columns, ending in "..." when cut.
func truncateWidth(s string, w int) string {
	if displayWidth(s) <= w {
		return s
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		rw := runeWidth(r)
		if used+rw > w-3 {
			break
		}
		b.WriteRune(r)
		used += rw
	}
	return b.String() + "..."
}

// layoutTable aligns rows under headers, two spaces apart, as they are
// (no upper-casing, no placeholders for empty cells).
func layoutTable(headers []string, rows [][]string) string {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = displayWidth(h)
	}
	for _, r := range rows {
		for i := range headers {
			if i < len(r) {
				w[i] = max(w[i], displayWidth(r[i]))
			}
		}
	}
	var b strings.Builder
	line := func(cells []string) {
		var l strings.Builder
		for i := range headers {
			c := ""
			if i < len(cells) {
				c = cells[i]
			}
			l.WriteString(c)
			if i < len(headers)-1 {
				l.WriteString(strings.Repeat(" ", w[i]-displayWidth(c)+2))
			}
		}
		b.WriteString(strings.TrimRight(l.String(), " ") + "\n")
	}
	line(headers)
	for _, r := range rows {
		line(r)
	}
	return b.String()
}

// dataTable is layoutTable with upper-case headers and "-" for empty
// cells, like the other komando lists.
func dataTable(headers []string, rows [][]string) string {
	up := make([]string, len(headers))
	for i, h := range headers {
		up[i] = strings.ToUpper(h)
	}
	for _, r := range rows {
		for i := range r {
			if r[i] == "" {
				r[i] = "-"
			}
		}
	}
	return layoutTable(up, rows)
}
