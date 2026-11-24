// Package term holds what every command prints to a terminal: how wide text
// is in columns, text tables and the line an empty list says. It needs no
// cobra and no komando state, so commands and their tests share it.
package term

import (
	"strings"
	"unicode"

	"golang.org/x/text/width"
)

// Text tables for data commands (db, cache, storage). Cells are measured in
// terminal columns, not bytes or runes: CJK characters and emoji take two
// columns, combining marks none, so columns line up as in psql.

// DisplayWidth is how many terminal columns s takes.
func DisplayWidth(s string) int {
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

// TruncateWidth cuts s to at most w columns, ending in "…" (one column) when cut.
func TruncateWidth(s string, w int) string {
	if DisplayWidth(s) <= w {
		return s
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		rw := runeWidth(r)
		if used+rw > w-1 {
			break
		}
		b.WriteRune(r)
		used += rw
	}
	return b.String() + "…"
}

// LayoutTable aligns rows under headers, two spaces apart, as they are
// (no upper-casing, no placeholders for empty cells).
func LayoutTable(headers []string, rows [][]string) string {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = DisplayWidth(h)
	}
	for _, r := range rows {
		for i := range headers {
			if i < len(r) {
				w[i] = max(w[i], DisplayWidth(r[i]))
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
				l.WriteString(strings.Repeat(" ", w[i]-DisplayWidth(c)+2))
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

// DataTable is LayoutTable with upper-case headers and "-" for empty
// cells, like the other komando lists.
func DataTable(headers []string, rows [][]string) string {
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
	return LayoutTable(up, rows)
}
