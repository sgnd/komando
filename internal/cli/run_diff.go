package cli

import (
	"fmt"
	"strings"
)

// unifiedDiff is a real line diff in unified format (like diff -u, without
// the file header): hunks with ctx lines of context and correct
// "@@ -start,count +start,count @@" headers. It finds the longest common
// subsequence of the changed middle (after the common start and end are
// set aside); a middle too big for that shows as one removed and one added
// block, which is still a correct diff.
func unifiedDiff(a, b string, ctx int) string {
	if a == b {
		return ""
	}
	al, bl := diffLines(a), diffLines(b)
	ops := diffOps(al, bl)
	return formatHunks(ops, ctx)
}

// diffLines splits text into lines; a missing final newline is marked the
// way diff does.
func diffLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i, l := range lines {
		if strings.HasSuffix(l, "\n") {
			lines[i] = strings.TrimSuffix(l, "\n")
		} else {
			lines[i] = l + "\n\\ No newline at end of file"
		}
	}
	return lines
}

type diffOp struct {
	kind byte // ' ', '-', '+'
	text string
}

const maxLCSCells = 4_000_000

func diffOps(a, b []string) []diffOp {
	p := 0
	for p < len(a) && p < len(b) && a[p] == b[p] {
		p++
	}
	s := 0
	for s < len(a)-p && s < len(b)-p && a[len(a)-1-s] == b[len(b)-1-s] {
		s++
	}
	var ops []diffOp
	for _, l := range a[:p] {
		ops = append(ops, diffOp{' ', l})
	}
	am, bm := a[p:len(a)-s], b[p:len(b)-s]
	if len(am)*len(bm) > maxLCSCells {
		for _, l := range am {
			ops = append(ops, diffOp{'-', l})
		}
		for _, l := range bm {
			ops = append(ops, diffOp{'+', l})
		}
	} else {
		ops = append(ops, lcsOps(am, bm)...)
	}
	for _, l := range a[len(a)-s:] {
		ops = append(ops, diffOp{' ', l})
	}
	return ops
}

// lcsOps is the classic dynamic-programming LCS, read back into
// keep/remove/add operations (removals before additions in a change).
func lcsOps(a, b []string) []diffOp {
	n, m := len(a), len(b)
	t := make([][]int, n+1)
	for i := range t {
		t[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				t[i][j] = t[i+1][j+1] + 1
			} else {
				t[i][j] = max(t[i+1][j], t[i][j+1])
			}
		}
	}
	var ops []diffOp
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			ops = append(ops, diffOp{' ', a[i]})
			i++
			j++
		case j >= m || i < n && t[i+1][j] >= t[i][j+1]:
			ops = append(ops, diffOp{'-', a[i]})
			i++
		default:
			ops = append(ops, diffOp{'+', b[j]})
			j++
		}
	}
	return ops
}

// formatHunks groups changes that are less than 2*ctx lines apart.
func formatHunks(ops []diffOp, ctx int) string {
	var sb strings.Builder
	i := 0
	for i < len(ops) {
		// next change
		for i < len(ops) && ops[i].kind == ' ' {
			i++
		}
		if i >= len(ops) {
			break
		}
		start := max(0, i-ctx)
		end := i
		for {
			for end < len(ops) && ops[end].kind != ' ' {
				end++
			}
			k := end
			for k < len(ops) && ops[k].kind == ' ' {
				k++
			}
			if k < len(ops) && k-end <= 2*ctx { // the next change is close: one hunk
				end = k
				continue
			}
			end = min(len(ops), end+ctx)
			break
		}
		// line numbers of the hunk start in a and b
		la, lb := 1, 1
		for _, o := range ops[:start] {
			if o.kind != '+' {
				la++
			}
			if o.kind != '-' {
				lb++
			}
		}
		ca, cb := 0, 0
		for _, o := range ops[start:end] {
			if o.kind != '+' {
				ca++
			}
			if o.kind != '-' {
				cb++
			}
		}
		if ca == 0 {
			la-- // diff -u writes an empty range as the line before it
		}
		if cb == 0 {
			lb--
		}
		fmt.Fprintf(&sb, "@@ -%s +%s @@\n", hunkRange(la, ca), hunkRange(lb, cb))
		for _, o := range ops[start:end] {
			sb.WriteString(string(o.kind) + o.text + "\n")
		}
		i = end
	}
	return sb.String()
}

func hunkRange(start, count int) string {
	if count == 1 {
		return fmt.Sprint(start)
	}
	return fmt.Sprintf("%d,%d", start, count)
}
