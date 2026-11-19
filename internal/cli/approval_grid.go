package cli

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/sgnd/komando/internal/policy"
)

// The approval window's grid, its risk wording, and how the command box
// wraps and marks dangerous commands (approval_view.go holds the rest).

// rowKind is how a grid row is drawn.
type rowKind int

const (
	rowPlain rowKind = iota
	rowBadge         // a small framed label ("Protected")
	rowRisk          // a red warning symbol, then the text
)

// gridRow is one line of the two-column grid above the command.
type gridRow struct {
	Label, Text string // Label is "" on a row that continues the one above
	Kind        rowKind
}

// grid is where it runs (when the title does not name it), whether that
// is protected, each risk in plain words, one per line, and the stops the
// flags skip.
func (v approvalView) grid() []gridRow {
	if v.raw != "" {
		return nil
	}
	var g []gridRow
	if len(v.Targets) > 1 {
		g = append(g, gridRow{"Target", strings.Join(v.Targets, ", "), rowPlain})
	}
	if v.Protected {
		g = append(g, gridRow{"Status", "Protected", rowBadge})
	}
	label := "Risk"
	for _, r := range v.Risks {
		for _, w := range riskWords(r) {
			g = append(g, gridRow{label, w, rowRisk})
			label = ""
		}
	}
	if f := v.skips(); f != "" {
		g = append(g, gridRow{"Skips", f, rowPlain})
	}
	return g
}

// destructive says whether "Allow once" has red text: whenever a risk
// line shows or the target is protected (a skipped flag alone is not).
func (v approvalView) destructive() bool {
	if v.raw != "" {
		return false
	}
	return v.Protected || slices.ContainsFunc(v.grid(), func(r gridRow) bool { return r.Kind == rowRisk })
}

// header is the grid as plain text, for the golden test.
func (v approvalView) header() string {
	var b []string
	for _, r := range v.grid() {
		t := r.Text
		switch r.Kind {
		case rowBadge:
			t = "[" + t + "]"
		case rowRisk:
			t = "(!) " + t
		}
		b = append(b, fmt.Sprintf("%-8s %s", r.Label, t))
	}
	return strings.Join(b, "\n")
}

// gridArg is the grid for the macOS script's argv: one row a line,
// kind, label and text split by tabs (unshowable keeps both out of a text).
func (v approvalView) gridArg() string {
	var b []string
	for _, r := range v.grid() {
		b = append(b, strconv.Itoa(int(r.Kind))+"\t"+r.Label+"\t"+r.Text)
	}
	return strings.Join(b, "\n")
}

// ruleTrigger is the command a built-in deny rule (internal/policy) is
// about, shown after its reason so a person sees what triggered it.
var ruleTrigger = map[string]string{
	"rm-root": "rm -rf", "rm-cd-root": "rm -rf", "find-delete-root": "find -delete", "rm-system-dir": "rm -rf",
	"mkfs": "mkfs", "dd-device": "dd", "redirect-device": "> /dev", "wipefs": "wipefs", "fdisk": "fdisk",
	"power": "shutdown", "power-systemctl": "systemctl reboot", "fork-bomb": "fork bomb",
	"chmod-root": "chmod -R", "chown-root": "chown -R", "firewall-flush": "firewall flush", "firewall-drop-all": "iptables -P DROP",
	"sshd-stop": "stop sshd", "passwd-files": "/etc/passwd", "passwd-files-write": "/etc/passwd", "db-drop": "DROP DATABASE",
	"docker-prune-all": "docker prune", "kubectl-delete-ns": "kubectl delete", "base64-pipe-sh": "base64 | sh",
	"curl-pipe-sh": "curl | sh", "crontab-r": "crontab -r", "userdel": "userdel",
	"win-rm-root": "Remove-Item -Recurse", "win-format": "Format-Volume", "win-power": "Stop-Computer", "win-remote-access": "Stop-Service",
	"win-firewall-block": "Set-NetFirewallProfile", "win-user-delete": "Remove-LocalUser", "win-encoded": "-EncodedCommand",
	"win-download-run": "download | iex", "win-backups": "vssadmin delete", "win-registry-hive": "reg delete",
}

// riskWords is a risk reason in plain words, one line each: a deny-rule
// reason ("[rm-system-dir,db-drop] deletes ...; drops a database") loses
// its rule ids and names what triggered it ("Deletes a system folder
// recursively (rm -rf)"); any other reason is shown as it is, capitalised.
func riskWords(r string) []string {
	if ids, rest, ok := strings.Cut(strings.TrimPrefix(r, "["), "] "); ok && strings.HasPrefix(r, "[") {
		idl, reasons := strings.Split(ids, ","), strings.Split(rest, "; ")
		if len(idl) == len(reasons) {
			var out []string
			for i, id := range idl {
				t, known := ruleTrigger[id]
				if !known && !strings.HasPrefix(id, "custom-") {
					out = nil
					break
				}
				w := capitalise(reasons[i])
				if t != "" {
					w += " (" + t + ")"
				}
				if !slices.Contains(out, w) {
					out = append(out, w)
				}
			}
			if out != nil {
				return out
			}
		}
	}
	return []string{capitalise(r)}
}

func capitalise(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 {
		return s
	}
	return strings.ToUpper(string(r)) + s[n:]
}

// flagSkip is the stop each approval flag skips, in a few words.
var flagSkip = map[string]string{
	"--yes":             "the protected-server stop",
	"--allow-dangerous": "the dangerous-command stop",
	"--reveal":          "the secret-hiding stop",
}

// skips is the stops the flags skip, on one line.
func (v approvalView) skips() string {
	var b []string
	for _, f := range v.Flags {
		what := flagSkip[f]
		if what == "" {
			what = "a safety stop"
		}
		if !slices.Contains(b, what) {
			b = append(b, what)
		}
	}
	return strings.Join(b, ", ")
}

// box is command() wrapped at boxCols; start[i] is the row where line i
// of command() begins.
func (v approvalView) box() (rows []string, start []int) {
	for _, l := range strings.Split(v.command(), "\n") {
		start = append(start, len(rows))
		rows = append(rows, wrapLine(escapeMark(l), boxCols)...)
	}
	return rows, start
}

// boxText is the command box's text.
func (v approvalView) boxText() string {
	rows, _ := v.box()
	return strings.Join(rows, "\n")
}

// wrapMark starts every wrapped row, so a row that continues the line
// above never looks like a line of its own.
const wrapMark = "» "

// escapeMark shows a real line whose text starts with the mark (after its
// indent or script line number) with a backslash in front, so it cannot
// pass for a wrapped row; a leading backslash before the mark is escaped
// the same way.
func escapeMark(l string) string {
	lead := len(l) - len(strings.TrimLeft(l, " "))
	if m := scriptLineNo.FindString(l); m != "" {
		lead = len(m)
	}
	text := strings.TrimLeft(l[lead:], "\\")
	if strings.HasPrefix(text, "»") {
		return l[:lead] + "\\" + l[lead:]
	}
	return l
}

// cellWidth is how many monospace columns r takes: 2 for wide East Asian
// characters and emoji, 8 for a tab (its widest), 1 for the rest.
func cellWidth(r rune) int {
	switch {
	case r == '\t':
		return 8
	case r >= 0x1100 && r <= 0x115F, r >= 0x2E80 && r <= 0xA4CF, r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF, r >= 0xFE30 && r <= 0xFE4F, r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6, r >= 0x1F300 && r <= 0x1FAFF, r >= 0x20000 && r <= 0x3FFFD:
		return 2
	}
	return 1
}

func cellsWidth(r []rune) int {
	w := 0
	for _, c := range r {
		w += cellWidth(c)
	}
	return w
}

// wrapLine breaks l into rows of at most cols columns, after a space, a
// comma or a slash; a token is split only when it is longer than a row.
// Rows after the first start with wrapMark and hang under the text: in a
// script line's number column, or two spaces in from the line's indent.
func wrapLine(l string, cols int) []string {
	r := []rune(l)
	if cellsWidth(r) <= cols {
		return []string{l}
	}
	indent := len(r) - len([]rune(strings.TrimLeft(l, " "))) + 4
	if m := scriptLineNo.FindString(l); m != "" {
		indent = utf8.RuneCountInString(m)
	}
	if indent > cols/2 {
		indent = 4
	}
	cont := strings.Repeat(" ", indent-utf8.RuneCountInString(wrapMark)) + wrapMark
	var rows []string
	pad := ""
	for len(r) > 0 {
		room := cols - cellsWidth([]rune(pad))
		fit, w := 0, 0
		for fit < len(r) && w+cellWidth(r[fit]) <= room {
			w += cellWidth(r[fit])
			fit++
		}
		if fit == len(r) {
			rows = append(rows, pad+string(r))
			break
		}
		cut := max(fit, 1)
		for i := fit; i > 0; i-- {
			if c := r[i-1]; c == ' ' || c == ',' || c == '/' {
				cut = i
				break
			}
		}
		rows = append(rows, pad+strings.TrimRight(string(r[:cut]), " "))
		r = []rune(strings.TrimLeft(string(r[cut:]), " "))
		pad = cont
	}
	return rows
}

// scriptLineNo is the number in front of a script line in the body.
var scriptLineNo = regexp.MustCompile(`^ *\d+  `)

// boxRows is how many rows the command box has.
func (v approvalView) boxRows() int {
	rows, _ := v.box()
	return len(rows)
}

// dangerRanges is where, in boxText(), the commands that a deny rule
// matched appear (rm -rf, DROP DATABASE): UTF-16 offset and length each,
// as AppKit counts. A trigger wrapped over two rows is not marked.
func (v approvalView) dangerRanges() [][2]int {
	text := v.boxText()
	var seen []string
	var out [][2]int
	for _, l := range strings.Split(v.command(), "\n") {
		for _, h := range policy.Check(l, nil) {
			t := ruleTrigger[h.ID]
			if t == "" || slices.Contains(seen, t) {
				continue
			}
			seen = append(seen, t)
			pat := regexp.QuoteMeta(t)
			if isWord(t[0]) {
				pat = `\b` + pat
			}
			if isWord(t[len(t)-1]) {
				pat += `\b`
			}
			for _, m := range regexp.MustCompile(`(?i)`+pat).FindAllStringIndex(text, -1) {
				off := len(utf16.Encode([]rune(text[:m[0]])))
				out = append(out, [2]int{off, len(utf16.Encode([]rune(text[m[0]:m[1]])))})
			}
		}
	}
	slices.SortFunc(out, func(a, b [2]int) int { return a[0] - b[0] })
	return out
}

func isWord(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// dangerArg is dangerRanges for the macOS script: "off:len" items, by commas.
func (v approvalView) dangerArg() string {
	var b []string
	for _, r := range v.dangerRanges() {
		b = append(b, strconv.Itoa(r[0])+":"+strconv.Itoa(r[1]))
	}
	return strings.Join(b, ",")
}
