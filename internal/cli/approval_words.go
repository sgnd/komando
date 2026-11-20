package cli

import (
	"slices"
	"strings"
	"unicode/utf8"
)

// The approval window's words: the plain lines under the title, and the
// command, cut to what a native alert can show (approval_view.go draws it).

// ruleTrigger is the command a built-in deny rule (internal/policy) is
// about, shown after its reason so a person sees what triggered it.
var ruleTrigger = map[string]string{
	"rm-root": "rm -rf", "rm-cd-root": "rm -rf", "find-delete-root": "find -delete", "rm-system-dir": "rm -rf",
	"mkfs": "mkfs", "dd-device": "dd", "redirect-device": "> /dev", "wipefs": "wipefs", "fdisk": "fdisk",
	"power": "shutdown or reboot", "power-systemctl": "systemctl reboot", "fork-bomb": "fork bomb",
	"chmod-root": "chmod -R", "chown-root": "chown -R", "firewall-flush": "firewall flush", "firewall-drop-all": "iptables -P DROP",
	"sshd-stop": "stop sshd", "passwd-files": "/etc/passwd", "passwd-files-write": "/etc/passwd", "db-drop": "DROP DATABASE",
	"docker-prune-all": "docker prune", "kubectl-delete-ns": "kubectl delete", "base64-pipe-sh": "base64 | sh",
	"curl-pipe-sh": "curl | sh", "crontab-r": "crontab -r", "userdel": "userdel",
	"win-rm-root": "Remove-Item -Recurse", "win-format": "Format-Volume", "win-power": "Stop-Computer or shutdown", "win-remote-access": "stopping sshd or WinRM",
	"win-firewall-block": "Set-NetFirewallProfile", "win-user-delete": "Remove-LocalUser", "win-encoded": "-EncodedCommand",
	"win-download-run": "download | iex", "win-backups": "vssadmin delete", "win-registry-hive": "reg delete",
}

// riskWords is a risk reason in plain words, one line each: a deny-rule
// reason ("[rm-system-dir,db-drop] deletes ...; drops a database") loses
// its rule ids and names what triggered it ("Deletes a system folder
// recursively (rm -rf)"); any other reason is shown as it is, capitalised.
func riskWords(r, lang string) []string {
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
				w := reasons[i]
				if tr, ok := riskID[id]; lang == "id" && ok && tr.en == w {
					w = tr.id
				}
				w = capitalise(w)
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

// skips is the checks the flags skip, on one line. --yes on a protected
// target is left out: "Status: Protected" says it already.
func (v approvalView) skips() string {
	words := wordsFor(v.Lang)
	var b []string
	for _, f := range v.Flags {
		if f == "--yes" && v.Protected {
			continue
		}
		what := words.flagSkip[f]
		if what == "" {
			what = words.aSafetyCheck
		}
		if !slices.Contains(b, what) {
			b = append(b, what)
		}
	}
	return strings.Join(b, ", ")
}

// details is the window's text under the title: who asks, the status,
// risk and skip lines, then the command as it is shown.
func (v approvalView) details() string {
	if v.raw != "" {
		return v.shown()
	}
	return v.info() + "\n\n" + v.shown()
}

// info is the lines about the request: who asks, the targets, status,
// risks, skipped checks and options. The macOS window lets a person
// select and copy them, so they keep plain ASCII hyphens.
func (v approvalView) info() string {
	if v.raw != "" {
		return ""
	}
	words := wordsFor(v.Lang)
	var b []string
	if v.Agent != "" {
		b = append(b, words.askedBy+v.Agent)
	}
	if len(v.Targets) > 1 {
		b = append(b, words.targets+strings.Join(v.Targets, ", "))
	}
	if v.Protected {
		b = append(b, words.protected)
	}
	for _, r := range v.Risks {
		for _, w := range riskWords(r, v.Lang) {
			b = append(b, words.risk+w)
		}
	}
	if s := v.skips(); s != "" {
		b = append(b, words.skips+s)
	}
	if v.What != "" {
		b = append(b, words.alsoLets+v.What)
	}
	if o := v.optionLine(); o != "" {
		b = append(b, o)
	}
	return strings.Join(b, "\n")
}

// optionLine is "Options: ..." for the flags before "--" (or on a
// --script line) that change what runs or where, or "".
func (v approvalView) optionLine() string {
	pre, _, split := strings.Cut(v.Line, " -- ")
	if !split && !strings.Contains(v.Line, " --script ") {
		return ""
	}
	if o := v.options(pre); o != "" {
		return wordsFor(v.Lang).options + o
	}
	return ""
}

// shown is what runs, as the window shows it: the command after "--" (or
// the whole line when it has none), then a script or file whole with its
// size and SHA-256. A body
// reaches the window only when approval_body.go can show it whole
// (bodyMaxLines); a longer one opens no window at all.
func (v approvalView) shown() string {
	if v.raw != "" {
		return strings.TrimRight(v.raw, "\n")
	}
	words := wordsFor(v.Lang)
	var out []string
	_, run, split := strings.Cut(v.Line, " -- ")
	switch {
	case split:
		out = append(out, words.command+run)
	case strings.Contains(v.Line, " --script "):
	default:
		out = append(out, words.command+v.Line)
	}
	if body := strings.TrimRight(v.Body, "\n"); body != "" {
		if first, rest, _ := strings.Cut(body, "\n"); bodyHead.MatchString(first) {
			m := bodyHead.FindStringSubmatch(first)
			kind, name, _ := strings.Cut(m[1], " ")
			heading := words.kinds[kind]
			if heading == "" {
				heading = capitalise(kind)
			}
			body = heading + ": " + name + " · " + m[3] + words.lines + " · " + m[2] + words.byts + "\nSHA-256: " + shortSum(m[4]) + "\n" + rest
		}
		if len(out) > 0 {
			out = append(out, "")
		}
		out = append(out, body)
	}
	return strings.Join(out, "\n")
}

// shortSum is a SHA-256 as the window shows it: its first 16 hex digits,
// enough to compare with `shasum -a 256` on one line.
func shortSum(sum string) string {
	if len(sum) <= 16 {
		return sum
	}
	return sum[:16] + "…"
}

// coveredFlags are said by the Status, Risk and Skips lines already.
var coveredFlags = []string{"--yes", "--allow-dangerous", "--reveal"}

// options is every flag in pre (the command line before "--") that
// changes what runs or where, with its value: --user root, --via bastion,
// --env NAME (the name only, never the value), --timeout 30s, and --sudo
// unless a Risk line names it. --script is shown as its own section.
// Words after the flags stay too, so nothing that runs is left out.
func (v approvalView) options(pre string) string {
	f := strings.Fields(pre)
	i := slices.IndexFunc(f, func(t string) bool { return strings.HasPrefix(t, "-") })
	if i < 0 {
		return ""
	}
	sudoSaid := strings.Contains(strings.ToLower(strings.Join(v.Risks, " ")), "sudo")
	var out []string
	for ; i < len(f); i++ {
		t := f[i]
		if !strings.HasPrefix(t, "-") {
			out = append(out, t) // a word after the flags
			continue
		}
		name, val, hasVal := strings.Cut(t, "=")
		if !hasVal && i+1 < len(f) && !strings.HasPrefix(f[i+1], "-") && !slices.Contains(coveredFlags, name) && name != "--sudo" {
			val, hasVal = f[i+1], true
			i++
		}
		switch {
		case slices.Contains(coveredFlags, name), name == "--script", name == "--sudo" && sudoSaid:
			continue
		case name == "--env" && hasVal:
			val, _, _ = strings.Cut(val, "=")
		}
		if hasVal {
			out = append(out, name+" "+val)
		} else {
			out = append(out, name)
		}
	}
	return strings.Join(out, ", ")
}

// textRows is how many rows s takes, wrapped at cols.
func textRows(s string, cols int) int {
	n := 0
	for l := range strings.SplitSeq(s, "\n") {
		n += max(1, (utf8.RuneCountInString(l)+cols-1)/cols)
	}
	return n
}
