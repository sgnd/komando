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

// details is the window's text under the title: who asks, the status,
// risk and skip lines, then the command as it is shown.
func (v approvalView) details() string {
	if v.raw != "" {
		return v.shown()
	}
	var b []string
	if v.Agent != "" {
		b = append(b, "Asked by "+v.Agent)
	}
	if len(v.Targets) > 1 {
		b = append(b, "Targets: "+strings.Join(v.Targets, ", "))
	}
	if v.Protected {
		b = append(b, "Status: Protected")
	}
	for _, r := range v.Risks {
		for _, w := range riskWords(r) {
			b = append(b, "Risk: "+w)
		}
	}
	if s := v.skips(); s != "" {
		b = append(b, "Skips: "+s)
	}
	if v.What != "" {
		b = append(b, "Also lets through: "+v.What)
	}
	return strings.Join(b, "\n") + "\n\n" + v.shown()
}

// shown is the command as the window shows it: every line. A body
// reaches the window only when approval_body.go can show it whole
// (bodyMaxLines); a longer one opens no window at all.
func (v approvalView) shown() string {
	return v.command()
}

// command is the command line, then the body, as sent; a body's
// "It also sends ..." line becomes a caption and its full SHA-256.
func (v approvalView) command() string {
	if v.raw != "" {
		return strings.TrimRight(v.raw, "\n")
	}
	if v.Body == "" {
		return v.Line
	}
	body := strings.TrimRight(v.Body, "\n")
	if first, rest, _ := strings.Cut(body, "\n"); bodyHead.MatchString(first) {
		m := bodyHead.FindStringSubmatch(first)
		body = capitalise(m[1]) + ": " + m[3] + " lines, " + m[2] + " bytes\nSHA-256: " + m[4] + "\n" + rest
	}
	return v.Line + "\n\n" + body
}

// textRows is how many rows s takes, wrapped at cols.
func textRows(s string, cols int) int {
	n := 0
	for l := range strings.SplitSeq(s, "\n") {
		n += max(1, (utf8.RuneCountInString(l)+cols-1)/cols)
	}
	return n
}
