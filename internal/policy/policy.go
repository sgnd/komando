// Package policy detects destructive commands so an agent cannot wreck a
// server by accident. Blocked commands need an explicit --allow-dangerous.
// It is a guardrail against mistakes, not a sandbox: a determined user can
// always write a command it does not recognise.
package policy

import (
	"regexp"
	"strings"
)

type Rule struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
	re     *regexp.Regexp
}

var builtin = []struct{ id, pattern, reason string }{
	{"rm-root", `\brm\s+` + rmOpts + `+(/|/\*|~|~/\*|\$HOME)(\s|$|;|&)`, "recursive delete of / or home"},
	{"rm-system-dir", `\brm\s+` + rmOpts + `+/(etc|usr|var|boot|bin|sbin|lib|lib64|opt|srv|home|root|var/lib|usr/(bin|sbin|lib|lib64|local))/?\*?(\s|$|;|&)`, "recursive delete of a system directory"},
	{"mkfs", `\bmkfs(\.\w+)?\b`, "formats a filesystem"},
	{"dd-device", `\bdd\b.*\bof=/dev/(sd|nvme|vd|xvd|hd|mmcblk|disk)`, "writes raw data to a block device"},
	{"redirect-device", `>\s*/dev/(sd|nvme|vd|xvd|hd)[a-z0-9]*`, "overwrites a block device"},
	{"wipefs", `\b(wipefs|shred|sgdisk\s+(-Z|--zap-all)|blkdiscard)\b`, "wipes disks or partition tables"},
	{"fdisk", `\b(fdisk|parted|sfdisk)\b`, "edits partition tables"},
	{"power", `(^|[;&|(]\s*|\b(sudo|doas|nohup|exec|env|nice|setsid)\s+(-\S+\s+)*)((/usr)?/s?bin/)?(shutdown|poweroff|halt|reboot|init\s+[06])(\s|$|;|&|\))`, "powers off or reboots the server"},
	{"power-systemctl", `\bsystemctl\s+(poweroff|reboot|halt|kexec)\b`, "powers off or reboots the server"},
	{"fork-bomb", `:\(\)\s*\{\s*:\|:&\s*\};:`, "fork bomb"},
	{"chmod-root", `\bchmod\s+(-[a-zA-Z]*R[a-zA-Z]*\s+)+[0-7]{3,4}\s+/(\s|$)`, "recursive chmod of /"},
	{"chown-root", `\bchown\s+(-[a-zA-Z]*R[a-zA-Z]*\s+)+\S+\s+/(\s|$)`, "recursive chown of /"},
	{"firewall-flush", `\b(iptables\s+-F|nft\s+flush\s+ruleset|ufw\s+(disable|reset))\b`, "drops firewall rules (may lock you out)"},
	{"sshd-stop", `\b(systemctl|service)\s+(stop|disable|mask)\s+(ssh|sshd)\b`, "stops sshd (locks out remote access)"},
	{"passwd-files", `>\s*/etc/(passwd|shadow|sudoers)\b`, "overwrites authentication files"},
	{"db-drop", `(?i)\b(drop\s+(database|schema)|flushall|dropdatabase\(\))`, "drops a database"},
	{"docker-prune-all", `\bdocker\s+(system|volume)\s+prune\b.*(-a|--all|--volumes)`, "deletes docker volumes/images"},
	{"kubectl-delete-ns", `\bkubectl\s+delete\s+(ns|namespace|nodes?)\b`, "deletes kubernetes namespaces or nodes"},
	{"curl-pipe-sh", `\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z)?sh\b`, "pipes a remote script into a shell"},
	{"crontab-r", `\bcrontab\s+-r\b`, "removes all cron jobs"},
	{"userdel", `\b(userdel|deluser)\b`, "deletes a user account"},
}

// rmOpts matches one option of rm: short flags with r or f, the long forms,
// and the "--" end-of-options marker.
const rmOpts = `(-[a-zA-Z]*[rRf][a-zA-Z]*\s+|--(recursive|force|no-preserve-root|one-file-system|verbose)\s+|--\s+)`

var compiled []Rule

func init() {
	for _, b := range builtin {
		compiled = append(compiled, Rule{ID: b.id, Reason: b.reason, re: regexp.MustCompile(b.pattern)})
	}
}

// Check returns the rules a command matches. extra are user patterns from
// settings (raw regexps).
func Check(cmd string, extra []string) []Rule {
	hits := []Rule{}
	norm := Normalize(cmd)
	for _, r := range compiled {
		if r.re.MatchString(norm) {
			hits = append(hits, r)
		}
	}
	for i, p := range extra {
		re, err := regexp.Compile(p)
		if err == nil && re.MatchString(norm) {
			hits = append(hits, Rule{ID: "custom-" + itoa(i), Reason: "matches custom deny pattern " + p})
		}
	}
	return hits
}

// Normalize prepares a command for matching: line breaks become ";" (the
// shell treats both as command separators), runs of white space become one
// space, and a word that is entirely quoted ("/" or '/') loses its quotes.
func Normalize(cmd string) string {
	cmd = strings.ReplaceAll(cmd, "\r\n", "\n")
	lines := strings.Split(cmd, "\n")
	var words []string
	for i, line := range lines {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if i > 0 && len(words) > 0 {
			words = append(words, ";")
		}
		for _, w := range f {
			if len(w) >= 2 && (w[0] == '"' || w[0] == '\'') && w[len(w)-1] == w[0] && !strings.ContainsRune(w[1:len(w)-1], rune(w[0])) {
				w = w[1 : len(w)-1]
			}
			words = append(words, w)
		}
	}
	return strings.Join(words, " ")
}

func Rules() []Rule {
	out := make([]Rule, len(compiled))
	copy(out, compiled)
	return out
}

func Pattern(r Rule) string {
	if r.re == nil {
		return ""
	}
	return r.re.String()
}

func itoa(i int) string {
	const d = "0123456789"
	if i < 10 {
		return d[i : i+1]
	}
	return itoa(i/10) + d[i%10:i%10+1]
}
