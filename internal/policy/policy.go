// Package policy detects destructive commands so an agent cannot wreck a
// server by accident. Blocked commands need an explicit --allow-dangerous.
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
	{"rm-root", `\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(--no-preserve-root\s+)?(/|/\*|~|\$HOME)(\s|$|;|&)`, "recursive delete of / or home"},
	{"rm-system-dir", `\brm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)+/(etc|usr|var|boot|bin|sbin|lib|lib64|opt|srv|home|root)/?(\s|$|;|&)`, "recursive delete of a system directory"},
	{"mkfs", `\bmkfs(\.\w+)?\b`, "formats a filesystem"},
	{"dd-device", `\bdd\b.*\bof=/dev/(sd|nvme|vd|xvd|hd|mmcblk|disk)`, "writes raw data to a block device"},
	{"redirect-device", `>\s*/dev/(sd|nvme|vd|xvd|hd)[a-z0-9]*`, "overwrites a block device"},
	{"wipefs", `\b(wipefs|shred|sgdisk\s+(-Z|--zap-all)|blkdiscard)\b`, "wipes disks or partition tables"},
	{"fdisk", `\b(fdisk|parted|sfdisk)\b`, "edits partition tables"},
	{"power", `(^|[;&|(]\s*|\bsudo\s+(-\S+\s+)*)(shutdown|poweroff|halt|reboot|init\s+[06])(\s|$|;|&|\))`, "powers off or reboots the server"},
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
	norm := strings.Join(strings.Fields(cmd), " ")
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
