package cli

import (
	"path"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// --read-only is a promise from the caller that lets a command skip the
// confirmation protected servers need. checkReadOnly holds the caller to it
// with a cheap look at the command: a word that clearly changes something
// (rm, mv, tee, a > redirect, systemctl restart, apt install ...) breaks the
// promise. It is not a sandbox: it catches mistakes, not a determined user.

// writeVerbs are commands that change something whatever their arguments.
var writeVerbs = map[string]bool{
	"rm": true, "rmdir": true, "mv": true, "cp": true, "tee": true, "truncate": true, "dd": true,
	"shred": true, "ln": true, "mkdir": true, "touch": true, "install": true, "rsync": true,
	"chmod": true, "chown": true, "chgrp": true, "chattr": true, "setfacl": true,
	"useradd": true, "userdel": true, "usermod": true, "groupadd": true, "groupdel": true,
	"groupmod": true, "passwd": true, "chpasswd": true, "adduser": true, "deluser": true,
	"kill": true, "killall": true, "pkill": true, "reboot": true, "shutdown": true,
	"halt": true, "poweroff": true, "mount": true, "umount": true, "swapoff": true,
	"swapon": true, "unlink": true, "wipefs": true, "fdisk": true, "parted": true, "mkswap": true,
}

// writeSubs are commands whose first argument decides: systemctl status
// reads, systemctl restart changes.
var writeSubs = map[string][]string{
	"systemctl":   {"start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask", "kill", "daemon-reload", "reload-or-restart", "try-restart", "isolate", "set-property", "edit", "reboot", "poweroff"},
	"service":     {"start", "stop", "restart", "reload"}, // service NAME start: checked on any argument
	"apt":         {"install", "remove", "purge", "upgrade", "full-upgrade", "dist-upgrade", "autoremove", "update"},
	"apt-get":     {"install", "remove", "purge", "upgrade", "dist-upgrade", "autoremove", "update", "clean"},
	"dnf":         {"install", "remove", "erase", "upgrade", "update", "autoremove", "downgrade", "reinstall"},
	"yum":         {"install", "remove", "erase", "upgrade", "update", "autoremove", "downgrade", "reinstall"},
	"apk":         {"add", "del", "upgrade", "update", "fix"},
	"zypper":      {"install", "in", "remove", "rm", "update", "up", "dist-upgrade", "dup"},
	"pacman":      {"-S", "-R", "-Syu", "-Rs", "-U"},
	"pip":         {"install", "uninstall"},
	"pip3":        {"install", "uninstall"},
	"npm":         {"install", "i", "uninstall", "update", "ci"},
	"docker":      {"run", "rm", "rmi", "stop", "start", "restart", "kill", "create", "pull", "push", "prune", "update", "rename", "pause", "unpause", "cp", "commit", "tag", "build"},
	"podman":      {"run", "rm", "rmi", "stop", "start", "restart", "kill", "create", "pull", "push", "prune"},
	"kubectl":     {"apply", "create", "delete", "edit", "patch", "replace", "scale", "rollout", "drain", "cordon", "uncordon", "label", "annotate", "set", "taint"},
	"git":         {"commit", "push", "pull", "reset", "checkout", "clean", "merge", "rebase", "stash", "fetch", "clone", "init", "rm", "mv", "add"},
	"crontab":     {"-r", "-e", "-"},
	"ip":          {"add", "del", "delete", "set", "flush", "replace", "change"},
	"hostnamectl": {"set-hostname"},
	"timedatectl": {"set-time", "set-timezone", "set-ntp"},
	"journalctl":  {"--vacuum-size", "--vacuum-time", "--rotate", "--flush"},
	"sysctl":      {"-w", "--write", "-p", "--load"},
	"ufw":         {"allow", "deny", "reject", "delete", "enable", "disable", "reset", "limit", "insert"},
	"iptables":    {"-A", "-D", "-I", "-R", "-F", "-X", "-P", "-N", "-Z", "--append", "--delete", "--insert", "--flush"},
}

// wrappers run the next word as the command.
var wrappers = map[string]bool{"sudo": true, "doas": true, "env": true, "nohup": true, "nice": true, "time": true,
	"command": true, "exec": true, "xargs": true, "timeout": true, "ionice": true, "stdbuf": true, "setsid": true}

// readOnlyViolation returns what in command changes something, or "".
func readOnlyViolation(command string) string {
	segs, redirect := shellSegments(command)
	if redirect != "" {
		return redirect
	}
	for _, words := range segs {
		if w := segmentWrite(words); w != "" {
			return w
		}
	}
	return ""
}

func segmentWrite(words []string) string {
	i := 0
	for i < len(words) {
		w := words[i]
		switch {
		case isAssign(w): // FOO=1 cmd
			i++
			continue
		case wrappers[path.Base(w)]:
			i++
			// skip the wrapper's options and values (sudo -u root, timeout 10)
			for i < len(words) && (strings.HasPrefix(words[i], "-") || isAssign(words[i]) || isNumberish(words[i])) {
				if words[i] == "-u" || words[i] == "-g" || words[i] == "-n" && path.Base(w) == "nice" {
					i++
				}
				i++
			}
			continue
		}
		break
	}
	if i >= len(words) {
		return ""
	}
	cmd := path.Base(words[i])
	args := words[i+1:]
	if writeVerbs[cmd] {
		return cmd
	}
	if strings.HasPrefix(cmd, "mkfs") {
		return cmd
	}
	switch cmd {
	case "sed", "perl":
		for _, a := range args {
			if a == "-i" || strings.HasPrefix(a, "-i") && cmd == "perl" || strings.HasPrefix(a, "-i.") || strings.HasPrefix(a, "--in-place") || (cmd == "sed" && strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a, "i") && len(a) <= 4) {
				return cmd + " -i"
			}
		}
	case "sh", "bash", "zsh", "dash", "ash", "ksh":
		for j, a := range args {
			if a == "-c" && j+1 < len(args) {
				return readOnlyViolation(args[j+1])
			}
		}
	case "find":
		for _, a := range args {
			if a == "-delete" || a == "-exec" || a == "-execdir" {
				return "find " + a
			}
		}
	}
	if subs, ok := writeSubs[cmd]; ok {
		for _, a := range args {
			for _, s := range subs {
				if a == s || strings.HasPrefix(a, s+"=") {
					return cmd + " " + a
				}
			}
			if cmd != "service" && cmd != "ip" && !strings.HasPrefix(a, "-") {
				break // only the first real argument is the subcommand
			}
		}
	}
	return ""
}

func isAssign(w string) bool {
	k, _, ok := strings.Cut(w, "=")
	return ok && k != "" && validShellName(k)
}

func validShellName(k string) bool {
	for i, r := range k {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func isNumberish(w string) bool {
	if w == "" {
		return false
	}
	for _, r := range w {
		if !(r >= '0' && r <= '9' || r == '.' || r == 's' || r == 'm' || r == 'h') {
			return false
		}
	}
	return w[0] >= '0' && w[0] <= '9'
}

// shellSegments splits a command line into simple commands (on ; & | && ||
// newlines, ( ) and $( ), each a list of words with quotes removed. It also
// reports the first output redirect to a file (> or >>), except to
// /dev/null or another descriptor.
func shellSegments(s string) (segs [][]string, redirect string) {
	var words []string
	var cur strings.Builder
	inWord := false
	endWord := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	endSeg := func() {
		endWord()
		if len(words) > 0 {
			segs = append(segs, words)
		}
		words = nil
	}
	pendingRedirect := false
	checkRedirect := func() {
		// the word after a > is the file
		if pendingRedirect && len(words) > 0 {
			t := words[len(words)-1]
			if t != "/dev/null" && !strings.HasPrefix(t, "&") && redirect == "" {
				redirect = "> " + t
			}
			words = words[:len(words)-1]
			pendingRedirect = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				j = len(s) - i - 1
			}
			cur.WriteString(s[i+1 : i+1+j])
			inWord = true
			i += j + 1
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				j++
			}
			cur.WriteString(s[i+1 : min(j, len(s))])
			inWord = true
			i = j
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			inWord = true
			i++
		case c == ' ' || c == '\t':
			endWord()
			checkRedirect()
		case c == ';' || c == '\n' || c == '|' || c == '&' || c == '(' || c == ')' || c == '`':
			if c == '&' && i > 0 && s[i-1] == '>' {
				cur.WriteByte(c) // >&2
				inWord = true
				continue
			}
			endWord()
			checkRedirect()
			endSeg()
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			endSeg()
			i++
		case c == '>':
			if i+1 < len(s) && s[i+1] == '>' {
				i++
			}
			// "2>" or "1>": the digit belongs to the redirect, not to the words
			if inWord && cur.Len() == 1 && cur.String()[0] >= '0' && cur.String()[0] <= '9' {
				cur.Reset()
				inWord = false
			}
			endWord()
			if i+1 < len(s) && s[i+1] == '&' {
				i++ // >&2: to another descriptor
				for i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
					i++
				}
				continue
			}
			pendingRedirect = true
		case c == '<':
			endWord()
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	endWord()
	checkRedirect()
	endSeg()
	return segs, redirect
}

// checkReadOnly is the --read-only promise check, as a safety stop.
func checkReadOnly(command string) error {
	w := readOnlyViolation(command)
	if w == "" {
		return nil
	}
	return policyStop(out.Errf(out.ExitPolicy, "READ_ONLY_VIOLATION", "drop --read-only and confirm with --yes",
		"--read-only, but the command changes something (%s)", w))
}
