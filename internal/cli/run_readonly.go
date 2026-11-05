package cli

import (
	"maps"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
)

// --read-only is a promise from the caller that lets a command skip the
// confirmation protected servers need. checkReadOnly holds the caller to it
// with a cheap look at the command: a word that clearly changes something
// (rm, mv, tee, a > redirect, systemctl restart, apt install ...) breaks the
// promise. What it cannot follow breaks it too (a command name in a
// variable, eval, a shell or python reading a script it cannot see), so an
// unclear command needs --yes like any other. It is not a sandbox: it
// catches mistakes and the usual tricks, not every program that can write.

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
	"sudoedit": true, "at": true, "batch": true, "systemd-run": true,
	"zip": true, "sqlite3": true, "sqlite": true,
}

// writeSubs are commands where a word decides: systemctl status reads,
// systemctl restart changes. The word may come anywhere (kubectl -n prod
// delete, iptables -t nat -A), so every argument is compared.
var writeSubs = map[string][]string{
	"systemctl":   {"start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask", "kill", "daemon-reload", "reload-or-restart", "try-restart", "isolate", "set-property", "edit", "reboot", "poweroff", "halt", "kexec", "set-environment", "unset-environment", "import-environment", "link", "revert", "preset", "preset-all", "reenable", "freeze", "thaw", "clean", "default", "rescue", "emergency"},
	"service":     {"start", "stop", "restart", "reload"},
	"apt":         {"install", "remove", "purge", "upgrade", "full-upgrade", "dist-upgrade", "autoremove", "update", "reinstall", "autoclean", "clean", "edit-sources"},
	"apt-get":     {"install", "remove", "purge", "upgrade", "dist-upgrade", "autoremove", "update", "clean", "autoclean", "build-dep", "source", "reinstall"},
	"dnf":         {"install", "remove", "erase", "upgrade", "update", "autoremove", "downgrade", "reinstall", "distro-sync", "swap", "makecache", "clean", "group"},
	"yum":         {"install", "remove", "erase", "upgrade", "update", "autoremove", "downgrade", "reinstall", "distro-sync", "swap", "makecache", "clean", "groupinstall", "groupremove"},
	"apk":         {"add", "del", "upgrade", "update", "fix", "cache"},
	"zypper":      {"install", "in", "remove", "rm", "update", "up", "dist-upgrade", "dup", "patch", "refresh", "ref", "addrepo", "ar", "removerepo", "rr"},
	"pacman":      {"-S", "-R", "-Syu", "-Rs", "-U", "-Sy", "-Syy", "-Syyu", "-Su", "-Rn", "-Rns", "-Rsn", "-Sc", "-Scc", "--sync", "--remove", "--upgrade"},
	"pip":         {"install", "uninstall", "download", "wheel"},
	"pip3":        {"install", "uninstall", "download", "wheel"},
	"npm":         {"install", "i", "uninstall", "update", "ci", "run", "run-script", "exec", "start", "stop", "restart", "test", "publish", "link", "rebuild", "prune", "dedupe"},
	"docker":      {"run", "rm", "rmi", "stop", "start", "restart", "kill", "create", "pull", "push", "prune", "update", "rename", "pause", "unpause", "cp", "commit", "tag", "build", "exec", "up", "down", "load", "import", "scale", "rollback", "deploy", "init", "join", "leave", "promote", "demote", "attach"},
	"podman":      {"run", "rm", "rmi", "stop", "start", "restart", "kill", "create", "pull", "push", "prune", "update", "rename", "pause", "unpause", "cp", "commit", "tag", "build", "exec", "up", "down", "load", "import", "attach"},
	"kubectl":     {"apply", "create", "delete", "edit", "patch", "replace", "scale", "rollout", "drain", "cordon", "uncordon", "label", "annotate", "set", "taint", "run", "expose", "autoscale", "exec", "cp", "debug", "attach", "approve", "deny", "use-context", "set-context", "delete-context", "set-cluster", "set-credentials", "rename-context"},
	"ip":          {"add", "del", "delete", "set", "flush", "replace", "change"},
	"hostnamectl": {"set-hostname"},
	"timedatectl": {"set-time", "set-timezone", "set-ntp"},
	"journalctl":  {"--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush", "--relinquish-var", "--setup-keys"},
	"sysctl":      {"-w", "--write", "-p", "--load", "--system"},
	"ufw":         {"allow", "deny", "reject", "delete", "enable", "disable", "reset", "limit", "insert", "route", "reload"},
	"iptables":    {"-A", "-D", "-I", "-R", "-F", "-X", "-P", "-N", "-Z", "-E", "--append", "--delete", "--insert", "--replace", "--flush", "--delete-chain", "--policy", "--new-chain", "--zero", "--rename-chain"},
}

// argChecks are commands whose arguments decide whether they write: each
// one says what in them changes something, or "". input: the command
// reads a pipe or a redirect.
var argChecks = map[string]func(cmd string, args []string, input bool) string{
	"find": findWrite, "sed": sedWrite, "tar": tarWrite, "curl": curlWrite, "wget": wgetWrite,
	"awk": awkWrite, "gawk": awkWrite, "mawk": awkWrite, "nawk": awkWrite,
	"gzip": compressWrite, "gunzip": compressWrite, "bzip2": compressWrite, "bunzip2": compressWrite,
	"xz": compressWrite, "unxz": compressWrite, "zstd": compressWrite, "unzstd": compressWrite,
	"lz4": compressWrite, "lzma": compressWrite, "unlzma": compressWrite, "pigz": compressWrite,
	"unzip": unzipWrite, "patch": patchWrite, "crontab": crontabWrite, "git": gitWrite, "hash": hashWrite,
	"psql": psqlWrite, "mysql": mysqlWrite, "mariadb": mysqlWrite,
}

// argSensitive: the arguments of cmd decide what it does, so an argument
// komando cannot see (find /data $X) may turn it into a write.
func argSensitive(cmd string) bool {
	_, a := argChecks[cmd]
	_, b := writeSubs[cmd]
	return a || b
}

// wrappers run the next word as the command. The list is the options that
// take a value (sudo -u root, timeout -s KILL): the value is not the command.
var wrappers = map[string][]string{
	"sudo":     {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-R", "-T", "--user", "--group", "--close-from", "--chdir", "--host", "--prompt", "--role", "--type", "--other-user", "--chroot", "--command-timeout"},
	"doas":     {"-u", "-C"},
	"env":      {"-u", "-C", "--unset", "--chdir"},
	"nice":     {"-n", "--adjustment"},
	"timeout":  {"-s", "-k", "--signal", "--kill-after"},
	"ionice":   {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"},
	"stdbuf":   {"-i", "-o", "-e", "--input", "--output", "--error"},
	"xargs":    {"-I", "-L", "-n", "-P", "-d", "-E", "-s", "-a", "--max-args", "--max-lines", "--max-procs", "--delimiter", "--eof", "--max-chars", "--arg-file", "--replace", "--process-slot-var"},
	"time":     {"-f", "--format"},
	"chrt":     {"-T", "-P", "-D", "--sched-runtime", "--sched-period", "--sched-deadline"},
	"taskset":  nil,
	"numactl":  {"-i", "-m", "-N", "-C", "-p", "--interleave", "--membind", "--cpunodebind", "--physcpubind", "--preferred"},
	"prlimit":  {"-p", "-o", "--pid", "--output"},
	"fakeroot": {"-l", "-s", "-i", "-b", "--lib", "--faked"},
	"faketime": nil,
	"command":  nil, "nohup": nil, "setsid": nil, "busybox": nil, // busybox APPLET ARGS
}

// wrapperWords are the words a wrapper takes before its command: chrt
// PRIORITY CMD, taskset MASK CMD, faketime TIME CMD.
var wrapperWords = map[string]int{"chrt": 1, "taskset": 1, "faketime": 1}

// shellKeywords come before a command (if rm x; then ...): the command is
// the next word.
var shellKeywords = map[string]bool{"{": true, "}": true, "!": true, "if": true, "then": true, "elif": true,
	"else": true, "fi": true, "do": true, "done": true, "while": true, "until": true, "esac": true, "coproc": true, "[[": true, "]]": true}

// runsHidden are commands that run text komando does not see as a command,
// or run another program in a way it cannot follow.
var runsHidden = map[string]bool{"eval": true, ".": true, "source": true, "exec": true, "trap": true, "alias": true,
	"builtin": true, "function": true, "enable": true, "nsenter": true, "chroot": true, "unshare": true, "flock": true,
	"watch": true, "parallel": true, "ssh": true, "vim": true, "vi": true, "nvim": true, "view": true, "ex": true, "ed": true,
	"emacs": true, "nano": true, "script": true, "sg": true, "newgrp": true, "pkexec": true, "strace": true, "ltrace": true,
	"gdb": true, "unbuffer": true, "run-parts": true}

// interpreters run code given inline (-c, -e) or read from a file or their
// input; only --version and --help are read-only for sure.
var interpreters = map[string]bool{"perl": true, "ruby": true, "node": true, "nodejs": true, "php": true,
	"lua": true, "luajit": true, "tclsh": true, "wish": true, "Rscript": true, "pwsh": true, "osascript": true,
	"expect": true, "irb": true, "deno": true, "bun": true}

// versionV: -v only prints the version (python -v is verbose, and runs).
var versionV = map[string]bool{"node": true, "nodejs": true, "php": true, "perl": true, "bun": true}

// envRunsCode are environment variables a program reads as code to run, a
// library to load or settings that change what it runs (PS4 with bash -x,
// BASH_ENV, LD_PRELOAD, a pager or editor).
var envRunsCode = map[string]bool{"BASH_ENV": true, "ENV": true, "PS0": true, "PS1": true, "PS2": true, "PS3": true,
	"PS4": true, "PROMPT_COMMAND": true, "SHELLOPTS": true, "BASHOPTS": true, "PAGER": true, "EDITOR": true,
	"VISUAL": true, "GIT_SSH": true, "GIT_SSH_COMMAND": true, "GIT_EXTERNAL_DIFF": true, "GIT_PAGER": true,
	"GIT_EDITOR": true, "GIT_ASKPASS": true, "GIT_EXEC_PATH": true, "GIT_PROXY_COMMAND": true, "SSH_ASKPASS": true,
	"SUDO_ASKPASS": true, "SUDO_EDITOR": true, "LESSOPEN": true, "LESSCLOSE": true, "MANPAGER": true,
	"SYSTEMD_PAGER": true, "SYSTEMD_EDITOR": true, "KUBE_EDITOR": true, "PERL5OPT": true, "PERL5LIB": true,
	"PERLLIB": true, "PYTHONSTARTUP": true, "PYTHONPATH": true, "PYTHONHOME": true, "NODE_OPTIONS": true,
	"RUBYOPT": true, "RUBYLIB": true, "PSQLRC": true, "PSQL_PAGER": true}

// envWrite: setting this variable (NAME=VALUE) can run code.
func envWrite(assign string) string {
	name, _, _ := strings.Cut(assign, "=")
	for _, p := range []string{"LD_", "BASH_FUNC_", "GIT_CONFIG", "DYLD_"} {
		if strings.HasPrefix(name, p) {
			return "setting " + name + " can run commands"
		}
	}
	if envRunsCode[name] || !validShellName(name) || name == "" {
		return "setting " + name + " can run commands"
	}
	return ""
}

func isInterpreter(cmd string) bool {
	return interpreters[cmd] || strings.HasPrefix(cmd, "python") || strings.HasPrefix(cmd, "pypy")
}

// readOnlyViolation returns what in command changes something, or "".
func readOnlyViolation(command string) string {
	return readOnlyCheck(command, 0)
}

func readOnlyCheck(command string, depth int) string {
	if depth > 8 {
		return "shells nested too deep"
	}
	lines, bad := policy.Lex(command)
	if bad != "" {
		return "komando cannot read the command (" + bad + ")"
	}
	for _, toks := range lines {
		var words []policy.Token
		input := false // the segment reads a pipe or a file
		for i := 0; i <= len(toks); i++ {
			if i == len(toks) || toks[i].Op && segmentEnd[toks[i].Text] {
				if w := segmentWrite(words, input, depth); w != "" {
					return w
				}
				words = nil
				input = i < len(toks) && toks[i].Text == "|"
				continue
			}
			t := toks[i]
			if !t.Op {
				words = append(words, t)
				continue
			}
			target := "" // a redirect: the next word is its file or descriptor
			if i+1 < len(toks) && !toks[i+1].Op {
				target = toks[i+1].Text
				i++
			}
			if t.Text == "<" || t.Text == "<<" || t.Text == "<<<" || t.Text == "<>" {
				input = true
			}
			if w := redirectWrite(t.Text, target); w != "" {
				return w
			}
		}
	}
	return ""
}

var segmentEnd = map[string]bool{";": true, "|": true, "||": true, "&": true, "&&": true, "(": true, ")": true}

// redirectWrite: > >> >| &> <> and >&FILE write a file; /dev/null, the
// standard streams and another descriptor (>&2, >&-) do not.
func redirectWrite(op, target string) string {
	switch op {
	case "<", "<<", "<<<", "<&":
		return ""
	case ">&":
		if policy.IsDescriptor(target) {
			return ""
		}
	}
	switch target {
	case "/dev/null", "/dev/stdout", "/dev/stderr":
		return ""
	}
	return "> " + target
}

func texts(toks []policy.Token) []string {
	w := make([]string, len(toks))
	for i, t := range toks {
		w[i] = t.Text
	}
	return w
}

func segmentWrite(toks []policy.Token, input bool, depth int) string {
	words := texts(toks)
	i := 0
	xargs := false
	for i < len(words) {
		w := words[i]
		switch {
		case isAssign(w): // FOO=1 cmd
			if v := envWrite(w); v != "" {
				return v
			}
			i++
			continue
		case shellKeywords[w]:
			i++
			continue
		case w == "for" || w == "select" || w == "case":
			return "" // for NAME in WORDS: the words are not a command
		}
		if opts, ok := wrappers[path.Base(w)]; ok {
			xargs = xargs || path.Base(w) == "xargs"
			next, v := skipWrapper(path.Base(w), opts, toks, i+1, input, depth)
			if v != "" || next < 0 {
				return v
			}
			i = next
			continue
		}
		break
	}
	if i >= len(words) {
		return ""
	}
	name := words[i]
	if strings.ContainsAny(name, "$`*?{") || strings.Contains(name, "[") && name != "[" {
		return "command name " + name + " is only known when it runs"
	}
	cmd := path.Base(name)
	args := words[i+1:]
	if xargs && (argSensitive(cmd) || policy.IsShell(cmd)) {
		return "xargs " + cmd + " (xargs adds arguments komando cannot see)"
	}
	if argSensitive(cmd) {
		for k, t := range toks[i+1:] {
			if cmd == "crontab" && k > 0 && args[k-1] == "-u" && t.Quoted {
				continue // crontab -l -u "$u": one word, a user name
			}
			if t.Expands {
				return cmd + " argument " + t.Text + " is only known when it runs"
			}
		}
	}
	switch {
	case writeVerbs[cmd], strings.HasPrefix(cmd, "mkfs"):
		return cmd
	case runsHidden[cmd]:
		if cmd == "exec" && len(args) == 0 {
			return "" // exec 2>&1: only redirects, checked on their own
		}
		return cmd
	case policy.IsShell(cmd):
		return shellWrite(cmd, args, depth)
	case isInterpreter(cmd):
		if len(args) == 0 {
			return cmd + " running code from its input"
		}
		for _, a := range args {
			if a != "--version" && a != "-V" && a != "--help" && a != "-h" && (a != "-v" || !versionV[cmd]) {
				return cmd + " running code"
			}
		}
		return ""
	}
	switch cmd {
	case "export", "declare", "typeset", "local", "readonly":
		for _, a := range args {
			if strings.Contains(a, "=") {
				if v := envWrite(a); v != "" {
					return v
				}
			}
		}
	}
	if check, ok := argChecks[cmd]; ok {
		return check(cmd, args, input)
	}
	if subs, ok := writeSubs[cmd]; ok {
		for _, a := range args {
			for _, s := range subs {
				if a == s || strings.HasPrefix(a, s+"=") {
					return cmd + " " + a
				}
			}
		}
	}
	return ""
}

// shellWrite checks what a shell runs: the text after -c, also with the
// arguments it gets ($0, $1 ...) filled in.
func shellWrite(cmd string, args []string, depth int) string {
	if len(args) > 0 && !slices.ContainsFunc(args, func(a string) bool { return a != "--version" && a != "--help" }) {
		return ""
	}
	script, params, ok := policy.ShellScript(cmd, args)
	if !ok {
		return cmd + " running a script from a file or its input"
	}
	if w := readOnlyCheck(script, depth+1); w != "" || len(params) == 0 {
		return w
	}
	return readOnlyCheck(policy.FillParams(script, params), depth+1)
}

// skipWrapper steps over a wrapper's options and values (sudo -u root,
// timeout 10) and returns where its command starts, -1 when there is
// nothing more to check, or why the wrapper itself changes something.
func skipWrapper(name string, opts []string, toks []policy.Token, i int, input bool, depth int) (int, string) {
	words := texts(toks)
	shell := false // sudo -s / -i: a shell runs the command, or reads its input
	positional := 0
	for i < len(words) {
		a := words[i]
		if a == "--" {
			i++
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			long := strings.HasPrefix(a, "--")
			flags := ""
			if !long {
				flags = a[1:]
			}
			switch {
			case name == "command" && (a == "-v" || a == "-V"):
				return -1, "" // only says where a command is
			case (name == "sudo" || name == "doas") && (strings.ContainsAny(flags, "e") && name == "sudo" || a == "--edit"):
				return -1, "sudo -e"
			case (name == "sudo" || name == "doas") && (strings.ContainsAny(flags, "si") || a == "--shell" || a == "--login"):
				shell = true
			case name == "env" && (strings.Contains(flags, "S") || strings.HasPrefix(a, "--split-string")):
				return -1, "env -S"
			case name == "time" && (strings.Contains(flags, "o") || strings.HasPrefix(a, "--output")):
				return -1, "time -o"
			}
			switch takesValue(opts, a) {
			case valueNext:
				i++
			case valueMaybe: // -uroot or -nu root: check both readings
				if v := segmentWrite(toks[i+1:], input, depth); v != "" {
					return -1, v
				}
				i++
			}
			i++
			continue
		}
		if isAssign(a) || name == "env" && strings.Contains(a, "=") { // env NAME=VALUE, sudo NAME=VALUE
			if v := envWrite(a); v != "" {
				return -1, v
			}
			i++
			continue
		}
		if words := wrapperWords[name] - positional; words > 0 { // taskset MASK, chrt PRIORITY
			positional++
			i++
			continue
		}
		if isNumberish(a) {
			i++
			continue
		}
		break
	}
	if i >= len(words) {
		if shell {
			return -1, "a shell reading commands from its input"
		}
		return -1, ""
	}
	return i, ""
}

const (
	valueNone  = iota
	valueNext  // -u root, --user root
	valueMaybe // -nu root or -uroot: a group of flags, or a value attached
)

// takesValue says whether option a takes the next word as its value.
func takesValue(opts []string, a string) int {
	if strings.Contains(a, "=") {
		return valueNone
	}
	for _, o := range opts {
		if a == o {
			return valueNext
		}
	}
	if strings.HasPrefix(a, "--") || len(a) <= 2 {
		return valueNone
	}
	letters := true // -nu: a group of flags; -I{} or -n5: a value attached
	for _, r := range a[1:] {
		letters = letters && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
	}
	for _, o := range opts {
		if len(o) == 2 && letters && strings.ContainsRune(a[1:], rune(o[1])) {
			return valueMaybe
		}
	}
	return valueNone
}

func findWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		switch a {
		case "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls":
			return "find " + a
		}
	}
	return ""
}

// sedWrite: sed -i edits files, and a sed program can run commands (e,
// s///e) and write files (w, W, s///w); a program from a file (-f) is not
// seen at all.
func sedWrite(cmd string, args []string, _ bool) string {
	var progs []string
	given := false // the program came with -e
	for k := 0; k < len(args); k++ {
		a := args[k]
		switch {
		case a == "--":
			if !given && k+1 < len(args) {
				progs = append(progs, args[k+1])
			}
			k = len(args)
		case strings.HasPrefix(a, "--in-place"):
			return cmd + " -i"
		case a == "--expression" || strings.HasPrefix(a, "--expression="):
			given = true
			if v, ok := strings.CutPrefix(a, "--expression="); ok {
				progs = append(progs, v)
			} else if k+1 < len(args) {
				progs = append(progs, args[k+1])
				k++
			}
		case a == "--file" || strings.HasPrefix(a, "--file="):
			return cmd + " -f"
		case a == "--line-length":
			k++
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for j := 1; j < len(a); j++ {
				switch a[j] {
				case 'i':
					return cmd + " -i"
				case 'f':
					return cmd + " -f"
				case 'e':
					given = true
					if j+1 < len(a) {
						progs = append(progs, a[j+1:])
					} else if k+1 < len(args) {
						progs = append(progs, args[k+1])
						k++
					}
					j = len(a)
				case 'l':
					if j+1 == len(a) {
						k++
					}
					j = len(a)
				}
			}
		default:
			if !given {
				progs = append(progs, a) // the program; the rest are files
				given = true
			}
		}
	}
	for _, p := range progs {
		if sedProgramWrites(p) {
			return cmd + " running commands or writing files (e, w)"
		}
	}
	return ""
}

// sedProgramWrites reads a sed program closely enough to find its e, w
// and W commands and the e and w flags of s///.
func sedProgramWrites(p string) bool {
	n := len(p)
	i := 0
	skip := func() { // a regex or s/// part, from its opening delimiter
		if i >= n {
			return
		}
		d := p[i]
		i++
		for i < n && p[i] != d {
			if p[i] == '\\' {
				i++
			}
			i++
		}
		i++
	}
	for i < n {
		switch c := p[i]; {
		case c == '/':
			skip()
		case c == '\\' && i+1 < n: // \%regex%
			i++
			skip()
		case c == 'e' || c == 'w' || c == 'W':
			return true
		case (c == 's' || c == 'y') && i+1 < n:
			i++
			skip()
			i = min(i, n) - 1 // the closing delimiter of the first part opens the second
			skip()
			for i < n && strings.IndexByte(";}\n", p[i]) < 0 {
				if c == 's' && (p[i] == 'w' || p[i] == 'e') {
					return true
				}
				i++
			}
		case c == 'a' || c == 'i' || c == 'c' || c == 'r' || c == 'R' || c == '#':
			for i < n && p[i] != '\n' { // text or a file name, to the line end
				i++
			}
		case c == 'b' || c == 't' || c == 'T' || c == ':':
			for i < n && p[i] != ';' && p[i] != '\n' { // a label
				i++
			}
		default:
			i++
		}
	}
	return false
}

// awkWrite: an awk program can run commands (system, | "cmd") and write
// files (print > "file"); a program from a file (-f) is not seen at all,
// and neither is a function called by name (gawk @f()).
func awkWrite(cmd string, args []string, _ bool) string {
	var progs []string
	given := false
	for k := 0; k < len(args); k++ {
		a := args[k]
		switch {
		case a == "--":
			if !given && k+1 < len(args) {
				progs = append(progs, args[k+1])
			}
			k = len(args)
		case a == "-f" || strings.HasPrefix(a, "-f") || strings.HasPrefix(a, "--file") || a == "-E" || strings.HasPrefix(a, "--exec") ||
			a == "-i" || strings.HasPrefix(a, "--include") || a == "-l" || strings.HasPrefix(a, "--load") || strings.HasPrefix(a, "-We") || a == "-W" && k+1 < len(args) && strings.HasPrefix(args[k+1], "e"):
			return cmd + " " + a
		case a == "-F" || a == "-v" || a == "-W" || a == "--assign" || a == "--field-separator":
			k++
		case a == "-e" || a == "--source":
			given = true
			if k+1 < len(args) {
				progs = append(progs, args[k+1])
			}
			k++
		case strings.HasPrefix(a, "--source="):
			given = true
			progs = append(progs, strings.TrimPrefix(a, "--source="))
		case strings.HasPrefix(a, "-e"):
			given = true
			progs = append(progs, a[2:])
		case strings.HasPrefix(a, "-") && a != "-":
		default: // the program; the rest are files
			if !given {
				progs = append(progs, a)
			}
			k = len(args)
		}
	}
	for _, p := range progs {
		if awkProgramWrites.MatchString(awkPlain(p)) {
			return cmd + " running commands or writing files"
		}
	}
	return ""
}

// awkProgramWrites: system(), a pipe to or from a command (| or |&), a
// file written with > or >>, and gawk's call by name (@f) or @include.
var awkProgramWrites = regexp.MustCompile(`\bsystem\s*\(|(^|[^|])\|($|[^|])|>>|>\s*["$(a-zA-Z_]|@[A-Za-z_]`)

// awkPlain empties the strings and /regex/ literals of an awk program, so
// that /ERROR|WARN/ or "a > b" is not read as a pipe or a redirect.
func awkPlain(p string) string {
	var b strings.Builder
	prev := byte(0) // the last character that was not a space
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '"' || c == '/' && (prev == 0 || strings.IndexByte("(,~!{};&|?:\n", prev) >= 0):
			b.WriteByte(c)
			for i++; i < len(p) && p[i] != c; i++ {
				if p[i] == '\\' {
					i++
				}
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
		if c != ' ' && c != '\t' {
			prev = c
		}
	}
	return b.String()
}

func isStdout(v string) bool {
	return v == "-" || v == "/dev/null" || v == "/dev/stdout" || v == "/dev/stderr"
}

// tarWrite: only listing (-t), comparing (-d) and creating an archive on
// standard output are read-only; extracting, appending and options that
// run a program (--to-command, --checkpoint-action, -I) are not.
func tarWrite(cmd string, args []string, _ bool) string {
	mode, archive := "", ""
	takes := "bCfgHIKLNTVX" // short options with a value
	letter := func(l byte, value func() string) string {
		switch {
		case strings.IndexByte("Arux", l) >= 0:
			return "tar -" + string(l)
		case l == 'I' || l == 'g':
			return "tar -" + string(l)
		case l == 'c' || l == 't' || l == 'd':
			mode = string(l)
		}
		if strings.IndexByte(takes, l) >= 0 {
			v := value()
			if l == 'f' {
				archive = v
			}
		}
		return ""
	}
	for k := 0; k < len(args); k++ {
		a := args[k]
		next := func() string {
			if k+1 < len(args) {
				k++
				return args[k]
			}
			return ""
		}
		switch {
		case k == 0 && a != "" && a[0] != '-': // old style: tar xzf FILE
			for j := 0; j < len(a); j++ {
				if w := letter(a[j], next); w != "" {
					return w
				}
			}
		case strings.HasPrefix(a, "--"):
			name, val, has := strings.Cut(a, "=")
			switch name {
			case "--extract", "--get", "--append", "--update", "--catenate", "--concatenate", "--delete",
				"--to-command", "--checkpoint-action", "--use-compress-program", "--info-script", "--new-volume-script",
				"--rsh-command", "--rmt-command", "--index-file", "--remove-files", "--listed-incremental", "--volno-file":
				return "tar " + name
			case "--list":
				mode = "t"
			case "--diff", "--compare":
				mode = "d"
			case "--create":
				mode = "c"
			case "--file":
				if !has {
					val = next()
				}
				archive = val
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for j := 1; j < len(a); j++ {
				l := a[j]
				rest := a[j+1:]
				if w := letter(l, func() string {
					if rest != "" {
						return rest
					}
					return next()
				}); w != "" {
					return w
				}
				if strings.IndexByte(takes, l) >= 0 {
					break
				}
			}
		}
	}
	if mode == "c" && archive != "" && !isStdout(archive) {
		return "tar -c writing " + archive
	}
	return ""
}

// curlWrite: curl saves files (-o FILE, -O, -c jar) and sends data or a
// changing request (-d, -F, -T, -X POST); -K reads options komando does
// not see. Output to standard output or /dev/null is fine.
func curlWrite(cmd string, args []string, _ bool) string {
	getish := func(m string) bool {
		m = strings.ToUpper(m)
		return m == "GET" || m == "HEAD" || m == "OPTIONS"
	}
	for k := 0; k < len(args); k++ {
		a := args[k]
		next := func() string {
			if k+1 < len(args) {
				k++
				return args[k]
			}
			return ""
		}
		if strings.HasPrefix(a, "--") {
			name, val, has := strings.Cut(a, "=")
			switch name {
			case "--output", "--dump-header", "--trace", "--trace-ascii", "--stderr", "--libcurl", "--cookie-jar",
				"--etag-save", "--hsts", "--alt-svc", "--output-dir":
				if !has {
					val = next()
				}
				if !isStdout(val) || name == "--output-dir" {
					return "curl " + name + " " + val
				}
			case "--remote-name", "--remote-name-all", "--remote-header-name", "--upload-file", "--config", "--create-dirs",
				"--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--form", "--form-string", "--json", "--quote":
				return "curl " + name
			case "--request":
				if !has {
					val = next()
				}
				if !getish(val) {
					return "curl " + name + " " + val
				}
			}
			continue
		}
		if !strings.HasPrefix(a, "-") || len(a) < 2 {
			continue
		}
		for j := 1; j < len(a); j++ {
			l := a[j]
			if strings.IndexByte("OTKJdFQ", l) >= 0 {
				return "curl -" + string(l)
			}
			if strings.IndexByte("AbCcDdEeFHKmoPQrTtUuwXxYyz", l) < 0 {
				continue
			}
			v := a[j+1:]
			if v == "" {
				v = next()
			}
			if (l == 'o' || l == 'D' || l == 'c') && !isStdout(v) || l == 'X' && !getish(v) {
				return "curl -" + string(l) + " " + v
			}
			break
		}
	}
	return ""
}

// wgetWrite: wget saves what it gets unless it goes to standard output
// (-O -) or nothing is fetched (--spider).
func wgetWrite(cmd string, args []string, _ bool) string {
	safe := false
	for k := 0; k < len(args); k++ {
		a := args[k]
		next := func() string {
			if k+1 < len(args) {
				k++
				return args[k]
			}
			return ""
		}
		if strings.HasPrefix(a, "--") {
			name, val, has := strings.Cut(a, "=")
			switch name {
			case "--output-document", "--output-file", "--append-output":
				if !has {
					val = next()
				}
				if !isStdout(val) {
					return "wget " + name + " " + val
				}
				safe = safe || name == "--output-document"
			case "--spider":
				safe = true
			case "--post-data", "--post-file", "--method", "--body-data", "--body-file", "--recursive", "--mirror", "--execute":
				return "wget " + name
			}
			continue
		}
		if !strings.HasPrefix(a, "-") || len(a) < 2 {
			continue
		}
		for j := 1; j < len(a); j++ {
			l := a[j]
			if l == 'e' || l == 'r' || l == 'm' {
				return "wget -" + string(l)
			}
			if strings.IndexByte("OoaiBPUtTlADRIXwQ", l) < 0 {
				continue
			}
			v := a[j+1:]
			if v == "" {
				v = next()
			}
			if l == 'O' || l == 'o' || l == 'a' {
				if !isStdout(v) {
					return "wget -" + string(l) + " " + v
				}
				safe = safe || l == 'O'
			}
			break
		}
	}
	if !safe {
		return "wget saving a file"
	}
	return ""
}

// compressWrite: gzip FILE replaces the file; -c (to standard output), -l
// and -t only read, and so does compressing a pipe.
func compressWrite(cmd string, args []string, _ bool) string {
	files, reads := 0, false
	for _, a := range args {
		switch {
		case a == "--stdout" || a == "--to-stdout" || a == "--list" || a == "--test":
			reads = true
		case strings.HasPrefix(a, "--"), a == "-":
		case strings.HasPrefix(a, "-"):
			reads = reads || strings.ContainsAny(a[1:], "clt")
		default:
			files++
		}
	}
	if files > 0 && !reads {
		return cmd + " replacing files"
	}
	return ""
}

// unzipWrite: only listing, testing and printing (-l -t -v -p -c -z -Z)
// leave the files alone.
func unzipWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.ContainsAny(a[1:], "ltvpczZ") {
			return ""
		}
	}
	return "unzip"
}

func patchWrite(cmd string, args []string, _ bool) string {
	if slices.Contains(args, "--dry-run") {
		return ""
	}
	return "patch"
}

// crontabWrite: only crontab -l (and -u USER -l) reads; crontab FILE and
// crontab with nothing install a new table.
func crontabWrite(cmd string, args []string, _ bool) string {
	list := false
	for k := 0; k < len(args); k++ {
		switch a := args[k]; a {
		case "-u":
			k++
		case "-l":
			list = true
		default:
			return "crontab " + a
		}
	}
	if !list {
		return "crontab reading a new table from its input"
	}
	return ""
}

func hashWrite(cmd string, args []string, _ bool) string {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && strings.Contains(a, "p") {
			return "hash -p" // runs another program under a known name
		}
	}
	return ""
}

// gitWrites are git subcommands that change the repository, the work tree
// or a remote, or run a program.
var gitWrites = map[string]bool{"commit": true, "push": true, "pull": true, "reset": true, "checkout": true, "clean": true,
	"merge": true, "rebase": true, "fetch": true, "clone": true, "init": true, "rm": true, "mv": true, "add": true,
	"apply": true, "am": true, "cherry-pick": true, "revert": true, "restore": true, "switch": true, "worktree": true,
	"submodule": true, "gc": true, "prune": true, "update-ref": true, "notes": true, "replace": true, "filter-branch": true,
	"update-index": true, "repack": true, "bisect": true, "fast-import": true, "maintenance": true, "sparse-checkout": true,
	"lfs": true, "symbolic-ref": true, "pack-refs": true, "read-tree": true, "checkout-index": true, "commit-tree": true,
	"write-tree": true, "mktag": true, "mktree": true, "credential": true, "send-email": true, "daemon": true,
	"instaweb": true, "difftool": true, "mergetool": true, "hook": true, "bundle": true, "format-patch": true, "svn": true,
	"p4": true, "imap-send": true, "http-push": true, "upload-pack": true, "receive-pack": true, "shell": true, "archive": true}

// gitWrite: git -c sets config for one run (an alias, a pager or a hook
// that runs anything), so it is never read-only; the global options that
// take a value (-C DIR) are not the subcommand.
func gitWrite(cmd string, args []string, _ bool) string {
	k := 0
	for ; k < len(args); k++ {
		a := args[k]
		switch {
		case a == "-c" || strings.HasPrefix(a, "-c") || strings.HasPrefix(a, "--config-env"):
			return "git " + a + " (config for one run can run commands)"
		case a == "-C" || a == "--git-dir" || a == "--work-tree" || a == "--namespace" || a == "--super-prefix":
			k++
		case strings.HasPrefix(a, "-"):
		default:
			return gitSubWrite(a, args[k+1:])
		}
	}
	return ""
}

func gitSubWrite(sub string, rest []string) string {
	for _, a := range rest {
		for _, o := range []string{"--output", "--upload-pack", "--receive-pack", "--exec", "--ext-diff"} {
			if a == o || strings.HasPrefix(a, o+"=") {
				return "git " + sub + " " + o
			}
		}
	}
	first := ""
	if len(rest) > 0 {
		first = rest[0]
	}
	switch sub {
	case "stash":
		if first != "list" && first != "show" {
			return "git stash"
		}
	case "branch":
		return gitRefWrite("branch", rest, "dDmMcCfut", []string{"--delete", "--move", "--copy", "--force", "--set-upstream-to", "--unset-upstream", "--edit-description", "--track"},
			[]string{"-l", "--list", "-a", "--all", "-r", "--remotes", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at", "--show-current"})
	case "tag":
		return gitRefWrite("tag", rest, "dfasmFue", []string{"--delete", "--force", "--annotate", "--sign", "--message", "--file", "--local-user", "--edit"},
			[]string{"-l", "--list", "-n", "--contains", "--no-contains", "--merged", "--no-merged", "--points-at"})
	case "remote":
		switch first {
		case "add", "remove", "rm", "rename", "set-url", "set-head", "set-branches", "prune", "update":
			return "git remote " + first
		}
	case "reflog":
		if first == "expire" || first == "delete" {
			return "git reflog " + first
		}
	case "hash-object":
		if slices.Contains(rest, "-w") {
			return "git hash-object -w"
		}
	case "config":
		return gitConfigWrite(rest)
	default:
		if gitWrites[sub] {
			return "git " + sub
		}
	}
	return ""
}

// gitRefWrite: git branch and git tag list, unless they get a change
// option or a name without a listing option (git branch new).
func gitRefWrite(sub string, rest []string, letters string, long, listing []string) string {
	list, names := false, 0
	for _, a := range rest {
		opt, _, _ := strings.Cut(a, "=")
		switch {
		case slices.Contains(listing, opt) || strings.HasPrefix(a, "-n") && sub == "tag":
			list = true
		case slices.Contains(long, opt):
			return "git " + sub + " " + a
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-"):
			if strings.ContainsAny(a[1:], letters) {
				return "git " + sub + " " + a
			}
		default:
			names++
		}
	}
	if names > 0 && !list {
		return "git " + sub + " NAME"
	}
	return ""
}

// gitConfigWrite: git config NAME and --get/--list read; NAME VALUE, the
// set/unset subcommands and the change options write.
func gitConfigWrite(rest []string) string {
	get, names := false, 0
	for k := 0; k < len(rest); k++ {
		a := rest[k]
		switch {
		case a == "--unset" || a == "--unset-all" || a == "--add" || a == "--replace-all" || a == "--remove-section" ||
			a == "--rename-section" || a == "-e" || a == "--edit":
			return "git config " + a
		case strings.HasPrefix(a, "--get") || a == "-l" || a == "--list":
			get = true
		case a == "-f" || a == "--file" || a == "--blob" || a == "--type" || a == "--default":
			k++
		case strings.HasPrefix(a, "-"):
		default:
			if names == 0 {
				switch a {
				case "set", "unset", "rename-section", "remove-section", "edit":
					return "git config " + a
				case "get", "list":
					get = true
				}
			}
			names++
		}
	}
	if names >= 2 && !get {
		return "git config NAME VALUE"
	}
	return ""
}

// psqlMeta and mysqlMeta are client commands that run a shell or read and
// write local files: the server's read-only settings do not cover them.
var (
	psqlMeta  = regexp.MustCompile(`\\(!|copy|setenv|lo_export|lo_import|include(_relative)?|ir|i|o|out|w|write|s|cd|e|edit|ef|ev)(\s|$|\\|;)|\\g[a-z]*[ \t]+[^\s;\\]`)
	mysqlMeta = regexp.MustCompile(`(?im)\\[!.TPe]|(^|;)\s*(system|tee|pager|source|edit)\b`)
)

// psqlWrite: psql -c is SQL, which the database itself holds to its
// rules, but a \! or \o in it runs a shell or writes a file here; a file
// (-f) or commands from a pipe are not seen at all.
func psqlWrite(cmd string, args []string, input bool) string {
	inline := false
	for k := 0; k < len(args); k++ {
		a := args[k]
		val := ""
		switch {
		case a == "-c" || a == "--command":
			inline = true
			if k+1 < len(args) {
				val = args[k+1]
				k++
			}
		case strings.HasPrefix(a, "--command="):
			inline = true
			val = strings.TrimPrefix(a, "--command=")
		case a == "--file" || strings.HasPrefix(a, "--file=") || a == "--output" || strings.HasPrefix(a, "--output=") ||
			a == "--log-file" || strings.HasPrefix(a, "--log-file="):
			return cmd + " " + a
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 1:
			for j := 1; j < len(a); j++ {
				switch l := a[j]; {
				case l == 'c':
					inline = true
					if j+1 < len(a) {
						val = a[j+1:]
					} else if k+1 < len(args) {
						val = args[k+1]
						k++
					}
					j = len(a)
				case l == 'f' || l == 'o' || l == 'L':
					return cmd + " -" + string(l)
				case strings.IndexByte("dhpUvPFRT", l) >= 0:
					if j+1 == len(a) {
						k++
					}
					j = len(a)
				}
			}
		}
		if psqlMeta.MatchString(val) {
			return cmd + ` running a shell or writing files (\! \o \w \copy ...)`
		}
	}
	if !inline && input {
		return cmd + " reading commands from a pipe or a file"
	}
	return ""
}

// mysqlWrite is psqlWrite for mysql -e (system, \!, tee, pager).
func mysqlWrite(cmd string, args []string, input bool) string {
	inline := false
	for k := 0; k < len(args); k++ {
		a := args[k]
		val := ""
		opt, _, _ := strings.Cut(a, "=")
		switch {
		case a == "-e" || a == "--execute":
			inline = true
			if k+1 < len(args) {
				val = args[k+1]
				k++
			}
		case strings.HasPrefix(a, "--execute="):
			inline = true
			val = strings.TrimPrefix(a, "--execute=")
		case opt == "--tee" || opt == "--pager" || opt == "--init-command" || opt == "--init-command-add" || opt == "--plugin-dir" ||
			opt == "--load-data-local-dir" || opt == "--local-infile" || opt == "--default-auth" || opt == "--defaults-file" || opt == "--defaults-extra-file":
			return cmd + " " + opt
		case strings.HasPrefix(a, "-e"):
			inline = true
			val = a[2:]
		case strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) == 2 && strings.IndexByte("hPuDS", a[1]) >= 0:
			k++
		}
		if mysqlMeta.MatchString(val) {
			return cmd + " running a shell or writing files (system, tee, pager ...)"
		}
	}
	if !inline && input {
		return cmd + " reading commands from a pipe or a file"
	}
	return ""
}

// sqlClients read SQL from their input: with exec --stdin-file, that
// input is checked for the client commands that run a shell.
var sqlClient = regexp.MustCompile(`\b(psql|mysql|mariadb)\b`)

func sqlInputWrite(command string, stdin []byte) string {
	if !sqlClient.MatchString(command) {
		return ""
	}
	if psqlMeta.Match(stdin) || mysqlMeta.Match(stdin) {
		return `the input runs a shell or writes files (\!, \o, system, tee ...)`
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

// stdinShells read a script from their input when given no -c and no file.
var stdinShells = map[string]bool{"sh": true, "bash": true, "dash": true, "ash": true, "ksh": true, "zsh": true, "mksh": true}

// stdinShell: the whole command is a shell reading its script from its
// input (bash -s, sh -eu -o pipefail -s -- ARGS), so checking that input is
// checking the script.
func stdinShell(command string) bool {
	lines := policy.Tokens(command)
	if len(lines) != 1 || len(lines[0]) == 0 {
		return false
	}
	toks := lines[0]
	for _, t := range toks {
		if t.Op {
			return false
		}
	}
	if !stdinShells[path.Base(toks[0].Text)] || strings.ContainsAny(toks[0].Text, "$`*?[") {
		return false
	}
	for i := 1; i < len(toks); i++ {
		w := toks[i].Text
		switch {
		case w == "--":
			// the rest are the script's arguments ($1 ...): a check of
			// the script cannot see what they fill in, so none may follow
			return i == len(toks)-1
		case (toks[i-1].Text == "-o" || toks[i-1].Text == "+o") && validShellName(w):
		case len(w) > 1 && (w[0] == '-' || w[0] == '+') && validShellName(w[1:]) && !strings.ContainsRune(w[1:], 'c'):
		default:
			return false
		}
	}
	return true
}

// checkReadOnly is the --read-only promise check, as a safety stop.
func checkReadOnly(command string) error {
	if w := readOnlyViolation(command); w != "" {
		return readOnlyStop(w)
	}
	return nil
}

// checkReadOnlyEnv is checkReadOnly for a command run with -e values: it
// looks at the command with the values filled in (with -e X=-delete,
// find / $X deletes), each word of a value quoted the way the shell splits
// it. A variable that runs code (BASH_ENV, PS4, LD_PRELOAD) breaks the
// promise whatever the command.
func checkReadOnlyEnv(command string, env []string) error {
	if len(env) == 0 {
		return checkReadOnly(command)
	}
	kv, err := parseKV(env)
	if err != nil {
		return checkReadOnly(command) // runFleet reports the bad -e
	}
	for _, k := range slices.Sorted(maps.Keys(kv)) {
		if w := envWrite(k + "="); w != "" {
			return readOnlyStop(w)
		}
	}
	filled := os.Expand(command, func(k string) string {
		v, ok := kv[k]
		if !ok {
			return "${" + k + "}"
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			return "''"
		}
		for i := range f {
			f[i] = sshx.Q(f[i])
		}
		return strings.Join(f, " ")
	})
	return checkReadOnly(filled)
}

func readOnlyStop(what string) error {
	return policyStop(out.Errf(out.ExitPolicy, "READ_ONLY_VIOLATION", "drop --read-only and confirm with --yes",
		"--read-only, but the command changes something (%s)", what))
}
