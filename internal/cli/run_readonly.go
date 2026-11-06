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
