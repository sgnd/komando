package cli

import (
	"maps"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
)

// --read-only is a promise from the caller that lets a command skip the
// confirmation protected servers need, and it is all a read-only ssh-gate
// key may run. checkReadOnly holds the caller to it with a strict
// allowlist: the command runs only when komando knows every part of it
// only reads. A word that clearly changes something (rm, tee, a >
// redirect, systemctl restart) breaks the promise, and so does anything
// komando does not know: a command that is not on its lists, an option or
// subcommand it has not heard of, a command name in a variable, text bash
// would expand or evaluate before the command runs. Such a command runs
// without --read-only, with the confirmation that takes.

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
	"zip": true, "sqlite3": true, "sqlite": true, "split": true, "csplit": true,
}

// argChecks are commands whose arguments decide whether they write: each
// one says what in them changes something, or "". input: the command
// reads a pipe or a redirect.
var argChecks = map[string]func(cmd string, args []string, input bool) string{
	"find": findWrite, "sed": sedWrite, "tar": tarWrite,
	"awk": awkWrite, "gawk": awkWrite, "mawk": awkWrite, "nawk": awkWrite,
	"gzip": compressWrite, "gunzip": compressWrite, "bzip2": compressWrite, "bunzip2": compressWrite,
	"xz": compressWrite, "unxz": compressWrite, "zstd": compressWrite, "unzstd": compressWrite,
	"lzma": compressWrite, "unlzma": compressWrite, "pigz": compressWrite,
	"zcat": catOnly, "bzcat": catOnly, "xzcat": catOnly, "zstdcat": catOnly, "lzcat": catOnly,
	"unzip": unzipWrite, "crontab": crontabWrite, "journalctl": noWrite, "set": setWrite,
	"sort": sortWrite, "uniq": uniqWrite, "openssl": opensslWrite, "date": dateWrite,
	"hostname": hostnameWrite, "dmesg": dmesgWrite,
	"redis-cli": redisCliWrite, "valkey-cli": redisCliWrite, "keydb-cli": redisCliWrite,
	"xxd": xxdWrite, "yq": yqWrite, "xmllint": xmllintWrite, "fuser": fuserWrite, "ss": ssWrite,
	"arp": arpWrite, "sar": sarWrite, "rg": rgWrite, "file": fileWrite, "lsof": lsofWrite, "pidstat": pidstatWrite,
	"nginx": configTest, "sshd": configTest, "apachectl": configTest, "apache2ctl": configTest, "httpd": configTest,
	"firewall-cmd": firewallCmdWrite,
	"blkid":        blkidWrite, "printf": printfWrite, "test": testWrite, "[": testWrite, "[[": testWrite, "read": readWrite,
}

// argSensitive: the arguments of cmd decide what it does, so an argument
// komando cannot see (find /data $X) may turn it into a write.
func argSensitive(cmd string) bool {
	_, a := argChecks[cmd]
	_, b := readSubs[cmd]
	return a || b
}

// shellKeywords come before a command (if rm x; then ...): the command is
// the next word.
var shellKeywords = map[string]bool{"{": true, "}": true, "!": true, "if": true, "then": true, "elif": true,
	"else": true, "fi": true, "do": true, "done": true, "while": true, "until": true, "esac": true}

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

// Under --read-only a variable may be set (NAME=VALUE, export, read, for
// or -e) only when no program reads it as settings, code or where things
// are. Programs read upper-case names (PATH, PS4, TAR_OPTIONS,
// JAVA_TOOL_OPTIONS, KUBECONFIG ...), and there are too many to list, so
// a name must have a lower-case letter, unless it only sets a language,
// a time zone or how output looks (safeEnv). A few lower-case names are
// read too: the proxy settings, and zsh's path, fpath and their like.
var (
	safeEnv  = set(`LANG LANGUAGE TZ TERM COLUMNS LINES NO_COLOR`)
	readEnvs = set(`path fpath cdpath manpath module_path mailpath fignore prompt histchars watch psvar`)
)

// envWrite: setting this variable (NAME=VALUE) is not known to change
// nothing.
func envWrite(assign string) string {
	name, _, _ := strings.Cut(assign, "=")
	switch {
	case name == "" || !validShellName(name):
		return "setting " + name + " (not a plain name)"
	case safeEnv[name] || strings.HasPrefix(name, "LC_"):
		return ""
	case readEnvs[name] || strings.HasSuffix(name, "_proxy") || strings.HasSuffix(name, "_functions") ||
		strings.HasPrefix(name, "BASH_FUNC_"):
		return "setting " + name + " (a program or the shell reads it)"
	case strings.ToUpper(name) == name:
		return "setting " + name + " (programs read upper-case names as settings or code: use a name with a lower-case letter, like dir)"
	}
	return ""
}

func isInterpreter(cmd string) bool {
	return interpreters[cmd] || strings.HasPrefix(cmd, "python") || strings.HasPrefix(cmd, "pypy")
}

// readOnlyViolation returns why command may not run as --read-only, or "":
// what in it changes something, or what komando does not know only reads.
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
		for _, t := range toks {
			switch {
			case t.Brace:
				return t.Text + " (bash expands the braces into words komando cannot see)"
			case t.Code:
				return t.Text + " (bash evaluates this expansion, which can run commands)"
			}
		}
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
		case w == "case":
			return "" // case WORD in: the word is not a command
		case w == "for": // for NAME in WORDS: the words are not a command, NAME is set
			if i+1 < len(words) {
				if v := envWrite(words[i+1] + "="); v != "" {
					return v
				}
			}
			return ""
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
	if xargs && !readCommands[cmd] {
		return "xargs " + cmd + " (xargs adds arguments komando cannot see)"
	}
	if argSensitive(cmd) {
		for k, t := range toks[i+1:] {
			if cmd == "crontab" && k > 0 && args[k-1] == "-u" && t.Quoted {
				continue // crontab -l -u "$u": one word, a user name
			}
			if t.Expands && !builtinExpands(cmd, k, t, toks[i+1:]) {
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
	case "export": // export NAME, export NAME=VALUE: a name with a [ ] in it is evaluated
		for _, a := range args {
			name, _, _ := strings.Cut(a, "=")
			if !validShellName(name) || name == "" {
				return "export " + a + " (not a plain name)"
			}
			if v := envWrite(a); v != "" {
				return v
			}
		}
		return ""
	}
	return classifyCommand(cmd, args, input)
}

// builtinExpands: argument k of a shell built-in may hold a value komando
// cannot see. printf's words after the format are only printed. test and
// [ take a quoted value as one word, which cannot become the -v that
// evaluates a name unless the word after it is unseen too; in [[ ]] the
// operators are read before anything expands.
func builtinExpands(cmd string, k int, t policy.Token, args []policy.Token) bool {
	switch cmd {
	case "printf":
		return k > 0
	case "[[":
		return true
	case "test", "[":
		return t.Quoted && (k+1 >= len(args) || !args[k+1].Expands)
	}
	return false
}

// classifyCommand rates the command word itself (after wrappers): one
// whose options decide (argChecks, with only the long options komando
// knows), one with subcommands (readSubs), or a plain read tool
// (readCommands). Anything else is not known to only read.
func classifyCommand(cmd string, args []string, input bool) string {
	if check, ok := argChecks[cmd]; ok {
		if w := longOptionUnknown(cmd, args); w != "" {
			return w
		}
		return check(cmd, args, input)
	}
	if rule, ok := readSubs[cmd]; ok {
		if cmd == "sysctl" && slices.ContainsFunc(args, func(a string) bool { return strings.Contains(a, "=") && !strings.HasPrefix(a, "-") }) {
			return "sysctl NAME=VALUE"
		}
		if cmd == "kubectl" {
			if w := kubectlConfigOption(args); w != "" {
				return w
			}
		}
		return subRead(cmd, args, rule)
	}
	if !readCommands[cmd] {
		return "the command " + cmd + " is not known to only read"
	}
	return ""
}

// readCommands only ever read, whatever their options: a read tool that
// prints to stdout, a shell built-in that changes nothing on the server.
// A command that can write by itself (tee, dd) is not here; one whose
// options or subcommand decide (find, sed, git, systemctl, docker ...) is
// classified above, not here; one that bash makes evaluate its arguments
// (let, unset, declare, wait, getopts) is left out.
var readCommands = set(`
	: true false echo cd pwd exit sleep seq
	grep egrep fgrep zgrep
	cat tac nl head tail wc rev cut paste join comm column fold fmt expand unexpand tr
	od hexdump strings cksum sum md5sum sha1sum sha224sum sha256sum sha384sum sha512sum b2sum
	base32 base64 basenc
	ls dir vdir stat readlink realpath basename dirname pathchk which whereis type
	df du free uptime uname arch nproc hostid id whoami who w users groups logname tty getconf locale cal
	last lastlog lsb_release
	ps pgrep pidof lslocks
	netstat lsblk lscpu lsmem lsusb lspci lsmod lsattr getfacl getcap
	objdump readelf size
	dig host nslookup getent
	vmstat iostat mpstat
	jq printenv`)

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
func checkReadOnly(cl *call, command string) error {
	if w := readOnlyViolation(command); w != "" {
		return readOnlyStop(cl, w)
	}
	return nil
}

// checkReadOnlyEnv is checkReadOnly for a command run with -e values: it
// looks at the command with the values filled in (with -e X=-delete,
// find / $X deletes), each word of a value quoted the way the shell splits
// it. A variable that runs code (BASH_ENV, PS4, LD_PRELOAD) breaks the
// promise whatever the command.
func checkReadOnlyEnv(cl *call, command string, env []string) error {
	filled, bad := readOnlyFill(command, env)
	if bad != "" {
		return readOnlyStop(cl, bad)
	}
	return checkReadOnly(cl, filled)
}

// readOnlyFill fills command's $VAR from the -e values, each word quoted the
// way the shell splits it, and reports a value that runs code (BASH_ENV,
// PS4, LD_PRELOAD) whatever the command. When there are no values, or they
// cannot be read (runFleet reports that), it returns command unchanged.
func readOnlyFill(command string, env []string) (filled, codeRunner string) {
	if len(env) == 0 {
		return command, ""
	}
	kv, err := parseKV(env)
	if err != nil {
		return command, ""
	}
	for _, k := range slices.Sorted(maps.Keys(kv)) {
		if w := envWrite(k + "="); w != "" {
			return command, w
		}
	}
	for _, k := range slices.Sorted(maps.Keys(kv)) {
		if strings.ContainsAny(kv[k], "*?[{\\~") {
			return command, "-e " + k + " has a * ? [ { ~ or backslash: bash would expand the value into words komando cannot see"
		}
	}
	if k := quotedEnv(command, kv); k != "" {
		return command, "-e " + k + ` in a command with double quotes ("$` + k + `" is one word komando cannot check: leave the quotes off)`
	}
	return os.Expand(command, func(k string) string {
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
	}), ""
}

// quotedEnv returns the name of a value in kv the command uses while it
// has a double quote anywhere, or "". Inside double quotes a value is one
// word komando cannot check, and bash's own quoting ($'..', comments,
// here-documents) can hide where a double quote starts, so any use counts.
func quotedEnv(command string, kv map[string]string) string {
	if !strings.Contains(command, `"`) {
		return ""
	}
	for _, k := range slices.Sorted(maps.Keys(kv)) {
		for rest := command; ; {
			i := strings.Index(rest, "$")
			if i < 0 {
				break
			}
			rest = strings.TrimPrefix(rest[i+1:], "{")
			if strings.HasPrefix(rest, k) && (len(rest) == len(k) || !isNameChar(rest[len(k)])) {
				return k
			}
		}
	}
	return ""
}

func isNameChar(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// readOnlyMutates reports whether command, with its -e values filled in,
// is anything but a read komando knows.
func readOnlyMutates(command string, env []string) bool {
	filled, bad := readOnlyFill(command, env)
	return bad != "" || readOnlyViolation(filled) != ""
}

func readOnlyStop(cl *call, what string) error {
	return cl.policyStop(out.Errf(out.ExitPolicy, "READ_ONLY_VIOLATION", "--read-only runs only what komando knows only reads: for a server's state use komando facts, logs, svc status or fs read; otherwise tell the user what the command does, then run it without --read-only (a protected server also needs --yes)",
		"--read-only, but the command is not known to only read (%s)", what))
}
