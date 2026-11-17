package cli

import (
	"maps"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/driver"
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
	"psql": psqlWrite, "mysql": mysqlWrite, "mariadb": mysqlWrite,
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
	"RUBYOPT": true, "RUBYLIB": true, "PSQLRC": true, "PSQL_PAGER": true,
	// where programs and files are found, or how words split
	"PATH": true, "IFS": true, "CDPATH": true, "HOME": true, "GLOBIGNORE": true, "SHELL": true,
	"KUBECONFIG": true, "DOCKER_CONFIG": true, "DOCKER_HOST": true, "HISTFILE": true}

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

// mysqlMeta are mysql client commands that run a shell or read and write
// local files: the server's read-only settings do not cover them.
var mysqlMeta = regexp.MustCompile(`(?im)\\[!.TPe]|(^|;)\s*(system|tee|pager|source|edit)\b`)

// psql's backslash commands run a shell (\!), read and write files (\o,
// \i, \copy, \lo_export), set variables (\set) and run query results as
// SQL (\gexec), and new ones keep coming. Only the ones that describe or
// list (\d and its family, \l, \z, \sf, \sv), \conninfo, \x, \timing,
// \echo and \q pass; psqlBackslash finds every other use of a backslash.
var (
	psqlBackslash = regexp.MustCompile(`\\(.?[A-Za-z_]*)`)
	psqlReadMeta  = regexp.MustCompile(`^(d[A-Za-z]*|l|z|sf|sv|conninfo|x|timing|echo|q)$`)
	// psqlVar is :name, :'name' or :"name", which psql replaces with a
	// variable's text before the server sees the SQL (not ::cast, not 12:30)
	psqlVar = regexp.MustCompile(`(^|[^:A-Za-z0-9_])[:]['"]?[A-Za-z_]`)
)

// psqlMetaWrite returns the backslash command in text that is not one of
// the read ones, or "".
func psqlMetaWrite(text string) string {
	for _, m := range psqlBackslash.FindAllStringSubmatch(text, -1) {
		if !psqlReadMeta.MatchString(m[1]) {
			return m[0]
		}
	}
	return ""
}

// psqlWrite: psql -c is SQL, which must only read (sqlWrite), and a \! or
// \o in it runs a shell or writes a file here; a file (-f) or commands from
// a pipe are not seen at all.
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
		if m := psqlMetaWrite(val); m != "" {
			return cmd + " " + m + ` (only the \d describe commands, \l, \x and \timing are known to read)`
		}
		if w := sqlWrite(val, false); w != "" {
			return cmd + " -c " + w
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
		if w := sqlWrite(val, true); w != "" {
			return cmd + " -e " + w
		}
	}
	if !inline && input {
		return cmd + " reading commands from a pipe or a file"
	}
	return ""
}

// sqlWrite returns what in sql may write, or "". psql and mysql are not
// in a read-only transaction the way `db query` is, so only statements
// that driver.ClassifySQL rates as reads pass: an unknown statement, a
// transaction command or SQL it cannot read breaks the promise. psql meta
// commands (\dt) are left to psqlMetaWrite.
func sqlWrite(sql string, mysql bool) string {
	kind := "postgres"
	if mysql {
		kind = "mysql"
	}
	var lines []string
	for _, l := range strings.Split(sql, "\n") {
		if mysql || !strings.HasPrefix(strings.TrimSpace(l), `\`) {
			lines = append(lines, l)
		}
	}
	if sql = strings.Join(lines, "\n"); strings.TrimSpace(sql) == "" {
		return ""
	}
	plan, err := driver.ClassifySQL(kind, sql)
	if err != nil {
		return "SQL komando cannot check (" + strings.SplitN(err.Error(), "\n", 2)[0] + ")"
	}
	for _, st := range plan.Statements {
		if st.Risk != driver.RiskRead || st.Unknown {
			if len(plan.Reasons) > 0 {
				return "SQL that " + plan.Reasons[0] + " (" + st.Keyword + ")"
			}
			return "SQL that may write (" + st.Keyword + ")"
		}
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
	psql := strings.Contains(command, "psql")
	if psql {
		if m := psqlMetaWrite(string(stdin)); m != "" {
			return "the input has " + m + ` (only the \d describe commands, \l, \x and \timing are known to read)`
		}
		if psqlVar.Match(stdin) {
			return "the input uses a psql variable (:name), which may hold SQL komando cannot see"
		}
	} else if mysqlMeta.Match(stdin) {
		return `the input runs a shell or writes files (\!, system, tee, source ...)`
	}
	if w := sqlWrite(string(stdin), !psql); w != "" {
		return "the input is " + w
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
