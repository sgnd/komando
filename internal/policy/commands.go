package policy

import (
	"path"
	"slices"
	"strings"
)

// simpleCommand is one command of a shell line as it runs: the program
// and its arguments with wrappers taken off (sudo, env, xargs, docker
// exec ...), where it runs, and what is piped into it.
type simpleCommand struct {
	args     []string
	at       folder
	upstream [][]string // the commands piped into this one, in order
}

// folder is where a command runs: the folder the cds before it on the
// line moved to ("" is the login folder), and whether komando can tell.
type folder struct {
	dir   string
	known bool
}

// cd is the folder after `cd ARGS` from f.
func (f folder) cd(args []string) folder {
	ops := operands(args)
	switch {
	case len(ops) == 0:
		return folder{known: f.known}
	case len(ops) > 1 || ops[0] == "-" || strings.ContainsAny(ops[0], "$~`*?["):
		return folder{}
	case path.IsAbs(ops[0]) || f.dir == "":
		return folder{dir: path.Clean(ops[0]), known: f.known}
	}
	return folder{dir: path.Join(f.dir, ops[0]), known: f.known}
}

// name is the program's base name in lower case (/bin/rm and RM are rm).
func (c simpleCommand) name() string { return strings.ToLower(path.Base(c.args[0])) }

// simpleCommands reads every command of cmd: those in command
// substitutions, and the text a line hands a shell (sh -c '...', eval,
// echo ... | sh), read the same way.
func simpleCommands(cmd string) []simpleCommand {
	at := folder{known: !strings.Contains(cmd, "COMPOSE_")} // compose settings in the environment move its files
	return commandsIn(cmd, 0, &at)
}

func commandsIn(cmd string, depth int, at *folder) []simpleCommand {
	var out []simpleCommand
	for _, line := range Tokens(cmd) {
		var cur simpleCommand
		var pipe [][]string // the commands of the pipeline so far
		flush := func() {
			args := unwrap(cur.args)
			switch {
			case len(args) == 0:
			case strings.EqualFold(path.Base(args[0]), "cd") || strings.EqualFold(path.Base(args[0]), "pushd"):
				*at = at.cd(args[1:])
			default:
				out = append(out, simpleCommand{args: args, at: *at, upstream: slices.Clone(pipe)})
			}
			pipe = append(pipe, args)
			cur = simpleCommand{}
		}
		for i := 0; i < len(line); i++ {
			t := line[i]
			switch {
			case !t.Op:
				cur.args = append(cur.args, t.Text)
			case isRedirect(t.Text):
				i++ // a redirect's file is not an argument
			default:
				flush()
				if t.Text != "|" {
					pipe = nil
				}
				if t.Text == "(" || t.Text == ")" {
					at.known = false // a cd in a subshell ends with it
				}
			}
		}
		flush()
		if depth < 8 {
			for _, s := range scripts(line) {
				out = append(out, commandsIn(s, depth+1, at)...)
			}
		}
	}
	return out
}

func isRedirect(op string) bool {
	return op[0] == '>' || op[0] == '<' || len(op) > 1 && op[0] == '&' && op[1] == '>'
}

// wrapper says how a program that runs another one reads its own words:
// options that take a value, and how many plain words come before the
// command (timeout 30 CMD, chroot DIR CMD).
type wrapper struct {
	valued   string // short options with a value, as letters
	long     []string
	operands int
}

var wrappers = map[string]wrapper{
	"sudo":     {valued: "ugpCDhrtUTR", long: []string{"--user", "--group", "--prompt", "--close-from", "--chdir", "--host", "--role", "--type", "--other-user", "--command-timeout", "--chroot"}},
	"doas":     {valued: "uC"},
	"env":      {valued: "uCS", long: []string{"--unset", "--chdir", "--split-string"}},
	"nice":     {valued: "n", long: []string{"--adjustment"}},
	"ionice":   {valued: "cnp", long: []string{"--class", "--classdata", "--pid"}},
	"timeout":  {valued: "sk", long: []string{"--signal", "--kill-after"}, operands: 1},
	"stdbuf":   {valued: "ioe", long: []string{"--input", "--output", "--error"}},
	"xargs":    {valued: "IiEeLlnPsdaR", long: []string{"--arg-file", "--delimiter", "--max-lines", "--max-args", "--max-procs", "--max-chars", "--replace", "--eof", "--process-slot-var"}},
	"chroot":   {long: []string{"--userspec", "--groups"}, operands: 1},
	"flock":    {valued: "wEn", long: []string{"--timeout", "--conflict-exit-code"}, operands: 1},
	"nohup":    {},
	"setsid":   {},
	"time":     {valued: "fo", long: []string{"--format", "--output"}},
	"exec":     {valued: "a"},
	"builtin":  {},
	"unbuffer": {},
	"then":     {}, "do": {}, "else": {}, "elif": {}, "if": {}, "while": {}, "until": {}, "!": {}, "{": {},
}

// xargsInput stands for the words xargs adds from its input.
const xargsInput = "{xargs input}"

// unwrap takes wrappers and variable settings off the front of a command,
// so the words start with the program that really runs. A word it cannot
// place is taken as the program: the rules then see more, not less.
func unwrap(args []string) []string {
	for depth := 0; len(args) > 0 && depth < 16; depth++ {
		for len(args) > 0 && isAssignment(args[0]) {
			args = args[1:]
		}
		if len(args) == 0 {
			return nil
		}
		name := strings.ToLower(path.Base(args[0]))
		switch {
		case name == "command":
			rest := args[1:]
			for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
				if rest[0] == "-v" || rest[0] == "-V" {
					return nil // a lookup: command -v rm runs nothing
				}
				rest = rest[1:]
			}
			args = rest
		case name == "cmd" || name == "cmd.exe":
			args = cmdScript(args[1:])
		case name == "docker" || name == "podman":
			inner, ok := dockerExecCommand(args[1:])
			if !ok {
				return args
			}
			args = inner
		case name == "docker-compose":
			inner, ok := composeExecCommand(args[1:])
			if !ok {
				return args
			}
			args = inner
		case name == "kubectl" || name == "oc":
			inner, ok := kubectlExecCommand(args[1:])
			if !ok {
				return args
			}
			args = inner
		case name == "k3s" || name == "microk8s":
			if len(args) < 2 || !strings.EqualFold(args[1], "kubectl") {
				return args
			}
			args = args[1:]
		default:
			w, ok := wrappers[name]
			if !ok {
				return args
			}
			args = skipOptions(args[1:], w)
			if name == "xargs" && len(args) > 0 {
				args = append(slices.Clip(args), xargsInput) // the words xargs reads are more arguments
			}
		}
	}
	return args
}

// skipOptions drops a wrapper's options and its plain words before the
// command it runs.
func skipOptions(args []string, w wrapper) []string {
	for len(args) > 0 {
		a := args[0]
		switch {
		case a == "--":
			args = args[1:]
			return skipOperands(args, w.operands)
		case strings.HasPrefix(a, "--"):
			args = args[1:]
			for _, l := range w.long {
				if a == l && len(args) > 0 {
					args = args[1:]
				}
			}
		case len(a) > 1 && a[0] == '-':
			args = args[1:]
			// -u root, -Eu root: a valued letter at the end takes the next word
			if strings.ContainsRune(w.valued, rune(a[len(a)-1])) && !gluedValue(a, w.valued) && len(args) > 0 {
				args = args[1:]
			}
		case isAssignment(a):
			args = args[1:] // env NAME=VALUE
		default:
			return skipOperands(args, w.operands)
		}
	}
	return nil
}

// gluedValue: an earlier letter of a short group takes the rest as its
// value (-uroot, -n10), so the last letter is part of that value.
func gluedValue(group, valued string) bool {
	return strings.ContainsAny(group[1:len(group)-1], valued)
}

func skipOperands(args []string, n int) []string {
	if len(args) < n {
		return nil
	}
	return args[n:]
}

func isAssignment(w string) bool {
	k, _, ok := strings.Cut(w, "=")
	if !ok || k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// cmdScript: cmd /c DEL x runs the words after /c (or /k).
func cmdScript(args []string) []string {
	for i, a := range args {
		if strings.EqualFold(a, "/c") || strings.EqualFold(a, "/k") {
			return args[i+1:]
		}
	}
	return nil
}

// dockerExecCommand: docker [container] exec [OPTIONS] CONTAINER CMD, and
// docker compose exec, run the command in a container. ok is false for
// any other docker command.
func dockerExecCommand(args []string) ([]string, bool) {
	v := skipGlobal(args, dockerGlobalValued)
	if len(v) > 0 && v[0] == "container" {
		v = v[1:]
	}
	if len(v) > 0 && v[0] == "compose" {
		return composeExecCommand(v[1:])
	}
	if len(v) == 0 || v[0] != "exec" {
		return nil, false
	}
	return afterTarget(v[1:], "uwe", []string{"--user", "--workdir", "--env", "--env-file", "--detach-keys"}), true
}

func composeExecCommand(args []string) ([]string, bool) {
	s := skipGlobal(args, composeGlobalValued)
	if len(s) == 0 || s[0] != "exec" {
		return nil, false
	}
	return afterTarget(s[1:], "uwe", []string{"--user", "--workdir", "--env", "--index"}), true
}

// afterTarget drops options and the container (or service) name: what is
// left is the command run in it.
func afterTarget(args []string, valued string, long []string) []string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "--"):
			if !strings.Contains(a, "=") && slices.Contains(long, a) {
				i++
			}
		case len(a) > 1 && a[0] == '-':
			if strings.ContainsRune(valued, rune(a[len(a)-1])) && !gluedValue(a, valued) {
				i++
			}
		default:
			return args[i+1:]
		}
	}
	return nil
}

// kubectlExecCommand: kubectl exec ... -- CMD runs CMD in a pod.
func kubectlExecCommand(args []string) ([]string, bool) {
	v := kubectlVerb(args)
	if len(v) == 0 || v[0] != "exec" {
		return nil, false
	}
	for i, a := range v {
		if a == "--" {
			return v[i+1:], true
		}
	}
	return nil, true
}

// kubectlGlobal are kubectl's options that take a value, also before the verb.
var kubectlGlobal = []string{"-n", "--namespace", "--context", "--kubeconfig", "--cluster", "--user", "-s", "--server", "--as", "--token", "-l", "--selector", "-c", "--container"}

// kubectlVerb is kubectl's verb and the words after it.
func kubectlVerb(args []string) []string {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		valued := !strings.Contains(args[0], "=") && slices.Contains(kubectlGlobal, args[0])
		args = args[1:]
		if valued && len(args) > 0 {
			args = args[1:]
		}
	}
	return args
}

// DockerRun is a docker command a shell line runs.
type DockerRun struct {
	Args []string // the words after docker; docker-compose reads as compose
	Dir  string   // the folder a cd before it moved to; "" is the login folder
	// DirKnown is false when komando cannot tell the folder or the compose
	// files: a cd to a variable or ~user, a subshell, COMPOSE_ settings
	DirKnown bool
}

// DockerRuns are the docker commands in cmd, with the folder each runs
// in, so the compose files they start containers from can be read.
func DockerRuns(cmd string) []DockerRun {
	var runs []DockerRun
	for _, c := range simpleCommands(cmd) {
		switch c.name() {
		case "docker", "podman":
			runs = append(runs, DockerRun{Args: c.args[1:], Dir: c.at.dir, DirKnown: c.at.known})
		case "docker-compose":
			runs = append(runs, DockerRun{Args: append([]string{"compose"}, c.args[1:]...), Dir: c.at.dir, DirKnown: c.at.known})
		}
	}
	return runs
}
