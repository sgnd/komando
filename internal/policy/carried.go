package policy

import (
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Rules for what komando's own commands once guarded, so the same words
// typed through exec stop the same way: deleting files, docker's deletes
// and host escapes, removing a package the server needs, scaling to zero
// and dropping a database user. What those commands only asked a person to
// type (pkg rm of other packages, cron rm) is not carried: it stopped no
// agent.

var carriedRules = []struct {
	id, reason string
	fn         func(simpleCommand) bool
}{
	{"rm-files", "deletes files", deletesFiles},
	{"docker-rm", "deletes docker containers, images, volumes or services", func(c simpleCommand) bool { return dockerRating(c) == "rm" }},
	{"docker-prune", "deletes unused docker containers, images, networks or build cache", func(c simpleCommand) bool { return dockerRating(c) == "prune" }},
	{"docker-kill", "stops containers or services, or changes the swarm (kill, scale to 0, swarm, node)", func(c simpleCommand) bool { return dockerRating(c) == "kill" }},
	{"docker-host", "gives a container the server (privileged, host namespaces, system folders, plugins)", func(c simpleCommand) bool { return dockerRating(c) == "host" }},
	{"pkg-remove-essential", "removes a package the server needs (ssh, sudo, systemd, libc ...), which can lock you out or break it", removesEssential},
	{"container-shell", "opens a shell, interpreter or database client in a container, or feeds one input (what it runs cannot be checked)", containerShell},
	{"kubectl-scale-zero", "scales a kubernetes workload to zero (an outage)", kubectlScalesToZero},
}

// dbDropUser is SQL or mongo text, which sits inside a quoted argument.
const dbDropUser = `(?i)\bdrop\s+(user|role|login)\b|\bdropuser\b|\bdropAllUsersFromDatabase\b`

// carried are the rules above as Rules. policy.go's init adds them after
// the built-in rules, so a built-in rule names a command first.
func carried() []Rule {
	rules := make([]Rule, 0, len(carriedRules)+1)
	for _, r := range carriedRules {
		rules = append(rules, Rule{ID: r.id, Reason: r.reason, argv: r.fn, carried: true})
	}
	return append(rules, Rule{ID: "db-drop-user", Reason: "deletes a database user or role", re: regexp.MustCompile(dbDropUser), carried: true})
}

// operands are the words of args that are not options.
func operands(args []string) []string {
	var out []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || a == "-" {
			out = append(out, a)
		}
	}
	return out
}

// deletesFiles: rm, unlink, rmdir, shred -u, find -delete or -exec rm,
// and PowerShell's and cmd's deletes. fs rm stopped on every path it
// deleted, a file or a folder (internal/cli/guard_delete.go guardFsRm).
func deletesFiles(c simpleCommand) bool {
	args := c.args[1:]
	switch c.name() {
	case "rm", "unlink", "rmdir", "rd":
		return len(operands(args)) > 0
	case "remove-item", "ri", "del", "erase":
		return true // PowerShell also deletes what a pipe hands it
	case "shred":
		return slices.ContainsFunc(args, func(a string) bool {
			return a == "--remove" || strings.HasPrefix(a, "--remove=") || len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a, 'u')
		})
	case "find":
		for i, a := range args {
			if a == "-delete" {
				return true
			}
			if (a == "-exec" || a == "-execdir" || a == "-ok" || a == "-okdir") && i+1 < len(args) {
				if inner, _ := unwrap(args[i+1:]); len(inner) > 0 && deletesFiles(simpleCommand{args: inner}) {
					return true
				}
			}
		}
	}
	return false
}

// hasOption: one of names is among args, alone or with =value.
func hasOption(args []string, names ...string) bool {
	return slices.ContainsFunc(args, func(a string) bool {
		k, _, _ := strings.Cut(a, "=")
		return slices.Contains(names, k)
	})
}

func countAboveZero(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0
}

// optionValue is the value of --name=VALUE or --name VALUE.
func optionValue(args []string, name string) (string, bool) {
	for i, a := range args {
		if v, ok := strings.CutPrefix(a, name+"="); ok {
			return v, true
		}
		if a == name && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// removedPackages are the package names a command removes by name, as
// pkg rm did (apt-get remove, dnf remove, apk del, zypper remove, pacman
// -R), also through the managers' other spellings of it. ok is false for
// any other command.
func removedPackages(c simpleCommand) (names []string, ok bool) {
	args := withoutValues(c.args[1:], "-o", "-c", "-t", "--option", "--config-file", "--target-release", "-X", "--repo", "--enablerepo", "--disablerepo")
	verb := ""
	if ops := operands(args); len(ops) > 0 {
		verb = strings.ToLower(ops[0])
	}
	after := func() []string { // the operands after the verb
		ops := operands(args)
		return ops[min(1, len(ops)):]
	}
	switch c.name() {
	case "apt", "apt-get", "aptitude":
		switch verb {
		case "remove", "purge":
			return after(), true
		case "install", "reinstall":
			for _, p := range after() {
				if strings.HasSuffix(p, "-") { // apt removes a package named with a trailing -
					names = append(names, strings.TrimSuffix(p, "-"))
				}
			}
			return names, len(names) > 0
		}
	case "dnf", "yum", "microdnf", "tdnf":
		if slices.Contains([]string{"remove", "erase", "rm"}, verb) {
			return after(), true
		}
	case "apk":
		if verb == "del" {
			return after(), true
		}
	case "zypper":
		if slices.Contains([]string{"remove", "rm"}, verb) {
			return after(), true
		}
	case "dpkg":
		if hasOption(args, "-r", "--remove", "-P", "--purge") {
			return operands(args), true
		}
	case "rpm":
		if hasOption(args, "--erase") || slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "-e") && !strings.HasPrefix(a, "--") }) {
			return operands(args), true
		}
	case "pacman":
		if hasOption(args, "--remove") || slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "-R") }) {
			return operands(args), true
		}
	}
	return nil, false
}

// withoutValues drops the options named and the word after each (apt-get
// -o Dpkg::Options=x remove ...), so the verb is the first operand.
func withoutValues(args []string, names ...string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		if slices.Contains(names, args[i]) {
			i++
			continue
		}
		out = append(out, args[i])
	}
	return out
}

func removesEssential(c simpleCommand) bool {
	names, _ := removedPackages(c)
	return slices.ContainsFunc(names, EssentialPackage)
}

// containerShell: a command in a container that reads its commands from a
// person or from its input, so komando cannot see them. docker raw exec
// and cluster raw exec counted every exec as destructive; a command given
// whole (sh -c '...', psql -c '...', ls) is checked like any other.
func containerShell(c simpleCommand) bool {
	return c.container && (c.stdin || len(c.upstream) > 0 || readsCommands(c.args))
}

var (
	shellNames       = []string{"sh", "bash", "zsh", "dash", "ash", "ksh", "mksh", "fish", "csh", "tcsh", "rbash", "busybox"}
	interpreterNames = []string{"python", "perl", "ruby", "node", "nodejs", "php", "lua", "irb", "pwsh", "powershell", "deno", "bun"}
)

// readsCommands: a shell, interpreter or database client started without
// the commands it is to run: no -c, -e, --eval or script file.
func readsCommands(args []string) bool {
	name := strings.ToLower(path.Base(args[0]))
	opts, ops := args[1:], operands(args[1:])
	switch base := strings.TrimRight(name, "0123456789."); {
	case slices.Contains(shellNames, name):
		return !slices.ContainsFunc(opts, IsCFlag) && (len(ops) == 0 || slices.Contains(ops, "-"))
	case slices.Contains(interpreterNames, base):
		return !hasOption(opts, "-c", "-e", "-E", "-m", "-r", "-p", "--eval", "--print", "-Command", "-command", "-File", "-file") && (len(ops) == 0 || slices.Contains(ops, "-"))
	case name == "psql":
		return !hasOption(opts, "-c", "--command", "-f", "--file", "-l", "--list", "-V", "--version")
	case name == "mysql" || name == "mariadb":
		return !hasOption(opts, "-e", "--execute", "-V", "--version")
	case name == "mongo" || name == "mongosh":
		return !hasOption(opts, "--eval", "--file", "-f", "--version") && !slices.ContainsFunc(ops, func(o string) bool { return strings.HasSuffix(o, ".js") })
	case name == "redis-cli" || name == "valkey-cli":
		return len(operands(withoutValues(opts, "-h", "-p", "-a", "-n", "-u", "--user", "--pass", "-s"))) == 0
	case name == "sqlite3":
		return len(ops) <= 1
	case name == "clickhouse-client":
		return !hasOption(opts, "-q", "--query", "--queries-file")
	}
	return false
}

// kubectlScalesToZero: kubectl scale with --replicas 0, or a count that
// is not a number above 0.
func kubectlScalesToZero(c simpleCommand) bool {
	if n := c.name(); n != "kubectl" && n != "oc" {
		return false
	}
	v := kubectlVerb(c.args[1:])
	if len(v) == 0 || v[0] != "scale" {
		return false
	}
	n, ok := optionValue(v, "--replicas")
	return ok && !countAboveZero(n)
}

// essentialPkgs are packages whose removal can lock you out of a server
// or break it.
var essentialPkgs = regexp.MustCompile(`^(openssh-server|openssh|ssh|sudo|systemd|systemd-sysv|init|libc6|glibc|libc|musl|bash|coreutils|util-linux|apt|dpkg|rpm|dnf|yum|apk-tools|busybox|base-files|login|passwd|linux-image.*|kernel.*|linux)$`)

// essentialSamples are names essentialPkgs matches, one per entry, for
// testing a name that a package manager reads as a pattern.
var essentialSamples = strings.Fields(`openssh-server openssh ssh sudo systemd systemd-sysv init libc6 glibc libc musl bash
coreutils util-linux apt dpkg rpm dnf yum apk-tools busybox base-files login passwd linux-image-generic kernel-core linux`)

// pkgVersionRe is the -1.2.3 that dnf and yum allow after a name.
var pkgVersionRe = regexp.MustCompile(`-[0-9].*$`)

// pkgArchRe is the .x86_64 that dnf, yum and zypper allow after a name.
var pkgArchRe = regexp.MustCompile(`\.(x86_64|i386|i586|i686|aarch64|armv7hl|armhfp|ppc64le|ppc64|s390x|noarch|src|amd64|arm64)$`)

// EssentialPackage reports whether name, written any way a package manager
// takes it (OpenSSH-Server, openssh-server:amd64, sudo=1.9.15,
// systemd/bookworm, openssh-server-8.0p1, sudo.x86_64), is an essential
// package. A name with a dot, * ? or [ is a pattern to apt, dnf or yum
// ("openssh.server", "ssh*"): it counts when it would pick one.
func EssentialPackage(name string) bool {
	n := strings.ToLower(name)
	if i := strings.IndexAny(n, ":=/@"); i >= 0 {
		n = n[:i]
	}
	noArch := pkgArchRe.ReplaceAllString(n, "")
	for _, c := range []string{n, noArch, pkgVersionRe.ReplaceAllString(n, ""), pkgVersionRe.ReplaceAllString(noArch, ""),
		pkgArchRe.ReplaceAllString(pkgVersionRe.ReplaceAllString(n, ""), "")} {
		if essentialPkgs.MatchString(c) {
			return true
		}
	}
	if !strings.ContainsAny(n, ".*?[") {
		return false
	}
	pat := regexp.QuoteMeta(n)
	pat = strings.NewReplacer(`\.`, ".", `\*`, ".*", `\?`, ".", `\[`, "[", `\]`, "]").Replace(pat)
	re, err := regexp.Compile(pat)
	if err != nil {
		return true // a pattern komando cannot read may pick anything
	}
	return slices.ContainsFunc(essentialSamples, re.MatchString)
}
