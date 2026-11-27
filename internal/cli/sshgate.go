package cli

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/version"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `komando ssh-gate` is a forced command for ~/.ssh/authorized_keys:
//
//	restrict,command="/usr/local/bin/komando ssh-gate --name phone" ssh-ed25519 AAAA... phone
//
// sshd then runs it whatever the key's owner asks for, with what they asked
// for in SSH_ORIGINAL_COMMAND. The gate runs that only when it is one
// komando command: it splits it into words as a shell would, but expands
// nothing and runs no shell, so `;`, `|`, `$(...)` and the like cannot add
// a second program. komando then runs as an AI agent does (secret values
// hidden, no flag that skips a safety stop counts without a person), and
// the gate writes every command it runs or refuses to the audit log, with
// the key's name. No key writes on this computer itself (gateHere), nor
// runs anything, a read either, on a target that is it (gateLocalTarget).
// With --read-only it runs only commands komando treats as reads, and of
// those only the ones that stay on the targets in the inventory, unless the
// line also has --network (sshgate_network.go).
// `restrict` turns off port, agent and X11 forwarding and the terminal, so
// the key opens nothing else (OpenSSH 7.2 and later). A line with --shell-access
// gives back the terminal (pty), for `komando host ssh shell SERVER` (sshgate_shell.go).

// gateEnv names the key (its --name) in the environment of the komando the
// gate runs: that komando counts as an agent (agentVars) and its audit
// records name the key.
const gateEnv = engine.GateEnv

// gateLabel is what --name may be: it goes into authorized_keys, a shell
// command line and the audit log as it is.
var gateLabel = engine.GateLabel

// gateExec replaces this process with the command; tests swap it.
var gateExec = syscall.Exec

// A --read-only key runs what komando treats as a read (kinds.go): a
// command of kind read, and one of kind depends only in its read form
// (gateReadForm). A change, or a command added later without a kind, is
// refused; a change that hands out access says so (gateNotForReadKey).

// gateReadForm: these read only with a flag (--read-only), or without one
// (--write, --analyze, --apply, --refresh). Why the command as given may
// change something, or "". The checks read flag values, which an old
// spelling of a flag shares (flag_alias.go), so every spelling counts.
var gateReadForm = map[safetyKey]func(c *cobra.Command) string{
	{"host", "", "exec"}:              needFlag("read-only"),
	{"host", "job", "start"}:          needFlag("read-only"),
	{"host", "docker", "exec"}:        needFlag("read-only"),
	{"cluster", "", "exec"}:           needFlag("read-only"),
	{"database", "", "query"}:         noFlag("write"),
	{"cache", "", "raw"}:              noFlag("write"),
	{"cluster", "", "raw"}:            noFlag("write"),
	{"database", "", "explain"}:       noFlag("write", "analyze"), // --analyze runs the statement
	{"host", "package", "upgradable"}: noFlag("refresh"),          // refreshes the package index
	{"host", "package", "security"}:   noFlag("refresh"),
	{"snippet", "", "exec"}:           gateRecipeWrites,
	{"", "", "copy"}:                  gateCopyWrites,
}

// gateCopyWrites: copy reads only when it streams a file to the key's own
// output (DESTINATION -, no --sync); every other copy writes at its
// destination.
func gateCopyWrites(c *cobra.Command) string {
	args := c.Flags().Args()
	if len(args) == 2 && args[1] == "-" && !copySync(c) {
		return ""
	}
	return "it writes the files at its destination (copy SOURCE - streams one file to the key's own output)"
}

// gateNotForReadKey are commands a read-only key does not run, with a
// better reason than "it changes something": they hand out access, so they
// are of kind change (OD-13), and full keys run them (gateOnServers).
var gateNotForReadKey = map[safetyKey]string{
	{"storage", "object", "link"}:  "it makes a link that opens the data without a login",
	{"cluster", "tunnel", "start"}: "it opens a port on the komando computer",
}

// No gate key, read-only or not, writes on the komando computer itself: a
// file it saves there could be ~/.ssh/authorized_keys or a shell startup
// file, and komando's own setup (inventory, VPN configs, settings, rules,
// vault, keys, recipes, skills, komando itself) decides what komando runs
// there next. Either way the key would get a shell here.
//
// For changes the rule fails closed: a command of kind change or depends
// runs only when gateOnServers names it, so one added later is refused until
// someone decides it acts on servers only. Reads change nothing here
// (kinds.go), except those that save a file you ask for: gateSavesHere.

// gateOnServers are the changes a key may run: they act on servers,
// databases, caches, storage and clusters, or connect a VPN komando already
// knows. A func says why the command as given writes here, or "".
var gateOnServers = map[safetyKey]func(c *cobra.Command) string{
	{"host", "", "exec"}: nil, {"snippet", "", "exec"}: nil,
	{"", "", "copy"}:         gateLocalDst,
	{"host", "job", "start"}: nil, {"host", "job", "kill"}: nil, {"host", "job", "rm"}: nil,
	{"host", "file", "chmod"}: nil, {"host", "file", "mkdir"}: nil, {"host", "file", "mv"}: nil, {"host", "file", "replace"}: nil, {"host", "file", "restore"}: nil, {"host", "file", "rm"}: nil, {"host", "file", "write"}: nil,
	{"host", "package", "install"}: nil, {"host", "package", "rm"}: nil, {"host", "package", "security"}: nil, {"host", "package", "update"}: nil, {"host", "package", "upgradable"}: nil, {"host", "package", "upgrade"}: nil,
	{"credential", "key", "install"}: gateSetDefault, {"credential", "key", "uninstall"}: nil,
	{"database", "", "explain"}: nil, {"database", "", "grant"}: nil, {"database", "", "kill"}: nil, {"database", "", "query"}: nil, {"database", "", "restore"}: nil, {"database", "", "revoke"}: nil,
	{"database", "user", "add"}: nil, {"database", "user", "passwd"}: nil, {"database", "user", "rm"}: nil,
	{"cache", "", "rm"}: nil, {"cache", "", "raw"}: nil, {"cache", "", "set"}: nil, {"storage", "object", "create"}: nil, {"storage", "object", "move"}: nil, {"storage", "object", "delete"}: nil,
	{"registry", "image", "copy"}: nil, {"registry", "image", "prune"}: nil, {"registry", "image", "delete"}: nil,
	{"host", "docker", "compose"}: nil, {"host", "docker", "exec"}: nil, {"host", "docker", "prune"}: nil, {"host", "docker", "pull"}: nil, {"host", "docker", "raw"}: nil,
	{"host", "docker", "restart"}: nil, {"host", "docker", "rm"}: nil, {"host", "docker", "start"}: nil, {"host", "docker", "stop"}: nil,
	{"cluster", "", "apply"}: nil, {"cluster", "", "deploy"}: nil, {"cluster", "", "exec"}: nil, {"cluster", "", "restart"}: nil,
	{"cluster", "", "rm"}: nil, {"cluster", "", "rollback"}: nil, {"cluster", "", "raw"}: gateKubectlCp, {"cluster", "", "scale"}: nil,
	{"cluster", "tunnel", "start"}: nil, {"storage", "object", "link"}: nil, // hand out access; as before OD-13 made them changes
	{"vpn", "", "start"}: nil, {"vpn", "", "stop"}: nil,
}

// gateSavesHere are reads that save a file on this computer, and when.
var gateSavesHere = map[safetyKey]func(c *cobra.Command) string{
	{"database", "", "backup"}: func(*cobra.Command) string { return "it saves a file on this computer" },
	{"", "", "export"}: func(c *cobra.Command) string {
		if to, _ := c.Flags().GetString("to"); to != "" {
			return "--to saves a file on this computer (without it, export prints)"
		}
		return ""
	},
}

// gateLocalDst: copy writes here when DESTINATION is not TARGET:PATH. It
// reads the arguments with the same splitArg the command uses.
func gateLocalDst(c *cobra.Command) string {
	cl := callOf(c)
	args := c.Flags().Args()
	if len(args) != 2 {
		return "" // a usage error: nothing runs
	}
	if args[1] == "-" && !copySync(c) {
		// the stream to the key's own output (with --sync, - is a folder
		// here); only from a server or storage: a file here is never sent
		if _, _, remote := splitArg(cl, args[0]); !remote {
			return "its SOURCE " + args[0] + " is on this computer; a key streams from servers or storage only"
		}
		return ""
	}
	if _, _, remote := splitArg(cl, args[1]); !remote {
		return "its DESTINATION is on this computer; a key copies to servers or storage only"
	}
	return ""
}

// gateSetDefault: key deploy --set-default changes komando's own setup,
// and --public-key-file lets another device in (a person's step, C372).
func gateSetDefault(c *cobra.Command) string {
	if on, _ := c.Flags().GetBool("set-default"); on {
		return "--set-default changes which key komando uses for those servers; deploy without it and set the key here"
	}
	if f := c.Flags().Lookup("public-key-file"); f != nil && f.Changed {
		return "--public-key-file lets a device log in to a server, which only a person at a terminal does"
	}
	return ""
}

// gateKubectlCp: kubectl cp saves files here whenever its SRC is POD:PATH,
// whatever DST looks like (kctl's cp reads them so: x:/../y is a local
// path to it). docker cp on a Swarm manager writes there.
func gateKubectlCp(c *cobra.Command) string {
	cl := callOf(c)
	args := c.Flags().Args()
	if len(args) < 2 {
		return ""
	}
	a, err := parseKargs(args[1:])
	if err != nil || a.verb != "cp" || len(a.pos) != 2 {
		return "" // not cp, or a usage error: nothing is saved here
	}
	if src := a.pos[0]; strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || !strings.Contains(src, ":") {
		return "" // SRC is here: it copies to the pod
	}
	if st, err := store.Load(); err == nil {
		if t, err := resolveCluster(cl, st, args[0]); err == nil && t.host != nil {
			return ""
		}
	}
	return "kubectl cp from a POD:PATH saves files on this computer"
}

// gateHere says why c writes on this computer, or "".
func gateHere(c *cobra.Command, name string) string {
	if f := gateSavesHere[cmdKeys[name]]; f != nil {
		return f(c)
	}
	if top, _, _ := strings.Cut(name, "."); c == c.Root() || top == "help" || top == "completion" {
		return "" // first steps, help and shell completion scripts: printed
	}
	k, ok := kindOf(c)
	if ok && k.Kind == kindRead {
		return ""
	}
	f, on := gateOnServers[cmdKeys[name]]
	switch {
	case !on:
		return "it changes komando's own setup on this computer (servers, VPNs, settings, rules, secrets, keys, recipes or komando itself)"
	case f != nil:
		return f(c)
	}
	return ""
}

func needFlag(name string) func(c *cobra.Command) string {
	return func(c *cobra.Command) string {
		if on, _ := c.Flags().GetBool(name); !on {
			return "without --" + name + " it can change something"
		}
		return ""
	}
}

func noFlag(names ...string) func(c *cobra.Command) string {
	return func(c *cobra.Command) string {
		for _, n := range names {
			if on, _ := c.Flags().GetBool(n); on {
				return "with --" + n + " it can change something"
			}
		}
		return ""
	}
}

// gateNeedsPerson are commands for a person at a terminal on this computer
// (a shell, a login, the vault's passphrase): a key never runs them.
var gateNeedsPerson = map[safetyKey]bool{
	{"host", "", "shell"}: true, {"database", "", "shell"}: true, {"cluster", "", "shell"}: true, {"login", "", "aws"}: true,
	{"config", "", "approval-code"}: true, {"config", "vault", "passphrase"}: true, {"credential", "", "check"}: true,
	{"", "", "ssh-gate"}: true, {"ssh-gate", "", "line"}: true,
}

// gateRequest is what the key asked for.
type gateRequest struct {
	raw   string   // SSH_ORIGINAL_COMMAND
	agent string   // KOMANDO_AGENT=NAME before komando: what the client calls itself
	args  []string // after "komando"
}

// parseGate reads SSH_ORIGINAL_COMMAND into the komando command it asks for.
func parseGate(raw string) (gateRequest, *out.Error) {
	req := gateRequest{raw: raw}
	if strings.TrimSpace(raw) == "" {
		return req, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "this key runs komando commands only, for example: ssh HOST komando list",
			"no command: this key opens no shell")
	}
	words, err := gateWords(raw)
	if err != nil {
		return req, out.Errf(out.ExitUsage, "SSH_GATE_SYNTAX", "send one komando command; put an argument with ; | & $ or backquotes in single quotes ($ and backquotes are refused even in double quotes)", "%v", err)
	}
	if len(words) > 0 && assignWord.MatchString(words[0]) {
		name, val, _ := strings.Cut(words[0], "=")
		if name != "KOMANDO_AGENT" {
			return req, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "only KOMANDO_AGENT=NAME may come before komando",
				"%s=... is not allowed: the key cannot set komando's environment", name)
		}
		req.agent, words = val, words[1:]
	}
	if len(words) == 0 || words[0] != "komando" {
		first := ""
		if len(words) > 0 {
			first = words[0]
		}
		return req, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "this key runs komando commands only, for example: ssh HOST komando list",
			"%q is not komando: this key runs komando and nothing else", first)
	}
	req.args = words[1:]
	return req, nil
}

var assignWord = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// gateWords splits s into words by the rules of a POSIX shell for quotes
// and backslashes, and refuses what a shell would give a meaning: command
// separators, pipes, redirects, subshells, $ and ` (expansions, also inside
// double quotes), a comment and an unquoted line break. Nothing is
// expanded: a glob or ~ stays as it is, as a shell keeps one that matches
// nothing.
func gateWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, errors.New("a ' is not closed")
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
			inWord = true
		case c == '"':
			inWord = true
			closed := false
			for i++; i < len(s); i++ {
				d := s[i]
				if d == '"' {
					closed = true
					break
				}
				switch {
				case d == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0:
					if s[i+1] != '\n' {
						cur.WriteByte(s[i+1])
					}
					i++
				case d == '$' || d == '`':
					return nil, fmt.Errorf("%q inside double quotes is expanded by a shell, and ssh-gate expands nothing: put that argument in single quotes", d)
				default:
					cur.WriteByte(d)
				}
			}
			if !closed {
				return nil, errors.New(`a " is not closed`)
			}
		case c == '\\':
			if i+1 >= len(s) {
				return nil, errors.New("the command ends with a \\")
			}
			i++
			if s[i] != '\n' { // a backslash and a line break continue the line
				cur.WriteByte(s[i])
				inWord = true
			}
		case c == '#' && !inWord:
			return nil, errors.New("a # starts a comment in a shell; quote it when it is part of an argument")
		case strings.IndexByte(";&|<>()$`\n\r", c) >= 0:
			return nil, fmt.Errorf("%q means something to a shell, and ssh-gate runs no shell, only one komando command; quote it when it is part of an argument", c)
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

// gateCheck says whether the key may run args: nil, or the stop, with the
// command's name and the -o it asked for. It finds the command and reads
// its flags as komando will, so `--reveal` after `--` (an argument for the
// server) is not mistaken for komando's.
func gateCheck(args []string, key gateKey) (name, output string, refused *out.Error) {
	sc, root := gateTree()
	return gateCheckIn(sc, root, args, key)
}

// gateTree is a command tree of its own, with its call: the key's flags
// are read here, apart from the gate's. A test that asks the gate many
// lines builds it once and gives it to gateCheckIn, which prepares the
// command of each line.
func gateTree() (*call, *cobra.Command) {
	sc := treeCall()
	root := newRootFor(sc, nil)
	// cobra adds its completion helper only as it runs, and finds it the
	// way Find does here (after `-o --`, the -- is -o's value and the next
	// word is the command): with the helper in this tree too, the gate
	// sees what komando would run
	root.AddCommand(&cobra.Command{Use: cobra.ShellCompRequestCmd, Aliases: []string{cobra.ShellCompNoDescRequestCmd},
		DisableFlagParsing: true, Run: func(*cobra.Command, []string) {}})
	return sc, root
}

// gateCheckIn is gateCheck on the tree gateTree made.
func gateCheckIn(sc *call, root *cobra.Command, args []string, key gateKey) (name, output string, refused *out.Error) {
	openPath(root, args) // a path opened for a line before stays open
	c, rest, err := root.Find(args)
	if err != nil {
		return "", "", gateUnknownLine(args)
	}
	if c.Name() == cobra.ShellCompRequestCmd {
		return c.Name(), "", out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "run it on the komando computer itself",
			"komando %s is the shell's completion helper, not for a key", c.Name())
	}
	name = commandName(c)
	if key.shellAccess && isHostShell(name) {
		return name, "", gateShell(c, args, key)
	}
	c.InitDefaultHelpFlag()
	if err := c.ParseFlags(rest); err != nil {
		return name, "", nil // the same: a usage error, nothing runs
	}
	output = sc.flags.output
	name, refused = gateRule(c, name, key)
	return name, output, refused
}

// gateRule is gateCheck's answer for the command c, its flags read.
func gateRule(c *cobra.Command, name string, key gateKey) (string, *out.Error) {
	cl := callOf(c)
	if help, _ := c.Flags().GetBool("help"); help && !gateNeedsPerson[cmdKeys[name]] {
		return name, nil // it only prints the command's help
	}
	for p := c; p != nil; p = p.Parent() {
		// a synonym (cluster info) carries the ID of the command it names and
		// gets that command's answer below; other hidden commands are plumbing
		if p.Hidden && p.Annotations[synonymNote] == "" {
			return name, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "run it on the komando computer itself",
				"komando %s is komando's own plumbing, not for a key", strings.ReplaceAll(name, ".", " "))
		}
	}
	// what the key typed, from its parsed command line: this command is
	// checked here, never run, so no begin stored a gate for it
	typed := newGate(c, cl.caller(), nil)
	switch {
	case gateNeedsPerson[cmdKeys[name]]:
		return name, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person runs it in a terminal on the komando computer itself",
			"komando %s needs a person at a terminal on this computer; a key cannot run it", strings.ReplaceAll(name, ".", " "))
	case typed.reveal:
		return name, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "secret values stay [hidden] for a key; a person reads one in a terminal on the komando computer",
			"--reveal is refused: a key never gets secret values")
	case typed.allowDangerous:
		return name, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person runs it in a terminal on the komando computer itself",
			"--allow-dangerous is refused: a key cannot skip the dangerous-command stop")
	}
	if !c.Runnable() || c.Annotations[groupOnly] == "true" {
		if len(c.Flags().Args()) > 0 {
			return name, gateUnknownLine(append(strings.Fields(strings.ReplaceAll(name, ".", " ")), c.Flags().Args()...))
		}
		return name, nil // a group only prints its help
	}
	if key.here {
		return name, gateServerRule(c, name, key) // on the server itself (sshgate_network.go)
	}
	here := func(why string) (string, *out.Error) {
		return name, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person runs it in a terminal on the komando computer itself",
			"komando %s is refused for a key: %s; the gate runs commands on servers, not on this computer", strings.ReplaceAll(name, ".", " "), why)
	}
	if why := gateHere(c, name); why != "" {
		return here(why)
	}
	if why := gateWrites(c, name); key.readOnly && why != "" {
		return name, out.Errf(out.ExitPolicy, "SSH_GATE_READ_ONLY", "this key was added with --read-only and runs only commands that read; use a key that may change things, or the komando computer itself",
			"komando %s is refused for a read-only key: %s", strings.ReplaceAll(name, ".", " "), why)
	}
	if why := gateLocalRead(c, name); why != "" {
		return name, gateLocalReadErr(name, why)
	}
	if why := gateLocalTarget(c, name); why != "" {
		return here(why)
	}
	if why := gateEgress(c, name); key.readOnly && !key.network && why != "" {
		return name, out.Errf(out.ExitPolicy, "SSH_GATE_NETWORK_REQUIRED", "this key was added with --read-only and without --network: it runs only reads that stay on the servers and conns in your list; a person adds a key for this with `komando ssh-gate line --read-only --network`, or runs it on the komando computer",
			"komando %s is refused for a read key without network: %s", strings.ReplaceAll(name, ".", " "), why)
	}
	return name, nil
}

// gateUnknownLine refuses a line that names no command, as for a person:
// komando would run nothing, and an old path must not pass as harmless.
func gateUnknownLine(words []string) *out.Error {
	return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person runs it in a terminal on the komando computer itself",
		"komando %s names no command; a key runs only commands komando knows", strings.Join(words, " "))
}

// gateWrites says why a read-only key may not run c, or "".
func gateWrites(c *cobra.Command, name string) string {
	top, _, _ := strings.Cut(name, ".")
	if c == c.Root() || top == "help" || top == "completion" {
		return "" // first steps, help and shell completion scripts
	}
	if why := gateNotForReadKey[cmdKeys[name]]; why != "" {
		return why
	}
	k, ok := kindOf(c)
	switch {
	case !ok || k.Kind == kindChange:
		return "it changes something"
	case k.Kind == kindDepends:
		form := gateReadForm[cmdKeys[name]]
		if form == nil {
			return "it may change something (" + k.Note + ")"
		}
		return form(c)
	}
	return ""
}

// gateRecipeWrites says why `snippet exec` may change something, or "": a
// recipe komando runs as a read is marked read-only, and its filled-in
// command passes the --read-only check.
func gateRecipeWrites(c *cobra.Command) string {
	args := c.Flags().Args()
	if len(args) != 2 {
		return "" // a usage error: nothing runs
	}
	st, err := store.Load()
	if err != nil {
		return "the recipes could not be read"
	}
	r, ok := findRecipe(st, args[0])
	if !ok {
		return "" // not found: nothing runs
	}
	if !r.ReadOnly {
		return "the recipe " + r.Name + " is not marked read-only"
	}
	// the values as typed: the string getters re-parse the flag's text, which
	// drops or splits a value with a comma or a double quote
	f := c.Flags().Lookup("var")
	if f == nil {
		return "the blanks could not be read"
	}
	sv, ok := f.Value.(pflag.SliceValue)
	if !ok {
		return "the blanks could not be read"
	}
	kv, err := parseKV(sv.GetSlice())
	if err != nil {
		return "the blanks could not be read"
	}
	if checkVars(r, kv) != nil {
		return ""
	}
	command, err := render(r.Command, r.Params, kv)
	if err != nil {
		return ""
	}
	if readOnlyMutates(command, nil) {
		return "the recipe's command may write"
	}
	return ""
}

// gateAudit writes the gate's record: which key, what it asked for (secret
// looking values hidden), from where, and whether it ran. A record that
// cannot be written stops the command.
func gateAudit(cl *call, label string, key gateKey, req gateRequest, name string, refused *out.Error) error {
	// written even when the audit setting is off: a key's commands are
	// always in the log
	var syslog string
	if st, err := store.Load(); err == nil {
		syslog = st.Settings.AuditSyslog
	}
	ran := out.MaskSecrets(req.raw)
	if len(ran) > 2000 {
		ran = ran[:2000] + "..."
	}
	rec := map[string]any{
		"ts":          time.Now().UTC().Format(time.RFC3339Nano),
		"command":     "ssh-gate",
		"ok":          refused == nil,
		"dry_run":     false,
		"actor":       actor(cl),
		"os_user":     osUser(),
		"agent":       "ssh-gate key " + label,
		"ssh_gate":    label,
		"read_only":   key.readOnly,
		"network":     key.network,
		"ssh_command": ran,
	}
	if key.shellAccess {
		rec["shell_access"] = true
	}
	if key.here {
		rec["here"] = true
	}
	if name != "" {
		rec["runs"] = name
	}
	if from, _, _ := strings.Cut(cl.getenv("SSH_CONNECTION"), " "); from != "" {
		rec["client"] = from
	}
	if req.agent != "" {
		rec["client_agent"] = req.agent // what the client calls itself
	}
	if refused != nil {
		rec["blocked"] = refused.Code
		rec["reason"] = refused.Message
	}
	if err := appendAudit(cl, syslog, rec); err != nil {
		return out.Errf(out.ExitError, "AUDIT_UNAVAILABLE", "fix the file or folder permissions on the komando computer (`komando doctor` checks them)",
			"the audit log cannot be written (%v), so the key's command does not run", err)
	}
	if key.here {
		gateSystemLog(rec) // a copy the paired user cannot change (rule e)
	}
	return nil
}

// gated: the call came through ssh-gate (the komando the gate runs).
func (cl *call) gated() bool { return strings.HasPrefix(cl.caller().Agent, "ssh-gate key ") }

// gateChildEnv is the environment of the komando the gate runs: this one,
// with the vault passphrase komando took out of it at start (SelfEnv), the
// key's name (so it runs as an agent) and no approval window: the person
// who could click Allow is not at this screen.
func gateChildEnv(label string) []string {
	var env []string
	for _, kv := range vault.SelfEnv() {
		k, _, _ := strings.Cut(kv, "=")
		if k == "SSH_ORIGINAL_COMMAND" || k == gateEnv || k == "KOMANDO_NO_DIALOG" {
			continue
		}
		env = append(env, kv)
	}
	return append(env, gateEnv+"="+label, "KOMANDO_NO_DIALOG=1")
}

// gateDecide reads what the key sent and says what the gate runs for it:
// the request, the command's name and the -o it asked for, or the stop.
func gateDecide(cl *call, key gateKey) (req gateRequest, runs, output string, refused *out.Error) {
	req, refused = parseGate(cl.getenv("SSH_ORIGINAL_COMMAND"))
	if refused == nil && cl.isAgent() {
		// sshd starts the gate for a key with none of an agent's
		// variables; an agent here runs komando itself, as an agent
		refused = out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "an AI agent runs komando directly (`komando list`), not through ssh-gate",
			"ssh-gate runs when sshd starts it for a key, and this call comes from an AI agent (%s)", cl.caller().Agent)
	}
	if refused == nil && key.here {
		refused = gateServerRoot()
	}
	if refused == nil && key.here && req.agent != "" {
		// the audit log names a phone's key by its line alone
		refused = out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "send the komando command alone, without KOMANDO_AGENT=",
			"KOMANDO_AGENT=%s is refused for this server's key: the key's line names it", req.agent)
	}
	if refused == nil {
		runs, output, refused = gateCheck(req.args, key)
		if refused == nil && key.here && runs != "ssh-gate.status" {
			refused = gateServerNotYet(runs)
		}
		if f, ok := outputFormat(cl, output); ok && refused != nil && output != "" {
			cl.out.Format = f // the refusal comes as the key asked for output
		}
	}
	return req, runs, output, refused
}

func sshGateCmd() *cobra.Command {
	var name string
	var readOnly, network, shellAccess, here bool
	c := &cobra.Command{
		Use:   "ssh-gate",
		Short: "Let an SSH key run komando here and nothing else",
		Long: `ssh-gate lets an SSH key (a phone's, say) run komando on this computer, and
nothing else: no shell, no file copy, no port forwarding. Add the key to
~/.ssh/authorized_keys with the line ` + "`komando ssh-gate line`" + ` prints; sshd then
runs ssh-gate for it, whatever the key asks for.

ssh-gate takes the command the key sent (SSH_ORIGINAL_COMMAND) only when it
is one komando command. It splits it into words like a shell, but expands
nothing and runs no shell: ; | & > < $ and backquotes are refused unless
they are quoted. One KOMANDO_AGENT=NAME may come before komando.

komando then runs as for an AI agent: secret values stay [hidden], --reveal
and --allow-dangerous are refused, and --yes for a protected server needs a
person on this computer. Commands that need a person at a terminal (shell,
database KIND shell, config vault passphrase ...) are refused (a --shell-access key may open
` + "`komando host ssh shell SERVER`" + `: see ssh-gate line; that shell is full control
of the server, outside these rules). The key runs commands on
servers, never one that writes on this computer or reads a file here (a
script, SQL or upload source by path; '-' for the key's own input works):
no copy to a file here (copy SRC - streams to
the key's own output), no change to servers, VPNs, settings, rules, secrets, keys or
recipes in komando, no update, no change on a sqlite file or a target at
localhost or 127.x. With --read-only only commands that read run (database
KIND query and cache redis raw without --write), and only those that stay on the
servers and conns in your list: no net, no cert check of a website, no
exec, job start, docker exec, cluster kubernetes exec or snippet exec, unless the line
also has --network. ` + "`komando ssh-gate status`" + ` tells a key which it is. Every command a key
runs or is refused is in ` + "`komando audit list`" + `, with --name, even when the
audit setting is off.`,
		Example: `  komando ssh-gate line --name phone ~/phone.pub
  komando ssh-gate line --name phone-read --read-only 'ssh-ed25519 AAAA... phone'`,
		Args: cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			if cl.getenv("SSH_ORIGINAL_COMMAND") == "" && cl.getenv("SSH_CONNECTION") == "" {
				// typed by a person, not run by sshd for a key: nothing to
				// let through or refuse, so no stop and no audit record
				if cl.out.Format == "json" {
					return out.Usage("ssh-gate runs when sshd starts it for a key; `komando ssh-gate line` prints the line that sets that up").
						WithHint("for example: komando ssh-gate line --name phone ~/phone.pub")
				}
				return cmd.Help()
			}
			if !gateLabel.MatchString(name) {
				return out.Usage("--name takes 1 to 64 letters, digits, dots, dashes or underscores")
			}
			if shellAccess && readOnly {
				return out.Usage("--shell-access goes with a key that may change things, not with --read-only: fix the key's line in authorized_keys")
			}
			if shellAccess && here {
				return out.Usage("--shell-access does not go with --here: a key on the server itself opens no shell; fix the key's line in authorized_keys")
			}
			// a key that may change things runs any program on servers, so
			// --network only narrows a read key
			key := gateKey{readOnly: readOnly, network: network || !readOnly, shellAccess: shellAccess, here: here, tty: gateTTY(cl)}
			cl.terminal = false // the key's terminal: the gate asks nobody anything on it
			req, runs, output, refused := gateDecide(cl, key)
			if err := gateAudit(cl, name, key, req, runs, refused); err != nil {
				return err
			}
			if refused != nil {
				return exitCode(cl.out.Fail("ssh-gate", refused))
			}
			if runs == "ssh-gate.status" {
				// the gate answers it itself: the key cannot fake its own mode
				if f, ok := outputFormat(cl, output); ok && output != "" {
					cl.out.Format = f
				}
				cl.out.Print("ssh-gate.status", gateStatus{Gate: true, Name: name, ReadOnly: key.readOnly, Network: key.network, ShellAccess: key.shellAccess,
					Here: key.here, Komando: version.Version}, nil)
				return nil
			}
			if isHostShell(runs) && key.shellAccess && key.tty {
				// allowed by gateShell: the gate opens it itself
				return gateRunShell(cl, cmd.Context(), name, req.args[len(req.args)-1])
			}
			self, err := os.Executable()
			if err != nil {
				return fmt.Errorf("finding komando itself: %w", err)
			}
			err = gateExec(self, append([]string{"komando"}, req.args...), gateChildEnv(name))
			return fmt.Errorf("running komando: %w", err) // Exec returns only when it failed
		}),
	}
	c.Flags().StringVar(&name, "name", "key", "the key's name in the audit log")
	c.Flags().BoolVar(&readOnly, "read-only", false, "run only commands that read")
	c.Flags().BoolVar(&network, "network", false, "with --read-only: also reads that reach the network")
	c.Flags().BoolVar(&shellAccess, "shell-access", false, "also komando host ssh shell SERVER, with a terminal")
	c.Flags().BoolVar(&here, "here", false, "server mode: the key runs komando on this server itself (a phone's key)")
	// set by the line `ssh-gate line` writes, not typed: its help lists them
	for _, f := range []string{"name", "read-only", "network", "shell-access", "here"} {
		_ = c.Flags().MarkHidden(f)
	}
	c.AddCommand(sshGateLineCmd(), sshGateStatusCmd())
	return c
}
