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

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

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
// With --read-only it runs only commands komando treats as reads.
// `restrict` turns off port, agent and X11 forwarding and the terminal, so
// the key opens nothing else (OpenSSH 7.2 and later).

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
// refused. A few reads still leave something on the komando computer or
// hand out access (gateNotForReadKey); those are refused too.

// gateReadForm: these read only with a flag (--read-only), or without one
// (--write, --analyze, --apply, --refresh). Why the command as given may
// change something, or "".
var gateReadForm = map[string]func(c *cobra.Command) string{
	"exec":           needFlag("read-only"),
	"script":         needFlag("read-only"),
	"job.start":      needFlag("read-only"),
	"docker.exec":    needFlag("read-only"),
	"cluster.exec":   needFlag("read-only"),
	"db.query":       noFlag("write"),
	"cache.run":      noFlag("write"),
	"cluster.run":    noFlag("write"),
	"db.explain":     noFlag("write", "analyze"), // --analyze runs the statement
	"pkg.upgradable": noFlag("refresh"),          // refreshes the package index
	"pkg.security":   noFlag("apply", "refresh"),
	"recipe.run":     gateRecipeWrites,
}

// gateNotForReadKey are reads a read-only key still does not run, and why.
var gateNotForReadKey = map[string]string{
	"storage.link":    "it makes a link that opens the data without a login",
	"cluster.forward": "it opens a port on the komando computer",
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
var gateOnServers = map[string]func(c *cobra.Command) string{
	"exec": nil, "script": nil, "reboot": nil, "upload": nil, "recipe.run": nil,
	"cp": gateLocalDst, "sync": gateLocalDst,
	"job.start": nil, "job.kill": nil, "job.rm": nil,
	"fs.chmod": nil, "fs.mkdir": nil, "fs.mv": nil, "fs.replace": nil, "fs.rm": nil, "fs.write": nil,
	"svc.daemon-reload": nil, "svc.disable": nil, "svc.enable": nil, "svc.reload": nil,
	"svc.restart": nil, "svc.start": nil, "svc.stop": nil,
	"pkg.install": nil, "pkg.rm": nil, "pkg.security": nil, "pkg.update": nil, "pkg.upgradable": nil, "pkg.upgrade": nil,
	"user.add": nil, "user.lock": nil, "user.rm": nil, "user.unlock": nil,
	"cron.rm": nil, "cron.set": nil, "key.deploy": gateSetDefault, "key.revoke": nil,
	"db.explain": nil, "db.grant": nil, "db.kill": nil, "db.query": nil, "db.restore": nil, "db.revoke": nil,
	"db.user.add": nil, "db.user.passwd": nil, "db.user.rm": nil,
	"cache.rm": nil, "cache.run": nil, "cache.set": nil, "storage.rm": nil, "storage.upload": nil,
	"registry.copy": nil, "registry.prune": nil, "registry.rm": nil,
	"docker.compose": nil, "docker.exec": nil, "docker.prune": nil, "docker.pull": nil, "docker.raw": nil,
	"docker.restart": nil, "docker.rm": nil, "docker.start": nil, "docker.stop": nil,
	"cluster.apply": nil, "cluster.deploy": nil, "cluster.exec": nil, "cluster.restart": nil,
	"cluster.rm": nil, "cluster.rollback": nil, "cluster.run": gateKubectlCp, "cluster.scale": nil,
	"vpn.up": nil, "vpn.down": nil,
}

// gateSavesHere are reads that save a file on this computer, and when.
var gateSavesHere = map[string]func(c *cobra.Command) string{
	"download": func(*cobra.Command) string { return "it saves files on this computer" },
	"db.dump":  func(*cobra.Command) string { return "it saves a file on this computer" },
	"storage.download": func(c *cobra.Command) string {
		if to, _ := c.Flags().GetString("to"); to == "-" {
			return "" // to the key's own output
		}
		return "it saves files on this computer (--to - prints one instead)"
	},
	"export": func(c *cobra.Command) string {
		if to, _ := c.Flags().GetString("to"); to != "" {
			return "--to saves a file on this computer (without it, export prints)"
		}
		return ""
	},
}

// gateLocalDst: cp and sync write here when DST is not TARGET:PATH. It
// reads the arguments with the same splitArg the command uses.
func gateLocalDst(c *cobra.Command) string {
	args := c.Flags().Args()
	if len(args) != 2 {
		return "" // a usage error: nothing runs
	}
	if _, _, remote := splitArg(args[1]); !remote {
		return "its DST is on this computer; a key copies to servers or storage only"
	}
	return ""
}

// gateSetDefault: key deploy --set-default changes komando's own setup.
func gateSetDefault(c *cobra.Command) string {
	if on, _ := c.Flags().GetBool("set-default"); on {
		return "--set-default changes which key komando uses for those servers; deploy without it and set the key here"
	}
	return ""
}

// gateKubectlCp: kubectl cp saves files here whenever its SRC is POD:PATH,
// whatever DST looks like (kctl's cp reads them so: x:/../y is a local
// path to it). docker cp on a Swarm manager writes there.
func gateKubectlCp(c *cobra.Command) string {
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
		if t, err := resolveCluster(st, args[0]); err == nil && t.host != nil {
			return ""
		}
	}
	return "kubectl cp from a POD:PATH saves files on this computer"
}

// gateHere says why c writes on this computer, or "".
func gateHere(c *cobra.Command, name string) string {
	if f := gateSavesHere[name]; f != nil {
		return f(c)
	}
	if top, _, _ := strings.Cut(name, "."); c == c.Root() || top == "help" || top == "completion" {
		return "" // first steps, help and shell completion scripts: printed
	}
	k, ok := kindOf(c)
	if ok && k.Kind == kindRead {
		return ""
	}
	f, on := gateOnServers[name]
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
var gateNeedsPerson = map[string]bool{
	"shell": true, "db.shell": true, "cluster.shell": true, "login.aws": true,
	"config.approval-code": true, "secret.passphrase": true, "secret.check": true,
	"ssh-gate": true, "ssh-gate.line": true,
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
func gateCheck(args []string, readOnly bool) (name, output string, refused *out.Error) {
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == cobra.ShellCompRequestCmd || a == cobra.ShellCompNoDescRequestCmd {
			// cobra adds these only as it runs, so Find below cannot see them
			return a, "", out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "run it on the komando computer itself",
				"komando %s is the shell's completion helper, not for a key", a)
		}
	}
	saved := g
	g = globalFlags{}
	defer func() { g = saved }()
	root := newRoot()
	c, rest, err := root.Find(args)
	if err != nil {
		return "", "", nil // komando reports it, and runs nothing
	}
	name = commandName(c)
	c.InitDefaultHelpFlag()
	if err := c.ParseFlags(rest); err != nil {
		return name, "", nil // the same: a usage error, nothing runs
	}
	output = g.output
	name, refused = gateRule(c, name, readOnly)
	return name, output, refused
}

// gateRule is gateCheck's answer for the command c, its flags read.
func gateRule(c *cobra.Command, name string, readOnly bool) (string, *out.Error) {
	if help, _ := c.Flags().GetBool("help"); help && !gateNeedsPerson[name] {
		return name, nil // it only prints the command's help
	}
	for p := c; p != nil; p = p.Parent() {
		if p.Hidden {
			return name, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "run it on the komando computer itself",
				"komando %s is komando's own plumbing, not for a key", strings.ReplaceAll(name, ".", " "))
		}
	}
	switch {
	case gateNeedsPerson[name]:
		return name, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person runs it in a terminal on the komando computer itself",
			"komando %s needs a person at a terminal on this computer; a key cannot run it", strings.ReplaceAll(name, ".", " "))
	case g.reveal:
		return name, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "secret values stay [hidden] for a key; a person reads one in a terminal on the komando computer",
			"--reveal is refused: a key never gets secret values")
	case g.allowDangerous:
		return name, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person runs it in a terminal on the komando computer itself",
			"--allow-dangerous is refused: a key cannot skip the dangerous-command stop")
	}
	if !c.Runnable() || c.Annotations[groupOnly] == "true" {
		return name, nil // a group only prints its help
	}
	here := func(why string) (string, *out.Error) {
		return name, out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED", "a person runs it in a terminal on the komando computer itself",
			"komando %s is refused for a key: %s; the gate runs commands on servers, not on this computer", strings.ReplaceAll(name, ".", " "), why)
	}
	if why := gateHere(c, name); why != "" {
		return here(why)
	}
	if why := gateWrites(c, name); readOnly && why != "" {
		return name, out.Errf(out.ExitPolicy, "SSH_GATE_READ_ONLY", "this key was added with --read-only and runs only commands that read; use a key that may change things, or the komando computer itself",
			"komando %s is refused for a read-only key: %s", strings.ReplaceAll(name, ".", " "), why)
	}
	if why := gateLocalTarget(c, name); why != "" {
		return here(why)
	}
	return name, nil
}

// gateWrites says why a read-only key may not run c, or "".
func gateWrites(c *cobra.Command, name string) string {
	top, _, _ := strings.Cut(name, ".")
	if c == c.Root() || top == "help" || top == "completion" {
		return "" // first steps, help and shell completion scripts
	}
	if why := gateNotForReadKey[name]; why != "" {
		return why
	}
	k, ok := kindOf(c)
	switch {
	case !ok || k.Kind == kindChange:
		return "it changes something"
	case k.Kind == kindDepends:
		form := gateReadForm[name]
		if form == nil {
			return "it may change something (" + k.Note + ")"
		}
		return form(c)
	}
	return ""
}

// gateRecipeWrites says why `recipe run` may change something, or "": a
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
	vars, _ := c.Flags().GetStringArray("var")
	kv, err := parseKV(vars)
	if err != nil {
		return ""
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
func gateAudit(label string, readOnly bool, req gateRequest, name string, refused *out.Error) error {
	// written even when the audit setting is off: a key's commands are
	// always in the log
	st, err := store.Load()
	if err == nil {
		auditSyslog = st.Settings.AuditSyslog
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
		"actor":       actor(),
		"os_user":     osUser(),
		"agent":       "ssh-gate key " + label,
		"ssh_gate":    label,
		"read_only":   readOnly,
		"ssh_command": ran,
	}
	if name != "" {
		rec["runs"] = name
	}
	if from, _, _ := strings.Cut(os.Getenv("SSH_CONNECTION"), " "); from != "" {
		rec["client"] = from
	}
	if req.agent != "" {
		rec["client_agent"] = req.agent // what the client calls itself
	}
	if refused != nil {
		rec["blocked"] = refused.Code
		rec["reason"] = refused.Message
	}
	if err := appendAudit(rec); err != nil {
		return out.Errf(out.ExitError, "AUDIT_UNAVAILABLE", "fix the file or folder permissions on the komando computer (`komando doctor` checks them); nothing was run",
			"the audit log cannot be written (%v), so the key's command does not run", err)
	}
	return nil
}

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

func sshGateCmd() *cobra.Command {
	var name string
	var readOnly bool
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
db shell, secret passphrase ...) are refused. The key runs commands on
servers, never one that writes on this computer: no download or cp to a
file here, no change to servers, VPNs, settings, rules, secrets, keys or
recipes in komando, no update, no change on a sqlite file or a target at
localhost or 127.x. With --read-only only commands that read run: exec
needs --read-only, db query and cache run no --write. Every command a key
runs or is refused is in ` + "`komando audit`" + `, with --name, even when the
audit setting is off.`,
		Example: `  komando ssh-gate line --name phone ~/phone.pub
  komando ssh-gate line --name phone-read --read-only 'ssh-ed25519 AAAA... phone'`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !gateLabel.MatchString(name) {
				return out.Usage("--name must be 1 to 64 letters, digits, dots, dashes or underscores")
			}
			req, refused := parseGate(os.Getenv("SSH_ORIGINAL_COMMAND"))
			runs := ""
			if refused == nil {
				var output string
				runs, output, refused = gateCheck(req.args, readOnly)
				if f, ok := outputFormat(output); ok && refused != nil && output != "" {
					out.P.Format = f // the refusal comes as the key asked for output
				}
			}
			if err := gateAudit(name, readOnly, req, runs, refused); err != nil {
				return err
			}
			if refused != nil {
				return exitCode(out.P.Fail("ssh-gate", refused))
			}
			self, err := os.Executable()
			if err != nil {
				return fmt.Errorf("finding komando itself: %w", err)
			}
			err = gateExec(self, append([]string{"komando"}, req.args...), gateChildEnv(name))
			return fmt.Errorf("running komando: %w", err) // Exec returns only when it failed
		},
	}
	c.Flags().StringVar(&name, "name", "key", "the key's name in the audit log")
	c.Flags().BoolVar(&readOnly, "read-only", false, "run only commands that read")
	c.AddCommand(sshGateLineCmd())
	return c
}

// gateLine is what `ssh-gate line` prints.
type gateLine struct {
	Line     string `json:"line"`
	Name     string `json:"name"`
	ReadOnly bool   `json:"read_only"`
	Komando  string `json:"komando"`
	AddTo    string `json:"add_to"`
}

func (l gateLine) Text() string { return l.Line + "\n" }

func sshGateLineCmd() *cobra.Command {
	var name string
	var readOnly bool
	c := &cobra.Command{
		Use:   "line PUBLIC_KEY",
		Short: "Print the authorized_keys line that limits a key to komando",
		Long: `Prints the line to add to ~/.ssh/authorized_keys on this computer, so the
key runs komando through ssh-gate and nothing else. PUBLIC_KEY is the key's
line (ssh-ed25519 AAAA... comment) or a .pub file holding it. The line names
this komando by its full path, as sshd does not search PATH.`,
		Example: `  komando ssh-gate line --name phone ~/phone.pub
  komando ssh-gate line --name phone-read --read-only 'ssh-ed25519 AAAA... phone'`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !gateLabel.MatchString(name) {
				return out.Usage("--name must be 1 to 64 letters, digits, dots, dashes or underscores")
			}
			key, err := gatePublicKey(args[0])
			if err != nil {
				return err
			}
			self := komandoPath()
			if !strings.HasPrefix(self, "/") {
				return out.Errf(out.ExitError, "SSH_GATE_PATH", "run komando by its full path, e.g. /usr/local/bin/komando ssh-gate line ...",
					"komando cannot tell its own full path, which the line needs")
			}
			command := gateShellQuote(self) + " ssh-gate --name " + name
			if readOnly {
				command += " --read-only"
			}
			// in authorized_keys, " and \ inside command="..." are escaped
			escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(command)
			out.P.Print("ssh-gate.line", gateLine{
				Line: `restrict,command="` + escaped + `" ` + key, Name: name, ReadOnly: readOnly,
				Komando: self, AddTo: "~/.ssh/authorized_keys",
			}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&name, "name", "", "the key's name in the audit log (required)")
	c.Flags().BoolVar(&readOnly, "read-only", false, "the key runs only commands that read")
	_ = c.MarkFlagRequired("name")
	return c
}

// gatePublicKey reads a public key line, or a file holding one, and gives
// it back as "TYPE BASE64 COMMENT", without options.
func gatePublicKey(arg string) (string, error) {
	text := arg
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(arg)); err != nil {
		if fi, serr := os.Stat(arg); serr == nil && fi.Mode().IsRegular() && fi.Size() < 64<<10 {
			b, rerr := os.ReadFile(arg)
			if rerr != nil {
				return "", rerr
			}
			text = string(b)
		}
	}
	pub, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(text))
	if err != nil {
		return "", out.Errf(out.ExitUsage, "USAGE", "give the key's public line (ssh-ed25519 AAAA... name) or its .pub file",
			"not an SSH public key")
	}
	if len(options) > 0 {
		return "", out.Errf(out.ExitUsage, "USAGE", "give the public key line without options; ssh-gate line adds its own",
			"the key line already has options (%s)", strings.Join(options, ","))
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if comment = strings.TrimSpace(comment); comment != "" && !strings.ContainsAny(comment, "\r\n") {
		line += " " + comment
	}
	return line, nil
}

// gateShellQuote quotes a path for the shell sshd runs the forced command
// with, when it needs it.
func gateShellQuote(s string) string {
	if regexp.MustCompile(`^[A-Za-z0-9/._+-]+$`).MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
