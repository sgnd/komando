// Package cli wires every komando command. Design rules:
//   - piped or agent output is exactly one JSON envelope (or NDJSON when
//     streaming); a terminal gets text
//   - an AI agent is never prompted, and missing input is an error with a
//     hint; a person at a terminal can be asked
//   - exit codes are stable (see internal/out)
//   - destructive actions require explicit flags; changes are audited,
//     except `update` run as root
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/tmpclean"
	"github.com/sgnd/komando/internal/vault"
)

var Version = "dev"

type globalFlags struct {
	output         string
	pretty         bool
	dryRun         bool
	yes            bool
	allowDangerous bool
	reveal         bool
	timeout        time.Duration
	connectTimeout time.Duration
	parallel       int
	hostKeyPolicy  string
	maxOutput      int
	// table is csv or tsv: -o csv or -o tsv on a command that prints rows
	// (annotation tableOutput); everything else then prints as text
	table string
}

// tableOutput marks a command that takes -o csv and -o tsv.
const tableOutput = "table_output"

// pickTableOutput fills an empty -o from $KOMANDO_OUTPUT, and turns -o
// csv or -o tsv into g.table on a command that prints rows; everything
// else then prints as text, so errors and notes go to stderr and stdout
// has only rows.
func pickTableOutput(cmd *cobra.Command) error {
	if g.output == "" {
		g.output = os.Getenv("KOMANDO_OUTPUT")
	}
	g.table = ""
	if (g.output == "csv" || g.output == "tsv") && cmd.Flags().Changed("output") {
		if cmd.Annotations[tableOutput] == "" {
			return out.Usage("-o %s works with db query only; here use -o json or -o text", g.output)
		}
		g.table, g.output = g.output, "text"
	}
	return nil
}

var g globalFlags

// exitCode signals that the command already printed its envelope and only
// the process exit code must still be propagated.
type exitCode int

func (e exitCode) Error() string { return "exit " + strconv.Itoa(int(e)) }

func Execute() int {
	// no program komando starts inherits the secret stores' unlock values
	vault.TakeUnlockEnv()
	// a Windows console shows colour and line clearing only when asked
	ok, restore := consoleVT(int(os.Stderr.Fd()))
	defer restore()
	vtOK = ok
	return executeArgs(os.Args[1:])
}

// vtOK: the terminal on stderr reads escape sequences (colour, clearing a
// line). Only an old Windows console does not.
var vtOK = true

// executeArgs runs komando with these arguments (os.Args[1:] for the real
// program): one command, its envelope or text, and its exit code.
func executeArgs(args []string) int {
	// the store is closed when the command ends: a run inside a program
	// that goes on (a test) leaves no file open, which Windows could then
	// not remove
	defer store.Close()
	if Version == "dev" {
		// `go install ...@v1.2.3` records the module version in the binary
		if bi, ok := debug.ReadBuildInfo(); ok && isRelease(bi.Main.Version) {
			Version = bi.Main.Version
		}
	}
	out.P.Version = Version
	// errors raised before flag parsing still need the right format
	if f, ok := outputFormat(os.Getenv("KOMANDO_OUTPUT")); ok {
		out.P.Format = f
	}
	// a person at a terminal who left something out is asked for it first
	// (prompter_fill.go); everyone else gets args as they are
	filled, err := promptFill(args)
	if err != nil {
		var done fillDone
		if errors.As(err, &done) {
			return done.code
		}
		out.P.Format = "text"
		return out.P.Fail("komando", promptStopped(err))
	}
	if !slices.Equal(filled, args) {
		args = filled
		os.Args = append([]string{os.Args[0]}, filled...) // what the audit and the approval window name
	}
	root := newRoot()
	root.SetArgs(args)
	ctx, cancel := signalContext()
	defer cancel()
	cmd, err := root.ExecuteContextC(ctx)
	if err == nil {
		promptNext()
		return 0
	}
	var ec exitCode
	if errors.As(err, &ec) {
		return int(ec)
	}
	name := "komando"
	if cmd != nil {
		name = envelopeName(cmd)
	}
	// argument and flag errors come before PersistentPreRunE, which applies
	// -o; apply it here so `-o text` (or a terminal) gets text for them too
	if f, ok := outputFormat(outputFlag()); ok {
		out.P.Format = f
	}
	var oe *out.Error
	if errors.Is(err, store.ErrDryRun) {
		err = toErr(err)
	}
	if !errors.As(err, &oe) && isUsageErr(err) {
		err = usageErr(cmd, err)
	}
	if errors.As(err, &oe) {
		if oe.Code == "USAGE" && oe.Hint == out.UsageHint && cmd != nil && cmd.HasParent() {
			oe.Hint = commandHint(cmd)
		}
		approvalHint(oe)
		c := cur()
		if cmd != nil && callFrom(cmd.Context()) != nil {
			c = callFrom(cmd.Context())
		}
		cancelled(c, oe)
		auditBlocked(cmd, oe)
		if cmd != nil {
			fillHint(oe, firstArg(cmd))
		}
		if cmd != nil && out.P.Format == "text" {
			notFoundSay(oe, cmd)
		}
		cancelled(c, oe)
	}
	return out.P.Fail(name, err)
}

// cancelled words a stop the person answered no to at the terminal: it was
// cancelled, and nothing was changed unless the command already saved
// something before the question.
func cancelled(c *call, oe *out.Error) {
	if !c.sess.PersonSaidNo() || oe.Exit != out.ExitPolicy {
		return
	}
	oe.Message = "cancelled: " + oe.Message + "; nothing was changed"
	oe.Hint = "run it again to be asked again"
	if c.wroteBefore() {
		oe.Message = strings.TrimSuffix(oe.Message, "; nothing was changed") + "; what this command saved before the question stays"
		return
	}
	oe.Cancel(cancelledText()) // text mode: the person's own choice, not an error
}

// firstArg is the first argument cmd was given (its TARGET or CONN), or "".
func firstArg(cmd *cobra.Command) string {
	if a := cmd.Flags().Args(); len(a) > 0 {
		return a[0]
	}
	return ""
}

// topCommand is the command family cmd belongs to ("db" for db query).
func topCommand(cmd *cobra.Command) string {
	for cmd.HasParent() && cmd.Parent().HasParent() {
		cmd = cmd.Parent()
	}
	return cmd.Name()
}

// outputFlag is -o/--output as given, also when flag parsing stopped early
// (an unknown flag), else KOMANDO_OUTPUT or auto.
func outputFlag() string {
	args := os.Args[1:]
	for i := 0; i < len(args) && args[i] != "--"; i++ {
		a := args[i]
		switch {
		case (a == "-o" || a == "--output") && i+1 < len(args):
			return args[i+1]
		case strings.HasPrefix(a, "--output="):
			return strings.TrimPrefix(a, "--output=")
		case strings.HasPrefix(a, "-o") && len(a) > 2:
			return strings.TrimPrefix(a[2:], "=")
		}
	}
	if v := os.Getenv("KOMANDO_OUTPUT"); v != "" {
		return v
	}
	return "auto"
}

// usageErr turns cobra's argument errors ("accepts 2 arg(s), received 1")
// into what people know from other tools: what is wrong and the usage line.
func usageErr(cmd *cobra.Command, err error) error {
	m := err.Error()
	if cmd == nil {
		return out.Usage("%s", m)
	}
	e := out.Usage("%s", m)
	e.Hint = "see `" + cmd.CommandPath() + " --help`"
	// cobra writes "unknown command \"exce\" for \"komando\"\n\nDid you mean
	// this?\n\texec\n": one line, the suggestion in the message, a hint
	// that points at the command meant
	if name, ok := quotedAfter(m, "unknown command "); ok && !cmd.HasSubCommands() && cmd.HasParent() {
		// cobra.NoArgs says "unknown command" too, but a leaf has no
		// commands to list: say it takes no arguments, and where it
		// filters with --target, how to give one
		e.Message = fmt.Sprintf("%s takes no arguments (got %q)", cmd.CommandPath(), name)
		e.Hint = commandHint(cmd)
		if cmd.Flags().Lookup("target") != nil {
			e.Hint = "pick targets with --target: " + cmd.CommandPath() + " --target " + name
		}
		return e
	} else if ok {
		if name == "add" && !cmd.HasParent() {
			e.Message = fmt.Sprintf("unknown command %q", name)
			e.Hint = "add a server with `komando host add`, a database with `komando db add` or a VPN with `komando vpn add`; typed alone at a terminal, each one asks step by step"
			return e
		}
		var rest []string
		if i := slices.Index(os.Args, name); i > 0 {
			rest = os.Args[i+1:]
		}
		return unknownCommandErr(cmd, name, rest)
	}
	// a flag value's own message and hint (flagHint), without pflag's
	// "invalid argument ... for ... flag:" around it
	if strings.HasPrefix(m, "invalid argument ") {
		if head, own, ok := strings.Cut(m, " flag: "); ok {
			name := head[strings.LastIndex(head, " ")+1:] // "--warn" or "-n, --namespace"
			name = strings.Trim(name, `"`)
			if len(name) == 3 { // a one-letter flag (cluster -n): its short spelling
				name = name[1:]
			}
			msg, hint, hinted := strings.Cut(own, flagHintSep)
			e.Message = name + ": " + msg
			switch {
			case hinted:
				e.Hint = hint
			case exampleWith(cmd, name) != "":
				e.Hint = "for example: " + exampleWith(cmd, name)
			}
			return e
		}
	}
	if rest, ok := strings.CutPrefix(m, "unknown shorthand flag: '"); ok && len(rest) > 1 {
		_, word, _ := strings.Cut(rest, " in ")
		if s := shorthandSuggest(cmd, rest[:1], strings.TrimSpace(word)); s != "" {
			e.Message += "; " + s
		}
		return e
	}
	if flag, ok := strings.CutPrefix(m, "unknown flag: "); ok {
		if s := closestFlag(cmd, strings.TrimLeft(flag, "-")); s != "" {
			e.Message += "; did you mean --" + s + "?"
			// a safety override is never handed out as a line to run
			if name, _, _ := strings.Cut(flag, "="); !slices.Contains(safetyOverrides, s) {
				suggest(e, name, "--"+s)
			}
		}
		return e
	}
	for _, p := range []string{"accepts ", "requires at least", "requires at most", "received"} {
		if strings.Contains(m, p) {
			what := "too many arguments"
			if n := argCounts.FindStringSubmatch(m); n != nil {
				if want, _ := strconv.Atoi(n[1]); n[2] != "" {
					if got, _ := strconv.Atoi(n[2]); got < want {
						what = "missing arguments"
					}
				}
			}
			if strings.Contains(m, "requires at least") || strings.Contains(m, "received 0") {
				what = "missing arguments"
			}
			e.Message = what + "; usage: " + strings.TrimSuffix(cmd.UseLine(), " [flags]")
			if ex := firstExample(cmd); ex != "" {
				e.Hint = "for example: " + ex
			}
			break
		}
	}
	return e
}

// argCounts reads "accepts 2 arg(s), received 1" and "accepts between 1 and
// 2 arg(s), received 0": the smallest count wanted, and the count given.
var argCounts = regexp.MustCompile(`accepts (?:between )?(\d+).*received (\d+)`)

// commandHint is the hint for a usage error that came without one: the
// command's own help, and its first example when it has one.
func commandHint(cmd *cobra.Command) string {
	h := "see `" + cmd.CommandPath() + " --help`"
	if ex := firstExample(cmd); ex != "" {
		h = "for example: " + ex + " (more in `" + cmd.CommandPath() + " --help`)"
	}
	return h
}

// quotedAfter reads the first quoted word after prefix in m.
func quotedAfter(m, prefix string) (string, bool) {
	_, rest, ok := strings.Cut(m, prefix)
	if !ok {
		return "", false
	}
	line, _, _ := strings.Cut(rest, "\n")
	before, _, _ := strings.Cut(line, " for ")
	s, err := strconv.Unquote(before)
	return s, err == nil
}

func isUsageErr(err error) bool {
	m := err.Error()
	for _, s := range []string{"unknown flag", "unknown command", "accepts ", "requires at least", "required flag", "invalid argument", "flag needs an argument", "unknown shorthand"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

// envelopeName is the command an error envelope names: an alias such as
// `vpn test` prints the command it stands for, as its result does.
func envelopeName(c *cobra.Command) string {
	if n := c.Annotations[aliasOf]; n != "" {
		return n
	}
	return commandName(c)
}

// commandName is c's ID (cmdid.go): what the envelopes, the audit log and
// every table keyed by command use.
func commandName(c *cobra.Command) string { return cmdID(c) }

// vaultValues returns every vault secret by name, so output can hide them
// (a remote .env, a log line). A vault that cannot be opened hides nothing.
func vaultValues() map[string]string {
	list, err := vault.List()
	if err != nil {
		return nil
	}
	m := make(map[string]string, len(list))
	for _, i := range list {
		if v, err := vault.Get(i.Name); err == nil {
			m[i.Name] = v
		}
	}
	return m
}

// localReads change nothing anywhere, so they run even when the store
// cannot be written; that is how a person finds out what is wrong.
var localReads = map[string]bool{
	"version": true, "help": true, "completion": true, "schema": true, "guide": true, "doctor": true,
	"audit": true, "list": true, "config.show": true, "policy.list": true, "policy.check": true,
	"conn.kinds": true, "conn.show": true, "host.show": true, "vpn.show": true, "key.list": true,
	"key.show": true, "secret.list": true, "group.list": true, "recipe.list": true, "vpn.status": true,
	"tunnel.list": true, "job.list": true, "status": true,
	"host.list": true, "conn.list": true, "vpn.list": true, "secret.show": true,
}

// checkStoreWritable refuses to run a command that may change something
// when the store (which holds the audit log) cannot be written: changes
// must not happen without a record (docs/design/principles.md, section 7).
func checkStoreWritable(cmd *cobra.Command) error {
	name := commandName(cmd)
	top, _, _ := strings.Cut(name, ".")
	if g.dryRun || backgroundCmd(cmd) || name == "komando" || localReads[name] || localReads[top] || leavesHomeNow(cmd) || top == "help" || top == "completion" || name == "secret.passphrase" { // it opens the store with the passphrase a person types
		return nil
	}
	err := store.CheckWritable()
	var oe *out.Error
	if err == nil || errors.As(err, &oe) {
		return err
	}
	return out.Errf(out.ExitError, "AUDIT_UNAVAILABLE", "fix the file or folder permissions (`komando doctor` checks them); nothing was run",
		"the store, which keeps the audit log, cannot be written: %v", err)
}

// leavesHome are commands that, run as root, never touch ~/.komando:
// `update` replaces only the komando program, often as root (sudo komando
// update, where HOME may still be the person's), and root must not leave
// files in a person's ~/.komando that they can no longer change. So no
// audit check, no VPN clean-up and no vault (for hiding secret values in
// the output) for them then. Run as anyone else they are audited as usual.
var leavesHome = map[string]bool{"update": true}

func leavesHomeNow(cmd *cobra.Command) bool { return leavesHome[commandName(cmd)] && asRoot() }

// startChecks are the last steps before every command: the data folder
// (guardHome), closing idle VPNs and
// --host-key-policy off. The audit log needs no check: the store refuses a
// change it cannot record.
func startChecks(cmd *cobra.Command) error {
	if err := guardHome(cmd); err != nil {
		return err
	}
	if cmd.Name() != "serve" && !leavesHomeNow(cmd) && !g.dryRun {
		netx.ReapIdle() // close VPN sessions nobody used for vpn_idle
	}
	if g.hostKeyPolicy == "off" {
		if g.dryRun && isAgent() {
			// an agent's preview still connects to read; it does that
			// with the usual identity check, since a dry run never asks
			// the person. People and scripts preview as they run.
			_ = guardSafety("--host-key-policy off (no server identity check)")
			g.hostKeyPolicy = ""
		} else if err := guardSafety("--host-key-policy off (no server identity check)"); err != nil {
			return err
		}
	}
	return checkStoreWritable(cmd)
}

func newRoot() *cobra.Command {
	out.P.Reset()
	askedAbout, blockAudited = nil, false
	interrupted = false
	root := &cobra.Command{
		Use:           "komando",
		Short:         "One safe CLI for servers, databases, caches, storage, clusters",
		Long:          rootLong,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
		RunE:          printFirstSteps,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			startCall(cmd) // answers count for one command only
			if err := pickTableOutput(cmd); err != nil {
				return err
			}
			f, ok := outputFormat(g.output)
			if !ok {
				if !cmd.Flags().Changed("output") && os.Getenv("KOMANDO_OUTPUT") != "" {
					return out.Usage("KOMANDO_OUTPUT=%s: it takes auto, json or text", os.Getenv("KOMANDO_OUTPUT"))
				}
				return out.Usage("--output takes auto, json or text (db query also takes csv and tsv)")
			}
			switch {
			case g.parallel < 0:
				return out.Usage("-P/--parallel takes 1 or more (0 means the setting, default 10)")
			case g.timeout < 0, g.connectTimeout < 0:
				return out.Usage("--timeout and --connect-timeout take a time more than 0, for example 30s or 5m")
			case g.maxOutput < 0:
				return out.Usage("--max-output takes a number of bytes, for example 1048576")
			}
			out.P.Format = f
			out.P.Pretty = g.pretty
			out.P.Version = Version
			out.P.DryRun = g.dryRun
			store.DryRun, store.AllowOldCopy = g.dryRun, g.dryRun // a dry run may look at an old copy: it changes nothing
			out.P.Start = time.Now()
			vault.Passphrase() // take KOMANDO_VAULT_PASS out of the environment children inherit
			// a person at the terminal answers what an SSH login asks
			// (a password, a two-factor code); nobody else is asked
			sshx.Ask = nil
			if interactive() {
				sshx.Ask = askSSH
			}
			out.P.Secrets = vaultValues
			if leavesHomeNow(cmd) {
				out.P.Secrets = nil // its output holds no secrets, and the vault is in ~/.komando
			}
			// AI agents see passwords, keys and tokens as [hidden]; people and
			// scripts see what the server sent (vault values are hidden for
			// all). `secret get --reveal` is for people only: an agent is never
			// asked and always sees [hidden]. A dry run never approves --reveal.
			out.P.Mask = isAgent() && (commandName(cmd) == "secret.show" || g.dryRun || !revealOK())
			startPersonal(cmd)
			if err := secretInArgs(cmd, args); err != nil {
				return err
			}
			if out.P.Mask && g.dryRun && g.reveal {
				out.P.WouldBlock(out.Errf(out.ExitPolicy, "REVEAL_NEEDS_PERSON", "values stay [hidden] in a dry run; run it without --dry-run to ask the user in a window on their screen",
					"--reveal needs the user's yes"))
			}
			return startChecks(cmd)
		},
	}
	pf := root.PersistentFlags()
	pf.StringVarP(&g.output, "output", "o", "", "json or text (default $KOMANDO_OUTPUT, or\ntext in a terminal, JSON when piped); db query also\ntakes csv and tsv")
	pf.BoolVar(&g.pretty, "pretty", false, "indent JSON output")
	pf.BoolVar(&g.dryRun, "dry-run", false, "show what would run, changing nothing")
	pf.BoolVarP(&g.yes, "yes", "y", false, "confirm a change on a protected target (an AI agent needs a person's yes)")
	pf.BoolVar(&g.allowDangerous, "allow-dangerous", false, "run a command the safety rules would block")
	pf.BoolVar(&g.reveal, "reveal", false, "show passwords and keys in output (an agent needs a person's yes)")
	durVar(pf, &g.timeout, "timeout", 0, "time limit per server, like 30s or 1h (default: setting default_timeout, 5m)")
	durVar(pf, &g.connectTimeout, "connect-timeout", 0, "time to connect, like 30s (default: setting connect_timeout, 15s)")
	pf.IntVarP(&g.parallel, "parallel", "P", 0, "servers at once (default: setting parallel, 10)")
	pf.StringVar(&g.hostKeyPolicy, "host-key-policy", "", "accept-new, strict or off: how a server's key is checked (default: setting host_key_policy, accept-new)")
	g.maxOutput = 0
	pf.Var(&bytesFlag{i: &g.maxOutput}, "max-output", "bytes kept per stream per server, like 1MiB (default: setting max_output_bytes, 256KiB)")
	for flag, key := range map[string]string{"timeout": "default_timeout", "connect-timeout": "connect_timeout", "parallel": "parallel", "host-key-policy": "host_key_policy", "max-output": "max_output_bytes"} {
		_ = pf.SetAnnotation(flag, defaultFrom, []string{"setting:" + key})
	}

	root.SetVersionTemplate(`{{.Version}}` + "\n")
	addCommands(root)
	addHelpTopics(root) // and cobra's help command
	root.InitDefaultCompletionCmd()
	labelBuiltinCmds(root) // before the conventions: `completion` alone, piped, is a USAGE envelope too
	applyConventions(root)
	useShortGlobals(root)
	addCompletion(root)
	stampIDs(root)
	applyHelpStandard(root)
	return root
}

// addCommands adds komando's commands to root under the groups of
// `komando` alone (personHelp), so --help reads the same.
func addCommands(root *cobra.Command) {
	root.AddGroup(
		&cobra.Group{ID: "servers", Title: "Servers:"},
		&cobra.Group{ID: "data", Title: "Data:"},
		&cobra.Group{ID: "platform", Title: "Platform:"},
		&cobra.Group{ID: "inventory", Title: "Inventory:"},
		&cobra.Group{ID: "access", Title: "Access:"},
		&cobra.Group{ID: "overview", Title: "Overview:"},
		&cobra.Group{ID: "setup", Title: "Setup:"},
	)
	add := func(group string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = group
			root.AddCommand(c)
		}
	}
	add("servers", execCmd(), logsCmd(), factsCmd(), fsCmd(), uploadCmd(), downloadCmd(), cpCmd(), syncCmd(),
		svcCmd(), jobCmd(), dockerCmd(), pkgCmd(), cronCmd(), userCmd(), rebootCmd(), shellCmd(), netCmd(), certCmd(), recipeCmd())
	add("data", dbCmd(), cacheCmd(), queueCmd(), storageCmd())
	add("platform", clusterCmd(), registryCmd())
	add("access", vpnCmd(), loginCmd(), logoutCmd(), loginHolderCmd(), secretCmd(), keyCmd(), tunnelCmd())
	add("overview", statusCmd(), auditCmd(), listCmd(), testCmd(), doctorCmd())
	add("inventory", hostCmd(), connCmd(), groupCmd(), importCmd(), exportCmd(), renameCmd())
	add("setup", configCmd(), policyCmd(), guideCmd(), schemaCmd(root), updateCmd(), versionCmd(), sshGateCmd())
	addNounAliases(root)
}

// labelBuiltinCmds files cobra's own help and completion commands under
// "setup" and gives them komando's wording; dropped old names suggest the
// command that does it now.
func labelBuiltinCmds(root *cobra.Command) {
	suggestHabitWords(root)
	for _, c := range root.Commands() {
		switch c.Name() {
		case "help":
			c.GroupID = "setup"
			c.Short = "Show the help of a command"
			c.Long = "Shows what a command does, its flags and examples: komando help db query\n(the same as komando db query --help)."
		case "completion":
			c.GroupID = "setup"
			c.Short = "Print a tab-completion script for your shell"
			c.Long = "Prints a script that lets Tab complete komando's commands, flags and names\nin bash, zsh, fish or PowerShell. Each one's help says how to load it:\nkomando completion zsh --help."
			for _, sh := range c.Commands() {
				shell := sh.Name()
				if shell == "powershell" {
					shell = "PowerShell"
				}
				sh.Short = "Print the tab-completion script for " + shell
			}
		}
	}
}

// rootLong is the top of `komando --help`: what komando is, then the first
// commands a person types. The notes for scripts come after the command
// list (rootScriptNotes).
const rootLong = `komando is one safe command line for
` + tagline + `,
for people and AI agents alike.

Start:
  komando host add NAME USER@ADDRESS   add a server
  komando conn add NAME URL            add a database, cache, queue, storage,
                                       cluster or registry
  komando import ssh-config            bring in the servers you already have
  komando list                         see everything komando knows about
  komando test TARGET                  check that it answers and lets you in
  komando guide install                let your AI agent use komando safely

Targets: a server or service name, a pattern (web-*), @group, tag:NAME,
label:key=value, kind:KIND (host, db, cache, storage, postgres, ...),
os:windows or os:linux, all, or user@addr:port for a server you have not
added. Combine with commas; put ! in front to leave one out.
See them all with ` + "`komando list`" + `.`

// rootScriptNotes close `komando --help`: what scripts and agents read.
const rootScriptNotes = `For scripts and AI agents:
  When piped, every command prints one JSON envelope on stdout; in a terminal
  it prints text (force it with -o json or -o text):
    {"ok":true,"command":"exec","data":{...},"meta":{...}}
    {"ok":false,"command":"exec","error":{"code":"AUTH_FAILED",...}}
  Exit codes: 0 ok, 1 error, 2 usage, 3 not found, 4 connect or login,
              5 failed on the server, 6 blocked for safety, 7 timeout,
              8 precondition or conflict.
  komando guide is the playbook for agents; komando schema lists every command.`

// printFirstSteps is `komando` alone: the commands by group for a person at
// a terminal, else the first steps, not a wall of text (ux.md, section 10).
func printFirstSteps(cmd *cobra.Command, args []string) error {
	if out.P.Format == "json" { // piped: one JSON envelope, never text
		return out.Usage("komando needs a command").WithHint("read `komando guide` (the playbook for agents) or `komando schema` (every command)")
	}
	if promptable(outputFlag()) { // a person at a terminal: what komando does, by group
		_, err := fmt.Fprint(cmd.OutOrStdout(), personHelp())
		return err
	}
	_, err := fmt.Fprint(cmd.OutOrStdout(), firstSteps)
	return err
}

// personHelp is `komando` alone for a person at a terminal: the commands
// by what they work on, START first, a few examples, and how to learn more.
func personHelp() string {
	var b strings.Builder
	b.WriteString("komando: one safe command line for " + tagline + "\n\n")
	if st, err := loadState(); err == nil && len(st.Hosts) == 0 && len(st.Conns) == 0 && len(st.Vpns) == 0 {
		b.WriteString("Nothing added yet: komando host add  or  komando import ssh-config\n\n")
	}
	for _, g := range [][2]string{
		{"START", "host add · conn add · import ssh-config · list · test TARGET · guide install"},
		{"SERVERS", "exec  logs  facts  fs  svc  job  docker  pkg  cron  user  reboot  shell"},
		{"DATA", "db  cache  queue  storage"},
		{"PLATFORM", "cluster  registry"},
		{"INVENTORY", "host  conn  group  import  export  rename"},
		{"ACCESS", "vpn  login  secret  key  tunnel"},
		{"OVERVIEW", "status  audit  list  test  doctor"},
		{"SETUP", "config  policy  guide  schema  completion"},
	} {
		fmt.Fprintf(&b, "%-12s %s\n", g[0], g[1])
	}
	b.WriteString(`
EXAMPLES
  $ komando host add web1 deploy@10.0.0.5
  $ komando logs web1 --unit nginx --since 30m
  $ komando db query prod-db "select now()"
  $ komando fs replace web1 /etc/nginx/nginx.conf --old A --new B --backup --dry-run

Leave out an argument at a terminal and komando asks for it.
LEARN MORE   komando <command> --help · komando help safety|environment|exit-codes|output
`)
	return b.String()
}

// tagline is what komando works with, said the same way in `komando`
// alone, `komando --help` and the README.
const tagline = "servers, databases, caches, queues, storage, clusters and VPNs"

// firstSteps is what `komando` alone prints.
const firstSteps = `komando: one safe command line for ` + tagline + `.

First steps:
  komando import ssh-config        bring in the servers you already have
  komando list                     see everything komando knows about
  komando exec web1 -- uptime      run a command on a server

More:
  komando --help                   every command
  komando guide                    the playbook for AI agents
  komando doctor                   check your setup
`

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the komando version and its home folder",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out.P.Print("version", map[string]string{"version": Version, "home": store.Home()}, nil)
			return nil
		},
	}
}

// outputFormat resolves auto|json|text. "auto" (or empty) means text for a
// human at a terminal and JSON for programs reading a pipe.
func outputFormat(v string) (string, bool) {
	switch v {
	case "json", "text":
		return v, true
	case "", "auto":
		if term.IsTerminal(int(os.Stdout.Fd())) {
			return "text", true
		}
		return "json", true
	}
	return "", false
}

// isRelease reports whether a module version is a real tag (not a local or
// pseudo version).
func isRelease(v string) bool {
	return strings.HasPrefix(v, "v") && !strings.HasPrefix(v, "v0.0.0-") && !strings.Contains(v, "+")
}

// signalContext is cancelled by the first Ctrl-C (or SIGTERM, or SIGHUP:
// the terminal closed), so the command stops cleanly. A second one ends
// komando at once, as with kubectl and gh, when the clean stop hangs: it
// first removes the temporary files and folders this run made
// (tmpclean), which the clean stop would have removed. A SIGHUP that was
// ignored when komando started (nohup, a background holder) stays ignored.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigs := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) {
		sigs = append(sigs, syscall.SIGHUP)
	}
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, sigs...)
	done := make(chan struct{})
	go func() {
		select {
		case <-ch:
			cancel()
		case <-done:
			return
		}
		select {
		case <-ch:
			hardStop()
		case <-done:
		}
	}()
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			cancel()
			signal.Stop(ch)
			close(done)
		})
	}
}

// hardStop ends komando on a second signal; tests replace it.
var hardStop = func() {
	tmpclean.RemoveAll()
	os.Exit(130)
}
