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

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/tmpclean"
	"github.com/sgnd/komando/internal/vault"
)

var Version = "dev"

func init() {
	if Version == "dev" {
		// `go install ...@v1.2.3` records the module version in the binary
		if bi, ok := debug.ReadBuildInfo(); ok && isRelease(bi.Main.Version) {
			Version = bi.Main.Version
		}
	}
}

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
	cl := callOf(cmd)
	if cl.flags.output == "" {
		cl.flags.output = cl.getenv("KOMANDO_OUTPUT")
	}
	cl.flags.table = ""
	if (cl.flags.output == "csv" || cl.flags.output == "tsv") && cmd.Flags().Changed("output") {
		if cmd.Annotations[tableOutput] == "" {
			return out.Usage("-o %s works with db query only; here use -o json or -o text", cl.flags.output)
		}
		cl.flags.table, cl.flags.output = cl.flags.output, "text"
	}
	return nil
}

// exitCode signals that the command already printed its envelope and only
// the process exit code must still be propagated.
type exitCode int

func (e exitCode) Error() string { return "exit " + strconv.Itoa(int(e)) }

// vtOK: the terminal on stderr reads escape sequences (colour, clearing a
// line). Only an old Windows console does not.
var vtOK = true

// execute runs one command with these arguments in cl: its envelope or
// text, and its exit code.
func (cl *call) execute(ctx context.Context, args []string) int {
	// the hooks of the lower packages answer for this call from its first
	// step (call_hooks.go): the store and the vault may open in any of
	// them, and an agent's call must count there before they do
	cl.enter()
	defer cl.leave()
	// errors raised before flag parsing still need the right format; the
	// command before in this call does not choose it
	cl.out.Format = "json"
	if f, ok := outputFormat(cl, cl.getenv("KOMANDO_OUTPUT")); ok {
		cl.out.Format = f
	}
	// a person at a terminal who left something out is asked for it first
	// (prompter_fill.go); everyone else gets args as they are
	filled, err := promptFill(cl, args)
	if err != nil {
		var done fillDone
		if errors.As(err, &done) {
			return done.code
		}
		cl.out.Format = "text"
		return cl.out.Fail("komando", promptStopped(err))
	}
	if !slices.Equal(filled, args) {
		args = filled
		cl.args = append([]string{cl.args[0]}, filled...) // what the audit and the approval window name
	}
	// Ctrl-C stops the command only once the questions are answered: one
	// at a question (or at a preview it offers) stops just that
	if cl.signals != nil {
		var cancel context.CancelFunc
		ctx, cancel = cl.signals(ctx)
		defer cancel()
	}
	if ctx.Err() != nil { // stopped while the questions were asked
		return cl.out.Fail("komando", promptStopped(ctx.Err()))
	}
	root := newRoot(cl)
	root.SetArgs(args)
	cmd, err := root.ExecuteContextC(withCall(ctx, cl))
	if err == nil {
		promptNext(cl)
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
	if f, ok := outputFormat(cl, outputFlag(cl)); ok {
		cl.out.Format = f
	}
	var oe *out.Error
	if errors.Is(err, store.ErrDryRun) {
		err = toErr(err)
	}
	if !errors.As(err, &oe) && isUsageErr(err) {
		err = usageErr(cl, cmd, err)
	}
	if errors.As(err, &oe) {
		if oe.Code == "USAGE" && oe.Hint == out.UsageHint && cmd != nil && cmd.HasParent() {
			oe.Hint = commandHint(cmd)
		}
		approvalHint(cl, oe)
		cancelled(cl, oe)
		auditBlocked(cl, cmd, oe)
		if cmd != nil {
			fillHint(oe, firstArg(cmd))
		}
		if cmd != nil && cl.out.Format == "text" {
			notFoundSay(cl, oe, cmd)
		}
		cancelled(cl, oe)
	}
	return cl.out.Fail(name, err)
}

// cancelled words a stop the person answered no to at the terminal: it was
// cancelled, and nothing was changed unless the command already saved
// something before the question.
func cancelled(cl *call, oe *out.Error) {
	if !cl.sess.PersonSaidNo() || oe.Exit != out.ExitPolicy {
		return
	}
	oe.Message = "cancelled: " + oe.Message + "; nothing was changed"
	oe.Hint = "run it again to be asked again"
	if cl.wroteBefore() {
		oe.Message = strings.TrimSuffix(oe.Message, "; nothing was changed") + "; what this command saved before the question stays"
		return
	}
	oe.Cancel(cancelledText(cl)) // text mode: the person's own choice, not an error
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
func outputFlag(cl *call) string {
	args := cl.args[1:]
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
	if v := cl.getenv("KOMANDO_OUTPUT"); v != "" {
		return v
	}
	return "auto"
}

// usageErr turns cobra's argument errors ("accepts 2 arg(s), received 1")
// into what people know from other tools: what is wrong and the usage line.
func usageErr(cl *call, cmd *cobra.Command, err error) error {
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
		if i := slices.Index(cl.args, name); i > 0 {
			rest = cl.args[i+1:]
		}
		return unknownCommandErr(cl, cmd, name, rest)
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
				suggest(cl, e, name, "--"+s)
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
	cl := callOf(cmd)
	name := commandName(cmd)
	top, _, _ := strings.Cut(name, ".")
	if cl.flags.dryRun || backgroundCmd(cmd) || name == "komando" || localReads[name] || localReads[top] || leavesHomeNow(cmd) || top == "help" || top == "completion" || name == "secret.passphrase" { // it opens the store with the passphrase a person types
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
	cl := callOf(cmd)
	if err := guardHome(cmd); err != nil {
		return err
	}
	if cmd.Name() != "serve" && !leavesHomeNow(cmd) && !cl.flags.dryRun {
		netx.ReapIdle() // close VPN sessions nobody used for vpn_idle
	}
	if cl.flags.hostKeyPolicy == "off" {
		if cl.flags.dryRun && cl.isAgent() {
			// an agent's preview still connects to read; it does that
			// with the usual identity check, since a dry run never asks
			// the person. People and scripts preview as they run.
			_ = guardSafety(cl, "--host-key-policy off (no server identity check)")
			cl.flags.hostKeyPolicy = ""
		} else if err := guardSafety(cl, "--host-key-policy off (no server identity check)"); err != nil {
			return err
		}
	}
	return checkStoreWritable(cmd)
}

// newRoot is the command tree of cl: its flags are cl's, and every
// command in it runs in cl (callOf). What the last command in cl
// recorded is forgotten.
func newRoot(cl *call) *cobra.Command {
	cl.out.Reset()
	cl.flags = globalFlags{} // the flags below bind to it with their defaults
	cl.askedAbout, cl.blockAudited, cl.interrupted = nil, false, false
	cl.personalCmd, cl.fsSudoRetry, cl.auditSyslog = false, "retry with --sudo", ""
	root := &cobra.Command{
		Use:           "komando",
		Short:         "One safe CLI for servers, databases, caches, storage, clusters",
		Long:          rootLong,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
		RunE:          printFirstSteps,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			cmd.SetContext(withCall(cmd.Context(), cl))
			cl.begin() // answers count for one command only
			if err := pickTableOutput(cmd); err != nil {
				return err
			}
			f, ok := outputFormat(cl, cl.flags.output)
			if !ok {
				if !cmd.Flags().Changed("output") && cl.getenv("KOMANDO_OUTPUT") != "" {
					return out.Usage("KOMANDO_OUTPUT=%s: it takes auto, json or text", cl.getenv("KOMANDO_OUTPUT"))
				}
				return out.Usage("--output takes auto, json or text (db query also takes csv and tsv)")
			}
			switch {
			case cl.flags.parallel < 0:
				return out.Usage("-P/--parallel takes 1 or more (0 means the setting, default 10)")
			case cl.flags.timeout < 0, cl.flags.connectTimeout < 0:
				return out.Usage("--timeout and --connect-timeout take a time more than 0, for example 30s or 5m")
			case cl.flags.maxOutput < 0:
				return out.Usage("--max-output takes a number of bytes, for example 1048576")
			}
			cl.out.Format = f
			cl.out.Pretty = cl.flags.pretty
			cl.out.Version = Version
			cl.out.DryRun = cl.flags.dryRun
			cl.oldCopy.Store(cl.flags.dryRun) // a dry run may look at an old copy: it changes nothing
			cl.out.Start = time.Now()
			vault.Passphrase() // take KOMANDO_VAULT_PASS out of the environment children inherit
			if leavesHomeNow(cmd) {
				cl.out.SetSecrets(nil) // its output holds no secrets, and the vault is in ~/.komando
			} else {
				cl.out.SetSecrets(vaultValues)
			}
			// AI agents see passwords, keys and tokens as [hidden]; people and
			// scripts see what the server sent (vault values are hidden for
			// all). `secret show --reveal` and `key show --reveal` are for
			// people only (secret_reveal.go): an agent is never asked and always sees
			// [hidden]. A dry run never approves --reveal.
			cl.out.Mask = cl.isAgent() && (revealNever[commandName(cmd)] || cl.flags.dryRun || !cl.revealOK())
			startPersonal(cmd)
			if cl.out.Mask && cl.flags.dryRun && cl.flags.reveal {
				cl.out.WouldBlock(out.Errf(out.ExitPolicy, "REVEAL_NEEDS_PERSON", "values stay [hidden] in a dry run; run it without --dry-run to ask the user in a window on their screen",
					"--reveal needs the user's yes"))
			}
			if err := startChecks(cmd); err != nil {
				return err
			}
			// after guardHome: the vault read is this home's
			return secretInArgs(cmd, args)
		},
	}
	// every command of the tree runs in cl (callOf), also before it runs
	root.SetContext(withCall(context.Background(), cl))
	// cobra's own output (help, usage, completion scripts) is the call's too
	root.SetOut(cl.out.W)
	root.SetErr(cl.out.Err)
	root.SetIn(cl.stdin)
	pf := root.PersistentFlags()
	pf.StringVarP(&cl.flags.output, "output", "o", "", "json or text (default $KOMANDO_OUTPUT, or\ntext in a terminal, JSON when piped); db query also\ntakes csv and tsv")
	pf.BoolVar(&cl.flags.pretty, "pretty", false, "indent JSON output")
	pf.BoolVar(&cl.flags.dryRun, "dry-run", false, "show what would run, changing nothing")
	pf.BoolVarP(&cl.flags.yes, "yes", "y", false, "confirm a change on a protected target (an AI agent needs a person's yes)")
	pf.BoolVar(&cl.flags.allowDangerous, "allow-dangerous", false, "run a command the safety rules would block")
	pf.BoolVar(&cl.flags.reveal, "reveal", false, "show passwords and keys in output (an agent needs a person's yes)")
	durVar(pf, &cl.flags.timeout, "timeout", 0, "time limit per server, like 30s or 1h (default: setting default_timeout, 5m)")
	durVar(pf, &cl.flags.connectTimeout, "connect-timeout", 0, "time to connect, like 30s (default: setting connect_timeout, 15s)")
	pf.IntVarP(&cl.flags.parallel, "parallel", "P", 0, "servers at once (default: setting parallel, 10)")
	pf.StringVar(&cl.flags.hostKeyPolicy, "host-key-policy", "", "accept-new, strict or off: how a server's key is checked (default: setting host_key_policy, accept-new)")
	cl.flags.maxOutput = 0
	pf.Var(&bytesFlag{i: &cl.flags.maxOutput}, "max-output", "bytes kept per stream per server, like 1MiB (default: setting max_output_bytes, 256KiB)")
	for flag, key := range map[string]string{"timeout": "default_timeout", "connect-timeout": "connect_timeout", "parallel": "parallel", "host-key-policy": "host_key_policy", "max-output": "max_output_bytes"} {
		_ = pf.SetAnnotation(flag, defaultFrom, []string{"setting:" + key})
	}

	root.SetVersionTemplate(`{{.Version}}` + "\n")
	addCommands(cl, root)
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
func addCommands(cl *call, root *cobra.Command) {
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
	add("access", vpnCmd(), loginCmd(cl), logoutCmd(cl), loginHolderCmd(), secretCmd(), keyCmd(), tunnelCmd())
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
	cl := callOf(cmd)
	if cl.out.Format == "json" { // piped: one JSON envelope, never text
		return out.Usage("komando needs a command").WithHint("read `komando guide` (the playbook for agents) or `komando schema` (every command)")
	}
	if promptable(cl, outputFlag(cl)) { // a person at a terminal: what komando does, by group
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
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			cl.out.Print("version", map[string]string{"version": Version, "home": store.Home()}, nil)
			return nil
		}),
	}
}

// outputFormat resolves auto|json|text for cl. "auto" (or empty) means
// text when the call's stdout is a terminal (a person reads it) and JSON
// for a pipe, a file or an app's writer.
func outputFormat(cl *call, v string) (string, bool) {
	switch v {
	case "json", "text":
		return v, true
	case "", "auto":
		if isTerminal(cl.out.W) {
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
func signalContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
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
		case s := <-ch:
			hardStop(s)
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

// hardStop ends komando on a second signal s, after removing this run's
// temporary files: it dies of s, so a shell that runs it (a loop) sees
// the Ctrl-C too. Tests replace it.
var hardStop = func(s os.Signal) {
	tmpclean.RemoveAll()
	signal.Reset(s)
	raise(s)
	os.Exit(130) // where a signal cannot end the process (Windows)
}
