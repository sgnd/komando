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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
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
	root := newRoot()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	cmd, err := root.ExecuteContextC(ctx)
	if err == nil {
		return 0
	}
	var ec exitCode
	if errors.As(err, &ec) {
		return int(ec)
	}
	name := "komando"
	if cmd != nil {
		name = commandName(cmd)
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
		if personSaidNo && oe.Exit == out.ExitPolicy {
			oe.Message = "cancelled: " + oe.Message
			oe.Hint = "nothing was changed"
			oe.Cancel(cancelledText()) // text mode: the person's own choice, not an error
		}
		if cmd != nil && out.P.Format == "text" {
			notFoundSay(oe, topCommand(cmd))
		}
	}
	return out.P.Fail(name, err)
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
	if name, ok := quotedAfter(m, "unknown command "); ok {
		e.Message = fmt.Sprintf("unknown command %q", name)
		if s := cmd.SuggestionsFor(name); len(s) > 0 {
			e.Message += "; did you mean " + strings.Join(s, " or ") + "?"
			e.Hint = "see `" + cmd.CommandPath() + " " + s[0] + " --help`"
		} else {
			e.Hint = "see `" + cmd.CommandPath() + " --help` for the list of commands"
		}
		return e
	}
	if flag, ok := strings.CutPrefix(m, "unknown flag: "); ok {
		if s := closestFlag(cmd, strings.TrimLeft(flag, "-")); s != "" {
			e.Message += "; did you mean --" + s + "?"
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

// closestFlag is the flag of cmd (its own or inherited) nearest to a
// mistyped name, or "" when none is near enough to be a typo.
func closestFlag(cmd *cobra.Command, typed string) string {
	best, bestD := "", 3 // more than 2 typos is not a typo
	var prefixed []string
	visit := func(f *pflag.Flag) {
		if f.Hidden || f.Deprecated != "" {
			return
		}
		if d := editDistance(typed, f.Name); d < bestD {
			best, bestD = f.Name, d
		}
		if len(typed) >= 3 && strings.HasPrefix(f.Name, typed) {
			prefixed = append(prefixed, f.Name)
		}
	}
	cmd.Flags().VisitAll(visit)
	cmd.InheritedFlags().VisitAll(visit)
	if best == "" && len(prefixed) == 1 {
		best = prefixed[0] // --conn for --connect-timeout
	}
	return best
}

func firstExample(cmd *cobra.Command) string {
	for _, l := range strings.Split(cmd.Example, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			if i := strings.Index(l, "  #"); i > 0 {
				l = strings.TrimSpace(l[:i])
			}
			// a typo is no reason to hand an AI agent a flag that skips a
			// safety stop: the first example without one
			if approvalFlag.MatchString(l) {
				continue
			}
			return l
		}
	}
	return ""
}

// approvalFlag: --yes, -y, --allow-dangerous or --reveal on a command line.
var approvalFlag = regexp.MustCompile(`(^|\s)(--yes|-y|--allow-dangerous|--reveal)(\s|=|$)`)

func isUsageErr(err error) bool {
	m := err.Error()
	for _, s := range []string{"unknown flag", "unknown command", "accepts ", "requires at least", "required flag", "invalid argument", "flag needs an argument", "unknown shorthand"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

func commandName(c *cobra.Command) string {
	p := strings.TrimPrefix(c.CommandPath(), "komando")
	p = strings.TrimSpace(p)
	if p == "" {
		return "komando"
	}
	return strings.ReplaceAll(p, " ", ".")
}

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

// localReads change nothing anywhere, so they run even when the audit log
// is broken; that is how a person finds out what is wrong.
var localReads = map[string]bool{
	"version": true, "help": true, "completion": true, "schema": true, "guide": true, "doctor": true,
	"audit": true, "list": true, "config.show": true, "policy.list": true, "policy.check": true,
	"conn.kinds": true, "conn.show": true, "host.show": true, "vpn.show": true, "key.list": true,
	"key.show": true, "secret.list": true, "group.list": true, "recipe.list": true, "vpn.status": true,
	"tunnel.list": true, "job.list": true, "status": true,
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
// (guardHome), closing idle VPNs, --host-key-policy off and the audit log.
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
	return checkAuditWritable(cmd)
}

// checkAuditWritable refuses to run when the audit log is on but cannot be
// written: changes must not happen without a record (docs/design/ux.md §6).
func checkAuditWritable(cmd *cobra.Command) error {
	name := commandName(cmd)
	top, _, _ := strings.Cut(name, ".")
	if g.dryRun || cmd.Hidden || name == "komando" || localReads[name] || leavesHomeNow(cmd) || top == "help" || top == "completion" {
		return nil
	}
	st, err := store.Load()
	if err != nil || !st.Settings.Audit {
		return nil // a broken state file shows its own error in the command
	}
	f, err := os.OpenFile(store.Path("audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return out.Errf(out.ExitError, "AUDIT_UNAVAILABLE", "fix the file or folder permissions (`komando doctor` checks them); nothing was run",
			"the audit log cannot be written: %v", err)
	}
	return f.Close()
}

func newRoot() *cobra.Command {
	resetApproval()
	out.P.Reset()
	personSaidNo, askedAbout = false, nil
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
			safetyApproved = map[string]bool{} // answers count for one command only
			dangerConfirmed = map[string]bool{}
			if err := pickTableOutput(cmd); err != nil {
				return err
			}
			f, ok := outputFormat(g.output)
			if !ok {
				if !cmd.Flags().Changed("output") && os.Getenv("KOMANDO_OUTPUT") != "" {
					return out.Usage("KOMANDO_OUTPUT=%s: it must be auto, json or text", os.Getenv("KOMANDO_OUTPUT"))
				}
				return out.Usage("--output must be auto, json or text (db query also takes csv and tsv)")
			}
			switch {
			case g.parallel < 0:
				return out.Usage("-P/--parallel must be 1 or more (0 means the setting, default 10)")
			case g.timeout < 0, g.connectTimeout < 0:
				return out.Usage("--timeout and --connect-timeout must be positive, e.g. 30s or 5m")
			case g.maxOutput < 0:
				return out.Usage("--max-output must be a number of bytes, e.g. 1048576")
			}
			out.P.Format = f
			out.P.Pretty = g.pretty
			out.P.Version = Version
			out.P.DryRun = g.dryRun
			store.DryRun = g.dryRun
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
			out.P.Mask = isAgent() && (commandName(cmd) == "secret.get" || g.dryRun || !revealOK())
			startPersonal(cmd)
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
	pf.BoolVarP(&g.yes, "yes", "y", false, "answer yes in advance, for scripts")
	pf.BoolVar(&g.allowDangerous, "allow-dangerous", false, "run a command the safety rules would block")
	pf.BoolVar(&g.reveal, "reveal", false, "show passwords and keys in output (an agent needs a person's yes)")
	pf.DurationVar(&g.timeout, "timeout", 0, "time limit per server (default: setting, 5m)")
	pf.DurationVar(&g.connectTimeout, "connect-timeout", 0, "time to connect (default: setting, 15s)")
	pf.IntVarP(&g.parallel, "parallel", "P", 0, "servers at once (default: setting, 10)")
	pf.StringVar(&g.hostKeyPolicy, "host-key-policy", "", "accept-new, strict or off: how a server's key is checked (default: setting, accept-new)")
	pf.IntVar(&g.maxOutput, "max-output", 0, "bytes kept per stream per server (default: setting, 256KiB)")

	root.SetVersionTemplate(`{{.Version}}` + "\n")
	root.AddGroup(
		&cobra.Group{ID: "inv", Title: "Inventory & credentials:"},
		&cobra.Group{ID: "run", Title: "Remote execution:"},
		&cobra.Group{ID: "data", Title: "Databases, caches, queues & storage:"},
		&cobra.Group{ID: "ops", Title: "DevOps modules:"},
		&cobra.Group{ID: "meta", Title: "Agent helpers & config:"},
	)
	add := func(group string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = group
			root.AddCommand(c)
		}
	}
	add("inv", listCmd(), testCmd(), importCmd(), exportCmd(), hostCmd(), connCmd(), vpnCmd(), groupCmd(), keyCmd(), secretCmd(), renameCmd(), loginCmd(), logoutCmd(), loginHolderCmd())
	add("run", execCmd(), scriptCmd(), jobCmd(), fsCmd(), uploadCmd(), downloadCmd(), cpCmd(), syncCmd(), tunnelCmd(), shellCmd(), recipeCmd())
	add("data", dbCmd(), cacheCmd(), queueCmd(), storageCmd(), clusterCmd(), registryCmd())
	add("ops", factsCmd(), svcCmd(), rebootCmd(), logsCmd(), dockerCmd(), pkgCmd(), netCmd(), userCmd(), cronCmd(), certCmd())
	add("meta", statusCmd(), promptCmd(), schemaCmd(root), guideCmd(), auditCmd(), configCmd(), policyCmd(), doctorCmd(), updateCmd(), versionCmd(), sshGateCmd())
	applyConventions(root)
	useShortGlobals(root)
	addCompletion(root)
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	labelBuiltinCmds(root)
	return root
}

// labelBuiltinCmds files cobra's own help and completion commands under
// "meta" and gives them komando's wording.
func labelBuiltinCmds(root *cobra.Command) {
	for _, c := range root.Commands() {
		switch c.Name() {
		case "help":
			c.GroupID = "meta"
			c.Short = "Show the help of a command"
			c.Long = "Shows what a command does, its flags and examples: komando help db query\n(the same as komando db query --help)."
		case "completion":
			c.GroupID = "meta"
			c.Short = "Print a tab-completion script for your shell"
			c.Long = "Prints a script that lets Tab complete komando's commands, flags and names\nin bash, zsh, fish or PowerShell. Each one's help says how to load it:\nkomando completion zsh --help."
		}
	}
}

// rootLong is the top of `komando --help`: what komando is, then the first
// commands a person types. The notes for scripts come after the command
// list (rootScriptNotes).
const rootLong = `komando is one safe command line for servers, databases, caches, storage,
clusters and registries, for people and AI agents alike.

First steps:
  komando                                  a menu of common tasks (in a terminal)
  komando host add web1 ubuntu@203.0.113.10
  komando test web1                        check that web1 answers
  komando guide install                    let your AI agent use komando safely

Targets: a server or service name, a pattern (web-*), @group, tag:NAME,
label:key=value, kind:KIND (host, db, cache, storage, postgres, ...), all, or
user@addr:port for a server you have not added. Combine with commas; put ! in
front to leave one out. See them all with ` + "`komando list`" + `.`

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

// printFirstSteps is `komando` alone: the menu for a person at a terminal
// (menu.go), else the first steps, not a wall of text (ux.md, section 10).
func printFirstSteps(cmd *cobra.Command, args []string) error {
	if out.P.Format == "json" { // piped: one JSON envelope, never text
		return out.Usage("komando needs a command").WithHint("read `komando guide` (the playbook for agents) or `komando schema` (every command)")
	}
	if menuWanted(cmd, args) {
		return runMenu()
	}
	_, err := fmt.Fprint(cmd.OutOrStdout(), firstSteps)
	return err
}

// firstSteps is what `komando` alone prints.
const firstSteps = `komando: one safe command line for servers, databases, caches, queues, storage, clusters and VPNs.

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
