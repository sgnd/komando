// Package cli wires every komando command. Design rules for AI agents:
//   - stdout is always exactly one JSON envelope (or NDJSON when streaming)
//   - nothing ever prompts; missing input is an error with a hint
//   - exit codes are stable (see internal/out)
//   - destructive actions require explicit flags; everything is audited
package cli

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

var Version = "dev"

type globalFlags struct {
	output         string
	pretty         bool
	dryRun         bool
	yes            bool
	allowDangerous bool
	timeout        time.Duration
	connectTimeout time.Duration
	parallel       int
	hostKeyPolicy  string
	maxOutput      int
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
	var oe *out.Error
	if !errors.As(err, &oe) && isUsageErr(err) {
		err = out.Usage("%s", err.Error())
	}
	return out.P.Fail(name, err)
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

func commandName(c *cobra.Command) string {
	p := strings.TrimPrefix(c.CommandPath(), "komando")
	p = strings.TrimSpace(p)
	if p == "" {
		return "komando"
	}
	return strings.ReplaceAll(p, " ", ".")
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "komando",
		Short: "Agent-first SSH & server operations CLI (Termius for AI agents)",
		Long: `komando lets AI agents (and humans) manage fleets of servers from a pure CLI.

When piped (how agents call it) every command prints one JSON envelope on
stdout; in an interactive terminal it prints readable text (force with -o json|text):
  {"ok":true,"command":"exec","data":{...},"meta":{...}}
  {"ok":false,"command":"exec","error":{"code":"AUTH_FAILED","message":"...","hint":"..."}}

Exit codes: 0 ok, 1 error, 2 usage, 3 not found, 4 connect/auth, 5 remote non-zero,
            6 policy blocked, 7 timeout, 8 precondition/conflict.

Targets (for exec, fs, svc, ops, ...): host name, glob (web-*), @group, tag:NAME,
label:key=value, all, user@addr:port (ad-hoc). Combine with commas; prefix ! to exclude.

Start here:  komando guide      (agent playbook)
             komando schema     (machine-readable command reference)`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			f, ok := outputFormat(g.output)
			if !ok {
				return out.Usage("--output must be auto, json or text")
			}
			out.P.Format = f
			out.P.Pretty = g.pretty
			out.P.Version = Version
			out.P.DryRun = g.dryRun
			out.P.Start = time.Now()
			return nil
		},
	}
	pf := root.PersistentFlags()
	defOut := "auto"
	if v := os.Getenv("KOMANDO_OUTPUT"); v != "" {
		defOut = v
	}
	pf.StringVarP(&g.output, "output", "o", defOut, "auto|json|text; auto = text in a terminal, JSON when piped (env KOMANDO_OUTPUT)")
	pf.BoolVar(&g.pretty, "pretty", false, "indent JSON output")
	pf.BoolVar(&g.dryRun, "dry-run", false, "show what would run without changing anything")
	pf.BoolVarP(&g.yes, "yes", "y", false, "confirm mutating actions on protected hosts")
	pf.BoolVar(&g.allowDangerous, "allow-dangerous", false, "allow commands matching destructive-command policy")
	pf.DurationVar(&g.timeout, "timeout", 0, "per-host command timeout (default from settings, 5m)")
	pf.DurationVar(&g.connectTimeout, "connect-timeout", 0, "SSH connect timeout (default from settings, 15s)")
	pf.IntVarP(&g.parallel, "parallel", "P", 0, "max hosts in parallel (default from settings, 10)")
	pf.StringVar(&g.hostKeyPolicy, "host-key-policy", "", "accept-new|strict|off (default from settings)")
	pf.IntVar(&g.maxOutput, "max-output", 0, "max bytes captured per stream per host (default 256KiB)")

	root.SetVersionTemplate(`{{.Version}}` + "\n")
	root.AddGroup(
		&cobra.Group{ID: "inv", Title: "Inventory & credentials:"},
		&cobra.Group{ID: "run", Title: "Remote execution:"},
		&cobra.Group{ID: "data", Title: "Databases, caches & storage:"},
		&cobra.Group{ID: "ops", Title: "DevOps modules:"},
		&cobra.Group{ID: "meta", Title: "Agent helpers & config:"},
	)
	add := func(group string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = group
			root.AddCommand(c)
		}
	}
	add("inv", hostCmd(), connCmd(), groupCmd(), keyCmd(), secretCmd())
	add("run", execCmd(), scriptCmd(), jobCmd(), fsCmd(), cpCmd(), tunnelCmd(), shellCmd(), snippetCmd())
	add("data", dbCmd())
	add("ops", factsCmd(), opsCmd(), svcCmd(), logsCmd(), dockerCmd(), pkgCmd(), netCmd(), userCmd(), cronCmd())
	add("meta", schemaCmd(root), guideCmd(), auditCmd(), configCmd(), policyCmd(), doctorCmd(), versionCmd())
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()
	for _, c := range root.Commands() {
		if c.Name() == "help" || c.Name() == "completion" {
			c.GroupID = "meta"
		}
	}
	return root
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
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
