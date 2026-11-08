package cli

import (
	_ "embed"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/vault"
)

//go:embed guide.md
var guideText string

type textBlob string

func (t textBlob) Text() string { return string(t) }

func guideCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "guide",
		Short: "Playbook for AI agents: workflow and safety rules (read first)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if out.P.Format == "text" {
				out.P.Print("guide", textBlob(guideText), nil)
				return nil
			}
			out.P.Print("guide", map[string]string{"format": "markdown", "content": guideText}, nil)
			return nil
		},
	}
	c.AddCommand(guideInstallCmd(), guideGuardCmd())
	return c
}

// skillText is the komando agent skill (SKILL.md, the Agent Skills format).
// skills/komando/SKILL.md in the repository is a copy of it.
//
//go:embed skill.md
var skillText string

// skillDirs are the folders AI agents read skills from: Claude Code reads
// .claude/skills, Codex, Cursor, Gemini CLI and others read .agents/skills.
var skillDirs = []string{".claude/skills", ".agents/skills"}

type skillFile struct {
	Path   string `json:"path"`
	Action string `json:"action"` // created | updated | unchanged
	Backup string `json:"backup,omitempty"`
	Note   string `json:"note,omitempty"`
}

func guideInstallCmd() *cobra.Command {
	var project, noGuard bool
	c := &cobra.Command{
		Use:   "install",
		Short: "Add the komando skill to Claude Code, Codex, Cursor, Gemini CLI",
		Long: `Adds the komando skill (komando/SKILL.md) to the folders AI agents read
skills from: ~/.claude/skills (Claude Code) and ~/.agents/skills (Codex,
Cursor, Gemini CLI and others). The agent then uses komando by itself whenever
a task touches a server, database, cache or storage.

It also adds a guard: before the agent reads a file or runs a shell command
on this computer, komando checks it and stops the ones that would read
secrets: ~/.komando, private keys, .env files, credential stores, all
environment variables at once, or ssh around komando. It goes into Claude
Code (.claude/settings.json), and into Cursor (.cursor/hooks.json), Gemini
CLI (.gemini/settings.json, v0.26+) and Codex (.codex/hooks.json; approve it
once in /hooks) where their folders exist. Skip it with --no-guard.

Safe to run again, for example after an update: a changed file is kept as
.bak. Remove the skill by deleting the komando folders, and the guard by
deleting its entry under hooks in .claude/settings.json.`,
		Example: `  komando guide install             # for every project on this computer
  komando guide install --project   # only for the folder you are in
  komando guide install --dry-run   # show where it would go`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			base, err := os.UserHomeDir()
			if project {
				base, err = os.Getwd()
			}
			if err != nil {
				return out.Errf(out.ExitError, "NO_FOLDER", "set HOME, or run it from the project folder", "cannot find the folder to install into: %v", err)
			}
			var files []skillFile
			for _, d := range skillDirs {
				f, err := installSkill(filepath.Join(base, d, "komando", "SKILL.md"), g.dryRun)
				if err != nil {
					return out.Errf(out.ExitError, "WRITE_FAILED", "check that you may write to this folder", "%v", err)
				}
				files = append(files, f)
			}
			if !noGuard {
				// Claude Code asks komando before each tool call (guard.go)
				f, err := installGuardHook(filepath.Join(base, ".claude", "settings.json"), komandoPath(), g.dryRun)
				if err != nil {
					return out.Errf(out.ExitError, "WRITE_FAILED", "fix the file, or pass --no-guard to skip the guard", "%v", err)
				}
				files = append(files, f)
				// the other agents, where the person uses them
				for _, h := range agentHooks {
					dir := filepath.Join(base, h.dir)
					if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
						continue
					}
					f, err := installAgentHook(filepath.Join(dir, h.file), h.add, shellQuote(komandoPath())+" guide guard --for "+h.name, g.dryRun)
					if err != nil {
						return out.Errf(out.ExitError, "WRITE_FAILED", "fix the file, or pass --no-guard to skip the guard", "%v", err)
					}
					if h.name == "codex" && f.Action != "unchanged" {
						f.Note = "open /hooks in Codex once to approve it"
					}
					files = append(files, f)
				}
			}
			out.P.Print("guide.install", skillResult{Files: files}, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&project, "project", false, "install into the current folder instead of your home folder")
	c.Flags().BoolVar(&noGuard, "no-guard", false, "do not add the guard that keeps AI agents away from secret files on this computer")
	return c
}

type skillResult struct {
	Files []skillFile `json:"files"`
}

func (r skillResult) Text() string {
	var b strings.Builder
	for _, f := range r.Files {
		b.WriteString(f.Action + "  " + f.Path + "\n")
		if f.Backup != "" {
			b.WriteString("  old version kept as " + f.Backup + "\n")
		}
		if f.Note != "" {
			b.WriteString("  " + f.Note + "\n")
		}
	}
	b.WriteString("Restart your AI agent so it sees the skill.")
	return b.String()
}

func installSkill(path string, dryRun bool) (skillFile, error) {
	f := skillFile{Path: path, Action: "created"}
	old, err := os.ReadFile(path)
	switch {
	case err == nil && string(old) == skillText:
		f.Action = "unchanged"
		return f, nil
	case err == nil:
		f.Action, f.Backup = "updated", path+".bak"
	case !errors.Is(err, fs.ErrNotExist):
		return f, err
	}
	if dryRun {
		return f, nil
	}
	if f.Backup != "" {
		if err := os.WriteFile(f.Backup, old, 0o644); err != nil {
			return f, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return f, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(skillText), 0o644); err != nil {
		return f, err
	}
	return f, os.Rename(tmp, path)
}

// ---------------------------------------------------------------- schema ---

type flagSchema struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Type      string `json:"type"`
	Default   string `json:"default,omitempty"`
	Usage     string `json:"usage"`
}

type cmdSchema struct {
	Path     string       `json:"path"`
	Usage    string       `json:"usage"`
	Short    string       `json:"short"`
	Long     string       `json:"long,omitempty"`
	Aliases  []string     `json:"aliases,omitempty"`
	Example  string       `json:"example,omitempty"`
	Flags    []flagSchema `json:"flags,omitempty"`
	Runnable bool         `json:"runnable"`
	Kind     string       `json:"kind,omitempty"`      // read, change or depends (kinds.go)
	KindNote string       `json:"kind_note,omitempty"` // on what, for depends
}

func schemaCmd(root *cobra.Command) *cobra.Command {
	var compact bool
	c := &cobra.Command{
		Use:   "schema [COMMAND...]",
		Short: "Every command, flag and exit code, machine-readable",
		Example: `  komando schema            # everything
  komando schema exec        # one command subtree
  komando schema host.add    # one command, as named in the envelope
  komando schema --compact   # paths + short descriptions only`,
		RunE: func(cmd *cobra.Command, args []string) error {
			start := root
			if len(args) == 1 && strings.Contains(args[0], ".") {
				args = strings.Split(args[0], ".") // host.add, as in the envelope's command
			}
			if len(args) > 0 {
				found, rest, err := root.Find(args)
				if err != nil || found == root || len(rest) > 0 {
					return out.Errf(out.ExitNotFound, "COMMAND_NOT_FOUND", "run `komando schema --compact` to see every command",
						"no command %q", strings.Join(args, " "))
				}
				start = found
			}
			var cmds []any
			var walk func(c *cobra.Command)
			walk = func(c *cobra.Command) {
				if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
					return
				}
				if c != root {
					if compact {
						cmds = append(cmds, map[string]string{"path": c.CommandPath(), "short": c.Short})
					} else {
						s := cmdSchema{Path: c.CommandPath(), Usage: c.UseLine(), Short: c.Short, Long: c.Long, Aliases: c.Aliases, Example: c.Example, Runnable: c.Runnable()}
						if k, ok := kindOf(c); ok && s.Runnable {
							s.Kind, s.KindNote = k.Kind, k.Note
						}
						c.LocalFlags().VisitAll(func(f *pflag.Flag) {
							if f.Hidden || f.Name == "help" {
								return
							}
							s.Flags = append(s.Flags, flagSchema{f.Name, f.Shorthand, f.Value.Type(), f.DefValue, f.Usage})
						})
						cmds = append(cmds, s)
					}
				}
				for _, sub := range c.Commands() {
					walk(sub)
				}
			}
			walk(start)
			var globals []flagSchema
			root.PersistentFlags().VisitAll(func(f *pflag.Flag) {
				globals = append(globals, flagSchema{f.Name, f.Shorthand, f.Value.Type(), f.DefValue, f.Usage})
			})
			res := map[string]any{
				"name":     "komando",
				"version":  Version,
				"contract": out.Contract,
				"commands": cmds,
			}
			if start == root {
				res["global_flags"] = globals
				res["envelope"] = map[string]string{
					"ok":      "bool: true on full success",
					"command": "dotted command name",
					"data":    "command-specific result; multi-host commands use data.results[] + data.summary",
					"error":   "{code, message, hint} when ok=false (data may still be present for partial failures)",
					"meta":    "{version, duration_ms, dry_run}",
				}
				res["exit_codes"] = map[string]string{
					"0": "success", "1": "generic error", "2": "usage error", "3": "not found",
					"4": "connection/auth/host-key failure, or the connection broke mid-command (CONNECTION_LOST: outcome unknown)", "5": "remote command exited non-zero",
					"6": "blocked by safety policy (needs --yes or --allow-dangerous)", "7": "timeout",
					"8": "precondition failed (e.g. replace text not found / ambiguous)",
				}
				res["target_selectors"] = map[string]string{
					"NAME":           "a server, conn or VPN from the inventory",
					"glob":           "web-* or db-?",
					"@GROUP":         "everything in a group (servers and conns)",
					"tag:TAG":        "everything with a tag",
					"label:KEY=VAL":  "everything with a label (label:KEY = any value)",
					"kind:KIND":      "by type: host, conn, vpn, a conn kind (postgres, redis, s3, ...), a command family (db, cache, storage, cluster, registry) or a VPN kind",
					"all":            "everything in the inventory",
					"user@addr:port": "ad-hoc server not in the inventory",
					"a,b,!c":         "union of selectors, ! excludes",
				}
				res["selector_note"] = "a selector picks servers and conns together; each command uses the ones it works with and lists the rest in meta.skipped"
				res["secret_refs"] = strings.Join(vault.Refs, " | ") // a string since contract 1
				res["secret_ref_list"] = vault.Refs
				res["env"] = map[string]string{
					"KOMANDO_HOME":       "state directory (default ~/.komando)",
					"KOMANDO_OUTPUT":     "default output format json|text",
					"KOMANDO_ACTOR":      "name recorded in the audit log (e.g. claude-agent)",
					"KOMANDO_VAULT_PASS": "vault passphrase (optional; otherwise vault.key or the OS keychain; komando secret passphrase sets or changes it)",
				}
			}
			out.P.Print("schema", res, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&compact, "compact", false, "only paths and short descriptions")
	return c
}
