package cli

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/cachex"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

//go:embed guide.md
var guideText string

type textBlob string

func (t textBlob) Text() string { return string(t) }

func guideCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "guide",
		Short: "Playbook for AI agents: workflow, safety rules, recipes (read this first)",
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
}

func schemaCmd(root *cobra.Command) *cobra.Command {
	var compact bool
	c := &cobra.Command{
		Use:   "schema [COMMAND...]",
		Short: "Machine-readable reference of every command, flag, exit code and selector",
		Example: `  komando schema            # everything
  komando schema exec        # one command subtree
  komando schema --compact   # paths + short descriptions only`,
		RunE: func(cmd *cobra.Command, args []string) error {
			start := root
			if len(args) > 0 {
				found, _, err := root.Find(args)
				if err != nil || found == root {
					return out.NotFound("command", strings.Join(args, " "))
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
					"4": "connection/auth/host-key failure", "5": "remote command exited non-zero",
					"6": "blocked by safety policy (needs --yes or --allow-dangerous)", "7": "timeout",
					"8": "precondition failed (e.g. replace text not found / ambiguous)",
				}
				res["target_selectors"] = map[string]string{
					"NAME":           "a host from the inventory",
					"glob":           "web-* or db-?",
					"@GROUP":         "all hosts in a group",
					"tag:TAG":        "all hosts with a tag",
					"label:KEY=VAL":  "all hosts with a label",
					"all":            "every host",
					"user@addr:port": "ad-hoc host not in the inventory",
					"a,b,!c":         "union of selectors, ! excludes",
				}
				res["secret_refs"] = "secret:NAME (vault) | env:VAR | file:PATH"
				res["env"] = map[string]string{
					"KOMANDO_HOME":       "state directory (default ~/.komando)",
					"KOMANDO_OUTPUT":     "default output format json|text",
					"KOMANDO_ACTOR":      "name recorded in the audit log (e.g. claude-agent)",
					"KOMANDO_VAULT_PASS": "vault passphrase (optional; otherwise vault.key)",
				}
			}
			out.P.Print("schema", res, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&compact, "compact", false, "only paths and short descriptions")
	return c
}

// ----------------------------------------------------------------- audit ---

func auditCmd() *cobra.Command {
	var limit int
	var host, command string
	var failed bool
	c := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log of actions taken (who, what, where, result)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := os.Open(store.Path("audit.jsonl"))
			if err != nil {
				out.P.Print("audit", map[string]any{"count": 0, "entries": []any{}}, nil)
				return nil
			}
			defer f.Close()
			var all []map[string]any
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1<<20), 16<<20)
			for sc.Scan() {
				var e map[string]any
				if json.Unmarshal(sc.Bytes(), &e) != nil {
					continue
				}
				if command != "" && !strings.HasPrefix(e["command"].(string), command) {
					continue
				}
				if failed && e["ok"] == true {
					continue
				}
				if host != "" {
					hs, _ := e["hosts"].([]any)
					cs, _ := e["conns"].([]any)
					match := false
					for _, h := range append(hs, cs...) {
						if h == host {
							match = true
						}
					}
					if !match {
						continue
					}
				}
				all = append(all, e)
			}
			if len(all) > limit {
				all = all[len(all)-limit:]
			}
			out.P.Print("audit", map[string]any{"count": len(all), "entries": all}, nil)
			return nil
		},
	}
	c.Flags().IntVarP(&limit, "limit", "n", 50, "last N entries")
	c.Flags().StringVar(&host, "host", "", "filter by host or conn name")
	c.Flags().StringVar(&command, "command", "", "filter by command prefix (e.g. exec, svc.)")
	c.Flags().BoolVar(&failed, "failed", false, "only failed/blocked actions")
	return c
}

// ---------------------------------------------------------------- config ---

func configCmd() *cobra.Command {
	c := &cobra.Command{Use: "config", Short: "Show or change settings (timeouts, parallelism, host-key policy, audit)"}
	c.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show settings and file locations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			out.P.Print("config.show", map[string]any{"settings": st.Settings, "home": store.Home(),
				"files": map[string]string{"state": store.Path("state.json"), "vault": store.Path("vault.json"), "known_hosts": sshx.KnownHostsPath(), "audit": store.Path("audit.jsonl")}}, nil)
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "set KEY VALUE",
		Short: "Set host_key_policy|default_user|default_timeout|connect_timeout|parallel|max_output_bytes|audit|audit_sql",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var res store.Settings
			err := store.Update(func(s *store.State) error {
				v := args[1]
				switch args[0] {
				case "host_key_policy":
					if v != "accept-new" && v != "strict" && v != "off" {
						return out.Usage("host_key_policy: accept-new|strict|off")
					}
					s.Settings.HostKeyPolicy = v
				case "default_user":
					s.Settings.DefaultUser = v
				case "default_timeout", "connect_timeout":
					if _, err := parseDur(v); err != nil {
						return out.Usage("invalid duration %q", v)
					}
					if args[0] == "default_timeout" {
						s.Settings.DefaultTimeout = v
					} else {
						s.Settings.ConnectTimeout = v
					}
				case "parallel", "max_output_bytes":
					n, err := strconv.Atoi(v)
					if err != nil || n <= 0 {
						return out.Usage("%s must be a positive integer", args[0])
					}
					if args[0] == "parallel" {
						s.Settings.Parallel = n
					} else {
						s.Settings.MaxOutputBytes = n
					}
				case "audit":
					s.Settings.Audit = v == "true" || v == "on" || v == "1"
				case "audit_sql":
					if v != "full" && v != "hash" && v != "off" {
						return out.Usage("audit_sql: full|hash|off (hash keeps a SHA-256 so repeated queries can be matched without storing their text)")
					}
					s.Settings.AuditSQL = v
				default:
					return out.Usage("unknown setting %q", args[0])
				}
				res = s.Settings
				return nil
			})
			if err != nil {
				return err
			}
			out.P.Print("config.set", res, nil)
			return nil
		},
	})
	return c
}

// ---------------------------------------------------------------- policy ---

func policyCmd() *cobra.Command {
	c := &cobra.Command{Use: "policy", Short: "Destructive-command guardrails: list rules, test a command, add deny patterns"}
	c.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List built-in and custom rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			var rules []map[string]string
			for _, r := range policy.Rules() {
				rules = append(rules, map[string]string{"id": r.ID, "reason": r.Reason, "pattern": policy.Pattern(r)})
			}
			out.P.Print("policy.list", map[string]any{"builtin": rules, "custom": st.Settings.ExtraDenyPattern, "sql": driver.SQLRules(), "redis": cachex.Rules(),
				"note": "guardrails catch common accidents; they are not a security boundary. Protected hosts and conns additionally need --yes for any mutating action. " +
					"SQL without --write also runs in a read-only transaction, so the database itself refuses writes."}, nil)
			return nil
		},
	})
	var kind string
	check := &cobra.Command{
		Use:   "check COMMAND",
		Short: "Test whether a shell command would be blocked, or rate SQL/Redis with --for KIND",
		Example: `  komando policy check 'rm -rf /var/www'
  komando policy check --for postgres 'delete from users'
  komando policy check --for redis FLUSHALL`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			switch kind {
			case "":
			case "redis":
				out.P.Print("policy.check", cachex.Classify(args), nil)
				return nil
			default:
				plan, err := driver.ClassifySQL(kind, strings.Join(args, " "))
				if err != nil {
					return err
				}
				out.P.Print("policy.check", plan, nil)
				return nil
			}
			hits := policy.Check(strings.Join(args, " "), st.Settings.ExtraDenyPattern)
			out.P.Print("policy.check", map[string]any{"blocked": len(hits) > 0, "matches": hits}, nil)
			return nil
		},
	}
	check.Flags().StringVar(&kind, "for", "", "rate the argument for a conn kind instead: postgres, mysql, sqlite or redis")
	c.AddCommand(check)
	c.AddCommand(&cobra.Command{
		Use:     "deny REGEX",
		Short:   "Add a custom deny pattern (Go regexp)",
		Example: `  komando policy deny 'kubectl\s+delete'`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkRegex(args[0]); err != nil {
				return out.Usage("invalid regex: %v", err)
			}
			var pats []string
			err := store.Update(func(s *store.State) error {
				s.Settings.ExtraDenyPattern = dedupe(append(s.Settings.ExtraDenyPattern, args[0]))
				pats = s.Settings.ExtraDenyPattern
				return nil
			})
			if err != nil {
				return err
			}
			out.P.Print("policy.deny", map[string]any{"custom": pats}, nil)
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "allow REGEX",
		Short: "Remove a custom deny pattern",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var pats []string
			err := store.Update(func(s *store.State) error {
				s.Settings.ExtraDenyPattern = remove(s.Settings.ExtraDenyPattern, args)
				pats = s.Settings.ExtraDenyPattern
				return nil
			})
			if err != nil {
				return err
			}
			out.P.Print("policy.allow", map[string]any{"custom": pats}, nil)
			return nil
		},
	})
	return c
}

// ---------------------------------------------------------------- doctor ---

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the local setup (state dir, vault, ssh-agent, keys, inventory)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			type check struct {
				Name   string `json:"name"`
				OK     bool   `json:"ok"`
				Detail string `json:"detail"`
			}
			var checks []check
			st, err := loadState()
			checks = append(checks, check{"state", err == nil, store.Home()})
			if err != nil {
				out.P.Print("doctor", map[string]any{"checks": checks}, toErr(err))
				return exitCode(1)
			}
			checks = append(checks, check{"hosts", len(st.Hosts) > 0, strconv.Itoa(len(st.Hosts)) + " host(s); add with `komando host add` or `komando host import`"})
			checks = append(checks, check{"keys", true, strconv.Itoa(len(st.Keys)) + " key(s) in keychain"})
			sock := os.Getenv("SSH_AUTH_SOCK")
			checks = append(checks, check{"ssh_agent", sock != "", map[bool]string{true: sock, false: "not running (optional)"}[sock != ""]})
			for _, k := range st.Keys {
				_, err := os.Stat(k.Path)
				checks = append(checks, check{"key:" + k.Name, err == nil, k.Path})
			}
			for _, h := range st.SortedHosts() {
				if h.Key != "" {
					if _, ok := st.Keys[h.Key]; !ok {
						checks = append(checks, check{"host:" + h.Name, false, "references missing key " + h.Key})
					}
				}
			}
			_, sshErr := exec.LookPath("ssh")
			checks = append(checks, check{"openssh_client", sshErr == nil, "optional; komando has a built-in SSH client"})
			checks = append(checks, check{"platform", true, runtime.GOOS + "/" + runtime.GOARCH})
			ok := true
			for _, c := range checks {
				if !c.OK && c.Name != "ssh_agent" && c.Name != "openssh_client" && c.Name != "hosts" {
					ok = false
				}
			}
			var soft *out.Error
			if !ok {
				soft = out.Errf(out.ExitError, "DOCTOR_FAILED", "fix the failing checks above", "some checks failed")
			}
			out.P.Print("doctor", map[string]any{"checks": checks}, soft)
			if soft != nil {
				return exitCode(1)
			}
			return nil
		},
	}
}
