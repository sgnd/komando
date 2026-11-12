package cli

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cachex"
	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/store"
)

type policyCheck struct {
	Blocked bool          `json:"blocked"`
	Matches []policy.Rule `json:"matches"`
}

func (p policyCheck) Text() string {
	if !p.Blocked {
		return "Allowed: no rule blocks this command.\n"
	}
	reasons := make([]string, len(p.Matches))
	for i, m := range p.Matches {
		reasons[i] = m.Reason + " (rule " + m.ID + ")"
	}
	return "Blocked: " + strings.Join(reasons, "; ") + "\n"
}

func policyCmd() *cobra.Command {
	c := &cobra.Command{Use: "policy", Short: "Rules that block destructive commands: see, test, add, remove"}
	var limit int
	list := &cobra.Command{
		Use:   "list",
		Short: "List built-in and custom rules",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			var rules []map[string]string
			for _, r := range shellRulesByID() {
				rules = append(rules, map[string]string{"id": r.ID, "reason": r.Reason, "pattern": policy.Pattern(r)})
			}
			var custom []map[string]string
			bad := policy.Invalid(st.Settings.ExtraDenyPattern)
			for i, p := range st.Settings.ExtraDenyPattern {
				r := map[string]string{"id": policy.CustomID(p), "pattern": p}
				if why, ok := bad[i]; ok {
					r["error"] = why
				}
				custom = append(custom, r)
			}
			n := limit // each kind of rule stops at --limit
			out.P.Print("policy.list", policyList{"builtin": cutRows(rules, n), "custom": cutRows(st.Settings.ExtraDenyPattern, n), "custom_rules": cutRows(custom, n),
				"sql": cutRows(rulesByID(driver.SQLRules()), n), "redis": cutRows(rulesByID(cachex.Rules()), n), "memcached": cutRows(rulesByID(cachex.MemcacheRules()), n),
				"mongodb": cutRows(rulesByID(dbx.MongoRules()), n), "queue": cutRows(rulesByID(queuePolicyRules()), n), "data": cutRows(rulesByID(driver.DataRules()), n),
				"note": "these rules catch common accidents; they are not a security boundary. Protected servers and conns also need --yes for any change. " +
					"SQL without --write also runs in a read-only transaction, so the database itself refuses writes."}, nil)
			return nil
		},
	}
	limitFlag(list, &limit, 0, "rules of each kind")
	c.AddCommand(list)
	c.AddCommand(policyCheckCmd())
	c.AddCommand(&cobra.Command{
		Use:     "deny REGEX",
		Aliases: []string{"add"},
		Short:   "Add a custom deny pattern (Go regexp)",
		Example: `  komando policy deny 'kubectl\s+delete'`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pat := args[0]
			if strings.TrimSpace(pat) == "" {
				return out.Errf(out.ExitUsage, "USAGE", `give a regular expression, for example 'kubectl\s+delete'`, "empty pattern: it would match every command")
			}
			if err := checkRegex(pat); err != nil {
				return out.Errf(out.ExitUsage, "USAGE", "the pattern is a Go regular expression (https://pkg.go.dev/regexp/syntax)", "komando cannot read the pattern: %v", err)
			}
			if regexp.MustCompile(pat).MatchString("") {
				return out.Errf(out.ExitUsage, "USAGE", `give a pattern that needs some text to match, for example 'kubectl\s+delete'`, "the pattern %s matches empty text, so it would match every command", pat)
			}
			var pats []string
			added := false
			err := store.Update(func(s *store.State) error {
				added = !slices.Contains(s.Settings.ExtraDenyPattern, pat)
				if added {
					s.Settings.ExtraDenyPattern = append(s.Settings.ExtraDenyPattern, pat)
				}
				pats = s.Settings.ExtraDenyPattern
				return nil
			})
			if err != nil {
				return err
			}
			if added {
				audit(nil, "policy.deny", nil, "", true, map[string]any{"pattern": pat})
			}
			out.P.Print("policy.deny", policyChange{Custom: pats, Added: &added, pattern: pat}.denied(), nil)
			return nil
		},
	})
	c.AddCommand(policyRmCmd())
	return c
}

// policyCheckCmd is `policy check`: whether a shell command would be
// blocked, or with --conn-kind how risky a statement is for a conn kind.
func policyCheckCmd() *cobra.Command {
	var kind string
	check := &cobra.Command{
		Use:   "check COMMAND",
		Short: "Check whether a command would be blocked",
		Example: `  komando policy check 'rm -rf /var/www'
  if komando policy check "$CMD" >/dev/null; then echo allowed; fi
  komando policy check --conn-kind postgres 'delete from users'
  komando policy check --conn-kind redis FLUSHALL`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			kind = strings.ToLower(kind)
			var rated any
			var v driver.Verdict
			switch {
			case kind == "":
			case kind == "redis" || kind == "memcached":
				// one quoted argument ("CLIENT LIST") is split as cache run splits it
				words, err := cachex.SplitCommand(args)
				if err != nil {
					return out.Usage("%v", err)
				}
				v = cachex.ClassifyFor(kind, words)
				rated = v
			case kind == "mongodb":
				doc, _, err := dbx.ParseMongoCommand(strings.Join(args, " "))
				if err != nil {
					return err
				}
				v = dbx.ClassifyMongo(doc)
				rated = v
			case slices.Contains(driver.SQLKinds(), kind):
				plan, err := driver.ClassifySQL(kind, strings.Join(args, " "))
				if err != nil {
					return err
				}
				v, rated = plan.Verdict, plan
			default:
				return out.Errf(out.ExitUsage, "USAGE", "--conn-kind takes one of: "+strings.Join(policyCheckKinds(), ", "),
					"--conn-kind %q is not a kind komando rates", kind)
			}
			if rated != nil {
				if v.Risk != driver.RiskDestructive {
					out.P.Print("policy.check", rated, nil)
					return nil
				}
				why := "destructive"
				if len(v.RuleIDs) > 0 {
					why = "blocked by [" + strings.Join(v.RuleIDs, ",") + "]"
				}
				out.P.Print("policy.check", rated, out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "komando would refuse to run it without --allow-dangerous", "%s", why))
				return exitCode(out.ExitPolicy)
			}
			hits := policy.Check(strings.Join(args, " "), st.Settings.ExtraDenyPattern)
			res := policyCheck{Blocked: len(hits) > 0, Matches: hits}
			if !res.Blocked {
				out.P.Print("policy.check", res, nil)
				return nil
			}
			ids := make([]string, len(hits))
			for i, h := range hits {
				ids[i] = h.ID
			}
			out.P.Print("policy.check", res, out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "komando would refuse to run it without --allow-dangerous",
				"blocked by [%s]", strings.Join(ids, ",")))
			return exitCode(out.ExitPolicy)
		},
	}
	check.Flags().StringVar(&kind, "conn-kind", "", "rate the argument for a conn kind instead: "+strings.Join(policyCheckKinds(), ", ")+" (a command document as JSON)")
	retiredFlag(check, "for", "conn-kind")
	return check
}

// policyCheckKinds are the kinds policy check --conn-kind rates.
func policyCheckKinds() []string {
	return append(driver.SQLKinds(), "redis", "memcached", "mongodb")
}

// policyRmCmd removes a rule added with policy deny.
func policyRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm RULE",
		Short: "Remove a deny rule you added (from komando only)",
		Long: `Removes a rule added with ` + "`policy deny`" + `. Give it as you wrote it, or by
its id in ` + "`policy list`" + ` (custom- and eight letters and digits, made from
the pattern, so it does not change when another rule goes). Built-in rules
cannot be removed. Removing a rule weakens a safety check, so komando asks first.`,
		Example: `  komando policy rm 'kubectl\s+delete'
  komando policy rm custom-1a2b3c4d`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			arg := args[0]
			for _, r := range policy.Rules() {
				if r.ID == arg {
					return out.Errf(out.ExitUsage, "BUILTIN_RULE", "built-in rules always apply (see them with `komando policy list`); for one intended command, confirm with the user and pass --allow-dangerous",
						"%s is a built-in rule and cannot be removed", arg)
				}
			}
			var pats []string
			removed := ""
			err := store.Update(func(s *store.State) error {
				list := s.Settings.ExtraDenyPattern
				i := slices.Index(list, arg)
				if i < 0 {
					i = slices.IndexFunc(list, func(p string) bool { return policy.CustomID(p) == arg })
				}
				if i < 0 {
					hint := "see the custom rules and their ids with `komando policy list`"
					if len(list) == 0 {
						hint = "there are no custom rules; built-in ones cannot be removed"
					}
					return out.Errf(out.ExitNotFound, "RULE_NOT_FOUND", hint, "no custom deny rule named %q", arg)
				}
				removed = list[i]
				if err := guardSafety("removing the deny rule " + removed); err != nil {
					return err
				}
				s.Settings.ExtraDenyPattern = slices.Delete(slices.Clone(list), i, i+1)
				pats = s.Settings.ExtraDenyPattern
				return nil
			})
			if err != nil {
				return err
			}
			audit(nil, "policy.rm", nil, "", true, map[string]any{"pattern": removed})
			out.P.Print("policy.rm", policyChange{Custom: orEmpty(pats), Removed: removed}, nil)
			return nil
		},
	}
}

// policyList is `policy list`: every rule as data; for people a table of
// what each rule stops (the patterns are in -o json).
type policyList map[string]any

// rulesByID and shellRulesByID sort rules by ID, so policy list reads like
// the other lists.
func rulesByID(rs []driver.Rule) []driver.Rule {
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	return rs
}

func shellRulesByID() []policy.Rule {
	rs := policy.Rules()
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	return rs
}

func (p policyList) Text() string {
	var rows [][]string
	if rs, ok := p["builtin"].([]map[string]string); ok {
		for _, r := range rs {
			rows = append(rows, []string{"shell", r["id"], r["reason"]})
		}
	}
	if rs, ok := p["custom_rules"].([]map[string]string); ok {
		for _, r := range rs {
			why := "your pattern: " + r["pattern"]
			if r["error"] != "" {
				why = "broken (" + r["error"] + "): " + r["pattern"]
			}
			rows = append(rows, []string{"shell", r["id"], why})
		}
	}
	for _, k := range []string{"sql", "redis", "memcached", "data"} {
		if rs, ok := p[k].([]driver.Rule); ok {
			for _, r := range rs {
				rows = append(rows, []string{k, r.ID, r.Reason})
			}
		}
	}
	note, _ := p["note"].(string)
	return textTable([]string{"for", "rule", "stops"}, rows) + "\n" + note +
		"\nthe patterns: komando policy list -o json; test a command: komando policy check '...'\n"
}

// policyChange is what policy deny and allow did, in words for people.
type policyChange struct {
	Custom  []string `json:"custom"`
	Added   *bool    `json:"added,omitempty"`   // deny
	Removed string   `json:"removed,omitempty"` // allow
	ID      string   `json:"id,omitempty"`      // deny: the rule's id, for policy rm
	Next    string   `json:"next,omitempty"`    // deny: how to try it and take it away
	pattern string
}

// denied is policy deny's result: the rule's id and the commands that
// follow, check and rm.
func (p policyChange) denied() policyChange {
	p.ID = policy.CustomID(p.pattern)
	p.Next = "komando policy check 'COMMAND' says whether it blocks a command  |  komando policy rm " + p.ID + " removes it"
	if !g.dryRun {
		sayNext("komando policy check 'COMMAND'", "komando policy rm "+p.ID)
	}
	return p
}

func (p policyChange) Text() string {
	n := countOf(len(p.Custom), "custom rule")
	switch {
	case p.Added != nil && *p.Added && g.dryRun:
		return fmt.Sprintf("would add the deny rule %s as %s (dry run; %s then)\n", p.pattern, p.ID, n)
	case p.Added != nil && *p.Added:
		return fmt.Sprintf("added the deny rule %s as %s (%s now)\n", p.pattern, p.ID, n)
	case p.Added != nil:
		return fmt.Sprintf("the deny rule %s is there already, as %s (%s)\n", p.pattern, p.ID, n)
	case g.dryRun:
		return fmt.Sprintf("would remove the deny rule %s (dry run; %s left then)\n", p.Removed, n)
	}
	return fmt.Sprintf("removed the deny rule %s (%s left)\n", p.Removed, n)
}
