package cli

import (
	"cmp"
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
		Short: "List the built-in rules and your deny rules",
		Args:  cobra.NoArgs,
		RunE: inCall(func(cl *call, cmd *cobra.Command, _ []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			var rules []map[string]string
			for _, r := range shellRulesByID() {
				rules = append(rules, map[string]string{"id": r.ID, "reason": r.Reason, "pattern": policy.Pattern(r), "off": switchOf(st.Settings.RulesOff, r.ID).where()})
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
			cl.out.Print("policy.list", policyList{"builtin": cutRows(cl, rules, n), "custom": cutRows(cl, st.Settings.ExtraDenyPattern, n), "custom_rules": cutRows(cl, custom, n),
				"sql": cutRows(cl, rulesByID(driver.SQLRules()), n), "redis": cutRows(cl, rulesByID(cachex.Rules()), n), "memcached": cutRows(cl, rulesByID(cachex.MemcacheRules()), n),
				"mongodb": cutRows(cl, rulesByID(dbx.MongoRules()), n), "queue": cutRows(cl, rulesByID(queuePolicyRules()), n), "data": cutRows(cl, rulesByID(driver.DataRules()), n),
				"note": "these rules catch common accidents; they are not a security boundary. Protected servers and conns also need --yes for any change. " +
					"SQL without --write also runs in a read-only transaction, so the database itself refuses writes."}, nil)
			return nil
		}),
	}
	limitFlag(list, &limit, 0, "rules of each kind")
	c.AddCommand(list)
	c.AddCommand(policyCheckCmd())
	c.AddCommand(&cobra.Command{
		Use:     "deny REGEX",
		Aliases: []string{"add"},
		Short:   "Add a deny rule (a Go regular expression)",
		Example: `  komando policy deny 'kubectl\s+delete'`,
		Args:    cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
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
			err := storeUpdate(cl, func(s *store.State) error {
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
				audit(cl, nil, "policy.deny", nil, "", true, map[string]any{"pattern": pat})
			}
			cl.out.Print("policy.deny", policyChange{Custom: pats, Added: &added, pattern: pat}.denied(cl), nil)
			return nil
		}),
	})
	c.AddCommand(policyRmCmd(), policyEditCmd(), policyShowCmd())
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
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
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
					cl.out.Print("policy.check", rated, nil)
					return nil
				}
				why := "destructive"
				if len(v.RuleIDs) > 0 {
					why = "blocked by [" + strings.Join(v.RuleIDs, ",") + "]"
				}
				cl.out.Print("policy.check", rated, out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "komando would refuse to run it without --allow-dangerous", "%s", why))
				return exitCode(out.ExitPolicy)
			}
			hits := policy.Check(strings.Join(args, " "), st.Settings.ExtraDenyPattern)
			res := policyCheck{Blocked: len(hits) > 0, Matches: hits}
			if !res.Blocked {
				cl.out.Print("policy.check", res, nil)
				return nil
			}
			ids := make([]string, len(hits))
			for i, h := range hits {
				ids[i] = h.ID
			}
			cl.out.Print("policy.check", res, out.Errf(out.ExitPolicy, "POLICY_BLOCKED", "komando would refuse to run it without --allow-dangerous",
				"blocked by [%s]", strings.Join(ids, ",")))
			return exitCode(out.ExitPolicy)
		}),
	}
	check.Flags().StringVar(&kind, "conn-kind", "", "rate the argument for a conn kind instead: "+strings.Join(policyCheckKinds(), ", ")+" (a command document as JSON)")
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
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			arg := args[0]
			for _, r := range policy.Rules() {
				if r.ID == arg {
					return out.Errf(out.ExitUsage, "BUILTIN_RULE", "built-in rules always apply (see them with `komando policy list`); for one intended command, confirm with the user and pass --allow-dangerous",
						"%s is a built-in rule and cannot be removed", arg)
				}
			}
			var pats []string
			removed := ""
			err := updateAskFirst(cl, func(s *store.State) error {
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
				if err := guardSafety(cl, "removing the deny rule "+removed); err != nil {
					return err
				}
				s.Settings.ExtraDenyPattern = slices.Delete(slices.Clone(list), i, i+1)
				pats = s.Settings.ExtraDenyPattern
				return nil
			})
			if err != nil {
				return err
			}
			audit(cl, nil, "policy.rm", nil, "", true, map[string]any{"pattern": removed})
			cl.out.Print("policy.rm", policyChange{Custom: orEmpty(pats), Removed: removed}, nil)
			return nil
		}),
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
			why := r["reason"]
			if r["off"] != "" {
				why += " (off on: " + r["off"] + ")"
			}
			rows = append(rows, []string{"shell", r["id"], why})
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
func (p policyChange) denied(cl *call) policyChange {
	p.ID = policy.CustomID(p.pattern)
	p.Next = "komando policy check 'COMMAND' says whether it blocks a command  |  komando policy rm " + p.ID + " removes it"
	if !cl.flags.dryRun {
		sayNext(cl, "komando policy check 'COMMAND'", "komando policy rm "+p.ID)
	}
	return p
}

func (p policyChange) TextFor(pr *out.Printer) string {
	n := countOf(len(p.Custom), "custom rule")
	switch {
	case p.Added != nil && *p.Added && pr.DryRun:
		return fmt.Sprintf("would add the deny rule %s as %s (dry run; %s then)\n", p.pattern, p.ID, n)
	case p.Added != nil && *p.Added:
		return fmt.Sprintf("added the deny rule %s as %s (%s now)\n", p.pattern, p.ID, n)
	case p.Added != nil:
		return fmt.Sprintf("the deny rule %s is there already, as %s (%s)\n", p.pattern, p.ID, n)
	case pr.DryRun:
		return fmt.Sprintf("would remove the deny rule %s (dry run; %s left then)\n", p.Removed, n)
	}
	return fmt.Sprintf("removed the deny rule %s (%s left)\n", p.Removed, n)
}

// policyHits are the rules command matches, less the built-in rules a
// person switched off for every one of hosts (`policy edit --off`). own leaves the
// carried rules out, for scripts komando writes whole (guardScript).
func policyHits(st *store.State, hosts []*store.Host, command string, own bool) []policy.Rule {
	check := policy.Check
	if own {
		check = policy.CheckScript
	}
	return slices.DeleteFunc(check(command, st.Settings.ExtraDenyPattern), func(r policy.Rule) bool {
		return ruleOffOn(st.Settings.RulesOff, r.ID, hosts)
	})
}

// ruleOffOn says whether the rule id is switched off on every one of
// hosts. A command bound to no server counts only a switch for everywhere.
func ruleOffOn(offs []store.RuleOff, id string, hosts []*store.Host) bool {
	i := slices.IndexFunc(offs, func(o store.RuleOff) bool { return o.Rule == id })
	if i < 0 {
		return false
	}
	o := offs[i]
	if len(o.Hosts) == 0 && len(o.Groups) == 0 {
		return true
	}
	if len(hosts) == 0 {
		return false
	}
	fold := func(want string) func(string) bool {
		return func(s string) bool { return strings.EqualFold(s, want) }
	}
	for _, h := range hosts {
		inGroup := slices.ContainsFunc(h.Groups, func(g string) bool { return slices.ContainsFunc(o.Groups, fold(g)) })
		if !inGroup && !slices.ContainsFunc(o.Hosts, fold(h.Name)) {
			return false
		}
	}
	return true
}

// builtinRule is the built-in shell rule with this id.
func builtinRule(id string) (policy.Rule, error) {
	for _, r := range policy.Rules() {
		if r.ID == id {
			return r, nil
		}
	}
	return policy.Rule{}, out.Errf(out.ExitNotFound, "RULE_NOT_FOUND", "see the built-in rules and their ids with `komando policy list`", "no built-in rule named %q", id)
}

// ruleScope is the servers and groups a switch names, as the list writes
// them; an unknown one is an error.
func ruleScope(cl *call, st *store.State, hosts, groups []string) ([]string, []string, error) {
	var hs, gs []string
	for _, n := range hosts {
		h, err := findHost(cl, st, n)
		if err != nil {
			return nil, nil, err
		}
		hs = append(hs, h.Name)
	}
	for _, g := range groups {
		g = strings.TrimPrefix(g, "@")
		if len(groupMembersOf(st, g)) == 0 {
			return nil, nil, groupNotFound(cl, st, g)
		}
		gs = append(gs, g)
	}
	return dedupe(hs), dedupe(gs), nil
}

// policySwitch is what policy edit did, and policy show's switch.
type policySwitch struct {
	Rule       string   `json:"rule"`
	Stops      string   `json:"stops"` // what the rule stops
	Off        bool     `json:"off"`
	Everywhere bool     `json:"everywhere"` // off on every server
	Hosts      []string `json:"hosts"`
	Groups     []string `json:"groups"`
}

func switchOf(offs []store.RuleOff, id string) policySwitch {
	p := policySwitch{Rule: id, Hosts: []string{}, Groups: []string{}}
	if r, err := builtinRule(id); err == nil {
		p.Stops = r.Reason
	}
	if i := slices.IndexFunc(offs, func(o store.RuleOff) bool { return o.Rule == id }); i >= 0 {
		o := offs[i]
		p.Off, p.Everywhere = true, len(o.Hosts) == 0 && len(o.Groups) == 0
		p.Hosts, p.Groups = append(p.Hosts, o.Hosts...), append(p.Groups, o.Groups...)
	}
	return p
}

// where says where a switched-off rule is off, in words.
func (p policySwitch) where() string {
	if p.Everywhere {
		return "everywhere"
	}
	var w []string
	w = append(w, p.Hosts...)
	for _, g := range p.Groups {
		w = append(w, "@"+g)
	}
	return strings.Join(w, ", ")
}

func (p policySwitch) Text() string {
	if !p.Off {
		return "the rule " + p.Rule + " is on everywhere\n"
	}
	return "komando no longer stops what the rule " + p.Rule + " stops (" + p.Stops + ") on: " + p.where() + "\n"
}

// setRuleOff switches id off on hosts and groups (everywhere when both are
// empty), keeping what an earlier switch named.
func setRuleOff(offs []store.RuleOff, id string, hosts, groups []string) []store.RuleOff {
	offs = slices.Clone(offs)
	i := slices.IndexFunc(offs, func(o store.RuleOff) bool { return o.Rule == id })
	switch {
	case i < 0:
		return append(offs, store.RuleOff{Rule: id, Hosts: hosts, Groups: groups})
	case len(hosts) == 0 && len(groups) == 0:
		offs[i] = store.RuleOff{Rule: id}
	case len(offs[i].Hosts) > 0 || len(offs[i].Groups) > 0: // off everywhere already otherwise
		offs[i].Hosts = dedupe(append(slices.Clone(offs[i].Hosts), hosts...))
		offs[i].Groups = dedupe(append(slices.Clone(offs[i].Groups), groups...))
	}
	return offs
}

// setRuleOn switches id on again: everywhere, or only on hosts and groups.
// A switch that names nothing more is taken away, so it never turns into
// one for everywhere.
func setRuleOn(offs []store.RuleOff, id string, hosts, groups []string) ([]store.RuleOff, error) {
	offs = slices.Clone(offs)
	i := slices.IndexFunc(offs, func(o store.RuleOff) bool { return o.Rule == id })
	if i < 0 {
		return offs, nil
	}
	if len(hosts) == 0 && len(groups) == 0 {
		return slices.Delete(offs, i, i+1), nil
	}
	o := offs[i]
	if len(o.Hosts) == 0 && len(o.Groups) == 0 {
		return nil, out.Usage("the rule %s is off everywhere: `komando policy edit %s --on` turns it on everywhere", id, id)
	}
	o.Hosts = slices.DeleteFunc(slices.Clone(o.Hosts), func(h string) bool {
		return slices.ContainsFunc(hosts, func(x string) bool { return strings.EqualFold(x, h) })
	})
	o.Groups = slices.DeleteFunc(slices.Clone(o.Groups), func(g string) bool {
		return slices.ContainsFunc(groups, func(x string) bool { return strings.EqualFold(x, g) })
	})
	if len(o.Hosts) == 0 && len(o.Groups) == 0 {
		return slices.Delete(offs, i, i+1), nil
	}
	offs[i] = o
	return offs, nil
}

func policyEditCmd() *cobra.Command {
	var hosts, groups []string
	var off, on bool
	c := &cobra.Command{
		Use:   "edit RULE (--off | --on)",
		Short: "Switch a built-in rule off or on, everywhere or on some servers",
		Long: `--off switches a built-in rule off, so it no longer stops a command. With
--host or --group it is off only on those servers: a command that also runs
on another server is still stopped. Switching a rule off weakens a safety
check, so komando asks a person first, and the audit log keeps it. --on
switches it on again, everywhere or only on the servers you name.`,
		Example: `  komando policy edit docker-prune --off --host build1
  komando policy edit pkg-remove --off --group lab
  komando policy edit docker-prune --on`,
		Args: cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			id := args[0]
			if off == on {
				return out.Usage("give --off or --on")
			}
			if _, err := builtinRule(id); err != nil {
				return err
			}
			var res policySwitch
			fn := func(s *store.State) error {
				hs, gs, err := ruleScope(cl, s, hosts, groups)
				if err != nil {
					return err
				}
				next := setRuleOff(s.Settings.RulesOff, id, hs, gs)
				if on {
					next, err = setRuleOn(s.Settings.RulesOff, id, hs, gs)
				}
				if err != nil {
					return err
				}
				res = switchOf(next, id)
				if off {
					if err := guardSafety(cl, "switching the built-in rule "+id+" off on: "+res.where()); err != nil {
						return err
					}
				}
				s.Settings.RulesOff = next
				return nil
			}
			update := storeUpdate
			if off {
				update = updateAskFirst
			}
			if err := update(cl, fn); err != nil {
				return err
			}
			audit(cl, nil, "policy.edit", nil, "", true, map[string]any{"rule": id, "off": off, "hosts": hosts, "groups": groups})
			cl.out.Print("policy.edit", res, nil)
			return nil
		}),
	}
	c.Flags().BoolVar(&off, "off", false, "switch the rule off")
	c.Flags().BoolVar(&on, "on", false, "switch the rule on again")
	c.Flags().StringSliceVar(&hosts, "host", nil, "only on this server (repeat it for more)")
	c.Flags().StringSliceVar(&groups, "group", nil, "only on the servers in this group (repeat it for more)")
	return c
}

// policyRule is policy show: one rule, its reason and where it is off.
type policyRule struct {
	ID      string       `json:"id"`
	Kind    string       `json:"kind"` // built-in | custom
	Reason  string       `json:"reason"`
	Pattern string       `json:"pattern"`
	Switch  policySwitch `json:"switch"`
}

func (p policyRule) Text() string {
	return textTable([]string{"rule", "kind", "stops", "off on"}, [][]string{{p.ID, p.Kind, p.Reason, cmp.Or(p.Switch.where(), "nowhere")}}) +
		"the pattern: komando policy show " + p.ID + " -o json\n"
}

func policyShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "show RULE",
		Short:   "Show one rule: what it stops and where it is off",
		Example: `  komando policy show docker-prune`,
		Args:    cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			id := args[0]
			if r, err := builtinRule(id); err == nil {
				cl.out.Print("policy.show", policyRule{ID: r.ID, Kind: "built-in", Reason: r.Reason, Pattern: policy.Pattern(r), Switch: switchOf(st.Settings.RulesOff, r.ID)}, nil)
				return nil
			}
			for _, p := range st.Settings.ExtraDenyPattern {
				if p == id || policy.CustomID(p) == id {
					cl.out.Print("policy.show", policyRule{ID: policy.CustomID(p), Kind: "custom", Reason: "your pattern", Pattern: p, Switch: policySwitch{Rule: policy.CustomID(p), Hosts: []string{}, Groups: []string{}}}, nil)
					return nil
				}
			}
			return out.Errf(out.ExitNotFound, "RULE_NOT_FOUND", "see every rule and its id with `komando policy list`", "no rule named %q", id)
		}),
	}
}
