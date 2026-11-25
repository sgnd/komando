package cli

import (
	"cmp"
	"fmt"
	"maps"
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
	Blocked bool              `json:"blocked"`
	Matches []policy.Rule     `json:"matches"`
	Off     map[string]string `json:"off"` // rule id: where a matching rule is switched off
}

func (p policyCheck) Text() string {
	if !p.Blocked {
		return "Allowed: no rule blocks this command.\n"
	}
	reasons := make([]string, len(p.Matches))
	for i, m := range p.Matches {
		reasons[i] = m.Reason + " (rule " + m.ID + ")"
		if where := p.Off[m.ID]; where != "" {
			reasons[i] = m.Reason + " (rule " + m.ID + " matches; off on " + where + ")"
		}
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
				rules = append(rules, map[string]string{"id": r.ID, "reason": r.Reason, "pattern": policy.Pattern(r), "off": switchOf(st, r.ID).where()})
			}
			var custom []map[string]string
			bad := policy.Invalid(st.Settings.ExtraDenyPattern)
			for i, p := range st.Settings.ExtraDenyPattern {
				r := map[string]string{"id": policy.CustomID(p), "pattern": p, "off": switchOf(st, policy.CustomID(p)).where()}
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
			res := policyCheck{Blocked: len(hits) > 0, Matches: hits, Off: map[string]string{}}
			for _, h := range hits {
				if where := switchOf(st, h.ID).where(); where != "" {
					res.Off[h.ID] = where
				}
			}
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
					return out.Errf(out.ExitUsage, "BUILTIN_RULE", "a built-in rule cannot be removed; switch it off with `komando policy edit RULE --off`",
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
	if !cl.dryRun() {
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

// withoutRulesOff is hits less the rules a person switched off for every
// one of hosts (policy edit --off).
func withoutRulesOff(st *store.State, hosts []*store.Host, hits []policy.Rule) []policy.Rule {
	return slices.DeleteFunc(hits, func(r policy.Rule) bool {
		return ruleOffOn(st.Settings.RulesOff, r.ID, hosts)
	})
}

// ruleOffOn says whether the rule id is switched off on every one of
// hosts. A command bound to no server counts only a switch for every server.
func ruleOffOn(offs []store.RuleOff, id string, hosts []*store.Host) bool {
	i := slices.IndexFunc(offs, func(o store.RuleOff) bool { return o.Rule == id })
	if i < 0 {
		return false
	}
	if offs[i].Everywhere {
		return true
	}
	if len(hosts) == 0 {
		return false
	}
	for _, h := range hosts {
		if h.Rec.ID == "" || !slices.Contains(offs[i].HostIDs, h.Rec.ID) {
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

// switchRule is a rule a person can switch off: a built-in rule, or one of
// their own deny rules by its id.
func switchRule(st *store.State, id string) (policy.Rule, error) {
	if r, err := builtinRule(id); err == nil {
		return r, nil
	}
	for _, p := range st.Settings.ExtraDenyPattern {
		if policy.CustomID(p) == id {
			return policy.Rule{ID: id, Reason: "matches your deny rule " + p}, nil
		}
	}
	return policy.Rule{}, out.Errf(out.ExitNotFound, "RULE_NOT_FOUND", "see every rule and its id with `komando policy list`", "no rule named %q", id)
}

// keystoneRules keep the other rules working: with one of them off, a
// command can hide what it runs from every rule, or wipe the server or its
// logins. Switching one off takes the rule's name, typed by the person.
var keystoneRules = []string{"check-failed", "base64-pipe-sh", "decode-run", "curl-pipe-sh", "win-encoded", "win-decode-run", "win-download-run",
	"rm-root", "rm-cd-root", "find-delete-root", "rm-system-dir", "chmod-root", "chown-root", "mkfs", "dd-device", "redirect-device", "wipefs",
	"win-rm-root", "win-format", "win-registry-hive", "win-backups", "passwd-files", "passwd-files-write", "docker-host",
	"sshd-stop", "win-remote-access", "firewall-drop-all"}

// ruleScope is the servers a switch names, as their record IDs: a group is
// read now, so a server added to it later is not in the switch. The groups
// are kept as labels.
//
// labels are the groups the switch already names: --rm-group takes one of
// them by name even when the group has no servers any more, so its label
// can go.
func ruleScope(cl *call, st *store.State, hosts, groups, labels []string) (ids, gs []string, err error) {
	for _, n := range hosts {
		h, err := findHost(cl, st, n)
		if err != nil {
			return nil, nil, err
		}
		ids = append(ids, h.Rec.ID)
	}
	for _, g := range groups {
		g = strings.TrimPrefix(g, "@")
		members := groupMembersOf(st, g)
		n := len(ids)
		for _, m := range members {
			if h, ok := st.Hosts[m]; ok {
				ids = append(ids, h.Rec.ID)
			}
		}
		switch {
		case len(ids) > n, slices.ContainsFunc(labels, func(l string) bool { return strings.EqualFold(l, g) }):
		case len(members) == 0:
			return nil, nil, groupNotFound(cl, st, g)
		default:
			return nil, nil, out.Usage("the group %s has no servers", g)
		}
		gs = append(gs, g)
	}
	ids = slices.DeleteFunc(ids, func(id string) bool { return id == "" })
	return dedupe(ids), dedupe(gs), nil
}

// policySwitch is where a rule is off: what policy edit did, and policy
// show's and policy list's off column.
type policySwitch struct {
	Rule       string   `json:"rule"`
	Stops      string   `json:"stops"` // what the rule stops
	Off        bool     `json:"off"`
	Everywhere bool     `json:"everywhere"` // off on every server
	Hosts      []string `json:"hosts"`      // the servers it is off on, by their names now
	HostIDs    []string `json:"host_ids"`   // and by their record IDs
	Groups     []string `json:"groups"`     // the groups named when it was switched off (their servers then)
}

// switchOf is the switch of rule id in st. A server that was removed drops
// out of it.
func switchOf(st *store.State, id string) policySwitch {
	p := policySwitch{Rule: id, Hosts: []string{}, HostIDs: []string{}, Groups: []string{}}
	if r, err := switchRule(st, id); err == nil {
		p.Stops = r.Reason
	}
	offs := st.Settings.RulesOff
	i := slices.IndexFunc(offs, func(o store.RuleOff) bool { return o.Rule == id })
	if i < 0 {
		return p
	}
	for _, name := range slices.Sorted(maps.Keys(st.Hosts)) {
		if h := st.Hosts[name]; h.Rec.ID != "" && slices.Contains(offs[i].HostIDs, h.Rec.ID) {
			p.Hosts, p.HostIDs = append(p.Hosts, name), append(p.HostIDs, h.Rec.ID)
		}
	}
	p.Groups = append(p.Groups, offs[i].Groups...)
	p.Everywhere = offs[i].Everywhere
	p.Off = p.Everywhere || len(p.Hosts) > 0
	return p
}

// where says where a switched-off rule is off, in words; "" when it is on.
func (p policySwitch) where() string {
	switch {
	case p.Everywhere:
		return "every server"
	case !p.Off:
		return ""
	}
	w := strings.Join(p.Hosts, ", ")
	if len(p.Groups) > 0 {
		w += " (from @" + strings.Join(p.Groups, ", @") + ")"
	}
	return w
}

func (p policySwitch) Text() string {
	if !p.Off {
		return "the rule " + p.Rule + " is on everywhere\n"
	}
	return "komando no longer stops what the rule " + p.Rule + " stops (" + p.Stops + ") on: " + p.where() + "\n"
}

// rulesOff are the rules switched off somewhere, the keystone rules first.
func rulesOff(st *store.State) []policySwitch {
	var keystone, rest []policySwitch
	for _, o := range st.Settings.RulesOff {
		if sw := switchOf(st, o.Rule); !sw.Off {
			continue
		} else if slices.Contains(keystoneRules, o.Rule) {
			keystone = append(keystone, sw)
		} else {
			rest = append(rest, sw)
		}
	}
	return append(keystone, rest...)
}

// offLine is the policy edit --off command a person runs for the same
// switch.
func offLine(id string, hosts, groups []string) string {
	words := []string{"komando", "policy", "edit", id, "--off"}
	for _, h := range hosts {
		words = append(words, "--add-server", h)
	}
	for _, g := range groups {
		words = append(words, "--add-group", g)
	}
	return strings.Join(words, " ")
}

// offSentence is what the confirm shows after verb ("switching", or
// "switches" for the typed question, which reads "This switches ..."): the
// rule, where, and what komando no longer stops.
func offSentence(verb string, r policy.Rule, sw policySwitch) string {
	head := verb + " the rule " + r.ID + " off on " + sw.where()
	switch {
	case r.ID == "check-failed":
		return head + ": with this off, komando no longer catches a command its checks cannot read, so such a command runs unchecked"
	case slices.Contains(keystoneRules, r.ID):
		return head + ": with this off, komando no longer catches a command that " + r.Reason
	}
	return head + ": komando no longer stops a command that " + r.Reason
}

// setRuleOff switches id off: on every server, or on the servers ids
// (groups as labels), keeping what an earlier switch named.
func setRuleOff(offs []store.RuleOff, id string, everywhere bool, ids, groups []string) []store.RuleOff {
	offs = slices.Clone(offs)
	i := slices.IndexFunc(offs, func(o store.RuleOff) bool { return o.Rule == id })
	switch {
	case i < 0:
		return append(offs, store.RuleOff{Rule: id, Everywhere: everywhere, HostIDs: ids, Groups: groups})
	case everywhere:
		offs[i] = store.RuleOff{Rule: id, Everywhere: true}
	case !offs[i].Everywhere:
		offs[i].HostIDs = dedupe(append(slices.Clone(offs[i].HostIDs), ids...))
		offs[i].Groups = dedupe(append(slices.Clone(offs[i].Groups), groups...))
	}
	return offs
}

// setRuleOn switches id on again: everywhere, or only on the servers ids.
// A switch left with no server is taken away, never widened.
func setRuleOn(offs []store.RuleOff, id string, everywhere bool, ids, groups []string) ([]store.RuleOff, error) {
	offs = slices.Clone(offs)
	i := slices.IndexFunc(offs, func(o store.RuleOff) bool { return o.Rule == id })
	switch {
	case i < 0:
		return offs, nil
	case everywhere:
		return slices.Delete(offs, i, i+1), nil
	case offs[i].Everywhere:
		return nil, out.Usage("the rule %s is off everywhere: `komando policy edit %s --off=false` turns it on everywhere", id, id)
	}
	o := offs[i]
	o.HostIDs = slices.DeleteFunc(slices.Clone(o.HostIDs), func(h string) bool { return slices.Contains(ids, h) })
	o.Groups = slices.DeleteFunc(slices.Clone(o.Groups), func(g string) bool {
		return slices.ContainsFunc(groups, func(x string) bool { return strings.EqualFold(x, g) })
	})
	if len(o.HostIDs) == 0 {
		return slices.Delete(offs, i, i+1), nil
	}
	offs[i] = o
	return offs, nil
}

// confirmOff asks before a rule goes off. A keystone rule takes its name,
// typed by a person at the terminal, --yes or not: with no terminal it is
// refused, and an AI agent is told the command for the person's own
// terminal. Any other rule takes the safety question, or for an AI agent
// the approval window on the person's screen. A dry run only reports.
func confirmOff(cl *call, r policy.Rule, sw policySwitch, line string) error {
	why := offSentence("switching", r, sw)
	if !slices.Contains(keystoneRules, r.ID) {
		return guardSafety(cl, why)
	}
	switch {
	case cl.caller().IsAgent():
		return cl.policyStop(out.Errf(out.ExitPolicy, "NEEDS_PERSON", "ask the person to run `"+line+"` in their own terminal and type the rule's name",
			"%s needs the rule's name typed by a person", why).NoFlag())
	case !cl.interactive():
		return cl.policyStop(out.Errf(out.ExitPolicy, "SAFETY_SETTING", "run it in a terminal: komando asks you to type the rule's name",
			"%s needs the rule's name typed at a terminal", why).NoFlag())
	}
	askTypes(cl, []string{r.ID}, "rules")
	if !confirmDangerous(cl, nil, offSentence("switches", r, sw)) {
		return cl.policyStop(approvalErr(cl, "SAFETY_SETTING", why+" weakens komando's safety checks"))
	}
	return nil
}

// switchEdit is what one policy edit asks for: the rule off (on the added
// servers, or everywhere when it adds none), or on again (everywhere with
// --off=false, or only on the removed servers).
type switchEdit struct {
	off           bool // the rule goes off
	hosts, groups []string
	everywhere    bool
}

// readSwitchEdit checks the flags of policy edit and says what it does.
func readSwitchEdit(cmd *cobra.Command, off bool, addH, addG, rmH, rmG []string) (switchEdit, error) {
	offSet, adds, rms := cmd.Flags().Changed("off"), len(addH)+len(addG) > 0, len(rmH)+len(rmG) > 0
	switch {
	case !offSet && !rms:
		return switchEdit{}, out.Usage("give --off (with --add-server or --add-group for some servers), --off=false, or --rm-server or --rm-group")
	case adds && !(offSet && off):
		return switchEdit{}, out.Usage("--add-server and --add-group go with --off")
	case rms && offSet:
		return switchEdit{}, out.Usage("--rm-server and --rm-group switch the rule on again on those servers; leave out --off")
	case offSet && off:
		return switchEdit{off: true, hosts: addH, groups: addG, everywhere: !adds}, nil
	case offSet:
		return switchEdit{everywhere: true}, nil
	}
	return switchEdit{hosts: rmH, groups: rmG}, nil
}

func policyEditCmd() *cobra.Command {
	var addH, addG, rmH, rmG []string
	var off bool
	c := &cobra.Command{
		Use:   "edit RULE",
		Short: "Switch a rule off or on, everywhere or on some servers",
		Long: `--off switches a rule off, so it no longer stops a command. With --add-server or
--add-group it is off only on those servers (a group as its servers are
now): a command that also runs on another server is still stopped.
Switching a rule off weakens a safety check, so komando asks first: an AI
agent's request opens the approval window on your screen, and for a rule
that keeps the others working (check-failed, decode-run, rm-root, mkfs,
sshd-stop, ...) you type the rule's name at a terminal, with --yes too, and
an AI agent's request for one is refused. The audit log keeps every switch,
and ` + "`komando doctor`" + ` names every rule that is off. --off=false switches
it on again everywhere; --rm-server and --rm-group switch it on again on those
servers only.`,
		Example: `  komando policy edit docker-prune --off --add-server build1
  komando policy edit pkg-remove-essential --off --add-group lab
  komando policy edit docker-prune --rm-server build1
  komando policy edit docker-prune --off=false`,
		Args: cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			id := args[0]
			e, err := readSwitchEdit(cmd, off, addH, addG, rmH, rmG)
			if err != nil {
				return err
			}
			var before, after policySwitch
			fn := func(s *store.State) error {
				r, err := switchRule(s, id)
				if err != nil {
					return err
				}
				var labels []string
				if !e.off {
					labels = switchOf(s, id).Groups
				}
				ids, gs, err := ruleScope(cl, s, e.hosts, e.groups, labels)
				if err != nil {
					return err
				}
				next := setRuleOff(s.Settings.RulesOff, id, e.everywhere, ids, gs)
				if !e.off {
					next, err = setRuleOn(s.Settings.RulesOff, id, e.everywhere, ids, gs)
				}
				if err != nil {
					return err
				}
				before = switchOf(s, id)
				s.Settings.RulesOff, next = next, s.Settings.RulesOff
				after = switchOf(s, id)
				if e.off {
					if err := confirmOff(cl, r, after, offLine(id, e.hosts, e.groups)); err != nil {
						s.Settings.RulesOff = next
						return err
					}
				}
				return nil
			}
			update := storeUpdate
			if e.off {
				update = updateAskFirst
			}
			if err := update(cl, fn); err != nil {
				return err
			}
			audit(cl, nil, "policy.edit", after.Hosts, "", true, map[string]any{"rule": id, "off": e.off, "before": before, "after": after})
			cl.out.Print("policy.edit", after, nil)
			return nil
		}),
	}
	c.Flags().BoolVar(&off, "off", false, "switch the rule off; --off=false switches it on again everywhere")
	c.Flags().StringSliceVar(&addH, "add-server", nil, "with --off: only on these servers")
	c.Flags().StringSliceVar(&addG, "add-group", nil, "with --off: only on the servers in these groups as they are now")
	c.Flags().StringSliceVar(&rmH, "rm-server", nil, "switch the rule on again on these servers")
	c.Flags().StringSliceVar(&rmG, "rm-group", nil, "switch the rule on again on the servers these groups named")
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
		Use:   "show RULE",
		Short: "Show one rule: what it stops and where it is off",
		Example: `  komando policy show docker-prune
  komando policy show rm-root -o json`,
		Args: cobra.ExactArgs(1),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			id := args[0]
			if r, err := builtinRule(id); err == nil {
				cl.out.Print("policy.show", policyRule{ID: r.ID, Kind: "built-in", Reason: r.Reason, Pattern: policy.Pattern(r), Switch: switchOf(st, r.ID)}, nil)
				return nil
			}
			for _, p := range st.Settings.ExtraDenyPattern {
				if p == id || policy.CustomID(p) == id {
					cl.out.Print("policy.show", policyRule{ID: policy.CustomID(p), Kind: "custom", Reason: "your pattern", Pattern: p, Switch: switchOf(st, policy.CustomID(p))}, nil)
					return nil
				}
			}
			return out.Errf(out.ExitNotFound, "RULE_NOT_FOUND", "see every rule and its id with `komando policy list`", "no rule named %q", id)
		}),
	}
}
