package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cachex"
	"github.com/sgnd/komando/internal/dbx"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// audit.

type auditList struct {
	Count   int              `json:"count"`
	Entries []map[string]any `json:"entries"`
	filters []string         // the filter flags given, for the empty line
}

// Text is one line per entry, like `git log --oneline`.
func (l auditList) Text() string {
	if len(l.Entries) == 0 && len(l.filters) > 0 {
		return noneMatch("audit entries", strings.Join(l.filters, " "), "fewer filters show more")
	}
	if len(l.Entries) == 0 {
		return noneYet("audit entries", "", "`komando config get audit` says whether the log is on")
	}
	var rows [][]string
	for _, e := range l.Entries {
		ts := fmt.Sprint(e["ts"])
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			ts = timeCell(t)
		}
		who := fmt.Sprint(e["actor"])
		if a, ok := e["agent"].(string); ok && a != "" {
			who += " (" + a + ")"
			if e["actor_claimed"] == true { // the agent is sure; the name is what it says
				who = a + " (as " + fmt.Sprint(e["actor"]) + ")"
			}
		}
		var targets []string
		for _, k := range []string{"hosts", "conns"} {
			if l, ok := e[k].([]any); ok {
				for _, x := range l {
					targets = append(targets, fmt.Sprint(x))
				}
			}
		}
		for _, k := range []string{"key", "secret", "group"} {
			if v, ok := e[k].(string); ok && v != "" {
				targets = append(targets, k+" "+v)
			}
		}
		if v, ok := e["ssh_command"].(string); ok && v != "" {
			targets = append(targets, strconv.Quote(v)) // what an ssh-gate key asked for, line breaks and escapes shown as \n, \x1b
		}
		res := "ok"
		switch {
		case e["dry_run"] == true:
			res = "dry-run"
		case e["blocked"] != nil:
			res = "blocked"
		case e["ok"] != true:
			res = "failed"
		}
		t := truncateWidth(auditCell(strings.Join(targets, ",")), 60)
		rows = append(rows, []string{auditCell(ts), auditCell(who), auditCell(fmt.Sprint(e["command"])), t, res})
	}
	return textTable([]string{"TIME", "ACTOR", "COMMAND", "TARGETS", "OK"}, rows)
}

// auditCell shows a value from the log on one row: a line break, a
// terminal escape or another control character comes out escaped (\n,
// \x1b), so a value cannot add or hide rows.
func auditCell(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return !unicode.IsPrint(r) }) < 0 {
		return s
	}
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

func auditCmd() *cobra.Command {
	var limit int
	var target, command, since, until, actorName string
	var failed bool
	c := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log: who did what, where, and the result",
		Long: `Every change komando makes, and every blocked attempt, is a sealed record in
~/.komando/store.db: when, who (and which AI agent), the command, its
targets and whether it worked. The newest entries come last.

--since and --until take how long ago (30m, 12h, 7d), today, yesterday,
or a time (2026-11-07, '2026-11-07 14:30', 2026-11-07T14:30:00Z); a time
without a zone is this computer's. --since keeps entries from that moment
on, --until those before it. With either, every match is shown unless -n
is given.`,
		Example: `  komando audit                      # the last 50
  komando audit -n 0 --target @prod  # everything about @prod
  komando audit --command host. --failed
  komando audit --since 2h           # everything in the last two hours
  komando audit --since yesterday --until today --target @prod
  komando audit --actor claude --since 7d        # what Claude Code did this week
  komando audit verify               # was the log changed outside komando?`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 0 {
				return out.Errf(out.ExitUsage, "USAGE", "-n takes how many of the newest entries to show; 0 shows all", "invalid -n %d", limit)
			}
			flt := auditFilter{command: command, failed: failed, byTarget: target != "", actor: actorName}
			if err := flt.setWindow(since, until, time.Now()); err != nil {
				return err
			}
			if (since != "" || until != "") && !cmd.Flags().Changed("limit") {
				limit = 0
			}
			if target != "" {
				st, err := loadState()
				if err != nil {
					return err
				}
				flt.names = targetNames(st, target)
			}
			// without a filter only the newest records are read
			var from int64
			if limit > 0 && command == "" && !failed && target == "" && actorName == "" && since == "" && until == "" {
				last, err := newestAuditSeq()
				if err != nil {
					return err
				}
				from = max(0, last-int64(limit))
			}
			all := []map[string]any{}
			err := eachAuditAfter(from, func(_ int, b []byte) error {
				var e map[string]any
				if json.Unmarshal(b, &e) != nil {
					return nil
				}
				delete(e, "prev") // the chain is for `audit verify`
				if flt.keep(e) {
					all = append(all, e)
				}
				return nil
			})
			if errors.Is(err, sealdb.ErrTampered) {
				// the records before the broken one are still shown
				out.P.Warn(fmt.Sprintf("the audit log is broken after the %d records shown: %v; run `komando audit verify`", len(all), err))
			} else if err != nil {
				return err
			}
			if from > 0 && len(all) >= limit {
				out.P.Cut(limit) // older records were not read
			}
			all = cutLast(all, limit)
			var given []string
			for _, f := range []string{"target", "command", "failed", "actor", "since", "until"} {
				if cmd.Flags().Changed(f) {
					given = append(given, "--"+f)
				}
			}
			out.P.Print("audit", auditList{Count: len(all), Entries: all, filters: given}, nil)
			return nil
		},
	}
	c.AddCommand(auditVerifyCmd())
	c.Flags().IntVarP(&limit, "limit", "n", 50, "the newest N entries (0 = all; with --since or --until, all unless given)")
	c.Flags().StringVar(&target, "target", "", "only entries for these servers or conns (a selector, e.g. @prod)")
	c.Flags().StringVar(&command, "command", "", "only commands that start with this (e.g. exec, svc.)")
	c.Flags().BoolVar(&failed, "failed", false, "only actions that failed or were blocked")
	c.Flags().StringVar(&actorName, "actor", "", "only what this one did: part of the name in KOMANDO_ACTOR, the AI agent (claude, codex ...) or the computer account")
	c.Flags().StringVar(&since, "since", "", "only entries from this time on: 2h, 7d, today, 2026-11-07 or '2026-11-07 14:30'")
	c.Flags().StringVar(&until, "until", "", "only entries before this time (the same forms as --since)")
	return c
}

// policy.

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
				return out.Errf(out.ExitUsage, "USAGE", `give a regular expression, e.g. 'kubectl\s+delete'`, "empty pattern: it would match every command")
			}
			if err := checkRegex(pat); err != nil {
				return out.Errf(out.ExitUsage, "USAGE", "the pattern is a Go regular expression (https://pkg.go.dev/regexp/syntax)", "invalid regex: %v", err)
			}
			if regexp.MustCompile(pat).MatchString("") {
				return out.Errf(out.ExitUsage, "USAGE", `give a pattern that needs some text to match, e.g. 'kubectl\s+delete'`, "the pattern %s matches empty text, so it would match every command", pat)
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

// doctor.

type doctorCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type doctorReport struct {
	Checks    []doctorCheck   `json:"checks"`
	Inventory []securityCheck `json:"inventory"`
	Security  []securityCheck `json:"security"`
	optional  map[string]bool
}

// Text is a list like `brew doctor`: ✓ fine, ✗ to fix, ! worth a look.
func (r doctorReport) Text() string {
	var b strings.Builder
	fails, warns := 0, 0
	line := func(mark, name, detail string) {
		b.WriteString(mark + " " + name)
		if detail != "" {
			b.WriteString(": " + detail)
		}
		b.WriteString("\n")
	}
	for _, c := range r.Checks {
		switch {
		case c.OK:
			line("✓", c.Name, c.Detail)
		case r.optional[c.Name]:
			warns++
			line("!", c.Name, c.Detail)
		default:
			fails++
			line("✗", c.Name, c.Detail)
		}
	}
	for _, c := range append(append([]securityCheck{}, r.Inventory...), r.Security...) {
		switch {
		case c.Warning:
			warns++
			line("!", c.Name, c.Detail)
		case !c.OK:
			fails++
			line("✗", c.Name, c.Detail)
		default:
			line("✓", c.Name, c.Detail)
		}
	}
	switch {
	case fails == 0 && warns == 0:
		b.WriteString("\nAll good: komando is ready.\n")
	default:
		fmt.Fprintf(&b, "\n%s to fix, %s.\n", countOf(fails, "problem"), countOf(warns, "warning"))
	}
	return b.String()
}

// inventoryChecks finds settings komando would fail on later: bad ports,
// broken --via paths, missing files and secrets, plain-text passphrases,
// weak keys. Proxy commands are listed so a person knows they run here.
func inventoryChecks(st *store.State) []securityCheck {
	var cs []securityCheck
	fail := func(name, detail string) { cs = append(cs, securityCheck{Name: name, Detail: detail}) }
	warn := func(name, detail string) {
		cs = append(cs, securityCheck{Name: name, OK: true, Warning: true, Detail: detail})
	}
	secrets := map[string]bool{}
	for _, n := range secretNames() {
		secrets[n] = true
	}
	ref := func(name, flag, r string) {
		switch {
		case r == "":
		case !vault.ValidRef(r):
			fail(name, flag+" holds plain text instead of a reference: store it with `komando secret set NAME` and use secret:NAME")
		case strings.HasPrefix(r, "secret:") && !secrets[strings.TrimPrefix(r, "secret:")]:
			warn(name, flag+" "+r+" is not in the vault: `komando secret set "+strings.TrimPrefix(r, "secret:")+"`")
		}
	}
	for _, h := range st.SortedHosts() {
		name := "host:" + h.Name
		if err := validPort(h.Port); err != nil {
			fail(name, toErr(err).Message)
		}
		if err := checkHostVia(st, h); err != nil {
			fail(name, toErr(err).Message)
		}
		if h.Identity != "" {
			if _, err := os.Stat(expandHome(h.Identity)); err != nil {
				fail(name, "identity file "+h.Identity+" not found")
			}
		}
		if h.Key != "" && st.Keys[h.Key] == nil {
			fail(name, "uses missing key "+h.Key)
		}
		ref(name, "password_ref", h.PasswordRef)
		ref(name, "sudo_ref", h.SudoRef)
		if h.ProxyCommand != "" && h.ProxyCommand != ssmProxy {
			warn(name, "runs `"+h.ProxyCommand+"` on this computer to connect")
		}
	}
	for _, c := range st.SortedConns() {
		name := "conn:" + c.Name
		if c.Via != "" {
			if _, _, err := resolveVia(st, c.Via); err != nil {
				fail(name, toErr(err).Message)
			}
		}
		ref(name, "password_ref", c.PasswordRef)
		for _, r := range urlSecretRefs(c.URL) {
			ref(name, "URL option "+r.Option, "secret:"+r.Name)
		}
	}
	connHygiene(st, warn)
	for _, e := range cloudNamed(st) {
		warn(e.kind+":"+e.name, cloudNameText(e))
	}
	for _, n := range mapKeys(st.Keys) {
		k := st.Keys[n]
		name := "key:" + k.Name
		if store.SealedKey(k) {
			// a key komando made lives in the store: it must still open
			if _, err := store.ReadPrivateKey(k); err != nil {
				fail(name, "the key is missing from the store: "+err.Error())
			}
		} else if _, err := os.Stat(k.Path); err != nil {
			fail(name, k.Path+" not found")
		}
		ref(name, "passphrase_ref", k.PassphraseRef)
		if b := rsaBits(k.PublicKey); b > 0 && b < minRSABits {
			warn(name, fmt.Sprintf("RSA %d bits is weak: make a new key with `komando key gen` (ed25519)", b))
		}
	}
	return cs
}

// connHygiene warns about conns that work but are worth a look:
//   - an unprotected conn with the password secret of a protected server
//     or conn: that password is used without a person's yes, and changing
//     it for the protected one breaks this conn;
//   - two conns of the same kind with the same URL (user included) and
//     --via: one is enough;
//   - an unprotected conn with the label host=SERVER of a protected server.
func connHygiene(st *store.State, warn func(name, detail string)) {
	prot := map[string][]string{} // secret name → the protected targets using it
	for _, h := range st.SortedHosts() {
		for _, r := range []string{h.PasswordRef, h.SudoRef} {
			if n, ok := strings.CutPrefix(r, "secret:"); ok && h.Protected && !slices.Contains(prot[n], "server "+h.Name) {
				prot[n] = append(prot[n], "server "+h.Name)
			}
		}
	}
	for _, c := range st.SortedConns() {
		if n, ok := strings.CutPrefix(c.PasswordRef, "secret:"); ok && c.Protected {
			prot[n] = append(prot[n], "conn "+c.Name)
		}
	}
	same := map[string]string{} // kind, URL and via → the first conn with them
	for _, c := range st.SortedConns() {
		name := "conn:" + c.Name
		if n, ok := strings.CutPrefix(c.PasswordRef, "secret:"); ok && !c.Protected && len(prot[n]) > 0 {
			warn(name, fmt.Sprintf("is not protected but shares %s with protected %s: that password is used here without a person's yes, and changing it there breaks this conn; give it its own with `komando secret cp %s NEW` and `komando conn edit %s --password-ref secret:NEW`",
				c.PasswordRef, strings.Join(prot[n], ", "), n, c.Name))
		}
		key := c.Kind + "\x00" + c.URL + "\x00" + c.Via
		if first, ok := same[key]; ok {
			warn(name, "has the same kind, URL and --via as conn "+first+"; if they are the same thing, keep one: `komando conn rm "+c.Name+"`")
		} else {
			same[key] = c.Name
		}
		if h := st.Hosts[c.Labels["host"]]; h != nil && h.Protected && !c.Protected {
			warn(name, "has the label host="+h.Name+", a protected server, but is not protected itself: `komando conn edit "+c.Name+" --protected`")
		}
	}
}

func doctorCmd() *cobra.Command {
	var acceptOld bool
	c := &cobra.Command{
		Use:   "doctor",
		Short: "Check the local setup, the inventory and its security",
		Long: `Checks komando's folder, vault, audit log and tools, then the inventory:
ports, --via paths, key files, secrets that references point at, plain-text
passphrases, weak keys, proxy commands, and conns that share a protected
password, repeat another conn or belong to a protected server without being
protected. ✗ lines need fixing (exit 1); ! lines are worth a look.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if acceptOld {
				return acceptOldCopy()
			}
			defer lookAtOldCopy()() // doctor must be able to say what is wrong
			r := doctorReport{optional: map[string]bool{"ssh_agent": true, "openssh_client": true, "hosts": true, "agent_skill": true, "agent_guard": true}}
			add := func(name string, ok bool, detail string) { r.Checks = append(r.Checks, doctorCheck{name, ok, detail}) }
			st, err := loadState()
			add("state", err == nil, store.Home())
			if err != nil {
				out.P.Print("doctor", r, toErr(err))
				return exitCode(1)
			}
			if st.Settings.Audit {
				add("audit_log", true, "sealed in "+store.Path(store.StoreFile))
			}
			hostDetail := countOf(len(st.Hosts), "host")
			if len(st.Hosts) == 0 {
				hostDetail = "none yet; add with `komando host add` or `komando import ssh-config`"
			}
			add("hosts", len(st.Hosts) > 0, hostDetail)
			add("keys", true, countOf(len(st.Keys), "SSH key"))
			sock := os.Getenv("SSH_AUTH_SOCK")
			add("ssh_agent", sock != "", map[bool]string{true: sock, false: "not running (optional)"}[sock != ""])
			_, sshErr := exec.LookPath("ssh")
			add("openssh_client", sshErr == nil, "optional; komando has a built-in SSH client")
			for _, v := range st.SortedVpns() { // programs the registered VPNs need
				for _, bin := range vpnClients(v) {
					_, err := exec.LookPath(bin)
					add("vpn:"+v.Name+":"+bin, err == nil, map[bool]string{true: "installed", false: installHint(bin)}[err == nil])
				}
			}
			add("platform", true, runtime.GOOS+"/"+runtime.GOARCH)
			// AI agents: the skill komando installs, and whether it is this
			// version's (an update needs `guide install` again)
			installed, stale := skillStatus()
			switch {
			case len(installed) == 0:
				add("agent_skill", false, "no AI agent has komando's skill yet: `komando guide install` teaches Claude Code, Codex, Cursor and Gemini CLI to use komando")
			case len(stale) > 0:
				detail := "from another komando version in " + strings.Join(stale, ", ") + ": run `komando guide install` again, so your AI agents use this version's commands"
				if cites := skillCites(stale); len(cites) > 0 {
					detail += "; it still teaches old spellings that go away in a later release: use " + strings.Join(cites, ", ")
				}
				add("agent_skill", false, detail)
			default:
				add("agent_skill", true, strings.Join(installed, ", "))
			}
			if home, err := os.UserHomeDir(); err == nil && len(installed) > 0 && slices.ContainsFunc(installed, func(p string) bool { return strings.Contains(p, ".claude") }) {
				switch found, problem := claudeGuard(filepath.Join(home, ".claude", "settings.json")); {
				case !found:
					add("agent_guard", false, "Claude Code runs without komando's guard, which keeps it away from secret files: `komando guide install` adds it")
				case problem != "":
					add("agent_guard", false, "komando's guard in Claude Code cannot run, so Claude Code goes on without it: "+problem+"; `komando guide install` sets it up again")
				default:
					add("agent_guard", true, "Claude Code asks komando before reading files or running shell commands")
				}
			}
			r.Inventory = inventoryChecks(st)
			r.Security = securityChecks(st)
			ok := true
			for _, c := range r.Checks {
				if !c.OK && !r.optional[c.Name] {
					ok = false
				}
			}
			for _, c := range append(append([]securityCheck{}, r.Inventory...), r.Security...) {
				if !c.OK {
					ok = false
				}
			}
			if r.Inventory == nil {
				r.Inventory = []securityCheck{}
			}
			var soft *out.Error
			if !ok {
				soft = out.Errf(out.ExitError, "DOCTOR_FAILED", "fix the checks marked ✗ (ok: false), then run `komando doctor` again", "some checks failed")
			}
			out.P.Print("doctor", r, soft)
			if soft != nil {
				return exitCode(1)
			}
			return nil
		},
	}
	c.Flags().BoolVar(&acceptOld, "accept-old-copy", false, "use the komando folder as it is now after a restore from a backup, though it is older than the keychain remembers (a person only)")
	return c
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
