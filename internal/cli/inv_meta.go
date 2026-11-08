package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/cachex"
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// ----------------------------------------------------------------- audit ---

type auditList struct {
	Count   int              `json:"count"`
	Entries []map[string]any `json:"entries"`
}

// Text is one line per entry, like `git log --oneline`.
func (l auditList) Text() string {
	if len(l.Entries) == 0 {
		return "no audit entries\n"
	}
	var rows [][]string
	for _, e := range l.Entries {
		ts := fmt.Sprint(e["ts"])
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			ts = t.Local().Format("2006-01-02 15:04:05")
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
		res := "ok"
		switch {
		case e["dry_run"] == true:
			res = "dry-run"
		case e["ok"] != true:
			res = "FAILED"
		}
		t := strings.Join(targets, ",")
		if len(t) > 60 {
			t = t[:57] + "..."
		}
		rows = append(rows, []string{ts, who, fmt.Sprint(e["command"]), t, res})
	}
	return textTable([]string{"TIME", "ACTOR", "COMMAND", "TARGETS", "OK"}, rows)
}

func auditCmd() *cobra.Command {
	var limit int
	var target, command string
	var failed bool
	c := &cobra.Command{
		Use:   "audit",
		Short: "Show the audit log of actions taken (who, what, where, result)",
		Long: `Every change komando makes, and every blocked attempt, is a line in
~/.komando/audit.jsonl: when, who (and which AI agent), the command, its
targets and whether it worked. The newest entries come last.`,
		Example: `  komando audit                      # the last 50
  komando audit -n 0 --target @prod  # everything about @prod
  komando audit --command host. --failed
  komando audit verify               # was the log changed outside komando?`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if limit < 0 {
				return out.Errf(out.ExitUsage, "USAGE", "-n takes how many of the newest entries to show; 0 shows all", "invalid -n %d", limit)
			}
			f, err := os.Open(store.Path("audit.jsonl"))
			if err != nil {
				out.P.Print("audit", auditList{Entries: []map[string]any{}}, nil)
				return nil
			}
			defer f.Close()
			var names map[string]bool
			if target != "" {
				st, err := loadState()
				if err != nil {
					return err
				}
				names = targetNames(st, target)
			}
			all := []map[string]any{}
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1<<20), 16<<20)
			for sc.Scan() {
				var e map[string]any
				if json.Unmarshal(sc.Bytes(), &e) != nil {
					continue
				}
				delete(e, "prev") // the chain is for `audit verify`
				if cmdName, _ := e["command"].(string); command != "" && !strings.HasPrefix(cmdName, command) {
					continue
				}
				if failed && e["ok"] == true {
					continue
				}
				if target != "" {
					hs, _ := e["hosts"].([]any)
					cs, _ := e["conns"].([]any)
					match := false
					for _, h := range append(hs, cs...) {
						if n, ok := h.(string); ok && names[n] {
							match = true
						}
					}
					if !match {
						continue
					}
				}
				all = append(all, e)
			}
			if limit > 0 && len(all) > limit {
				all = all[len(all)-limit:]
			}
			out.P.Print("audit", auditList{Count: len(all), Entries: all}, nil)
			return nil
		},
	}
	c.AddCommand(auditVerifyCmd())
	c.Flags().IntVarP(&limit, "limit", "n", 50, "the newest N entries (0 = all)")
	c.Flags().StringVar(&target, "target", "", "only entries for these servers or conns (a selector, e.g. @prod)")
	aliasFlag(c.Flags(), "host", "target")
	c.Flags().StringVar(&command, "command", "", "filter by command prefix (e.g. exec, svc.)")
	c.Flags().BoolVar(&failed, "failed", false, "only failed/blocked actions")
	return c
}

// ---------------------------------------------------------------- policy ---

type policyCheck struct {
	Blocked bool          `json:"blocked"`
	Matches []policy.Rule `json:"matches"`
}

func (p policyCheck) Text() string {
	if !p.Blocked {
		return "allowed: no rule matches\n"
	}
	var b strings.Builder
	for _, m := range p.Matches {
		b.WriteString("blocked by " + m.ID + ": " + m.Reason + "\n")
	}
	return b.String()
}

func policyCmd() *cobra.Command {
	c := &cobra.Command{Use: "policy", Short: "Rules that block destructive commands: list, test, add"}
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
			for _, r := range shellRulesByID() {
				rules = append(rules, map[string]string{"id": r.ID, "reason": r.Reason, "pattern": policy.Pattern(r)})
			}
			var custom []map[string]string
			bad := policy.Invalid(st.Settings.ExtraDenyPattern)
			for i, p := range st.Settings.ExtraDenyPattern {
				r := map[string]string{"id": "custom-" + strconv.Itoa(i), "pattern": p}
				if why, ok := bad[i]; ok {
					r["error"] = why
				}
				custom = append(custom, r)
			}
			out.P.Print("policy.list", policyList{"builtin": rules, "custom": st.Settings.ExtraDenyPattern, "custom_rules": custom, "sql": rulesByID(driver.SQLRules()), "redis": rulesByID(cachex.Rules()), "memcached": rulesByID(cachex.MemcacheRules()), "data": rulesByID(driver.DataRules()),
				"note": "guardrails catch common accidents; they are not a security boundary. Protected hosts and conns additionally need --yes for any mutating action. " +
					"SQL without --write also runs in a read-only transaction, so the database itself refuses writes."}, nil)
			return nil
		},
	})
	var kind string
	check := &cobra.Command{
		Use:   "check COMMAND",
		Short: "Would this command be blocked? (--for KIND rates SQL, Redis ...)",
		Example: `  komando policy check 'rm -rf /var/www'
  if komando policy check "$CMD" >/dev/null; then echo allowed; fi
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
			case "redis", "memcached":
				if len(args) == 1 { // one quoted argument: "CLIENT LIST"
					args = strings.Fields(args[0])
				}
				out.P.Print("policy.check", cachex.ClassifyFor(kind, args), nil)
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
	check.Flags().StringVar(&kind, "for", "", "rate the argument for a conn kind instead: postgres, mysql, sqlite, redis or memcached")
	c.AddCommand(check)
	c.AddCommand(&cobra.Command{
		Use:     "deny REGEX",
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
			out.P.Print("policy.deny", map[string]any{"custom": pats, "added": added}, nil)
			return nil
		},
	})
	c.AddCommand(&cobra.Command{
		Use:   "allow PATTERN|custom-N",
		Short: "Remove a custom deny pattern (built-in rules stay)",
		Long: `Removes a pattern added with ` + "`policy deny`" + `, given as written or by its id
(custom-0, custom-1, ... in ` + "`policy list`" + ` and in POLICY_BLOCKED errors). Built-in
rules cannot be removed: for one intended command, pass --allow-dangerous.
Removing a rule weakens a safety check, so it needs --yes.`,
		Example: `  komando policy allow 'kubectl\s+delete' --yes
  komando policy allow custom-0 --yes`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			arg := args[0]
			for _, r := range policy.Rules() {
				if r.ID == arg {
					return out.Errf(out.ExitUsage, "BUILTIN_RULE", "built-in rules always apply; for one intended command, confirm with the user and pass --allow-dangerous",
						"%s is a built-in rule and cannot be removed", arg)
				}
			}
			var pats []string
			removed := ""
			err := store.Update(func(s *store.State) error {
				list := s.Settings.ExtraDenyPattern
				i := slices.Index(list, arg)
				if n, ok := strings.CutPrefix(arg, "custom-"); ok && i < 0 {
					if k, err := strconv.Atoi(n); err == nil && k >= 0 && k < len(list) {
						i = k
					}
				}
				if i < 0 {
					hint := "see the custom rules with `komando policy list`"
					if len(list) == 0 {
						hint = "there are no custom rules; built-in ones cannot be removed"
					}
					return out.Errf(out.ExitNotFound, "RULE_NOT_FOUND", hint, "no custom deny rule %q", arg)
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
			audit(nil, "policy.allow", nil, "", true, map[string]any{"pattern": removed})
			out.P.Print("policy.allow", map[string]any{"custom": orEmpty(pats), "removed": removed}, nil)
			return nil
		},
	})
	return c
}

// ---------------------------------------------------------------- doctor ---

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
	for _, n := range mapKeys(st.Keys) {
		k := st.Keys[n]
		name := "key:" + k.Name
		if _, err := os.Stat(k.Path); err != nil {
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
	return &cobra.Command{
		Use:   "doctor",
		Short: "Check the local setup, the inventory and its security",
		Long: `Checks komando's folder, vault, audit log and tools, then the inventory:
ports, --via paths, key files, secrets that references point at, plain-text
passphrases, weak keys, proxy commands, and conns that share a protected
password, repeat another conn or belong to a protected server without being
protected. ✗ lines need fixing (exit 1); ! lines are worth a look.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := doctorReport{optional: map[string]bool{"ssh_agent": true, "openssh_client": true, "hosts": true}}
			add := func(name string, ok bool, detail string) { r.Checks = append(r.Checks, doctorCheck{name, ok, detail}) }
			st, err := loadState()
			add("state", err == nil, store.Home())
			if err != nil {
				out.P.Print("doctor", r, toErr(err))
				return exitCode(1)
			}
			if st.Settings.Audit {
				f, err := os.OpenFile(store.Path("audit.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
				detail := store.Path("audit.jsonl")
				if err == nil {
					f.Close()
				} else {
					detail = err.Error() + " (changes are refused until this is fixed)"
				}
				add("audit_log", err == nil, detail)
			}
			hostDetail := countOf(len(st.Hosts), "host")
			if len(st.Hosts) == 0 {
				hostDetail = "none yet; add with `komando host add` or `komando import ssh-config`"
			}
			add("hosts", len(st.Hosts) > 0, hostDetail)
			add("keys", true, countOf(len(st.Keys), "key")+" in keychain")
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
				soft = out.Errf(out.ExitError, "DOCTOR_FAILED", "fix the checks marked ✗ (ok: false)", "some checks failed")
			}
			out.P.Print("doctor", r, soft)
			if soft != nil {
				return exitCode(1)
			}
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
				why = "BROKEN (" + r["error"] + "): " + r["pattern"]
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
