package cli

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The command standard (docs: command-standard.md, changes.md section 11),
// checked on the cobra tree, the same data `komando schema` prints. Each
// test fails with the command path and the rule. Where a rule has
// exceptions from before it, they are written in the allow-list next to
// the test (standard_allow_test.go); an allow-list may only shrink, and an
// entry that no longer breaks the rule fails too.

// visibleCmds are the commands a person sees in help: not hidden, not a
// help topic, not cobra's completion scripts.
func visibleCmds(root *cobra.Command) []*cobra.Command {
	var res []*cobra.Command
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, s := range c.Commands() {
			if s.Hidden || !s.IsAvailableCommand() && !s.Runnable() || s.Parent().Name() == "completion" {
				continue
			}
			res = append(res, s)
			walk(s)
		}
	}
	walk(root)
	return res
}

// isGroup: c has sub-commands of its own (svc, db user).
func isGroup(c *cobra.Command) bool { return c.HasAvailableSubCommands() }

// cmdPathOf is c's path without "komando ".
func cmdPathOf(c *cobra.Command) string { return strings.TrimPrefix(c.CommandPath(), "komando ") }

// allowCheck fails for each key in got that allow does not list, and for
// each allow entry got no longer has (the list may only shrink).
func allowCheck(t *testing.T, rule string, got map[string]string, allow []string) {
	t.Helper()
	keys := make([]string, 0, len(got))
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !slices.Contains(allow, k) {
			t.Errorf("%s: %s: %s", rule, k, got[k])
		}
	}
	for _, a := range allow {
		if _, ok := got[a]; !ok {
			t.Errorf("%s: %q is in the allow-list but keeps the rule now; drop it", rule, a)
		}
	}
}

// S-1.4, S-1.4a: the top-level names are a closed list; ssh-gate's
// --name and --read-only are frozen.
func TestStandardTopLevel(t *testing.T) {
	root := newRoot()
	want := []string{
		// nouns (S-2.1)
		"host", "conn", "vpn", "group", "secret", "key", "recipe", "policy", "job", "tunnel", "config",
		"fs", "svc", "pkg", "user", "cron", "docker", "net", "cert", "db", "cache", "queue", "storage", "cluster", "registry",
		// shortcuts
		"list", "test", "exec", "shell", "logs", "cp", "upload", "download", "sync", "facts", "reboot", "status",
		"login", "logout", "import", "export", "rename",
		// about komando
		"audit", "doctor", "schema", "guide", "update", "version", "seal", "completion", "help", "ssh-gate",
	}
	var got []string
	for _, c := range root.Commands() {
		if !c.Hidden && c.Runnable() {
			got = append(got, c.Name())
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("S-1.4: top-level commands %v, want %v", got, want)
	}
	gate := findCmd(t, root, "ssh-gate")
	for _, n := range []string{"name", "read-only"} {
		f := gate.Flags().Lookup(n)
		if f == nil || f.Shorthand != "" {
			t.Errorf("S-1.4a: ssh-gate --%s must stay as written, without a shorthand", n)
		}
	}
}

// S-1.6: every command carries its stable ID.
func TestStandardStableIDs(t *testing.T) {
	for _, c := range allCommands(newRoot()) {
		if c.Runnable() && c.Annotations[cmdIDNote] == "" {
			t.Errorf("S-1.6: %s has no ID", c.CommandPath())
		}
	}
}

// S-1.1: a leaf is noun verb, or noun sub verb; a top-level shortcut is one
// word.
func TestStandardPathShape(t *testing.T) {
	got := map[string]string{}
	for _, c := range visibleCmds(newRoot()) {
		if isGroup(c) {
			continue
		}
		n := len(strings.Fields(cmdPathOf(c)))
		if n == 1 && c.Parent() == c.Root() {
			continue // a shortcut (TestStandardTopLevel keeps their list)
		}
		if n < 2 || n > 3 {
			got[cmdPathOf(c)] = fmt.Sprintf("%d words", n)
		}
	}
	allowCheck(t, "S-1.1", got, nil)
}

// S-2.1: each noun has its plural and its help word as aliases.
func TestStandardNounAliases(t *testing.T) {
	root := newRoot()
	for noun, aliases := range map[string][]string{
		"host": {"hosts", "server", "servers"}, "conn": {"conns"}, "vpn": {"vpns"}, "group": {"groups"},
		"secret": {"secrets"}, "key": {"keys"}, "recipe": {"recipes"}, "policy": {"policies"}, "job": {"jobs"},
		"tunnel": {"tunnels"}, "fs": {"files"}, "svc": {"service", "services"}, "pkg": {"package", "packages"},
		"user": {"users"}, "cron": {"crons"}, "docker": {"container", "containers"}, "net": {"network"},
		"cert": {"certs"}, "db": {"dbs", "database", "databases"}, "cache": {"caches"}, "queue": {"queues"},
		"cluster": {"clusters"}, "registry": {"registries"},
	} {
		want := findCmd(t, root, noun)
		for _, a := range aliases {
			if c, _, err := root.Find([]string{a}); err != nil || c != want {
				t.Errorf("S-2.1: %s does not find %s", a, noun)
			}
		}
	}
}

// verbTable is S-3.1's verbs, toolWords S-3.3's.
var (
	verbTable = []string{"list", "show", "add", "edit", "rename", "rm", "test", "cp", "check",
		"describe", "get", "info", "status", "logs", "history", "events", "create", "set",
		"start", "stop", "restart", "reload", "enable", "disable", "kill", "wait", "purge", "prune",
		"exec", "run", "query", "shell", "upload", "download", "sync", "dump", "restore", "up", "down",
		"login", "logout", "install", "uninstall", "update", "upgrade",
		"grant", "revoke", "deploy", "gen", "trust", "lock", "unlock", "passwd"}
	toolWords = []string{"docker ps", "docker images", "docker pull", "docker compose", "docker raw", "docker inspect",
		"registry inspect", "registry copy", "cache keys", "user add", "db user add", "db grant", "db revoke",
		"pkg installed", "pkg upgradable", "pkg security", "queue peek", "queue send", "queue lag", "queue groups",
		"db activity", "db locks", "db sizes", "db explain", "db kill",
		"fs cat", "fs stat", "fs chmod", "fs mkdir", "fs write", "fs replace", "fs mv", "svc daemon-reload",
		"cluster scale", "cluster apply", "cluster rollback", "cluster forward", "cluster helm values",
		"net dns", "net http", "net ports", "net check", "key gen", "key deploy", "host trust", "host ssh-command",
		"ssh-gate line", "conn kinds", "audit verify", "config approval-code", "secret keychain", "secret passphrase"}
)

// S-3.1, S-3.3: every leaf verb is in the verb table or a tool word.
func TestStandardVerbs(t *testing.T) {
	got := map[string]string{}
	for _, c := range visibleCmds(newRoot()) {
		if isGroup(c) || c.Parent() == c.Root() {
			continue
		}
		if !slices.Contains(verbTable, c.Name()) && !slices.Contains(toolWords, cmdPathOf(c)) {
			got[cmdPathOf(c)] = "verb " + c.Name() + " is in neither S-3.1 nor S-3.3"
		}
	}
	allowCheck(t, "S-3.1", got, allowVerbs)
}

// S-3.2: pairs stay pairs.
func TestStandardPairs(t *testing.T) {
	pairs := [][2]string{{"start", "stop"}, {"up", "down"}, {"login", "logout"}, {"grant", "revoke"},
		{"lock", "unlock"}, {"install", "uninstall"}, {"enable", "disable"}}
	got := map[string]string{}
	for _, c := range append([]*cobra.Command{newRoot()}, visibleCmds(newRoot())...) {
		if !isGroup(c) && c.Parent() != nil {
			continue
		}
		var names []string // a hidden alias counts as the other half (S-1.7)
		for _, s := range c.Commands() {
			names = append(append(names, s.Name()), s.Aliases...)
		}
		for _, p := range pairs {
			a, b := slices.Contains(names, p[0]), slices.Contains(names, p[1])
			if a != b {
				got[strings.TrimSpace(cmdPathOf(c)+" "+p[0]+"/"+p[1])] = "has only one half of the pair"
			}
		}
		// add/rm in komando's own list, create/rm on a target
		family := slices.Contains([]string{"db", "cache", "queue", "storage", "cluster", "registry"}, cmdPathOf(c))
		if !family && slices.Contains(names, "add") && !slices.Contains(names, "rm") || slices.Contains(names, "create") && !slices.Contains(names, "rm") {
			got[strings.TrimSpace(cmdPathOf(c)+" add|create/rm")] = "has no rm"
		}
	}
	allowCheck(t, "S-3.2", got, allowPairs)
}

// S-3.4: in a family noun the only conn-level verb is add.
func TestStandardFamilyVerbs(t *testing.T) {
	root := newRoot()
	for _, fam := range []string{"db", "cache", "queue", "storage", "cluster", "registry"} {
		for _, s := range findCmd(t, root, fam).Commands() {
			if !s.Hidden && slices.Contains([]string{"edit", "rename", "test", "show"}, s.Name()) {
				t.Errorf("S-3.4: %s %s acts on the conn itself; that is conn %s", fam, s.Name(), s.Name())
			}
		}
	}
}

// S-3.5, S-5.9: no --apply switch; a depends command has exactly one of
// --write and --read-only.
func TestStandardReadNoWriteFlag(t *testing.T) {
	got := map[string]string{}
	for _, c := range visibleCmds(newRoot()) {
		if f := c.LocalFlags().Lookup("apply"); f != nil && !f.Hidden {
			t.Errorf("S-5.9: %s shows --apply; use --write", c.CommandPath())
		}
		k, ok := kindOf(c)
		if !ok || k.Kind != kindDepends || slices.Contains([]string{"docker raw", "docker compose", "cluster shell"}, cmdPathOf(c)) {
			continue
		}
		w, r := c.Flags().Lookup("write") != nil, c.Flags().Lookup("read-only") != nil
		if w == r {
			got[cmdPathOf(c)] = "kind depends needs exactly one of --write and --read-only"
		}
	}
	allowCheck(t, "S-5.9", got, allowDependsSwitch)
}

// useWords are the words a Use line may hold (S-4.2), and the command's
// own item words S-4.2 allows by name.
var useWords = []string{"TARGET", "SERVER", "CONN", "NAME", "GROUP", "USER", "JOB", "TUNNEL", "RULE", "SETTING",
	"KEY", "OBJECT", "CONSUMER", "IMAGE", "TYPE/NAME", "POD", "FILE", "PATH", "ADDRESS", "PORT", "DOMAIN", "URL",
	"COMMAND", "ARGS",
	// an item of the command's own kind
	"MODE", "PID", "SQL", "TABLE", "TOPIC", "UNIT", "PACKAGE", "RELEASE", "REPLICAS", "SECTION", "SOURCE",
	"VERSION", "KIND", "OLD", "NEW", "VALUE", "TEXT", "PATTERN", "PREFIX", "REGEX", "PUBLIC_KEY", "SRC", "DST",
	"DEST", "CONTAINER", "REPO", "LOCAL", "REMOTE", "SPEC", "SCHEDULE", "REF", "SRC_CONN", "DST_CONN", "TYPE"}

var useToken = regexp.MustCompile(`[A-Z][A-Z_]*(/[A-Z]+)?`)

// S-4.1, S-4.2: a Use line parses (brackets close, words are UPPERCASE but
// `--` and flags), each word is in useWords, and each picker word maps to a
// list.
func TestStandardUseGrammar(t *testing.T) {
	got := map[string]string{}
	for _, c := range visibleCmds(newRoot()) {
		if c.Name() == "help" {
			continue // cobra's own
		}
		f := strings.Fields(c.Use)
		if !balanced(strings.Join(f[1:], " ")) || strings.Count(c.Use, "(") != strings.Count(c.Use, ")") {
			got[cmdPathOf(c)] = "brackets do not close: " + c.Use
			continue
		}
		for _, w := range f[1:] {
			bare := strings.Trim(w, "[]()|")
			switch {
			case bare == "--" || bare == "" || strings.HasPrefix(bare, "-"):
				continue
			case strings.ToUpper(bare) != bare:
				got[cmdPathOf(c)] = fmt.Sprintf("%q is not UPPERCASE (S-4.1)", w)
			}
			for _, tok := range useToken.FindAllString(bare, -1) {
				if !slices.Contains(useWords, tok) {
					got[cmdPathOf(c)] = fmt.Sprintf("%q is not an S-4.2 word", tok)
				}
			}
		}
	}
	allowCheck(t, "S-4.2", got, nil)
	for _, w := range []string{"TARGET", "SERVER", "CONN", "GROUP", "JOB", "TUNNEL"} {
		if p, _ := formArgPick(w); p == "" {
			t.Errorf("S-4.2: %s has no picker", w)
		}
	}
}

// S-4.3: a required flag is in the usage line with an UPPERCASE value, and
// a flag in the usage line is required (by cobra or by the command's own
// check, listed in requiredByCode).
func TestStandardRequiredInUse(t *testing.T) {
	inUse := regexp.MustCompile(`(?:^|\s)--([a-z-]+) [A-Z_]+`)
	for _, c := range visibleCmds(newRoot()) {
		shown := map[string]bool{}
		for _, m := range inUse.FindAllStringSubmatch(c.Use, -1) {
			shown[m[1]] = true
		}
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			req := len(f.Annotations[cobra.BashCompOneRequiredFlag]) > 0
			switch {
			case req && !shown[f.Name]:
				t.Errorf("S-4.3: %s --%s is required but not in its usage line", c.CommandPath(), f.Name)
			case shown[f.Name] && !req && !slices.Contains(requiredByCode, cmdPathOf(c)+" --"+f.Name):
				t.Errorf("S-4.3: %s shows --%s in its usage line but does not require it", c.CommandPath(), f.Name)
			}
		})
	}
}

// requiredByCode are flags a command requires with its own check (a USAGE
// error that says how), not cobra's.
var requiredByCode = []string{"db restore --from", "db user add --password-ref", "db user passwd --password-ref",
	"fs replace --old", "fs replace --new", "cluster deploy --image", "cluster apply --file"}

// S-5.1, S-5.6: one type per flag name, except the S-5.1 exceptions.
func TestStandardFlagTypes(t *testing.T) {
	types := map[string]map[string][]string{}
	for _, c := range visibleCmds(newRoot()) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Hidden {
				return
			}
			if types[f.Name] == nil {
				types[f.Name] = map[string][]string{}
			}
			types[f.Name][f.Value.Type()] = append(types[f.Name][f.Value.Type()], cmdPathOf(c))
		})
	}
	got := map[string]string{}
	for name, ts := range types {
		if len(ts) > 1 {
			got["--"+name] = fmt.Sprintf("%d types: %v", len(ts), ts)
		}
	}
	allowCheck(t, "S-5.1", got, allowFlagTypes)
}

// S-5.4, S-5.11: a shared flag has one usage text.
func TestStandardSinceUntil(t *testing.T) {
	texts := map[string]map[string]string{}
	for _, c := range visibleCmds(newRoot()) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Hidden || !slices.Contains([]string{"since", "until", "sudo", "no-sudo", "namespace", "protected"}, f.Name) {
				return
			}
			if texts[f.Name] == nil {
				texts[f.Name] = map[string]string{}
			}
			texts[f.Name][f.Usage] = cmdPathOf(c)
		})
	}
	got := map[string]string{}
	for name, ts := range texts {
		if len(ts) > 1 {
			got["--"+name] = fmt.Sprintf("%d usage texts", len(ts))
		}
	}
	allowCheck(t, "S-5.11", got, allowSharedUsage)
}

// S-5.5: never both --X and --no-X on one command.
func TestStandardNegatives(t *testing.T) {
	got := map[string]string{}
	for _, c := range visibleCmds(newRoot()) {
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if pos, ok := strings.CutPrefix(f.Name, "no-"); ok && !f.Hidden {
				if p := c.Flags().Lookup(pos); p != nil && !p.Hidden {
					got[cmdPathOf(c)+" --"+f.Name] = "has --" + pos + " too"
				}
			}
		})
	}
	allowCheck(t, "S-5.5", got, allowNegatives)
}

// S-5.7: defaults are the real ones, durations in short form, never -1.
func TestStandardDefaults(t *testing.T) {
	long := regexp.MustCompile(`^\d+h\d+m\d+s$|^\d+m\d+s$|^0s$`)
	for _, c := range visibleCmds(newRoot()) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.DefValue == "-1" || long.MatchString(f.DefValue) {
				t.Errorf("S-5.7: %s --%s shows the default %q", c.CommandPath(), f.Name, f.DefValue)
			}
		})
	}
}

// S-5.13: edit commands show --add-X/--rm-X, not --group/--tag.
func TestStandardEditFlags(t *testing.T) {
	for _, c := range visibleCmds(newRoot()) {
		if c.Name() != "edit" {
			continue
		}
		for _, n := range []string{"group", "tag"} {
			if f := c.Flags().Lookup(n); f != nil && !f.Hidden {
				t.Errorf("S-5.13: %s shows --%s; it takes --add-%s and --rm-%s", c.CommandPath(), n, n, n)
			}
			if f := c.Flags().Lookup("add-" + n); f == nil && c.Flags().Lookup(n) != nil {
				t.Errorf("S-5.13: %s has no --add-%s", c.CommandPath(), n)
			}
		}
	}
}

// S-6.1..S-6.4: the Short of a leaf and of a group; person-only marker.
func TestStandardShort(t *testing.T) {
	flagWord := regexp.MustCompile(`(^|\s)--?[a-zA-Z]`)
	got := map[string]string{}
	seen := map[string]string{}
	for _, c := range visibleCmds(newRoot()) {
		s, p := c.Short, cmdPathOf(c)
		limit := 72
		if c.Parent() == c.Root() {
			limit = 64
		}
		bad := func(why string) { got[p] = why + ": " + s }
		switch {
		case s == "":
			bad("no Short")
		case len([]rune(s)) > limit:
			bad(fmt.Sprintf("over %d characters", limit))
		case strings.HasSuffix(s, "."), strings.Contains(s, ";"), strings.Contains(s, "?"):
			bad("a full stop, a semicolon or a question (S-6.1)")
		case strings.Contains(s, "e.g.") || strings.Contains(s, "etc."):
			bad("e.g. or etc. (S-6.1)")
		case flagWord.MatchString(s):
			bad("names a flag (S-6.1)")
		case strings.ToUpper(s[:1]) != s[:1]:
			bad("not in sentence case (S-6.1)")
		case strings.Contains(strings.ToLower(s), "same as"):
			bad("says Same as (S-6.3)")
		case strings.Count(strings.TrimSuffix(s, " "+personOnlyMark), "(") > 1:
			bad("more than one parenthesis (S-6.1)")
		}
		if personOnly(c) != strings.HasSuffix(s, personOnlyMark) {
			got[p] = "the person-only marker does not match the rule table (S-6.4): " + s
		}
		if !isGroup(c) {
			if other, ok := seen[s]; ok {
				got[p] = "the same Short as " + other + " (S-1.3)"
			}
			seen[s] = p
		}
		if isGroup(c) {
			// S-6.2: never a partial list of its own commands
			_, jobs, ok := strings.Cut(s, ": ")
			if !ok {
				continue
			}
			var subs []string
			for _, sc := range c.Commands() {
				if !sc.Hidden {
					subs = append(subs, sc.Name())
				}
			}
			items := strings.Split(jobs, ", ")
			all := true
			for _, it := range items {
				all = all && slices.Contains(subs, strings.ToLower(strings.TrimSpace(it)))
			}
			if all && len(items) < len(subs) {
				got[p] = "lists some of its commands (S-6.2): " + s
			}
		}
	}
	allowCheck(t, "S-6.1", got, allowShort)
}

// S-6.5: a change or depends command has a Long with the Safety line after
// its first paragraph; no Long line is wider than 76 columns.
func TestStandardLong(t *testing.T) {
	got := map[string]string{}
	for _, c := range visibleCmds(newRoot()) {
		k, ok := kindOf(c)
		if ok && (k.Kind == kindChange || k.Kind == kindDepends) && c.Runnable() {
			paras := strings.Split(c.Long, "\n\n")
			if len(paras) < 2 || !strings.HasPrefix(paras[1], "Safety: ") {
				got[cmdPathOf(c)] = "no Safety line after the first paragraph (S-6.5)"
			}
		}
		for _, l := range strings.Split(c.Long, "\n") {
			if len([]rune(l)) > helpWidth {
				got[cmdPathOf(c)] = fmt.Sprintf("a line of %d columns (S-6.5)", len([]rune(l)))
			}
		}
	}
	allowCheck(t, "S-6.5", got, allowLong)
}

// sampleNames are S-6.8's sample names, and selectors that pick them.
var sampleNames = []string{"web1", "web2", "db1", "@web", "prod-db", "staging-db", "prod-redis", "prod-kafka",
	"backups", "ghcr", "harbor", "prod-k8s", "swarm1", "office", "alice", "app", "all"}

// S-6.6..S-6.9: example counts, a dry-run line per change command,
// approval lines after their dry run and marked, sample names, English.
func TestStandardExamples(t *testing.T) {
	root := newRoot()
	got := map[string]string{}
	names := map[string]string{}
	for _, c := range visibleCmds(root) {
		p := cmdPathOf(c)
		if p == "help" || p == "completion" {
			continue // cobra's own
		}
		var own []string
		for _, l := range strings.Split(c.Example, "\n") {
			if strings.TrimSpace(l) != "" {
				own = append(own, l)
			}
		}
		switch {
		case isGroup(c) && (len(own) < 3 || len(own) > 5):
			got[p] = fmt.Sprintf("a group shows %d examples, want 3 to 5 (S-6.6)", len(own))
		case !isGroup(c) && c.Runnable() && len(own) < 2:
			got[p] = fmt.Sprintf("%d example, want at least 2 (S-6.6)", len(own))
		}
		k, _ := kindOf(c)
		dry := false
		for i, l := range own {
			if !exampleOf(c, l) {
				continue
			}
			flags := exampleFlags(l)
			dry = dry || slices.Contains(flags, "--dry-run")
			if slices.ContainsFunc(flags, func(f string) bool { return f == "--yes" || f == "-y" || f == "--allow-dangerous" || f == "--reveal" }) {
				prevDry := i > 0 && exampleOf(c, own[i-1]) && slices.Contains(exampleFlags(own[i-1]), "--dry-run")
				if !prevDry || !strings.HasSuffix(l, approvalComment) {
					t.Errorf("S-6.7: %s: %q is not right after its --dry-run line or not marked %q", p, l, approvalComment)
				}
			}
			// S-6.8: the target names come from the sample table
			for _, w := range exampleTargets(c, l) {
				if !slices.Contains(sampleNames, w) && !strings.ContainsAny(w, "@:*!,/~") {
					names[w] = p
				}
			}
			for _, word := range []string{"kantor", "budi", "contoh", "rahasia"} {
				if strings.Contains(l, word) {
					t.Errorf("S-6.8: %s: %q is not English", p, l)
				}
			}
		}
		if (k.Kind == kindChange) && c.Runnable() && !isGroup(c) && len(own) > 0 && !dry {
			got[p+" dry-run"] = "a change command without a --dry-run example (S-6.7)"
		}
	}
	allowCheck(t, "S-6.6", got, allowExamples)
	gotNames := map[string]string{}
	for n, p := range names {
		gotNames[n] = "in " + p + ", not in the S-6.8 sample table"
	}
	allowCheck(t, "S-6.8", gotNames, allowSampleNames)
}

// exampleTargets are the words of an example line in TARGET, SERVER or
// CONN places of c's usage line.
func exampleTargets(c *cobra.Command, l string) []string {
	words := shellWords(exampleCommand(strings.TrimSpace(l)))
	n := len(strings.Fields(c.CommandPath()))
	var args []string
	for _, w := range words[min(n, len(words)):] {
		if w == "--" {
			break
		}
		if strings.HasPrefix(w, "-") {
			break // flags come after the positionals in examples
		}
		args = append(args, w)
	}
	var res []string
	for i, u := range strings.Fields(c.Use)[1:] {
		if i >= len(args) {
			break
		}
		u = strings.Trim(u, "[]")
		for _, alt := range strings.Split(strings.TrimSuffix(u, "..."), "|") {
			if gateTargetWords[alt] {
				res = append(res, args[i])
			}
		}
	}
	return res
}

var (
	backticked = regexp.MustCompile("`komando ([^`]*)`")
	upperWord  = regexp.MustCompile(`\b[A-Z][A-Z_]+\b`)
)

// S-6.10, S-8.7: every backticked `komando …` in help, the error catalog
// and Next: lines names a real command, and its UPPERCASE words are that
// command's Use words (a flag's value may be any word).
func TestStandardReferences(t *testing.T) {
	root := newRoot()
	got := map[string]string{}
	check := func(where, ref string) {
		words := shellWords(strings.ReplaceAll(ref, "\n", " "))
		if len(words) == 0 {
			return
		}
		c, rest, err := root.Find(words)
		if err != nil || c == root && words[0] != "" && !strings.HasPrefix(words[0], "-") {
			got[where+": komando "+ref] = "names no command"
			return
		}
		use := strings.Join(strings.Fields(c.Use)[1:], " ")
		for i, w := range rest {
			if w == "--" {
				break // the words of another program
			}
			if i > 0 && strings.HasPrefix(rest[i-1], "-") && !strings.Contains(rest[i-1], "=") {
				if f := c.Flags().Lookup(strings.TrimLeft(rest[i-1], "-")); f == nil || f.Value.Type() != "bool" {
					continue // a flag's value
				}
			}
			if strings.ContainsAny(w, " \t") {
				continue // a quoted value: SQL, a shell line
			}
			for _, u := range upperWord.FindAllString(w, -1) {
				if !strings.Contains(use, u) {
					got[where+": komando "+ref] = u + " is not a Use word of " + c.CommandPath() + " (" + use + ")"
				}
			}
		}
	}
	for _, c := range visibleCmds(root) {
		for _, text := range []string{c.Short, c.Long} {
			for _, m := range backticked.FindAllStringSubmatch(text, -1) {
				check(cmdPathOf(c), m[1])
			}
		}
	}
	for _, e := range errorCodes {
		for _, m := range backticked.FindAllStringSubmatch(e.Hint, -1) {
			if !strings.Contains(m[1], "…") {
				check(e.Code, m[1])
			}
		}
	}
	for key, h := range formHints {
		for _, n := range h.next {
			check(key+" next", strings.ReplaceAll(n, "{}", "web1"))
		}
	}
	allowCheck(t, "S-6.10", got, allowReferences)
}

// S-10.1: each inventory kind's journey verbs resolve (an alias counts).
func TestStandardJourneys(t *testing.T) {
	root := newRoot()
	for kind, verbs := range map[string][]string{
		"host":   {"add", "test", "show", "list", "edit", "rename", "rm"},
		"conn":   {"add", "test", "show", "list", "edit", "rename", "rm"},
		"vpn":    {"add", "test", "show", "list", "edit", "rename", "rm"},
		"key":    {"gen", "add", "show", "list", "edit", "rename", "rm"},
		"secret": {"set", "add", "check", "show", "get", "list", "rename", "rm"},
		"group":  {"add", "show", "list", "rename", "rm"},
		"recipe": {"add", "show", "list", "rm"},
		"policy": {"deny", "add", "check", "list", "rm"},
		"job":    {"start", "status", "show", "list", "kill", "stop", "rm"},
		"tunnel": {"start", "show", "list", "stop"},
	} {
		noun := findCmd(t, root, kind)
		for _, v := range verbs {
			if c, _, err := noun.Find([]string{v}); err != nil || c == noun {
				t.Errorf("S-10.1: %s %s does not resolve", kind, v)
			}
		}
	}
	// export backs up host, conn, vpn, group, recipe and policy rules
	findCmd(t, root, "export")
}
