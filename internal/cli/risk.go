package cli

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

// One rule table says how much each command and flag combination needs
// before it runs (docs/design/command-standard.md, S-7.1 and S-7.2). It
// replaces two lists that disagreed: formDestructive, which decided when a
// person at a terminal types a name, and the safety stops in the commands
// themselves. Each row takes the higher tier of the two, so no stop is
// lost: a person now types the name for every command that stops an AI
// agent with POLICY_BLOCKED, and every command a person had to type a name
// for is in the table (TestStandardConfirmTable checks both against the
// stops TestAgentGolden records).
//
// The stops themselves stay in the commands (guard, guardConns,
// guardProtection, ...): they see what a table cannot, such as which
// server is protected or what a SQL statement does. A row marked dynamic
// gives the most the command can need; the command decides at run time.
// Like protection (T2), a cluster conn whose kubeconfig logs in with a
// command the policy blocks is decided by the target, for every cluster
// command, so it has no row.

// tier is how much a run needs, from nothing to a person at a terminal.
type tier int

const (
	tierRead      tier = iota // T0: looks only
	tierChange                // T1: reversible, or only komando's own list
	tierProtected             // T2: decided by the target (PROTECTED_HOST, PROTECTED_TARGET)
	tierDangerous             // T3: cannot be undone, or an outage (POLICY_BLOCKED)
	tierSafety                // T3s: weakens komando's own checks (SAFETY_SETTING and friends)
	tierPerson                // T4: only a person at a terminal (NEEDS_PERSON and friends)
)

func (t tier) String() string {
	return [...]string{"read", "change", "protected", "dangerous", "safety", "person"}[t]
}

// riskRow is one row: the command (by ID), when it applies, its tier and
// what it does that cannot be undone (for the typed-name question).
type riskRow struct {
	id      string
	when    func(words []string) bool // nil: always
	cond    string                    // when, in words for `komando schema` (set with when)
	tier    tier
	what    string // "deletes the keys": the person reads "This deletes the keys."
	dynamic string // set: the tier holds only when this is so; the command decides
	bulk    string // set: a bulk confirm the command keeps (CONFIRM_REQUIRED)

	// typed: a T1 row (an agent needs nothing more, OD-7: easy to redo)
	// for which a person at the terminal who was asked for the command's
	// words also types the name of what goes; items says what those are
	typed, items string
}

// givesFlag: words give --name (or --name=true).
func givesFlag(name string) func([]string) bool {
	return func(w []string) bool { return slices.Contains(w, "--"+name) || slices.Contains(w, "--"+name+"=true") }
}

// anyWord: one of words (an argument) is in set.
func anyWord(set ...string) func([]string) bool {
	return func(w []string) bool {
		return slices.ContainsFunc(w, func(s string) bool { return slices.Contains(set, s) })
	}
}

// sshUnit: a unit word is ssh or sshd (with .service or .socket).
func sshUnit(w []string) bool {
	return slices.ContainsFunc(w, func(s string) bool {
		s = strings.TrimSuffix(strings.TrimSuffix(s, ".service"), ".socket")
		return s == "ssh" || s == "sshd"
	})
}

// protectionOff: --protected=false (an edit that turns protection off).
func protectionOff(w []string) bool { return slices.Contains(w, "--protected=false") }

// riskRows is the table. Rows for one ID are read in order; the highest
// tier that applies wins.
var riskRows = []riskRow{
	// T3: cannot be undone, or an outage. Rows from both old lists.
	{id: "queue.purge", tier: tierDangerous, what: "deletes every waiting message"},
	{id: "queue.rm", tier: tierDangerous, what: "deletes the topics or queues with their messages"},
	{id: "cache.rm", tier: tierDangerous, what: "deletes the keys"},
	{id: "storage.rm", tier: tierDangerous, what: "deletes the files"},
	{id: "cluster.rm", tier: tierDangerous, what: "deletes it from the cluster"},
	{id: "cluster.scale", when: anyWord("0", "--replicas=0"), cond: "REPLICAS is 0", tier: tierDangerous, what: "stops every copy of the app"},
	{id: "registry.rm", tier: tierDangerous, what: "deletes the images"},
	{id: "registry.prune", tier: tierDangerous, what: "deletes the images"},
	{id: "db.restore", tier: tierDangerous, what: "replaces what is in the database now"},
	{id: "db.user.rm", tier: tierDangerous, what: "deletes the database user"},
	{id: "db.kill", tier: tierChange, typed: "ends the session (its client loses the connection)", items: "sessions"},
	{id: "fs.rm", tier: tierDangerous, what: "deletes the files"},
	{id: "docker.rm", tier: tierDangerous, what: "deletes the containers"},
	{id: "docker.prune", tier: tierDangerous, what: "deletes stopped containers and unused images"},
	{id: "user.rm", when: givesFlag("remove-home"), cond: "with --remove-home", tier: tierDangerous, what: "deletes the user and their home folder"},
	{id: "user.rm", tier: tierDangerous, what: "deletes the user"},
	{id: "secret.rm", tier: tierDangerous, what: "deletes the saved passwords"},
	{id: "key.rm", when: givesFlag("delete-file"), cond: "with --delete-file, for a key komando made", tier: tierDangerous, what: "deletes the private key komando keeps"},
	{id: "pkg.rm", when: func(w []string) bool { return slices.ContainsFunc(riskArgs(w), essentialPkg) }, cond: "a package the server needs (openssh-server, sudo, systemd, ...)", tier: tierDangerous, what: "removes a package the server needs to run or to let you in"},
	{id: "pkg.rm", tier: tierChange, typed: "removes the packages", items: "packages"},
	{id: "cron.rm", tier: tierChange, typed: "deletes the scheduled task", items: "scheduled tasks"},
	{id: "reboot", tier: tierDangerous, what: "restarts the server (it is away until it is back)"},
	{id: "svc.stop", when: sshUnit, cond: "the unit is ssh or sshd", tier: tierDangerous, what: "stops sshd (no one can log in remotely)"},
	{id: "svc.disable", when: sshUnit, cond: "the unit is ssh or sshd", tier: tierDangerous, what: "turns sshd off (no one can log in remotely after a restart)"},
	{id: "sync", when: givesFlag("delete"), cond: "with --delete", tier: tierDangerous, what: "deletes the files in DST that SRC does not have"},

	// T3 when the command's own check finds it: a policy or classifier hit
	// on what the command runs, decided at run time.
	{id: "exec", tier: tierDangerous, dynamic: "the command matches a destructive rule"},
	{id: "job.start", tier: tierDangerous, dynamic: "the command matches a destructive rule"},
	{id: "recipe.run", tier: tierDangerous, dynamic: "the recipe's command matches a destructive rule"},
	{id: "docker.exec", tier: tierDangerous, dynamic: "the command matches a destructive rule"},
	{id: "docker.raw", tier: tierDangerous, dynamic: "the docker command deletes or stops something"},
	{id: "docker.compose", tier: tierDangerous, dynamic: "the compose command deletes or stops something"},
	{id: "cluster.exec", tier: tierDangerous, dynamic: "the command matches a destructive rule"},
	{id: "cluster.run", tier: tierDangerous, dynamic: "the kubectl command deletes something"},
	{id: "cache.run", tier: tierDangerous, dynamic: "the cache command deletes data (FLUSHALL, ...)"},
	{id: "db.query", tier: tierDangerous, dynamic: "the SQL deletes data (DROP, DELETE without WHERE, ...)"},
	{id: "db.explain", cond: "with --analyze", tier: tierDangerous, dynamic: "the SQL deletes data"},
	{id: "pkg.security", when: givesFlag("apply"), cond: "with --apply", tier: tierDangerous, dynamic: "an update would remove a package the server needs"},
	{id: "pkg.upgrade", when: givesFlag("security"), cond: "with --security", tier: tierDangerous, dynamic: "an update would remove a package the server needs"},
	{id: "key.revoke", tier: tierDangerous, dynamic: "it is the key komando logs in with"},
	{id: "host.edit", tier: tierDangerous, dynamic: "--proxy-command matches a destructive rule"},
	{id: "host.add", tier: tierDangerous, dynamic: "--proxy-command matches a destructive rule"},
	{id: "import", tier: tierDangerous, dynamic: "an imported ProxyCommand matches a destructive rule"},

	// T3s: weakens komando's own checks.
	{id: "policy.rm", tier: tierSafety, what: "removes a deny rule"},
	{id: "config.set", tier: tierSafety, dynamic: "the setting turns a check off (audit, keychain, host key policy, ...)"},
	{id: "host.edit", when: protectionOff, cond: "with --protected=false", tier: tierSafety, what: "turns protection off"},
	{id: "conn.edit", when: protectionOff, cond: "with --protected=false", tier: tierSafety, what: "turns protection off"},
	{id: "vpn.edit", when: protectionOff, cond: "with --protected=false", tier: tierSafety, what: "turns protection off"},
	{id: "vpn.edit", when: anyWord("--mfa=false"), cond: "with --mfa=false", tier: tierSafety, what: "turns --mfa off (komando may then connect it without a person)"},
	{id: "update", tier: tierSafety, dynamic: "it installs an older version"},
	{id: "tunnel.start", tier: tierSafety, dynamic: "it listens on an open address (OPEN_BIND)"},
	{id: "secret.keychain", tier: tierSafety, dynamic: "it turns the keychain off"},

	// T4: only a person at a terminal.
	{id: "config.approval-code", tier: tierPerson},
	{id: "secret.passphrase", tier: tierPerson},
	{id: "secret.check", tier: tierPerson},
	{id: "shell", tier: tierPerson},
	{id: "db.shell", tier: tierPerson},
	{id: "cluster.shell", tier: tierPerson},
	{id: "login", tier: tierPerson},
	{id: "login.aws", tier: tierPerson},
	{id: "ssh-gate", tier: tierPerson},
	{id: "host.trust", when: anyWord("--reset", "--reset=true"), cond: "with --reset, when a key is pinned", tier: tierPerson, what: "replaces a pinned host key (OD-9)"},

	// a bulk change keeps its own confirm (CONFIRM_REQUIRED for an agent)
	{id: "group.rm", when: func(w []string) bool { return len(riskArgs(w)) == 1 }, cond: "GROUP alone", tier: tierChange, bulk: "deleting a group of more than 3 members"},
}

// riskArgs are the words that are no flags (the positionals, roughly:
// a flag's value counts as a word, which only matters to group.rm, whose
// flags take none).
func riskArgs(w []string) []string {
	var a []string
	for _, s := range w {
		if s == "--" {
			break
		}
		if !strings.HasPrefix(s, "-") {
			a = append(a, s)
		}
	}
	return a
}

// riskOf is the row that decides command id with these words (its
// arguments and flags, without the command's own name), or a plain row
// from the command's kind: read (T0), change or depends (T1).
func riskOf(c *cobra.Command, words []string) riskRow {
	id := cmdID(c)
	best := riskRow{id: id, tier: tierRead}
	if k, ok := kindOf(c); !ok || k.Kind != kindRead {
		best.tier = tierChange
	}
	for _, r := range riskRows {
		if r.id != id || r.when != nil && !r.when(words) {
			continue
		}
		if r.tier > best.tier || r.tier == best.tier && best.what == "" && best.dynamic == "" && best.bulk == "" {
			best = r
		}
	}
	return best
}

// typedWhat is what the command does for good when a person must type a
// name before it runs (a T3 row that holds whatever the command runs, or a
// T1 row a person types the name for), or "".
func (r riskRow) typedWhat() string {
	switch {
	case r.tier == tierDangerous && r.dynamic == "":
		return r.what
	case r.typed != "":
		return r.typed
	}
	return ""
}

// riskOfLine is riskOf for a command line ("cache rm c1 k").
func riskOfLine(line []string) riskRow {
	root := newRoot()
	c, rest, err := root.Find(line)
	if err != nil || c == root {
		return riskRow{tier: tierRead}
	}
	return riskOf(c, rest)
}

// riskRowIDs are the IDs the table names (TestTablesKeyedByID).
func riskRowIDs() []string {
	ids := make([]string, 0, len(riskRows))
	for _, r := range riskRows {
		ids = append(ids, r.id)
	}
	return ids
}

// flag is what an AI agent or a script adds for a tier: none for a read or
// a change, and none for a person-only step (no flag lifts it).
func (t tier) flag() string {
	switch t {
	case tierDangerous:
		return "--allow-dangerous"
	case tierProtected, tierSafety:
		return "--yes"
	}
	return ""
}

// confirmSchema is one approval of a command in `komando schema` (S-7.7):
// its tier, the flag an AI agent or a script adds for it, and when it
// holds ("" = always). A change on a protected server or conn also needs
// --yes (PROTECTED_HOST, PROTECTED_TARGET); the target decides that, so it
// is no entry.
type confirmSchema struct {
	Tier string `json:"tier"`           // read, change, dangerous, safety or person
	Flag string `json:"flag,omitempty"` // --allow-dangerous or --yes
	When string `json:"when,omitempty"`
}

// confirmOf is c's approvals from the rule table: first the one it always
// has, then each one it reaches only sometimes, in table order.
func confirmOf(c *cobra.Command) []confirmSchema {
	id := cmdID(c)
	always := confirmSchema{Tier: tierRead.String()}
	if k, ok := kindOf(c); !ok || k.Kind != kindRead {
		always.Tier = tierChange.String()
	}
	var more []confirmSchema
	for _, r := range riskRows {
		if r.id != id {
			continue
		}
		e := confirmSchema{Tier: r.tier.String(), Flag: r.tier.flag(), When: r.cond}
		switch {
		case r.bulk != "":
			e.Flag, e.When = "--yes", r.cond+": "+r.bulk+" (CONFIRM_REQUIRED)"
		case r.dynamic != "" && e.When != "":
			e.When += ", when " + r.dynamic
		case r.dynamic != "":
			e.When = "when " + r.dynamic
		}
		if e.When == "" {
			always = e
			continue
		}
		more = append(more, e)
	}
	res := []confirmSchema{always}
	for _, e := range more {
		if e.Tier != always.Tier || e.Flag != always.Flag {
			res = append(res, e) // one it always needs anyway says nothing more
		}
	}
	return res
}
