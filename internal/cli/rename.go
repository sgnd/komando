package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// `komando rename --prefix OLD NEW` renames every server, conn, VPN, secret,
// key and group whose name starts with OLD, with the engine in
// rename_engine.go.

// renameSkip is a name that matched but is left alone, and why.
type renameSkip struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// renameResult is what `komando rename` prints.
type renameResult struct {
	Prefix    *renamePair             `json:"prefix,omitempty"` // OLD and NEW
	Action    string                  `json:"action"`           // renamed | would_rename | unchanged
	Count     int                     `json:"count"`            // entries renamed
	Renamed   map[string][]renamePair `json:"renamed"`          // by kind
	Protected []string                `json:"protected"`        // protected servers and conns it changes ("host NAME", old names)
	Updated   []renameRef             `json:"updated"`          // references that follow
	Moved     []renamePair            `json:"moved"`            // key files and VPN state folders
	Skipped   []renameSkip            `json:"skipped,omitempty"`
	Kept      []renameKept            `json:"kept,omitempty"` // old names left in notes and labels, and why
	Warnings  []string                `json:"warnings,omitempty"`
}

func (r renameResult) Text() string {
	var sb strings.Builder
	verb := map[string]string{"renamed": "renamed", "would_rename": "would rename", "unchanged": "nothing to rename"}[r.Action]
	if r.Action == "unchanged" {
		sb.WriteString(verb)
	} else {
		fmt.Fprintf(&sb, "%s %d %s", verb, r.Count, renameNoun(r.Count, "entry"))
	}
	if r.Prefix != nil {
		fmt.Fprintf(&sb, " (prefix %s -> %s)", r.Prefix.From, r.Prefix.To)
	}
	sb.WriteString("\n")
	var rows [][]string
	head := []string{"KIND", "FROM", "TO"}
	if len(r.Protected) > 0 {
		head = append(head, "PROTECTED")
	}
	for _, k := range renameKinds {
		for _, p := range r.Renamed[k] {
			row := []string{k, p.From, p.To}
			if len(r.Protected) > 0 {
				row = append(row, map[bool]string{true: "yes", false: "no"}[p.Protected])
			}
			rows = append(rows, row)
		}
	}
	if len(rows) > 0 {
		sb.WriteString(textTable(head, rows))
	}
	if len(r.Updated) > 0 {
		fmt.Fprintf(&sb, "references that follow (%d):\n", len(r.Updated))
		for _, u := range r.Updated {
			fmt.Fprintf(&sb, "  %s: %s -> %s\n", u, u.From, u.To)
		}
	}
	for _, m := range r.Moved {
		fmt.Fprintf(&sb, "moves %s -> %s\n", m.From, m.To)
	}
	for _, s := range r.Skipped {
		fmt.Fprintf(&sb, "left alone: %s %s (%s)\n", s.Kind, s.Name, s.Reason)
	}
	if len(r.Kept) > 0 {
		fmt.Fprintf(&sb, "old names kept in notes and labels (%d):\n", len(r.Kept))
		for _, k := range r.Kept {
			why := k.Reason
			if k.To != "" {
				why += "; it would become " + k.To
			}
			fmt.Fprintf(&sb, "  %s %s: %s (%s)\n", k.Entry, k.Field, k.Name, why)
		}
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&sb, "warning: %s\n", w)
	}
	return sb.String()
}

// nouns gives "entrys" for entry; renameNoun is the plural that reads.
func renameNoun(n int, noun string) string {
	if noun == "entry" && n != 1 {
		return "entries"
	}
	return nouns(n, noun)
}

// prefixRenames is every name of the kinds asked for that starts with old,
// with new in its place. When old ends in -, the name old without it is
// renamed too (group shop for --prefix shop- acme-shop-). When new
// starts with old, a name that starts with new already is left alone, so
// running the same rename twice changes nothing the second time.
func prefixRenames(s *store.State, old, new string, kinds map[string]bool) (renameSet, []renameSkip) {
	bareOld, bareNew := "", ""
	if strings.HasSuffix(old, "-") {
		bareOld, bareNew = strings.TrimSuffix(old, "-"), strings.TrimSuffix(new, "-")
	}
	grows := len(new) > len(old) && strings.HasPrefix(new, old)
	set := renameSet{}
	var skipped []renameSkip
	add := func(kind string, names []string) {
		for _, n := range names {
			var to string
			switch {
			case strings.HasPrefix(n, old):
				to = new + n[len(old):]
			case bareOld != "" && bareNew != "" && n == bareOld:
				to = bareNew
			default:
				continue
			}
			switch {
			case grows && (strings.HasPrefix(n, new) || (bareNew != "" && n == bareNew)):
				skipped = append(skipped, renameSkip{kind, n, "it has the new name already"})
			case kind == "secret" && n == approvalSecret:
				skipped = append(skipped, renameSkip{kind, n, "komando's approval code; a person manages it with `komando config approval-code`"})
			default:
				if set[kind] == nil {
					set[kind] = map[string]string{}
				}
				set[kind][n] = to
			}
		}
	}
	for _, k := range renameKinds {
		if !kinds[k] {
			continue
		}
		switch k {
		case "host":
			add(k, mapKeys(s.Hosts))
		case "conn":
			add(k, mapKeys(s.Conns))
		case "vpn":
			add(k, mapKeys(s.Vpns))
		case "secret":
			add(k, secretNames())
		case "key":
			add(k, mapKeys(s.Keys))
		case "group":
			add(k, mapKeys(allGroups(s).Groups))
		}
	}
	return set, skipped
}

// guardRenameProtected asks once for every protected server and conn a
// rename changes: --yes (for an AI agent, a person's "Allow once" in
// komando's window), or a yes at the terminal.
func guardRenameProtected(what string, prot []string) error {
	hosts := 0
	names := make([]string, len(prot))
	for i, p := range prot {
		kind, name, _ := strings.Cut(p, " ")
		if kind == "host" {
			hosts++
		}
		names[i] = name
	}
	conns := len(prot) - hosts
	var count string
	switch {
	case hosts == 1 && conns == 0:
		count = "1 protected server"
	case hosts == 0 && conns == 1:
		count = "1 protected conn"
	case conns == 0:
		count = fmt.Sprintf("%d protected servers", hosts)
	case hosts == 0:
		count = fmt.Sprintf("%d protected conns", conns)
	default:
		count = fmt.Sprintf("%d protected entries (%d %s, %d %s)", len(prot), hosts, nouns(hosts, "server"), conns, nouns(conns, "conn"))
	}
	shown := names
	more := ""
	if len(shown) > 8 { // the window stays short; --dry-run lists them all
		shown, more = shown[:8], fmt.Sprintf(" and %d more", len(names)-8)
	}
	why := fmt.Sprintf("%s changes %s in one step: %s%s", what, count, strings.Join(shown, ", "), more)
	if yesOK(why) || confirmYes(why+". Change them anyway?") {
		return nil
	}
	code := "PROTECTED_TARGET"
	if hosts > 0 {
		code = "PROTECTED_HOST"
	}
	return policyStop(out.Errf(out.ExitPolicy, code, "see them all with --dry-run, then re-run with --yes after the user confirms (one yes covers all of them)",
		"%s changes %s: %s", what, count, strings.Join(names, ", ")))
}

func renameCmd() *cobra.Command {
	var prefix, notes, labels bool
	var kinds []string
	c := &cobra.Command{
		Use:   "rename OLD NEW",
		Short: "Rename one entry, or every name that starts with OLD (--prefix)",
		Long: `Without --prefix: renames the one server, conn, VPN, secret, key or group
named OLD, as ` + "`komando host rename`" + ` and the others do. When OLD names
two kinds of entry (a server and a secret), it says which commands to use.

With --prefix: renames every server, conn, VPN, secret, key and group whose
name starts with OLD: OLD is replaced with NEW. When OLD ends in -, the name OLD without
it is renamed too (--prefix shop- acme-shop- turns group shop into acme-shop).

Every reference follows, as with ` + "`host rename`" + ` and ` + "`secret rename`" + `: --via paths,
password, sudo, key, preshared key and passphrase references, secret:NAME
options in conn URLs, the key a server uses, group membership, jobs and
tunnels. A key komando made (key gen) moves its files in ~/.komando/keys.
The protected mark, labels, notes and creation time stay. Names inside
URLs (a bucket, a database user) are the resource's own and do not change.

--notes also replaces old names in notes, and --labels in label values:
server, conn, VPN and secret names as whole words, a group written @NAME,
and a pattern such as shop-db-* when it matches the same entries after the
rename. OLD without its -, group names without @, key names, and a name
that is also the user, host, bucket or database in a conn URL stay: they
often mean something else. The result lists each one it keeps ("kept"),
and each label value that names an old entry, with or without --labels.

Everything changes in one step, or nothing does: a new name that is taken
(or two old names that would get one new name) stops it before anything
is written. When NEW starts with OLD, names that start with NEW already
are left alone, so a second run changes nothing.

Renaming protected servers and conns needs --yes once, for all of them
(an AI agent's --yes opens one window for a person). See what would change
with --dry-run first. --kind renames only some kinds; references still
follow.
To rename one entry, use host rename, conn rename, vpn rename, secret rename, key rename or
group rename.`,
		Example: `  komando rename web1 web-01 --dry-run                 # one entry, whatever kind it is
  komando rename --prefix shop- acme-shop- --dry-run   # the old -> new list and every reference
  komando rename --prefix shop- acme-shop- --yes       # some of them are protected
  komando rename --prefix old-registry registry --kind conn,secret
  komando rename --prefix lab- test- --notes --labels --dry-run`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			old, new := args[0], args[1]
			if !prefix {
				if notes || labels || len(kinds) > 0 {
					return out.Errf(out.ExitUsage, "USAGE", "add --prefix: komando rename --prefix "+old+" "+new+" --dry-run",
						"--notes, --labels and --kind go with --prefix")
				}
				return renameOne(cmd, old, new)
			}
			if old == "" {
				return out.Usage("OLD cannot be empty: it would match every name")
			}
			if old == new {
				return out.Usage("the old and the new prefix are the same")
			}
			want := map[string]bool{}
			for _, k := range kinds {
				k = strings.TrimSpace(strings.ToLower(k))
				if !slices.Contains(renameKinds, k) {
					return out.Errf(out.ExitUsage, "USAGE", "--kind takes: "+strings.Join(renameKinds, ", "), "unknown kind %q", k)
				}
				want[k] = true
			}
			if len(want) == 0 {
				for _, k := range renameKinds {
					want[k] = true
				}
			}
			var skipped []renameSkip
			what := fmt.Sprintf("renaming %s* to %s*", old, new)
			res, err := renameTx(func(s *store.State) (renameSet, renameOpts, error) {
				set, sk := prefixRenames(s, old, new, want)
				skipped = sk
				if set.size() == 0 && len(sk) == 0 {
					return nil, renameOpts{}, out.Errf(out.ExitNotFound, "NOTHING_TO_RENAME", "check OLD with `komando list` and `komando secret list`; names are matched from the start, as written",
						"no %s starts with %q", strings.Join(slices.Sorted(maps.Keys(want)), ", "), old)
				}
				return set, renameOpts{notes: notes, labels: labels, prefix: &renamePair{From: old, To: new},
					guard: func(prot []string) error { return guardRenameProtected(what, prot) }}, nil
			})
			if err != nil {
				return err
			}
			res.Prefix = &renamePair{From: old, To: new}
			res.Skipped = skipped
			if res.Action == "renamed" {
				audit(nil, "rename", renamedNames(res), "", true, map[string]any{"prefix": old, "new_prefix": new, "count": res.Count, "renamed": res.Renamed, "updated": len(res.Updated)})
			}
			out.P.Print("rename", res, nil)
			return nil
		},
	}
	c.Flags().BoolVar(&prefix, "prefix", false, "rename every name that starts with OLD")
	c.Flags().StringSliceVar(&kinds, "kind", nil, "rename only these kinds: host, conn, vpn, secret, key, group (default: all)")
	c.Flags().BoolVar(&notes, "notes", false, "also replace old names in notes (server, conn, VPN and secret names, @group, OLD* patterns)")
	c.Flags().BoolVar(&labels, "labels", false, "also replace old names in label values, as --notes does (label names stay)")
	return c
}

// renamedNames are the new names of the servers and conns a rename
// changed, for the audit log's targets.
func renamedNames(r renameResult) []string {
	var n []string
	for _, k := range []string{"host", "conn"} {
		for _, p := range r.Renamed[k] {
			n = append(n, p.To)
		}
	}
	return n
}

// renameKindWords name each kind renameOne may find OLD as.
var renameKindWords = map[string]string{"host": "server", "conn": "conn", "vpn": "VPN", "secret": "secret", "key": "key", "group": "group"}

// renameOne is `komando rename OLD NEW` without --prefix: it finds the one
// kind of entry named OLD and runs that kind's own rename command (host
// rename, ...), so every check, prompt, audit record and the envelope are
// that command's.
func renameOne(cmd *cobra.Command, old, new string) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	var found []string
	if st.Hosts[old] != nil {
		found = append(found, "host")
	}
	if st.Conns[old] != nil {
		found = append(found, "conn")
	}
	if st.Vpns[old] != nil {
		found = append(found, "vpn")
	}
	if slices.Contains(secretNames(), old) {
		found = append(found, "secret")
	}
	if st.Keys[old] != nil {
		found = append(found, "key")
	}
	if len(groupMembersOf(st, strings.TrimPrefix(old, "@"))) > 0 {
		found = append(found, "group")
	}
	switch len(found) {
	case 0: // USAGE, as before this form existed (rename needed --prefix)
		return out.Errf(out.ExitUsage, "USAGE",
			"to rename every name that starts with it: `komando rename --prefix "+old+" "+new+" --dry-run`; check the name with `komando list`, `komando secret list`, `komando key list` and `komando group list`",
			"no server, conn, VPN, secret, key or group is named %q", old)
	case 1:
	default:
		var what, cmds []string
		for _, k := range found {
			what = append(what, renameKindWords[k])
			cmds = append(cmds, "`komando "+k+" rename "+old+" "+new+"`")
		}
		return out.Errf(out.ExitUsage, "USAGE", "say which: "+strings.Join(cmds, " or "),
			"%q is a %s; rename one of them", old, strings.Join(what, " and a "))
	}
	sub, _, err := cmd.Root().Find([]string{found[0], "rename"})
	if err != nil || sub.RunE == nil {
		return fmt.Errorf("komando: no %s rename command", found[0])
	}
	return sub.RunE(sub, []string{old, new})
}
