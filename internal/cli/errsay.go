package cli

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// cancelledText is what a person reads after they answered no.
func cancelledText() string {
	if len(askedAbout) == 0 {
		return "Cancelled. Nothing was changed."
	}
	return "Cancelled. Nothing was changed on " + joinAnd(askedAbout) + "."
}

// changeSay says what a change did, first, in words: "added web1 to
// @web", or under --dry-run "would add web1 to @web (dry run)". An empty
// what is "nothing to add".
func changeSay(verb, what, where string) string {
	if what == "" {
		return "nothing to " + verb
	}
	s := strings.TrimSpace(map[string]string{"add": "added", "remove": "removed", "save": "saved", "import": "imported"}[verb] + " " + what + " " + where)
	if g.dryRun {
		s = strings.TrimSpace("would "+verb+" "+what+" "+where) + " (dry run)"
	}
	return s
}

// joinAnd lists names for a sentence: "a", "a and b", "a, b and c".
func joinAnd(names []string) string {
	if len(names) < 2 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// Text-mode words for a person at a safety stop. JSON keeps the stable
// message and hint; an AI agent gets its own hint from approvalHint.
const (
	protectedHint = "Run it again in a terminal to answer the question, or add --yes in a script if you are sure. Try --dry-run first to see what it would do."
	dangerHint    = "If you mean it, run it again in a terminal and type the name to confirm, or add --allow-dangerous in a script. Try --dry-run first."
)

func protectedSay(names []string, kind string) string {
	if len(names) == 1 {
		return fmt.Sprintf("%s is a protected %s (production), so komando asks before changing it", names[0], kind)
	}
	return fmt.Sprintf("%s are protected (production), so komando asks before changing them", joinAnd(names))
}

func dangerSay(reasons []string) string {
	return "this can delete or break things (" + strings.Join(reasons, "; ") + "), so komando asks first"
}

// familyWord is how a person calls what a command family works with.
var familyWord = map[string][2]string{
	"db":       {"database", "databases"},
	"cache":    {"cache", "caches"},
	"queue":    {"queue", "queues"},
	"storage":  {"file storage", "file storages"},
	"cluster":  {"cluster", "clusters"},
	"registry": {"image registry", "image registries"},
}

// connWord names the kind of the protected conns ("database"), or
// "service" when they are of different kinds.
func connWord(conns []*store.Conn, names []string) string {
	w := ""
	for _, c := range conns {
		if !slices.Contains(names, c.Name) {
			continue
		}
		f, ok := familyWord[connFamily(c)]
		if !ok || w != "" && w != f[0] {
			return "service"
		}
		w = f[0]
	}
	if w == "" {
		return "service"
	}
	return w
}

// notFoundSay rewrites an unknown-name error for a person, scoped to what
// the command works with: "No database named "x". Did you mean prod-db?
// Your databases: prod-db, shop-db." A name that exists as another kind
// says so ("web1 is a server, not a conn"). JSON is unchanged.
func notFoundSay(e *out.Error, cmd *cobra.Command) {
	switch e.Code {
	case "HOST_NOT_FOUND", "CONN_NOT_FOUND", "TARGET_NOT_FOUND", "VPN_NOT_FOUND":
	default:
		return
	}
	if e.TextMessage() != e.Message {
		return // the command has its own words for a person
	}
	i := strings.IndexByte(e.Message, '"')
	j := -1
	if i >= 0 {
		j = strings.IndexByte(e.Message[i+1:], '"')
	}
	if j < 0 {
		return
	}
	name := e.Message[i+1 : i+1+j]
	if name == "" || strings.ContainsAny(name, "@:,!*") {
		return // a selector, not a name: the usual message explains it better
	}
	st, err := loadState()
	if err != nil {
		return
	}
	family := topCommand(cmd)
	one, many, names := wantedNames(st, e.Code, family)
	if kind, have, ok := st.FindName(name); ok {
		if msg, hint := otherKindSay(st, cmd, kind, have, one); msg != "" {
			e.Say(msg, hint)
		}
		return // or it is the kind wanted, and the error is about something else
	}
	if len(names) == 0 {
		e.Say(fmt.Sprintf("No %s named %q.", one, name), fmt.Sprintf("You have no %s yet: %s.", one, addHint(family, e.Code)))
		return
	}
	msg := fmt.Sprintf("No %s named %q.", one, name)
	if s := closest(name, names); s != "" {
		msg += " Did you mean " + s + "?"
	}
	list := names
	if len(list) > 10 {
		list = append(append([]string{}, list[:10]...), fmt.Sprintf("and %d more", len(names)-10))
	}
	e.Say(msg, fmt.Sprintf("Your %s: %s. See them all with komando list.", many, strings.Join(list, ", ")))
}

// wantedNames is what a not-found command works with, in words, and the
// names of that kind: a family's conns (db: databases), the kind of a
// host, conn or vpn command, else what the error code says it looked for.
func wantedNames(st *store.State, code, family string) (one, many string, names []string) {
	hosts := func() {
		for _, h := range st.SortedHosts() {
			names = append(names, h.Name)
		}
	}
	conns := func(family string) {
		for _, c := range st.SortedConns() {
			if family == "" || connFamily(c) == family {
				names = append(names, c.Name)
			}
		}
	}
	vpns := func() {
		for _, v := range st.SortedVpns() {
			names = append(names, v.Name)
		}
	}
	if w, ok := familyWord[family]; ok {
		conns(family)
		return w[0], w[1], names
	}
	switch {
	case family == "host" || family != "conn" && family != "vpn" && code == "HOST_NOT_FOUND":
		hosts()
		return "server", "servers", names
	case family == "conn" || family != "vpn" && code == "CONN_NOT_FOUND":
		conns("")
		return "conn", "conns", names
	case family == "vpn" || code == "VPN_NOT_FOUND":
		vpns()
		return "VPN", "VPNs", names
	}
	hosts()
	conns("")
	vpns()
	slices.SortFunc(names, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	return "server, conn or VPN", "servers, conns and VPNs", names
}

// otherKindSay explains a name that exists, but not as what the command
// wanted (one): "pg2 is a postgres conn, not a server." It says nothing
// ("", "") when the name is of the kind wanted.
func otherKindSay(st *store.State, cmd *cobra.Command, kind, name, one string) (msg, hint string) {
	what, use := "", ""
	switch kind {
	case "host":
		if one == "server" || one == "server, conn or VPN" {
			return "", ""
		}
		what, use = "a server", "use it with `komando exec` and the other server commands"
	case "conn":
		c := st.Conns[name]
		f := connFamily(c)
		if w, ok := familyWord[f]; one == "conn" || one == "server, conn or VPN" || ok && w[0] == one {
			return "", ""
		}
		what, use = "a "+c.Kind+" conn", "use it with `komando "+cmp.Or(f, "conn")+"`"
	case "vpn":
		if one == "VPN" || one == "server, conn or VPN" {
			return "", ""
		}
		what, use = "a VPN", "use it in a --via path, or with `komando vpn`"
	default:
		return "", ""
	}
	// `conn edit web1` for a server: the same verb under host
	if top := topCommand(cmd); cmd.HasParent() && (top == "host" || top == "conn" || top == "vpn") && top != kind {
		if c, rest, err := cmd.Root().Find([]string{kind, cmd.Name()}); err == nil && len(rest) == 0 && c.Name() == cmd.Name() {
			use = "use `komando " + kind + " " + cmd.Name() + " " + name + "`"
		}
	}
	return fmt.Sprintf("%s is %s, not a %s.", name, what, one), strings.ToUpper(use[:1]) + use[1:] + "."
}

// addHint says how to add the first of what a command works with: the
// command to type, for a person and an agent alike.
func addHint(family, code string) string {
	switch {
	case familyWord[family] != [2]string{} || family == "conn" || family != "host" && family != "vpn" && code == "CONN_NOT_FOUND":
		return "add one with `komando conn add NAME URL` (`komando conn kinds` lists the kinds)"
	case family == "vpn" || code == "VPN_NOT_FOUND":
		return "add one with `komando vpn add NAME KIND` (see `komando vpn add --help`)"
	}
	return "add one with `komando host add NAME user@address`, or bring in ~/.ssh/config with `komando import ssh-config`"
}

// fillHint puts the target into the commands a hint names with a
// placeholder: drivers and helpers that do not know the conn's name write
// `komando conn test NAME` or `komando cluster events TARGET`, and the
// next step should be one to copy. target is the command's first argument.
// TARGET is filled only with a server or conn, CONN only with a conn, and
// `komando test NAME` with any of those or a VPN, so `vpn up corp` never
// turns into `komando exec corp`. `komando conn test` becomes
// `komando test`, the one spelling.
func fillHint(e *out.Error, target string) {
	if e.Hint == "" || !strings.Contains(e.Hint, "`komando ") {
		return
	}
	e.Hint = strings.ReplaceAll(e.Hint, "`komando conn test ", "`komando test ")
	if target == "" || !placeholder.MatchString(e.Hint) && !strings.Contains(e.Hint, "`komando test NAME") {
		return // nothing to fill: no need to read the inventory
	}
	st, err := loadState()
	if err != nil {
		return
	}
	kind, name, ok := st.FindName(target)
	if !ok {
		return
	}
	e.Hint = hintCmd.ReplaceAllStringFunc(e.Hint, func(c string) string {
		c = placeholder.ReplaceAllStringFunc(c, func(p string) string {
			word := strings.TrimSpace(p)
			if word == "CONN" && kind != "conn" || word == "TARGET" && kind == "vpn" {
				return p
			}
			return p[:len(p)-len(word)] + name
		})
		return strings.Replace(c, "`komando test NAME", "`komando test "+name, 1)
	})
}

var (
	hintCmd     = regexp.MustCompile("`komando [^`]*`")
	placeholder = regexp.MustCompile(`(\s)(?:TARGET|CONN)\b`)
)

// article is "a" or "an" for word, by its first letter.
func article(word string) string {
	if word != "" && strings.ContainsRune("aeiou", rune(word[0])) {
		return "an"
	}
	return "a"
}
