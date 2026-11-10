package cli

import (
	"fmt"
	"slices"
	"strings"

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

// notFoundSay rewrites an unknown-name error for a person, scoped to the
// command family: "No database named "x". Did you mean prod-db? Your
// databases: prod-db, shop-db." JSON is unchanged.
func notFoundSay(e *out.Error, family string) {
	switch e.Code {
	case "HOST_NOT_FOUND", "CONN_NOT_FOUND", "TARGET_NOT_FOUND":
	default:
		return
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
	one, many := "server", "servers"
	var names []string
	if w, ok := familyWord[family]; ok {
		one, many = w[0], w[1]
		for _, c := range st.SortedConns() {
			if connFamily(c) == family {
				names = append(names, c.Name)
			}
		}
	} else {
		for _, h := range st.SortedHosts() {
			names = append(names, h.Name)
		}
	}
	if len(names) == 0 {
		e.Say(fmt.Sprintf("No %s named %q.", one, name), fmt.Sprintf("You have no %s yet: run komando and pick Add.", one))
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
