package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

// typedSpec is what a person types to let a step that cannot be undone
// through (S-7.3, OD-8): the name of the one thing that goes, or how many
// things go, labelled; for a whole target, its name.
type typedSpec struct {
	items []string
	of    string // what the items are: "keys in cache1"
}

// askTypes tells this command's typed question what goes away: the items
// (keys, files, secrets) and what they are. Without it the question asks
// for the target (the server or conn) a whole-target step changes.
func askTypes(items []string, of string) { cur().typed = &typedSpec{items, of} }

// maxTypedName is the longest name a person is asked to type; a longer
// one, or several, is asked as a count.
const maxTypedName = 60

// typedAnswer is what a person types for items, and how the question
// shows it. It is never the bare word yes; no items, no answer.
func typedAnswer(items []string, of string) (want, shown string) {
	switch {
	case len(items) == 0:
		return "", ""
	case len(items) == 1 && utf8.RuneCountInString(items[0]) <= maxTypedName && unshowable(items[0]) == "" &&
		strings.TrimSpace(items[0]) == items[0] && items[0] != "":
		return items[0], "the name " + items[0]
	}
	n := strconv.Itoa(len(items))
	return n, n + " (" + of + ")"
}

// dangerLine is the first line of the typed question (S-7.2, M-11):
// "This deletes ... ." A reason is a verb phrase without a subject
// ("deletes the files", "stops every copy of deployment/api"), so it reads
// after "This". A reason that is not one (a command line such as "docker
// rm web") still reads as a sentence: "This is dangerous: docker rm web."
func dangerLine(reason string) string {
	reason = strings.TrimRight(reason, " .")
	first, _, _ := strings.Cut(reason, " ")
	if len(first) > 2 && strings.HasSuffix(first, "s") && first == strings.ToLower(first) && !strings.ContainsAny(first, "-/:") {
		return "This " + reason + "."
	}
	return "This is dangerous: " + reason + "."
}

// confirmDangerous asks a person at the terminal to confirm a step that
// cannot be undone by typing what goes (typedAnswer), so a reflex "y" is
// not enough.
func confirmDangerous(names []string, reason string) bool {
	return confirmDangerousOn(names, nil, reason)
}

// confirmDangerousOn is confirmDangerous on targets names, prot of which
// are protected: one typed question covers the protection too (S-7.4),
// so confirmProtected does not ask again about them.
func confirmDangerousOn(names, prot []string, reason string) bool {
	if g.dryRun || !interactive() {
		return false
	}
	askedAbout = names
	c := cur()
	items, of := names, "the number of targets"
	if c.typed != nil {
		items, of = c.typed.items, c.typed.of
	}
	want, shown := typedAnswer(items, of)
	if want != "" && c.sess.DangerConfirmed(want) {
		return true // the person typed it in this command already: one question per command (S-7.4)
	}
	fmt.Fprintln(os.Stderr, dangerLine(reason))
	if want == "" { // never "yes": with nothing to name, a person passes the flag
		fmt.Fprintln(os.Stderr, "komando has no name for you to type here; if you mean it, run it again with --allow-dangerous.")
		c.sess.SaidNo(true)
		return false
	}
	if len(prot) > 0 {
		fmt.Fprintf(os.Stderr, "%s (protected): your answer covers that too.\n", strings.Join(prot, ", "))
	}
	ok := ask("Type "+shown+" to continue: ") == want
	c.sess.SaidNo(!ok)
	if ok {
		c.sess.ConfirmDanger(want)
		c.typedProt = append(c.typedProt, prot...)
		ttyYes("typed " + want + ": " + reason)
	}
	return ok
}
