package cli

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/store"
)

// `komando host add` (conn add, vpn add, db add, cache add ...) typed alone
// by a person at a terminal asks that kind's own questions, one line each:
// which kind, a name, the address or the parts of a URL, how to log in,
// whether it is production. The answers make ordinary command lines, shown
// before they run (the add, then the test that shows it works), so the
// person learns them. A password is never asked here: the add command asks
// it itself, hidden (--ask-password).

// formAddCmd: host add, conn add, vpn add or a family's add (db add ...),
// which have questions of their own.
func formAddCmd(cmd *cobra.Command) bool {
	k := commandKey(cmd)
	return k == "host add" || k == "conn add" || k == "vpn add" || formFamilyAdd[k] != ""
}

// formAddGroups are the add forms an add command offers.
func formAddGroups(cmd *cobra.Command) []formGroup {
	k := commandKey(cmd)
	if g := formFamilyAdd[k]; g != "" {
		return formGroupNamed(g)
	}
	return formGroupsFor(strings.Fields(k)[0])
}

// promptAdd asks an add command's questions, shows the lines, asks Run it?
// and runs them here. It ends with fillDone and the exit code (or a cancel).
func promptAdd(st *store.State, cmd *cobra.Command) error {
	sp, err := promptAddKind(formAddGroups(cmd))
	if err != nil {
		return err
	}
	a := formAnswers{}
	for i, q := range sp.qs {
		if !q.visible(st, a) {
			continue
		}
		if q.advanced && (q.optional || formDefault(st, q, a) != "" || formEmptyRow(st, q, a)) {
			if d := formDefault(st, q, a); d != "" {
				a[q.key] = d
			}
			continue // a rarer option: its default, or typed on the command line later
		}
		v, err := promptAddAsk(st, sp, a, i)
		if err != nil {
			return err
		}
		a[q.key] = v
	}
	cmds := formBuild(st, sp, a)
	for _, c := range cmds {
		fmt.Fprintln(promptW, "$ komando "+menuCommandLine(c))
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	for {
		v, err := askRun()
		if err != nil {
			return err
		}
		if v == "n" {
			return promptNo()
		}
		if v == "y" {
			promptConfirmed = "Run it?"
			break
		}
		_, _ = menuRunOne(self, formDry(cmds))
	}
	code, reason, err := formRunAll(self, cmds)
	if err != nil {
		return err
	}
	if rm := formRemoveCmd(cmds); code != 0 && reason != "" && rm != nil {
		name := rm[2]
		fmt.Fprintf(promptW, "\n%s did not answer: %s\nIt stays in your list. What next:\n", name, reason)
		for _, l := range [][2]string{
			{"komando " + rm[0] + " edit " + name, "change how komando reaches it"},
			{"komando test " + name, "test it again"},
			{"komando " + rm[0] + " rm " + name, "take it out of your list"}} {
			fmt.Fprintf(promptW, "  %-*s  %s\n", len("komando "+rm[0]+" edit "+name), l[0], l[1])
		}
	}
	return fillDone{code: code}
}

// promptAddKind asks what to add when the command offers more than one
// kind: a database, then which one.
func promptAddKind(groups []formGroup) (formSpec, error) {
	if len(groups) == 0 {
		return formSpec{}, errPromptCancel
	}
	g := groups[0]
	if len(groups) > 1 {
		var rows []menuRow
		for _, x := range groups {
			rows = append(rows, menuRow{label: x.label, detail: x.detail, value: x.label})
		}
		v, err := askPick(promptQ{label: "KIND"}, rows, false)
		if err != nil {
			return formSpec{}, err
		}
		g = groups[slices.IndexFunc(groups, func(x formGroup) bool { return x.label == v })]
	}
	if len(g.kinds) == 1 {
		return g.kinds[0].spec(), nil
	}
	var rows []menuRow
	for _, k := range g.kinds {
		rows = append(rows, menuRow{label: k.label, detail: k.detail, value: k.label})
	}
	v, err := askPick(promptQ{label: "KIND", help: g.ask}, rows, false)
	if err != nil {
		return formSpec{}, err
	}
	return g.kinds[slices.IndexFunc(g.kinds, func(k formKind) bool { return k.label == v })].spec(), nil
}

// promptAddAsk asks one question of an add form: its short name, with an
// example, the question and its help on ?.
func promptAddAsk(st *store.State, sp formSpec, a formAnswers, i int) (string, error) {
	q := sp.qs[i]
	label, def := q.label, formDefault(st, q, a)
	if q.example != "" && q.choices == nil && def == "" {
		label += ", e.g. " + q.example
	}
	pq := promptQ{label: label, def: def, optional: q.optional, help: strings.TrimSpace(q.ask + " " + q.help)}
	check := func(v string) string {
		if q.check == nil {
			return ""
		}
		return q.check(st, a, v)
	}
	if q.choices == nil {
		pq.check = func(v string) string {
			if clean, found := pastedSecret(v); q.addr && found {
				v = clean
			}
			return check(v)
		}
		ask := askText
		if q.addr { // a pasted user:password@ is never drawn
			ask = func(pq promptQ) (string, error) {
				return askMasked(pq, func(s string) string { c, _ := pastedSecret(s); return c })
			}
		}
		v, err := ask(pq)
		if clean, found := pastedSecret(v); q.addr && found {
			fmt.Fprintln(promptW, "  ! a password was in it: komando took it out and keeps nothing; choose A password below and the add command asks for it, hidden.")
			v = clean
		}
		return v, err
	}
	pq.check = check
	rows := q.choices(st, a)
	if !q.optional {
		rows = slices.DeleteFunc(slices.Clone(rows), func(r menuRow) bool { return r.value == "" && !formEmptyRow(st, q, a) })
	}
	if pq.def == "" && formEmptyRow(st, q, a) {
		pq.optional = true // its list has a row for no answer ("Directly")
	}
	return askPick(pq, rows, q.free)
}
