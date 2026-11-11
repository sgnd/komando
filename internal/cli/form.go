package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Guided add: a person who picks Add in the menu, or types `komando host
// add` (conn add, vpn add) alone at a terminal, is asked one question at a
// time: a name, an address, a user, and so on, each with an example, a
// default Enter takes, and a check that runs before the next question. The
// answers build an ordinary komando command line, shown on a review screen
// before it runs, so the person learns it and every safety check works as
// when it is typed. Passwords are never asked here: the command asks them
// itself, hidden (--ask-password), so the menu never holds a secret
// (docs/design/ux.md, section 10).

// formAnswers are the answers so far, by question key.
type formAnswers map[string]string

// formQ is one question.
type formQ struct {
	key      string // the answer's key
	label    string // its short name in the answers and the review ("Address")
	ask      string // the question ("What is the server's address?")
	help     string // one dim line under it: what it is, where to find it
	example  string // shown while nothing is typed: "for example: 10.0.0.5"
	optional bool   // an empty answer is fine
	advanced bool   // asked only under More options on the review
	addr     bool   // a pasted user:password@ is taken out at once
	free     bool   // with choices: an answer not in the list may be typed
	// def is what Enter takes when nothing is typed (nil: nothing)
	def func(st *store.State, a formAnswers) string
	// choices makes it a list to pick from instead of a line to type
	choices func(st *store.State, a formAnswers) []menuRow
	// show: asked only while it says true (nil: always)
	show func(a formAnswers) bool
	// when: asked only while the inventory allows it (nil: always), like
	// "through which server" while komando knows a server
	when func(st *store.State) bool
	// check says what is wrong with an answer, "" when it is fine
	check func(st *store.State, a formAnswers, v string) string
}

// formSpec is one kind of thing to add: its questions and how the answers
// become commands (the add, then the test or login that shows it works).
type formSpec struct {
	title string // "Add a server"
	qs    []formQ
	build func(st *store.State, a formAnswers) [][]string
}

// formKind is one row of the "what is it?" lists.
type formKind struct {
	label, detail string
	spec          func() formSpec
}

// formGroup is a row of the first list: Server, Database, Cache, ...
type formGroup struct {
	label, detail string
	kinds         []formKind
	ask           string // the question above its kinds ("Which database?")
}

// errFormCancel: Ctrl-C (or q on a list) in the middle of a form. Nothing
// has run yet, so nothing is left to undo.
var errFormCancel = errors.New("form: cancelled")

// visible says whether q is asked with these answers.
func (q formQ) visible(st *store.State, a formAnswers) bool {
	return (q.show == nil || q.show(a)) && (q.when == nil || q.when(st))
}

// formDefault is q's default with these answers, or "".
func formDefault(st *store.State, q formQ, a formAnswers) string {
	if q.def == nil {
		return ""
	}
	return q.def(st, a)
}

// formFill asks sp's questions, then shows the review until the person
// runs it: the commands to run, or errMenuBack (Esc on the first
// question) or errFormCancel.
//
// try, when set, runs a command and comes back: the review then offers to
// run it with --dry-run before it runs for real.
func formFill(ctx context.Context, t *menuTerm, st *store.State, sp formSpec, scr menuScreen, try formTry) ([][]string, error) {
	return formFillFrom(ctx, t, st, sp, scr, try, formAnswers{})
}

// formFillFrom is formFill with answers given already (a is filled in
// place): with some, it opens on the review, to change one of them.
func formFillFrom(ctx context.Context, t *menuTerm, st *store.State, sp formSpec, scr menuScreen, try formTry, a formAnswers) ([][]string, error) {
	if len(a) == 0 {
		if err := formAskAll(ctx, t, st, sp, a, scr, false, false); err != nil {
			return nil, err
		}
	}
	askMissing := true
	for {
		formTidy(st, sp, a)
		if askMissing {
			if err := formAskMissing(ctx, t, st, sp, a, scr); err != nil && !errors.Is(err, errMenuBack) {
				return nil, err
			}
		}
		askMissing = true
		pick, err := formReview(ctx, t, st, sp, a, scr, try != nil)
		switch {
		case errors.Is(err, errMenuBack): // Esc: the questions again, from the last
			err := formAskAll(ctx, t, st, sp, a, scr, false, true)
			if errors.Is(err, errMenuBack) && !formHasBasic(st, sp, a) {
				return nil, errMenuBack // no question to go back to: the list before
			}
			if err != nil && !errors.Is(err, errMenuBack) {
				return nil, err
			}
		case err != nil:
			return nil, err
		case pick == formRunRow || pick == formDryRow:
			if _, missing := formMissing(st, sp, a); missing {
				continue // asked at the top of the loop
			}
			if pick == formRunRow {
				return formBuild(st, sp, a), nil
			}
			if err := try(formDry(formBuild(st, sp, a))); err != nil {
				return nil, err
			}
			askMissing = false
		case pick == formMoreRow:
			if err := formAskAll(ctx, t, st, sp, a, scr, true, false); err != nil && !errors.Is(err, errMenuBack) {
				return nil, err
			}
			askMissing = false
		default: // a line of the review: that question again
			if err := formEdit(ctx, t, st, sp, a, scr, pick); err != nil {
				return nil, err
			}
		}
	}
}

// formBuild builds the commands from the answers of the questions that
// show: an answer to a question an edit has hidden is not used.
func formBuild(st *store.State, sp formSpec, a formAnswers) [][]string {
	shown := formAnswers{}
	for _, q := range sp.qs {
		if v, ok := a[q.key]; ok && q.visible(st, a) {
			shown[q.key] = v
		}
	}
	return sp.build(st, shown)
}

// formDry is the command Try it first runs: the first one that is not a
// secret set (which would ask for the secret), with --dry-run before any
// --, where it is still a flag and not a word of the remote command.
func formDry(cmds [][]string) []string {
	c := cmds[0]
	for _, x := range cmds {
		if len(x) < 2 || x[0] != "secret" || x[1] != "set" {
			c = x
			break
		}
	}
	if i := slices.Index(c, "--"); i >= 0 {
		return slices.Insert(slices.Clone(c), i, "--dry-run")
	}
	return append(slices.Clone(c), "--dry-run")
}

// formTidy forgets an answer from a fixed list that is no longer on it
// (the S3 login after the service changed), so it is asked again.
func formTidy(st *store.State, sp formSpec, a formAnswers) {
	for _, q := range sp.qs {
		v, ok := a[q.key]
		if !ok || q.choices == nil || q.free || !q.visible(st, a) {
			continue
		}
		rows := formOptionalRows(q, q.choices(st, a))
		if len(rows) > 0 && !slices.ContainsFunc(rows, func(r menuRow) bool { return r.value == v }) {
			delete(a, q.key)
		}
	}
}

// formMissing is the first shown question that still needs an answer: a
// basic one with none, or a More options one that needs one and has no
// default.
func formMissing(st *store.State, sp formSpec, a formAnswers) (int, bool) {
	for i, q := range sp.qs {
		if _, done := a[q.key]; done || !q.visible(st, a) {
			continue
		}
		if !q.advanced || (!q.optional && formDefault(st, q, a) == "" && !formEmptyRow(st, q, a)) {
			return i, true
		}
	}
	return 0, false
}

// formEmptyRow: q's list has a row for no answer ("Directly"), so having
// none is a choice already made.
func formEmptyRow(st *store.State, q formQ, a formAnswers) bool {
	return q.choices != nil && slices.ContainsFunc(q.choices(st, a), func(r menuRow) bool { return r.value == "" })
}

// formHasBasic: a basic question shows, so Esc on the review has one to
// go back to.
func formHasBasic(st *store.State, sp formSpec, a formAnswers) bool {
	return slices.ContainsFunc(sp.qs, func(q formQ) bool { return !q.advanced && q.visible(st, a) })
}

// formEdit asks one question again; the questions its new answer brings in
// are asked next, by formFill.
func formEdit(ctx context.Context, t *menuTerm, st *store.State, sp formSpec, a formAnswers, scr menuScreen, key string) error {
	for i, q := range sp.qs {
		if q.key != key {
			continue
		}
		pos, total := formPos(st, sp, a, i)
		v, err := formAsk(ctx, t, st, sp, a, scr, i, pos, total)
		if errors.Is(err, errMenuBack) {
			return nil
		}
		if err != nil {
			return err
		}
		a[q.key] = v
	}
	return nil
}

// formAskMissing asks the questions formMissing finds, one after the
// other. Esc leaves the rest unanswered and goes to the review, which
// asks them again before anything runs.
func formAskMissing(ctx context.Context, t *menuTerm, st *store.State, sp formSpec, a formAnswers, scr menuScreen) error {
	for {
		i, missing := formMissing(st, sp, a)
		if !missing {
			return nil
		}
		pos, total := formPos(st, sp, a, i)
		v, err := formAsk(ctx, t, st, sp, a, scr, i, pos, total)
		if err != nil {
			return err
		}
		a[sp.qs[i].key] = v
	}
}

// formAskAll asks the basic questions (or with advanced, the More options
// ones) in order. Esc goes back one question; Esc on the first gives
// errMenuBack. fromEnd starts at the last question, for Esc on the review.
func formAskAll(ctx context.Context, t *menuTerm, st *store.State, sp formSpec, a formAnswers, scr menuScreen, advanced, fromEnd bool) error {
	var order []int
	for i, q := range sp.qs {
		if q.advanced == advanced {
			order = append(order, i)
		}
	}
	at := 0
	if fromEnd {
		if at = formPrev(st, sp, a, order, len(order)); at < 0 {
			return errMenuBack
		}
	}
	for at < len(order) {
		i := order[at]
		q := sp.qs[i]
		if !q.visible(st, a) {
			at++
			continue
		}
		pos, total := formPos(st, sp, a, i)
		v, err := formAsk(ctx, t, st, sp, a, scr, i, pos, total)
		if errors.Is(err, errMenuBack) {
			if at = formPrev(st, sp, a, order, at); at < 0 {
				return errMenuBack
			}
			continue
		}
		if err != nil {
			return err
		}
		a[q.key] = v
		at++
	}
	return nil
}

// formPrev is the place in order of the shown question before at, or -1.
func formPrev(st *store.State, sp formSpec, a formAnswers, order []int, at int) int {
	for at--; at >= 0; at-- {
		if sp.qs[order[at]].visible(st, a) {
			return at
		}
	}
	return -1
}

// formPos is question i's place among the shown questions of its tier, and
// how many there are, for "2 of 5".
func formPos(st *store.State, sp formSpec, a formAnswers, i int) (pos, total int) {
	for j, q := range sp.qs {
		if q.advanced != sp.qs[i].advanced || !q.visible(st, a) {
			continue
		}
		total++
		if j <= i {
			pos = total
		}
	}
	return pos, total
}

// formLead is the answers given so far (each shown question before i that
// has one), then the question itself.
func formLead(st *store.State, sp formSpec, a formAnswers, i int) [][]seg {
	w := 0
	for _, q := range sp.qs {
		w = max(w, displayWidth(q.label))
	}
	var lead [][]seg
	for _, q := range sp.qs[:i] {
		if v, ok := a[q.key]; ok && q.visible(st, a) && (!q.advanced || sp.qs[i].advanced || v != "") {
			pad := strings.Repeat(" ", max(0, w-displayWidth(q.label)))
			lead = append(lead, []seg{{"  " + q.label + pad + "  ", "2"}, {formShown(st, q, a, v), ""}})
		}
	}
	if len(lead) > 0 {
		lead = append(lead, nil)
	}
	return append(lead, []seg{{sp.qs[i].ask, "1"}})
}

// formShown is an answer as the person reads it: a choice by its label.
func formShown(st *store.State, q formQ, a formAnswers, v string) string {
	if q.choices != nil {
		for _, r := range q.choices(st, a) {
			if r.value == v {
				return r.label
			}
		}
	}
	if v == "" {
		return "none"
	}
	return v
}

// formAsk asks question i: a list to pick from, or a line to type.
func formAsk(ctx context.Context, t *menuTerm, st *store.State, sp formSpec, a formAnswers, scr menuScreen, i, pos, total int) (string, error) {
	q := sp.qs[i]
	title := fmt.Sprintf("%s · %d of %d", sp.title, pos, total)
	if q.advanced {
		title = fmt.Sprintf("%s · more options, %d of %d", sp.title, pos, total)
	}
	l := &menuList{title: title, lead: formLead(st, sp, a, i), note: q.help}
	cur, answered := a[q.key]
	if !answered {
		cur = formDefault(st, q, a)
	}
	if q.choices != nil && q.free {
		return formPickOrType(ctx, t, l, q, st, a, scr, cur)
	}
	if q.choices != nil {
		l.rows = formOptionalRows(q, q.choices(st, a))
		l.empty = "nothing here yet; Esc goes back, and Add in the menu adds one"
		l.point(cur)
		scr.footer = listKeys(l, "Esc back", formCancelKey(l))
		row, err := menuChoose(ctx, t, l, scr)
		if errors.Is(err, errMenuQuit) {
			return "", errFormCancel
		}
		return row.value, err
	}
	return formType(ctx, t, st, q, a, l, scr, cur)
}

// formType reads a typed answer and checks it; a problem shows under the
// line, marked "! " in bold, and the answer stays to be fixed.
func formType(ctx context.Context, t *menuTerm, st *store.State, q formQ, a formAnswers, l *menuList, scr menuScreen, cur string) (string, error) {
	def := formDefault(st, q, a)
	l.typing, l.prompt, l.filter = true, q.label+": ", cur
	if q.addr { // a pasted password is never drawn, not even before Enter
		l.mask = func(s string) string {
			clean, _ := pastedSecret(s)
			return clean
		}
	}
	if def != "" {
		l.prompt = q.label + " [" + def + "]: "
		if cur == def {
			l.filter = "" // Enter takes the default; typing replaces it
		}
	}
	if q.example != "" {
		l.empty = "for example: " + q.example
	}
	scr.footer = "Enter next · Esc back · Ctrl-C cancel"
	for {
		v, err := formLine(ctx, t, q, l, scr)
		if err != nil {
			return "", err
		}
		if v = strings.TrimSpace(v); v == "" {
			v = def
		}
		problem := ""
		switch {
		case v == "" && !q.optional:
			problem = "type an answer"
			if q.example != "" {
				problem += ", for example " + q.example
			}
		case v != "" && q.check != nil:
			problem = q.check(st, a, v)
		}
		if problem == "" {
			return v, nil
		}
		l.note, l.warn, l.filter = problem, true, v
	}
}

// formLine is menuAsk for a form: Esc clears the line, then goes back;
// Ctrl-C cancels the form. On an address line a pasted password is taken
// out before the screen is drawn again, so it is never shown.
func formLine(ctx context.Context, t *menuTerm, q formQ, l *menuList, s menuScreen) (string, error) {
	var text string
	err := menuShow(ctx, t, l, s, func(k menuKey, page int) (bool, error) {
		switch k.kind {
		case keyEnter:
			text = l.filter
			if clean, found := pastedSecret(text); q.addr && found {
				text = clean
			}
			l.setFilter("")
			return true, nil
		case keyEsc:
			if l.filter == "" {
				return true, errMenuBack
			}
			l.setFilter("")
		case keyQuit:
			return true, errFormCancel
		case keyRune, keyBackspace, keyClear:
			l.update(k, page)
			if _, found := pastedSecret(l.filter); q.addr && found {
				l.note, l.warn = "a password was in it: komando takes it out and keeps nothing; the command asks for it hidden", true
			}
		}
		return false, nil
	})
	return text, err
}

// pastedSecret takes the password out of user:password@host or
// scheme://user:password@host, as people paste them from a hosting email.
func pastedSecret(s string) (string, bool) {
	at := strings.LastIndex(s, "@")
	if at < 0 {
		return s, false
	}
	start := 0
	if i := strings.Index(s[:at], "://"); i >= 0 {
		start = i + 3
	}
	user := s[start:at]
	c := strings.Index(user, ":")
	if c < 0 {
		return s, false
	}
	return s[:start] + user[:c] + s[at:], true
}

// The review's own rows, besides one row per answer.
const (
	formRunRow  = "\x00run"
	formDryRow  = "\x00dry"
	formMoreRow = "\x00more"
)

// formReview shows every answer and the commands they make. Enter on the
// first row runs them; on an answer, asks it again.
func formReview(ctx context.Context, t *menuTerm, st *store.State, sp formSpec, a formAnswers, scr menuScreen, dry bool) (string, error) {
	l := formReviewList(st, sp, a, dry)
	scr.footer = listKeys(l, "Esc back", formCancelKey(l))
	row, err := menuChoose(ctx, t, l, scr)
	if errors.Is(err, errMenuQuit) {
		return "", errFormCancel
	}
	return row.value, err
}

// formReviewList is the review screen. Its commands are formBuild's, so
// what it shows is what Run it runs.
func formReviewList(st *store.State, sp formSpec, a formAnswers, dry bool) *menuList {
	l := &menuList{title: sp.title + ": check and run", note: "Enter on an answer changes it"}
	l.lead = append(l.lead, []seg{{"This runs:", "2"}})
	cmds := formBuild(st, sp, a)
	for _, c := range cmds {
		l.runs = append(l.runs, "$ komando "+menuCommandLine(c))
	}
	gone := formDestructive(cmds)
	if gone != "" { // a note, so it shows under the commands, not above them
		l.note, l.warn = "This "+gone+". It cannot be undone.", true
		if dry {
			l.note += " Try it first to see what and how much it would delete."
		}
	}
	l.rows = []menuRow{{label: "Run it", detail: "run the commands above", value: formRunRow}}
	if dry {
		l.rows = append(l.rows, menuRow{label: "Try it first", detail: "show what it would do, changing nothing (--dry-run)", value: formDryRow})
	}
	var more []string
	for _, q := range sp.qs {
		if !q.visible(st, a) {
			continue
		}
		v, ok := a[q.key]
		if q.advanced && (!ok || v == "") {
			more = append(more, strings.ToLower(q.label))
			continue
		}
		l.rows = append(l.rows, menuRow{label: q.label, detail: formShown(st, q, a, v), value: q.key})
	}
	if len(more) > 0 {
		l.rows = append(l.rows, menuRow{label: "More options", detail: strings.Join(more, ", "), value: formMoreRow})
	}
	if gone != "" && dry {
		l.point(formDryRow) // Enter tries it first; running for real is one row up
	}
	return l
}

// formDestructive says what a command deletes for good ("deletes keys"),
// or "" when it deletes nothing that cannot come back.
func formDestructive(cmds [][]string) string {
	for _, c := range cmds {
		if len(c) < 2 {
			continue
		}
		switch c[0] + " " + c[1] {
		case "queue purge":
			return "deletes every waiting message"
		case "queue rm":
			return "deletes the topics or queues with their messages"
		case "cache rm":
			return "deletes the keys"
		case "storage rm":
			return "deletes the files"
		case "cluster rm":
			return "deletes it from the cluster"
		case "registry rm", "registry prune":
			return "deletes the images"
		case "db restore":
			return "replaces what is in the database now"
		case "cluster scale":
			if slices.Contains(c, "0") || slices.Contains(c, "--replicas=0") {
				return "stops every copy of the app"
			}
		}
	}
	return ""
}

// formPick asks what to add: a group (Server, Database, ...), then a kind
// when the group has more than one. A list with one row is not shown; asked
// says whether any list was, so Esc on the form has somewhere to go back.
func formPick(ctx context.Context, t *menuTerm, groups []formGroup, scr menuScreen) (sp formSpec, asked bool, err error) {
	if len(groups) == 0 {
		return formSpec{}, false, errMenuBack
	}
	gl := &menuList{title: "Add: what is it?"}
	for _, g := range groups {
		gl.rows = append(gl.rows, menuRow{label: g.label, detail: g.detail, value: g.label})
	}
	for {
		g := groups[0]
		if len(groups) > 1 {
			scr.footer = listKeys(gl, "Esc back", formCancelKey(gl))
			row, err := menuChoose(ctx, t, gl, scr)
			if err != nil {
				return formSpec{}, true, formQuitIsCancel(err)
			}
			gl.point(row.value)
			g = groups[slices.IndexFunc(groups, func(x formGroup) bool { return x.label == row.value })]
		}
		if len(g.kinds) == 1 {
			return g.kinds[0].spec(), len(groups) > 1, nil
		}
		title := g.ask
		if title == "" {
			title = "Add " + strings.ToLower(g.label) + ": which kind?"
		}
		kl := &menuList{title: title, typing: len(g.kinds) > 9}
		for _, k := range g.kinds {
			kl.rows = append(kl.rows, menuRow{label: k.label, detail: k.detail, value: k.label})
		}
		scr.footer = listKeys(kl, "Esc back", formCancelKey(kl))
		row, err := menuChoose(ctx, t, kl, scr)
		if errors.Is(err, errMenuBack) && len(groups) > 1 {
			continue
		}
		if err != nil {
			return formSpec{}, true, formQuitIsCancel(err)
		}
		return g.kinds[slices.IndexFunc(g.kinds, func(k formKind) bool { return k.label == row.value })].spec(), true, nil
	}
}

// formChoose is what to add and its answers: Esc on a form's first
// question goes back to the kinds. It returns the commands to run.
func formChoose(ctx context.Context, t *menuTerm, st *store.State, groups []formGroup, scr menuScreen, try formTry) ([][]string, error) {
	_, _, cmds, err := formChooseFull(ctx, t, st, groups, scr, try)
	return cmds, err
}

// formChooseFull is formChoose that also gives the form and its answers,
// to ask them again when the new thing does not answer.
func formChooseFull(ctx context.Context, t *menuTerm, st *store.State, groups []formGroup, scr menuScreen, try formTry) (formSpec, formAnswers, [][]string, error) {
	for {
		sp, asked, err := formPick(ctx, t, groups, scr)
		if err != nil {
			return sp, nil, nil, err
		}
		a := formAnswers{}
		cmds, err := formFillFrom(ctx, t, st, sp, scr, try, a)
		if errors.Is(err, errMenuBack) && asked {
			continue
		}
		return sp, a, cmds, err
	}
}

// formCommand is `komando host add` (conn add, vpn add) alone at a
// person's terminal: the same questions as the menu's Add, then the
// commands run here, each shown first. It ends with the exit code of the
// first command that fails.
func formCommand(groups []formGroup) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	t, err := newMenuTerm()
	if err != nil {
		return err
	}
	scr := menuScreen{header: menuHeader(st), color: colorOK()}
	try := func(args []string) error {
		again, err := menuRun(context.Background(), t, self, [][]string{args}, false, "the questions")
		if err == nil && !again {
			err = errFormCancel // q after Try it first: leave
		}
		return err
	}
	sp, a, cmds, err := formChooseFull(context.Background(), t, st, groups, scr, try)
	t.leave()
	if errors.Is(err, errFormCancel) || errors.Is(err, errMenuBack) || errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "komando: nothing was added")
		return exitCode(out.ExitError)
	}
	if err != nil {
		return err
	}
	for {
		code, reason, err := formRunAll(self, cmds)
		if err != nil || code == 0 {
			return err
		}
		rm := formRemoveCmd(cmds)
		if reason == "" || rm == nil { // the add itself failed: nothing to undo
			return exitCode(max(code, out.ExitError))
		}
		next, err := formAfterFailedCheck(context.Background(), t, scr, a["name"], reason)
		t.leave()
		if err != nil {
			return exitCode(max(code, out.ExitError))
		}
		switch next {
		case formKeepRow:
			fmt.Fprintf(os.Stderr, "Kept %s in your list. Test it again later: komando test %s\n", a["name"], a["name"])
			return exitCode(max(code, out.ExitError))
		case formRemoveRow:
			c, _, err := formRunAll(self, [][]string{rm})
			if err != nil {
				return err
			}
			return exitCode(max(c, code, out.ExitError))
		}
		// change the answers: the questions again, filled in, then the old
		// one goes before the new one is added
		if st, err = loadState(); err != nil {
			return err
		}
		delete(st.Hosts, a["name"]) // its name is free again for the check
		delete(st.Conns, a["name"])
		delete(st.Vpns, a["name"])
		again, err := formFillFrom(context.Background(), t, st, sp, scr, try, a)
		t.leave()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Kept %s as it was. Test it again later: komando test %s\n", a["name"], a["name"])
			return exitCode(max(code, out.ExitError))
		}
		cmds = append([][]string{rm}, again...)
	}
}

// formArgs lets an add command take no arguments, for the questions; with
// any argument the usual rule holds.
func formArgs(rule cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return nil
		}
		return rule(cmd, args)
	}
}

// formOrUsage is an add command typed with nothing after it: the questions
// for a person at a terminal (no flags either, as for the menu), the usual
// usage error for everyone else, AI agents and scripts included.
func formOrUsage(cmd *cobra.Command, kind, example string) error {
	if menuWanted(cmd, nil) {
		return formCommand(formGroupsFor(kind))
	}
	return out.Errf(out.ExitUsage, "USAGE",
		"for example: "+example+". A person can type `komando "+kind+" add` alone at a terminal to be asked step by step",
		"komando %s add needs a name and what to add", kind)
}
