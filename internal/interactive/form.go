package interactive

import (
	"strings"

	"github.com/sgnd/komando/internal/cli/kit/term"
)

// Answers are a form's answers by field key.
type Answers = map[string]string

// Field is one question of a form, as internal/cli describes it from the
// command and its form hint. A secret or a value komando makes is never a
// field: internal/cli leaves those out. The functions read the answers
// given so far and nothing else may change through them.
type Field struct {
	Key      string // the answer's key: arg0, arg1 ... or flag:NAME
	Ask      string // the question
	Help     string
	Required bool
	Free     bool // with Rows: other text may be typed (tag:prod)
	Advanced bool // asked only after "more options"

	Default func(Answers) string // what an empty Enter takes; nil: nothing
	Rows    func(Answers) []Row  // the list it is picked from; nil: typed
	Show    func(Answers) bool   // asked only while true; nil: always
}

// Form asks a command's fields one after another: the required ones
// first, then the other main ones; the advanced ones only when the person
// asks for more options. Its answers go back to internal/cli, which builds
// the line.
type Form struct {
	Title   string
	fields  []Field // asked, in order
	rest    []Field // the advanced fields, until more options
	cur     int
	text    map[string]string // typed answers, by key
	taken   map[string]string // answers picked from a list, by key
	lists   map[string]*List  // the list of a field, made when it is entered
	more    *List             // the more-options step, while on it
	help    bool
	problem string // why the last Enter did not go on
}

// NewForm is a form on its first field.
func NewForm(title string, fields []Field) *Form {
	f := &Form{Title: title, text: map[string]string{}, taken: map[string]string{}, lists: map[string]*List{}}
	for _, pass := range []func(Field) bool{
		func(x Field) bool { return x.Required },
		func(x Field) bool { return !x.Required && !x.Advanced },
	} {
		for _, x := range fields {
			if pass(x) {
				f.fields = append(f.fields, x)
			}
		}
	}
	for _, x := range fields {
		if x.Advanced && !x.Required {
			f.rest = append(f.rest, x)
		}
	}
	f.cur = -1
	f.step(1)
	return f
}

// Field is the field being filled; the zero Field on the more-options step.
func (f *Form) Field() Field {
	if f.more != nil || f.cur < 0 || f.cur >= len(f.fields) {
		return Field{}
	}
	return f.fields[f.cur]
}

// AtMore says whether the form asks whether to see more options.
func (f *Form) AtMore() bool { return f.more != nil }

// Text is what is typed into the field being filled.
func (f *Form) Text() string { return f.text[f.Field().Key] }

// Key applies one key. Take comes with the answers: only shown fields
// that have a value.
func (f *Form) Key(k term.Key) (Result, Answers) {
	switch k.Kind {
	case term.KeyInterrupt:
		return Quit, nil
	case term.KeyTab:
		return f.step(1)
	case term.KeyBackTab:
		f.back()
		return Stay, nil
	}
	if f.more != nil {
		return f.moreKey(k)
	}
	if l := f.list(); l != nil {
		r, v := l.Key(k)
		switch r {
		case Take:
			f.taken[f.Field().Key] = v
			return f.step(1)
		case Back, Quit:
			return r, nil
		}
		return Stay, nil
	}
	return f.textKey(k)
}

// textKey edits a typed field.
func (f *Form) textKey(k term.Key) (Result, Answers) {
	key, t := f.Field().Key, f.Text()
	switch k.Kind {
	case term.KeyRune:
		if k.Rune == '?' && t == "" {
			f.help = !f.help
			return Stay, nil
		}
		f.text[key], f.problem = t+string(k.Rune), ""
	case term.KeyPaste:
		f.text[key], f.problem = t+oneLine(k.Text), ""
	case term.KeyBackspace:
		if r := []rune(t); len(r) > 0 {
			f.text[key] = string(r[:len(r)-1])
		}
	case term.KeyClear:
		f.text[key] = ""
	case term.KeyUp:
		f.back()
	case term.KeyDown:
		return f.step(1)
	case term.KeyEnter:
		x := f.Field()
		if t == "" && x.Default != nil {
			t = x.Default(f.answers(f.cur))
			f.text[key] = t
		}
		if t == "" && x.Required {
			f.problem = "an answer is needed here"
			return Stay, nil
		}
		return f.step(1)
	case term.KeyEsc:
		if t == "" {
			return Back, nil
		}
		f.text[key] = ""
	}
	return Stay, nil
}

// moreKey is the step that asks whether to see more options.
func (f *Form) moreKey(k term.Key) (Result, Answers) {
	r, v := f.more.Key(k)
	switch {
	case r == Take && v == "more":
		f.more = nil
		f.cur = len(f.fields) - 1
		f.fields, f.rest = append(f.fields, f.rest...), nil
		return f.step(1)
	case r == Take:
		return f.finish()
	case r == Back:
		f.back()
	}
	return Stay, nil
}

// step goes to the next shown field; past the last, to more options or
// the end.
func (f *Form) step(d int) (Result, Answers) {
	if f.more != nil {
		return Stay, nil
	}
	f.help, f.problem = false, ""
	for i := f.cur + d; i >= 0 && i < len(f.fields); i += d {
		if f.shown(i) {
			f.enter(i)
			return Stay, nil
		}
	}
	if d < 0 {
		return Stay, nil
	}
	if len(f.rest) > 0 {
		f.offerMore()
		return Stay, nil
	}
	return f.finish()
}

// back goes to the shown field before; from more options, to the last.
func (f *Form) back() {
	if f.more != nil {
		f.more = nil
		f.cur = len(f.fields)
	}
	f.step(-1)
}

// shown says whether field i is asked with the answers before it.
func (f *Form) shown(i int) bool {
	x := f.fields[i]
	return x.Show == nil || x.Show(f.answers(i))
}

// enter makes field i the one being filled; its list is made from the
// answers before it, on its answer or its default.
func (f *Form) enter(i int) {
	f.cur = i
	x := f.fields[i]
	if x.Rows == nil {
		return
	}
	a := f.answers(i)
	rows := x.Rows(a)
	want := f.taken[x.Key]
	if want == "" && x.Default != nil {
		want = x.Default(a)
	}
	l := NewList(x.Ask, x.Help, rows, x.Free)
	for j, r := range rows {
		if r.Value == want && want != "" {
			l.move(j, len(rows))
		}
	}
	f.lists[x.Key] = l
}

// answers are the answers of the shown fields before field n, in order.
func (f *Form) answers(n int) Answers {
	a := Answers{}
	for _, x := range f.fields[:min(n, len(f.fields))] {
		if x.Show != nil && !x.Show(a) {
			continue
		}
		if v := f.value(x); v != "" {
			a[x.Key] = v
		}
	}
	return a
}

func (f *Form) value(x Field) string {
	if x.Rows != nil {
		return f.taken[x.Key]
	}
	return f.text[x.Key]
}

func (f *Form) offerMore() {
	f.more = NewList("More options?", "", []Row{
		{Value: "review", Label: "review now", Detail: "see the command before it runs"},
		{Value: "more", Label: "more options", Detail: optionNames(f.rest)},
	}, false)
}

// finish ends the form, unless a shown required field has no answer:
// then it goes back to that field.
func (f *Form) finish() (Result, Answers) {
	for i, x := range f.fields {
		if x.Required && f.shown(i) && f.value(x) == "" {
			f.more = nil
			f.enter(i)
			f.problem = "an answer is needed here"
			return Stay, nil
		}
	}
	return Take, f.answers(len(f.fields))
}

// list is the list of the field being filled; nil for a typed field.
func (f *Form) list() *List {
	if f.more != nil || f.Field().Rows == nil {
		return nil
	}
	return f.lists[f.Field().Key]
}

// optionNames lists the advanced fields by their keys' names, for the
// more-options row.
func optionNames(fields []Field) string {
	var names []string
	for _, x := range fields {
		names = append(names, strings.TrimPrefix(x.Key, "flag:"))
	}
	return strings.Join(names, ", ")
}

// oneLine is pasted text as one line: line breaks and tabs become spaces,
// other control characters go.
func oneLine(s string) string {
	return term.CleanText(strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ", "\t", " ").Replace(s))
}
