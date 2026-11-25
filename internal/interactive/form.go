package interactive

import (
	"strings"

	"github.com/sgnd/komando/internal/cli/kit/term"
)

// Field is one question of a form, as internal/cli describes it from the
// command and its form hint. A secret or a value komando makes is never a
// field: internal/cli leaves those out.
type Field struct {
	Key      string // the answer's key: arg0, arg1 ... or flag:NAME
	Ask      string // the question
	Help     string
	Default  string
	Required bool
	Choices  []string // a few values, picked from a list
	Pick     string   // a list the Lister fills: server, db, ...
	Free     bool     // with Pick or Choices: other text may be typed
	Advanced bool     // asked only after "more options"
}

// Lister gives the rows of a pick list. It only reads.
type Lister func(kind string) []Row

// Form asks a command's fields one after another: the required ones
// first, then the other main ones; the advanced ones only when the person
// asks for more options. Its answers go back to internal/cli, which builds
// the line.
type Form struct {
	Title   string
	fields  []Field // asked, in order
	rest    []Field // the advanced fields, until more options
	lister  Lister
	cur     int
	text    map[string]string // typed answers, by key
	taken   map[string]string // answers picked from a list, by key
	lists   map[string]*List
	more    *List // the more-options step, while on it
	help    bool
	problem string // why the last Enter did not go on
}

// NewForm is a form on its first field.
func NewForm(title string, fields []Field, lister Lister) *Form {
	f := &Form{Title: title, lister: lister, text: map[string]string{}, taken: map[string]string{}, lists: map[string]*List{}}
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
		if x.Pick != "" || len(x.Choices) > 0 {
			f.lists[x.Key] = f.newList(x)
		}
	}
	if len(f.fields) == 0 {
		f.offerMore()
	}
	return f
}

// Field is the field being filled; the zero Field on the more-options step.
func (f *Form) Field() Field {
	if f.more != nil || f.cur >= len(f.fields) {
		return Field{}
	}
	return f.fields[f.cur]
}

// AtMore says whether the form asks whether to see more options.
func (f *Form) AtMore() bool { return f.more != nil }

// Text is what is typed into the field being filled.
func (f *Form) Text() string { return f.text[f.Field().Key] }

// Key applies one key. Take comes with the answers: only fields that have
// a value.
func (f *Form) Key(k term.Key) (Result, map[string]string) {
	switch k.Kind {
	case term.KeyInterrupt:
		return Quit, nil
	case term.KeyTab:
		return f.next()
	case term.KeyBackTab:
		f.prev()
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
			return f.next()
		case Back, Quit:
			return r, nil
		}
		return Stay, nil
	}
	return f.textKey(k)
}

// textKey edits a typed field.
func (f *Form) textKey(k term.Key) (Result, map[string]string) {
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
		f.prev()
	case term.KeyDown:
		return f.next()
	case term.KeyEnter:
		fl := f.Field()
		if t == "" {
			t = fl.Default
			f.text[key] = t
		}
		if t == "" && fl.Required {
			f.problem = "an answer is needed here"
			return Stay, nil
		}
		return f.next()
	case term.KeyEsc:
		if t == "" {
			return Back, nil
		}
		f.text[key] = ""
	}
	return Stay, nil
}

// moreKey is the step that asks whether to see more options.
func (f *Form) moreKey(k term.Key) (Result, map[string]string) {
	r, v := f.more.Key(k)
	switch {
	case r == Take && v == "more":
		f.more = nil
		f.cur = len(f.fields)
		f.fields, f.rest = append(f.fields, f.rest...), nil
	case r == Take:
		return f.finish()
	case r == Back:
		f.more = nil
		f.cur = max(0, len(f.fields)-1)
	}
	return Stay, nil
}

// next goes to the next field; past the last, to more options or the end.
func (f *Form) next() (Result, map[string]string) {
	if f.more != nil {
		return Stay, nil
	}
	f.help, f.problem = false, ""
	if f.cur < len(f.fields)-1 {
		f.cur++
		return Stay, nil
	}
	if len(f.rest) > 0 {
		f.offerMore()
		return Stay, nil
	}
	return f.finish()
}

func (f *Form) prev() {
	f.help, f.problem = false, ""
	if f.more != nil {
		f.more = nil
		f.cur = max(0, len(f.fields)-1)
		return
	}
	f.cur = max(0, f.cur-1)
}

func (f *Form) offerMore() {
	f.more = NewList("More options?", "", []Row{
		{Value: "review", Label: "review now", Detail: "see the command before it runs"},
		{Value: "more", Label: "more options", Detail: optionNames(f.rest)},
	}, false)
}

// finish ends the form, unless a required field has no answer: then it
// goes back to that field.
func (f *Form) finish() (Result, map[string]string) {
	a := map[string]string{}
	for i, x := range f.fields {
		v := f.taken[x.Key]
		if x.Pick == "" && len(x.Choices) == 0 {
			v = f.text[x.Key]
		}
		if v == "" && x.Required {
			f.more, f.cur, f.problem = nil, i, "an answer is needed here"
			return Stay, nil
		}
		if v != "" {
			a[x.Key] = v
		}
	}
	return Take, a
}

// list is the list of the field being filled; nil for a typed field.
func (f *Form) list() *List {
	if f.more != nil {
		return nil
	}
	return f.lists[f.Field().Key]
}

// newList is the list a pick or choices field is filled from, on its
// default row.
func (f *Form) newList(x Field) *List {
	var rows []Row
	for _, c := range x.Choices {
		rows = append(rows, Row{Value: c, Label: c})
	}
	if x.Pick != "" && f.lister != nil {
		rows = append(rows, f.lister(x.Pick)...)
	}
	l := NewList(x.Ask, x.Help, rows, x.Free)
	for i, r := range rows {
		if r.Value == x.Default && x.Default != "" {
			l.move(i, len(rows))
		}
	}
	return l
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
