package snippet

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/out"
)

// unitVar is a text variable like svc-status's unit.
var unitVar = Var{Name: "unit", Channel: Text, Pattern: regexp.MustCompile(`^[A-Za-z0-9@._:-]+$`), MaxLen: 8, Required: true, Longest: "nginx-ab"}

// sample is a valid text built-in; each test changes one thing.
func sample() Builtin {
	return Builtin{
		Name: "svc-status", Type: "host", Replaces: "svc status", Reader: "KomandoCall+Services.swift:36",
		Tier: capability.Read, Shape: "svc-status/1", Vars: []Var{unitVar},
		Text:  map[Family]string{Unix: "systemctl show -- {{var:unit}}", Windows: "Get-Service -Name {{var:unit}}"},
		Parse: func(o Output, _ Family) (any, error) { return []string{strings.TrimSpace(o.Stdout)}, nil },
	}
}

func code(err error) string {
	var e *out.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestNewRefusesBadDefinitions(t *testing.T) {
	cases := []struct {
		name string
		edit func(b *Builtin)
		want string // a word of the error
	}{
		{"bad name", func(b *Builtin) { b.Name = "Svc_Status" }, "name"},
		{"unknown type", func(b *Builtin) { b.Type = "queue" }, "type"},
		{"shape of another name", func(b *Builtin) { b.Shape = "svc-list/1" }, "shape"},
		{"shape without a major", func(b *Builtin) { b.Shape = "svc-status" }, "shape"},
		{"shape major zero", func(b *Builtin) { b.Shape = "svc-status/0" }, "shape"},
		{"no replaced command", func(b *Builtin) { b.Replaces = "" }, "replaces"},
		{"no reader", func(b *Builtin) { b.Reader = "" }, "reader"},
		{"text and run", func(b *Builtin) { b.Run = func(context.Context, Values) (any, error) { return nil, nil } }, "both"},
		{"neither text nor run", func(b *Builtin) { b.Text, b.Parse = nil, nil }, "neither"},
		{"text without parser", func(b *Builtin) { b.Parse = nil }, "parse"},
		{"unknown family", func(b *Builtin) { b.Text["plan9"] = "ls" }, "family"},
		{"undeclared variable in text", func(b *Builtin) { b.Text[Unix] = "ls {{var:path}}" }, "path"},
		{"broken marker", func(b *Builtin) { b.Text[Unix] = "ls {{var: unit}}" }, "marker"},
		{"client variable in text", func(b *Builtin) {
			b.Vars = []Var{{Name: "unit", Channel: SQLIdent, Pattern: unitVar.Pattern, MaxLen: 8, Longest: "nginx-ab"}}
		}, "text"},
		{"variable without pattern", func(b *Builtin) { b.Vars = []Var{{Name: "unit", Channel: Text, MaxLen: 8, Longest: "nginx-ab"}} }, "pattern"},
		{"unanchored pattern", func(b *Builtin) {
			b.Vars = []Var{{Name: "unit", Channel: Text, Pattern: regexp.MustCompile(`[a-z]+`), MaxLen: 8, Longest: "abcdefgh"}}
		}, "anchored"},
		{"no max length", func(b *Builtin) {
			b.Vars = []Var{{Name: "unit", Channel: Text, Pattern: unitVar.Pattern, Longest: "a"}}
		}, "length"},
		{"longest value too short", func(b *Builtin) { v := unitVar; v.Longest = "nginx"; b.Vars = []Var{v} }, "longest"},
		{"longest value off pattern", func(b *Builtin) { v := unitVar; v.Longest = "nginx ab"; b.Vars = []Var{v} }, "longest"},
		{"default off pattern", func(b *Builtin) { v := unitVar; v.Required, v.Default = false, "a b"; b.Vars = []Var{v} }, "default"},
		{"variable twice", func(b *Builtin) { b.Vars = []Var{unitVar, unitVar} }, "twice"},
		{"no channel", func(b *Builtin) { v := unitVar; v.Channel = 0; b.Vars = []Var{v} }, "channel"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := sample()
			b.Text = map[Family]string{Unix: b.Text[Unix], Windows: b.Text[Windows]}
			c.edit(&b)
			_, err := New([]Builtin{b})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("New() = %v, want an error naming %q", err, c.want)
			}
		})
	}
}

func TestNewAcceptsAndFinds(t *testing.T) {
	r, err := New([]Builtin{sample()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := r.Lookup("svc-status"); !ok || b.Shape != "svc-status/1" {
		t.Fatalf("Lookup(svc-status) = %v, %v", b.Name, ok)
	}
	for _, n := range []string{"SVC-STATUS", "svc-status ", "svc"} { // exact names only
		if _, ok := r.Lookup(n); ok {
			t.Errorf("Lookup(%q) found a built-in; only an exact name may", n)
		}
	}
	if got := r.Names(); len(got) != 1 || got[0] != "svc-status" {
		t.Errorf("Names() = %v", got)
	}
}

func TestNewRefusesTheSameNameTwice(t *testing.T) {
	if _, err := New([]Builtin{sample()}, []Builtin{sample()}); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("New() = %v, want a refusal of the second svc-status", err)
	}
}

// The open hooks of Audit's delta read: these two need a rule first.
func TestNewRefusesSnippetsThatWaitOnARule(t *testing.T) {
	for name, rule := range map[string]string{"fs-write": "Q1", "pkg-upgrade-all": "Q2"} {
		b := sample()
		b.Name, b.Shape = name, name+"/1"
		_, err := New([]Builtin{b})
		if err == nil || !strings.Contains(err.Error(), rule) {
			t.Errorf("New(%s) = %v, want a refusal naming %s", name, err, rule)
		}
	}
}

func TestNewEmptyIsTheProductionList(t *testing.T) {
	r, err := New()
	if err != nil || len(r.Names()) != 0 {
		t.Fatalf("New() = %v, %v; want an empty list", r.Names(), err)
	}
}

func TestFillQuotesEachFamilyItsOwnWay(t *testing.T) {
	b := sample()
	b.Vars[0].Pattern = regexp.MustCompile(`^.+$`)
	b.Vars[0].MaxLen = 40
	b.Vars[0].Longest = strings.Repeat("a", 40)
	hostile := []string{"a;reboot", "a'b", "a`b", "$(id)", "a b", "x*", "../..", `a"b`, "a$b"}
	for _, v := range hostile {
		got, err := Fill(b, Unix, map[string]string{"unit": v})
		if err != nil {
			t.Fatalf("Fill(%q): %v", v, err)
		}
		if want := "systemctl show -- " + shQ(v); got != want {
			t.Errorf("Unix Fill(%q) = %s, want %s", v, got, want)
		}
		got, err = Fill(b, Windows, map[string]string{"unit": v})
		if err != nil {
			t.Fatalf("Fill(%q): %v", v, err)
		}
		if want := "Get-Service -Name " + psQ(v); got != want {
			t.Errorf("Windows Fill(%q) = %s, want %s", v, got, want)
		}
	}
}

// shQ and psQ are the quoting the engine must use, written out here so a
// change to the engine's choice shows.
func shQ(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }
func psQ(s string) string {
	for _, q := range []string{"'", "‘", "’", "‚", "‛"} {
		s = strings.ReplaceAll(s, q, q+q)
	}
	return "'" + s + "'"
}

func TestFillRefusals(t *testing.T) {
	cases := []struct {
		name  string
		f     Family
		given map[string]string
		code  string
	}{
		{"unknown variable", Unix, map[string]string{"unit": "nginx", "user": "x"}, "UNKNOWN_VAR"},
		{"missing required", Unix, map[string]string{}, "USAGE"},
		{"off pattern", Unix, map[string]string{"unit": "a;b"}, "USAGE"},
		{"too long", Unix, map[string]string{"unit": "nginx-abc"}, "USAGE"},
		{"option-like", Unix, map[string]string{"unit": "-x"}, "OPTION_LIKE_VAR"},
		{"no text for the family", "macos", map[string]string{"unit": "nginx"}, "SNIPPET_OS_UNSUPPORTED"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Fill(sample(), c.f, c.given)
			if code(err) != c.code {
				t.Fatalf("Fill = %q, %v; want code %s", got, err, c.code)
			}
		})
	}
}

func TestFillRefusesControlCharactersWhateverThePattern(t *testing.T) {
	b := sample()
	b.Vars[0].Pattern = regexp.MustCompile(`(?s)^.+$`)
	b.Vars[0].MaxLen, b.Vars[0].Longest = 20, strings.Repeat("a", 20)
	for _, v := range []string{"a\nreboot", "a\rb", "a\x00b", "a\x1bb", "\xff"} {
		if _, err := Fill(b, Unix, map[string]string{"unit": v}); code(err) != "USAGE" {
			t.Errorf("Fill(%q) = %v, want USAGE", v, err)
		}
	}
}

func TestFillUsesTheDefault(t *testing.T) {
	b := sample()
	b.Vars[0].Required, b.Vars[0].Default = false, "cron"
	got, err := Fill(b, Unix, nil)
	if err != nil || got != "systemctl show -- 'cron'" {
		t.Fatalf("Fill = %q, %v", got, err)
	}
}

// A value that looks like a marker is not filled a second time.
func TestFillIsOnePass(t *testing.T) {
	b := sample()
	b.Vars = []Var{
		{Name: "a", Channel: Text, Pattern: regexp.MustCompile(`^[{}a-z:]+$`), MaxLen: 9, Longest: "{{var:b}}"},
		{Name: "b", Channel: Text, Pattern: regexp.MustCompile(`^[a-z]+$`), MaxLen: 1, Longest: "x"},
	}
	b.Text = map[Family]string{Unix: "echo {{var:a}} {{var:b}}"}
	got, err := Fill(b, Unix, map[string]string{"a": "{{var:b}}", "b": "x"})
	if err != nil || got != "echo '{{var:b}}' 'x'" {
		t.Fatalf("Fill = %q, %v", got, err)
	}
}

func TestCheckPerChannel(t *testing.T) {
	any := regexp.MustCompile(`(?s)^.+$`)
	mk := func(c Channel) Builtin {
		return Builtin{Name: "db-schema", Type: "database", Replaces: "db schema", Reader: "r", Tier: capability.Read, Shape: "db-schema/1",
			Vars: []Var{{Name: "v", Channel: c, Pattern: any, MaxLen: 300, Longest: strings.Repeat("a", 300)}},
			Run:  func(context.Context, Values) (any, error) { return nil, nil }}
	}
	// SQL and RESP values reach the client call unchanged: they are bind
	// parameters and separate arguments there, never spliced into a line
	for _, c := range []Channel{SQLIdent, SQLValue, RESP} {
		for _, v := range []string{"a;drop table x", "a'b", "*", "../..", `a"b`} {
			got, err := Check(mk(c), map[string]string{"v": v})
			if err != nil || got["v"] != v {
				t.Errorf("channel %d: Check(%q) = %q, %v; want it unchanged", c, v, got["v"], err)
			}
		}
	}
	for _, v := range []string{"a;b", "A", "a'b", "*", "..", "-a", "a-", strings.Repeat("a", 254)} {
		if _, err := Check(mk(KubeName), map[string]string{"v": v}); code(err) != "USAGE" {
			t.Errorf("KubeName Check(%q) = %v, want USAGE (DNS-1123)", v, err)
		}
	}
	for _, v := range []string{"web", "web-1.api", strings.Repeat("a", 253)} {
		if _, err := Check(mk(KubeName), map[string]string{"v": v}); err != nil {
			t.Errorf("KubeName Check(%q) = %v", v, err)
		}
	}
	for v, want := range map[string]string{"/srv/app/../x": "/srv/x", "/srv//a/./b": "/srv/a/b", "a;b": "a;b"} {
		got, err := Check(mk(SFTPPath), map[string]string{"v": v})
		if err != nil || got["v"] != want {
			t.Errorf("SFTPPath Check(%q) = %q, %v; want %q", v, got["v"], err, want)
		}
	}
	for _, c := range []Channel{SQLIdent, SQLValue, RESP, KubeName, SFTPPath} {
		if _, err := Check(mk(c), map[string]string{"v": "a\nb"}); code(err) != "USAGE" {
			t.Errorf("channel %d: a newline = %v, want USAGE", c, err)
		}
	}
}

func TestParse(t *testing.T) {
	b := sample()
	res, err := Parse(b, Unix, Output{Stdout: "ok\n"})
	if err != nil || len(res.([]string)) != 1 {
		t.Fatalf("Parse = %v, %v", res, err)
	}
	// a parser's own coded error is a carried check: it stays, with the
	// rows it read
	b.Parse = func(Output, Family) (any, error) {
		return []string{"nginx"}, out.Errf(out.ExitNotFound, "UNIT_NOT_FOUND", "", "no unit")
	}
	if res, err := Parse(b, Unix, Output{}); err == nil || err.Code != "UNIT_NOT_FOUND" || res == nil {
		t.Fatalf("Parse = %v, %v; want UNIT_NOT_FOUND with the rows", res, err)
	}
	// a parser of today returns (any, *out.Error): its nil error arrives as
	// a typed nil inside error and is no error
	b.Parse = func(Output, Family) (any, error) {
		var none *out.Error
		return []string{"ok"}, none
	}
	if res, err := Parse(b, Unix, Output{}); err != nil || res == nil {
		t.Fatalf("Parse with a typed nil error = %v, %v; want the result", res, err)
	}
	for name, p := range map[string]func(Output, Family) (any, error){
		"plain error": func(Output, Family) (any, error) { return []string{"partial"}, errors.New("bad line 3") },
		"panic":       func(Output, Family) (any, error) { panic("index out of range") },
		"nothing":     func(Output, Family) (any, error) { return nil, nil },
	} {
		b.Parse = p
		res, err := Parse(b, Unix, Output{Stdout: "secret-looking raw text"})
		if err == nil || err.Code != "SNIPPET_PARSE_FAILED" || res != nil {
			t.Errorf("%s: Parse = %v, %v; want SNIPPET_PARSE_FAILED and no result", name, res, err)
			continue
		}
		if strings.Contains(err.Message+err.Hint, "secret-looking") || strings.Contains(err.Message, "bad line") {
			t.Errorf("%s: the error carries raw text: %s / %s", name, err.Message, err.Hint)
		}
		if !strings.Contains(err.Hint, "`komando exec") {
			t.Errorf("%s: hint %q must name exec, which reads it as text", name, err.Hint)
		}
	}
}

func TestRate(t *testing.T) {
	b := sample()
	if got := Rate(b, 0); got != capability.Read {
		t.Errorf("Rate(read, no hit) = %v", got)
	}
	if got := Rate(b, 1); got != capability.Dangerous {
		t.Errorf("Rate(read, one hit) = %v, want dangerous", got)
	}
	b.Tier = capability.Person
	if got := Rate(b, 2); got != capability.Person {
		t.Errorf("Rate(person, hits) = %v; a hit never lowers the tier", got)
	}
	if Mutating(sample()) {
		t.Error("a read snippet is not mutating")
	}
	b.Tier = capability.Change
	if !Mutating(b) {
		t.Error("a change snippet is mutating")
	}
}

func TestRowDropsTheResultOfAFailure(t *testing.T) {
	b := sample()
	exit := 0
	ok := NewData(b, "dev", []string{"x"}, nil, &exit, nil)
	if !ok.OK || ok.Result == nil || ok.Shape != "svc-status/1" || ok.Snippet != "svc-status" || ok.Target != "dev" {
		t.Fatalf("NewData ok = %+v", ok)
	}
	bad := NewData(b, "dev", []string{"x"}, out.Errf(1, "SNIPPET_PARSE_FAILED", "", "x"), &exit, nil)
	if bad.OK || bad.Result != nil {
		t.Fatalf("NewData failed = %+v; want no result", bad)
	}
	// a carried check keeps the rows today's command keeps
	nf := NewData(b, "dev", []string{"x"}, out.Errf(1, "UNIT_NOT_FOUND", "", "x"), &exit, nil)
	if nf.OK || nf.Result == nil {
		t.Fatalf("NewData not found = %+v; want the rows kept", nf)
	}
	for _, c := range []string{"SNIPPET_OS_UNSUPPORTED", "SNIPPET_WRONG_TYPE"} {
		if d := NewData(b, "dev", "x", out.Errf(1, c, "", "x"), nil, nil); d.Result != nil {
			t.Errorf("%s kept a result", c)
		}
	}
}

func TestDecode(t *testing.T) {
	raw := []byte(`{"snippet":"svc-list","shape":"svc-list/1","target":"dev","ok":true,"result":[1],"new_field":"x"}`)
	d, err := Decode(raw, "svc-list/1")
	if err != nil || d.Target != "dev" {
		t.Fatalf("Decode = %+v, %v; unknown fields are ignored", d, err)
	}
	for _, want := range []string{"svc-list/2", "svc-status/1", "svc-list"} {
		if _, err := Decode(raw, want); err == nil {
			t.Errorf("Decode(want %s) of svc-list/1 = nil error", want)
		}
	}
	for _, s := range []string{"svc-list/2", "svc-list/x", "svc-list", "svc-list/1/2", ""} {
		raw, _ := json.Marshal(map[string]any{"snippet": "svc-list", "shape": s})
		if _, err := Decode(raw, "svc-list/1"); err == nil {
			t.Errorf("Decode of shape %q accepted as svc-list/1", s)
		}
	}
	if _, err := Decode([]byte(`{`), "svc-list/1"); err == nil {
		t.Error("Decode of broken JSON = nil error")
	}
}

func TestParseShape(t *testing.T) {
	if n, m, err := ParseShape("docker-ps/12"); err != nil || n != "docker-ps" || m != 12 {
		t.Fatalf("ParseShape = %q, %d, %v", n, m, err)
	}
	for _, s := range []string{"docker-ps", "docker-ps/", "docker-ps/0", "docker-ps/-1", "/1", "docker-ps/1x", "docker-ps/01"} {
		if _, _, err := ParseShape(s); err == nil {
			t.Errorf("ParseShape(%q) = nil error", s)
		}
	}
}
