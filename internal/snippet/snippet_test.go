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
		{"text and run", func(b *Builtin) { b.Run = func(context.Context, Client, Values) (any, error) { return nil, nil } }, "both"},
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
		{"pattern anchored only at its ends", func(b *Builtin) {
			b.Vars = []Var{{Name: "unit", Channel: Text, Pattern: regexp.MustCompile(`^a|b$`), MaxLen: 1, Longest: "a"}}
		}, "anchored"},
		{"pattern anchored at its start only", func(b *Builtin) {
			b.Vars = []Var{{Name: "unit", Channel: Text, Pattern: regexp.MustCompile(`^a`), MaxLen: 1, Longest: "a"}}
		}, "anchored"},
		{"pattern anchored at its end only", func(b *Builtin) {
			b.Vars = []Var{{Name: "unit", Channel: Text, Pattern: regexp.MustCompile(`a$`), MaxLen: 1, Longest: "a"}}
		}, "anchored"},
		{"pattern of two anchors in an alternation", func(b *Builtin) {
			b.Vars = []Var{{Name: "unit", Channel: Text, Pattern: regexp.MustCompile(`^|$`), MaxLen: 1, Longest: "a"}}
		}, "anchored"},
		{"family pattern anchored only at its ends", func(b *Builtin) {
			v := unitVar
			v.Families = map[Family]*regexp.Regexp{Windows: regexp.MustCompile(`^nginx-ab|x$`)}
			b.Vars = []Var{v}
		}, "anchored"},
		{"no max length", func(b *Builtin) {
			b.Vars = []Var{{Name: "unit", Channel: Text, Pattern: unitVar.Pattern, Longest: "a"}}
		}, "length"},
		{"max length zero with an empty longest", func(b *Builtin) {
			b.Vars = []Var{{Name: "unit", Channel: Text, Pattern: regexp.MustCompile(`^[a-z]*$`), MaxLen: 0, Longest: ""}}
		}, "length"},
		{"longest value too short", func(b *Builtin) { v := unitVar; v.Longest = "nginx"; b.Vars = []Var{v} }, "longest"},
		{"longest value off pattern", func(b *Builtin) { v := unitVar; v.Longest = "nginx ab"; b.Vars = []Var{v} }, "longest"},
		{"default off pattern", func(b *Builtin) { v := unitVar; v.Required, v.Default = false, "a b"; b.Vars = []Var{v} }, "default"},
		{"variable twice", func(b *Builtin) { b.Vars = []Var{unitVar, unitVar} }, "twice"},
		{"no channel", func(b *Builtin) { v := unitVar; v.Channel = 0; b.Vars = []Var{v} }, "channel"},
		{"list without a max count", func(b *Builtin) { v := unitVar; v.List = true; b.Vars = []Var{v} }, "items"},
		{"max count without a list", func(b *Builtin) { v := unitVar; v.MaxItems = 3; b.Vars = []Var{v} }, "items"},
		{"list on a client channel", func(b *Builtin) {
			b.Text, b.Parse = nil, nil
			b.Run = func(context.Context, Client, Values) (any, error) { return nil, nil }
			b.Vars = []Var{{Name: "unit", Channel: SQLIdent, Pattern: unitVar.Pattern, MaxLen: 8, Longest: "nginx-ab", List: true, MaxItems: 2}}
		}, "list"},
		{"list default off pattern", func(b *Builtin) {
			v := unitVar
			v.List, v.MaxItems, v.Required, v.Default = true, 2, false, "nginx,a b"
			b.Vars = []Var{v}
		}, "default"},
		{"family pattern unanchored", func(b *Builtin) {
			v := unitVar
			v.Families = map[Family]*regexp.Regexp{Windows: regexp.MustCompile(`[a-z]+`)}
			b.Vars = []Var{v}
		}, "anchored"},
		{"longest value off a family pattern", func(b *Builtin) {
			v := unitVar
			v.Families = map[Family]*regexp.Regexp{Windows: regexp.MustCompile(`^[a-z]+$`)}
			b.Vars = []Var{v}
		}, "longest"},
		{"family pattern of an unknown family", func(b *Builtin) {
			v := unitVar
			v.Families = map[Family]*regexp.Regexp{"plan9": regexp.MustCompile(`^[a-z-]+$`)}
			b.Vars = []Var{v}
		}, "family"},
		{"family pattern on a client channel", func(b *Builtin) {
			b.Text, b.Parse = nil, nil
			b.Run = func(context.Context, Client, Values) (any, error) { return nil, nil }
			b.Vars = []Var{{Name: "unit", Channel: SQLIdent, Pattern: unitVar.Pattern, MaxLen: 8, Longest: "nginx-ab",
				Families: map[Family]*regexp.Regexp{Unix: unitVar.Pattern}}}
		}, "family"},
		{"sudo without a Unix text", func(b *Builtin) { b.Sudo = true; delete(b.Text, Unix) }, "sudo"},
		{"sudo on a client call", func(b *Builtin) {
			b.Sudo, b.Text, b.Parse = true, nil, nil
			b.Run = func(context.Context, Client, Values) (any, error) { return nil, nil }
		}, "sudo"},
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

// A missing required variable is named, even when an empty value would
// also fail its pattern.
func TestFillNamesAMissingVariable(t *testing.T) {
	_, err := Fill(sample(), Unix, nil)
	var e *out.Error
	if !errors.As(err, &e) || e.Code != "USAGE" || !strings.Contains(e.Message, "--var unit=VALUE") {
		t.Fatalf("Fill without unit = %v; want USAGE naming --var unit=VALUE", err)
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
	anyRe := regexp.MustCompile(`(?s)^.+$`)
	mk := func(c Channel) Builtin {
		return Builtin{Name: "db-schema", Type: "database", Replaces: "db schema", Reader: "r", Tier: capability.Read, Shape: "db-schema/1",
			Vars: []Var{{Name: "v", Channel: c, Pattern: anyRe, MaxLen: 300, Longest: strings.Repeat("a", 300)}},
			Run:  func(context.Context, Client, Values) (any, error) { return nil, nil }}
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

func TestMutating(t *testing.T) {
	if Mutating(sample()) {
		t.Error("a read snippet is not mutating")
	}
	b := sample()
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
	for _, c := range []string{"SNIPPET_OS_UNSUPPORTED", "SNIPPET_TYPE_UNSUPPORTED"} {
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

// Every tier registers: the command stops a run by its tier
// (TestSnippetTierStops in internal/cli).
func TestNewTakesEveryTier(t *testing.T) {
	for tier := capability.Read; tier <= capability.Person; tier++ {
		b := sample()
		b.Tier = tier
		if _, err := New([]Builtin{b}); err != nil {
			t.Errorf("tier %d: %v", tier, err)
		}
	}
}

// listVar is a text variable that takes several values, like svc-status's
// units.
var listVar = Var{Name: "unit", Channel: Text, Pattern: unitVar.Pattern, MaxLen: 8, Required: true, Longest: "nginx-ab", List: true, MaxItems: 3}

func listSample() Builtin {
	b := sample()
	b.Vars = []Var{listVar}
	return b
}

// Each value of a list is checked alone and quoted as its own word, in
// the order given.
func TestFillListQuotesEachValue(t *testing.T) {
	for _, c := range []struct {
		f    Family
		want string
	}{
		{Unix, "systemctl show -- 'nginx' 'postfix'"},
		{Windows, "Get-Service -Name 'nginx', 'postfix'"}, // a PowerShell array
	} {
		got, err := Fill(listSample(), c.f, map[string]string{"unit": "nginx,postfix"})
		if err != nil || got != c.want {
			t.Errorf("Fill(%s) = %q, %v; want %q", c.f, got, err, c.want)
		}
	}
	if got, err := Fill(listSample(), Unix, map[string]string{"unit": "nginx"}); err != nil || got != "systemctl show -- 'nginx'" {
		t.Errorf("one value: %q, %v", got, err)
	}
}

func TestFillListRefusals(t *testing.T) {
	for _, c := range []struct {
		name, val, code string
	}{
		{"more than the max count", "a,b,c,d", "USAGE"},
		{"an empty value inside", "a,,b", "USAGE"},
		{"an empty value at the end", "a,", "USAGE"},
		{"an empty value at the start", ",a", "USAGE"},
		{"only a comma", ",", "USAGE"},
		{"one value off pattern", "nginx,a;b", "USAGE"},
		{"one value too long", "nginx,nginx-abc", "USAGE"},
		{"one value option-like", "nginx,-x", "OPTION_LIKE_VAR"},
		{"a control character", "nginx,a\nb", "USAGE"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := Fill(listSample(), Unix, map[string]string{"unit": c.val})
			if code(err) != c.code {
				t.Fatalf("Fill(%q) = %q, %v; want code %s", c.val, got, err, c.code)
			}
		})
	}
	// a comma in a value of a variable that is not a list is a value, and
	// its pattern decides
	if _, err := Fill(sample(), Unix, map[string]string{"unit": "a,b"}); code(err) != "USAGE" {
		t.Errorf("a comma in a single value: %v, want USAGE from the pattern", err)
	}
}

// LongestValue is the longest value a variable takes: for a list, the max
// count of longest values.
func TestLongestValue(t *testing.T) {
	if got := LongestValue(unitVar); got != "nginx-ab" {
		t.Errorf("LongestValue(single) = %q", got)
	}
	if got := LongestValue(listVar); got != "nginx-ab,nginx-ab,nginx-ab" {
		t.Errorf("LongestValue(list) = %q", got)
	}
	if _, err := Fill(listSample(), Unix, map[string]string{"unit": LongestValue(listVar)}); err != nil {
		t.Errorf("the longest list does not fill: %v", err)
	}
}

// An empty item is refused even when the pattern would take an empty
// value: a stray comma is a typo, not a value.
func TestFillListRefusesAnEmptyItemWhateverThePattern(t *testing.T) {
	b := sample()
	b.Vars = []Var{{Name: "unit", Channel: Text, Pattern: regexp.MustCompile(`^[a-z]*$`), MaxLen: 3, Required: true, Longest: "abc", List: true, MaxItems: 3}}
	if got, err := Fill(b, Unix, map[string]string{"unit": "a,,b"}); code(err) != "USAGE" {
		t.Fatalf("Fill(a,,b) = %q, %v; want USAGE", got, err)
	}
}

// A list's default is checked value by value, as a given list is.
func TestFillListDefault(t *testing.T) {
	b := listSample()
	b.Vars[0].Required, b.Vars[0].Default = false, "nginx,postfix"
	r, err := New([]Builtin{b})
	if err != nil {
		t.Fatal(err)
	}
	b, _ = r.Lookup("svc-status")
	if got, err := Fill(b, Unix, map[string]string{}); err != nil || got != "systemctl show -- 'nginx' 'postfix'" {
		t.Fatalf("Fill() = %q, %v", got, err)
	}
}

// A family pattern narrows the variable for that family's text only:
// systemd unit names and Windows service names differ.
func TestFillFamilyPattern(t *testing.T) {
	b := listSample()
	b.Vars[0].Families = map[Family]*regexp.Regexp{Windows: regexp.MustCompile(`^[a-z][a-z-]*$`)}
	if _, err := New([]Builtin{b}); err != nil {
		t.Fatal(err)
	}
	if got, err := Fill(b, Unix, map[string]string{"unit": "nginx,Web.1"}); err != nil || got != "systemctl show -- 'nginx' 'Web.1'" {
		t.Errorf("Unix: %q, %v", got, err)
	}
	for _, val := range []string{"Web.1", "nginx,Web.1"} {
		if got, err := Fill(b, Windows, map[string]string{"unit": val}); code(err) != "USAGE" {
			t.Errorf("Windows %q = %q, %v; want USAGE from the family pattern", val, got, err)
		}
	}
	if got, err := Fill(b, Windows, map[string]string{"unit": "nginx,web"}); err != nil || got != "Get-Service -Name 'nginx', 'web'" {
		t.Errorf("Windows: %q, %v", got, err)
	}
	// a default goes through the family pattern too
	b.Vars[0].Required, b.Vars[0].Default = false, "Web.1"
	if got, err := Fill(b, Windows, map[string]string{}); code(err) != "USAGE" {
		t.Errorf("Windows default %q, %v; want USAGE", got, err)
	}
}

// clientSample is a valid client built-in with one SFTP path variable.
func clientSample(run func(ctx context.Context, c Client, v Values) (any, error)) Builtin {
	return Builtin{
		Name: "fs-list", Type: "host", Replaces: "fs list", Reader: "KomandoCall.swift:252",
		Tier: capability.Read, Shape: "fs-list/1",
		Vars: []Var{{Name: "path", Channel: SFTPPath, Pattern: regexp.MustCompile(`^/[A-Za-z0-9/._-]*$`), MaxLen: 32, Longest: "/" + strings.Repeat("a", 31), Required: true}},
		Run:  run,
	}
}

// TestRunClientChecksBeforeItRuns: the only way to reach a client built-in's
// Run is RunClient, which checks every variable first, hands Run the cleaned
// values and the client it was given, and refuses a text built-in.
func TestRunClientChecksBeforeItRuns(t *testing.T) {
	type conn struct{ name string }
	called := 0
	var got Values
	var gotClient Client
	b := clientSample(func(_ context.Context, c Client, v Values) (any, error) {
		called++
		got, gotClient = v, c
		return map[string]string{"ok": "yes"}, nil
	})
	want := &conn{"web1"}
	res, err := RunClient(context.Background(), b, want, map[string]string{"path": "/etc//nginx/../hosts"})
	if err != nil || called != 1 {
		t.Fatalf("a valid call: %v after %d runs", err, called)
	}
	if got["path"] != "/etc/hosts" {
		t.Errorf("the path reached Run as %q, want it cleaned: /etc/hosts", got["path"])
	}
	if gotClient != Client(want) {
		t.Errorf("Run got client %v, want the one RunClient was given", gotClient)
	}
	if m, ok := res.(map[string]string); !ok || m["ok"] != "yes" {
		t.Errorf("result %v, want Run's", res)
	}
	for _, tc := range []struct {
		name  string
		given map[string]string
		want  string
	}{
		{"a value that fails its pattern", map[string]string{"path": "/etc;rm"}, "USAGE"},
		{"a value over the max length", map[string]string{"path": "/" + strings.Repeat("a", 32)}, "USAGE"},
		{"a variable the snippet does not name", map[string]string{"path": "/a", "other": "x"}, "UNKNOWN_VAR"},
		{"a missing required variable", map[string]string{}, "USAGE"},
	} {
		called = 0
		if _, err := RunClient(context.Background(), b, want, tc.given); code(err) != tc.want || called != 0 {
			t.Errorf("%s: code %q after %d runs, want %q and Run never called", tc.name, code(err), called, tc.want)
		}
	}
	if _, err := RunClient(context.Background(), sample(), want, map[string]string{"unit": "nginx"}); err == nil {
		t.Error("RunClient ran a text built-in; it has no client call")
	}
}
