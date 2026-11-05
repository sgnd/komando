package out

import (
	"strings"
	"testing"
)

// rebuild puts the original values back in place of the labels.
func rebuild(v View, orig string) string {
	var b strings.Builder
	last := 0
	for _, m := range v.marks {
		b.WriteString(v.Text[last:m.vs])
		b.WriteString(orig[m.ss:m.se])
		last = m.ve
	}
	b.WriteString(v.Text[last:])
	return b.String()
}

func viewPrinter() *Printer {
	return &Printer{Mask: true, Secrets: func() map[string]string {
		return map[string]string{"stripe": "VaultedTok3n99"}
	}}
}

// View shows exactly what Redact shows, and knows where each value was.
func TestViewMatchesRedact(t *testing.T) {
	cases := []string{
		"DB_PASSWORD=Sup3rS3cretValue\nSTRIPE_KEY=VaultedTok3n99\nHOST=db1\n",
		"note VaultedTok3n99 here, password: s3cret and postgres://app:pa55word@db/shop",
		"Authorization: Bearer abcdefghijklmnop\ntoken ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"root:$6$saltsalt$abcdefghijklmnop:19000:0\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl\n-----END OPENSSH PRIVATE KEY-----\nnext",
		"password_ref: secret:db\nPASSWORD=${DB_PASS}\nrequire_password: true\nDB_PASSWORD=[hidden]",
		"api_key=VaultedTok3n99x and TOKEN=VaultedTok3n99",
		"nothing to hide here",
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nb3Bl\n-----END PRIVATE KEY-----\n",
		"",
	}
	for _, s := range cases {
		p := viewPrinter()
		v := p.View(s)
		if want := p.Redact(s); v.Text != want {
			t.Errorf("View(%q)\n got %q\nwant %q", s, v.Text, want)
		}
		if got := rebuild(v, s); got != s {
			t.Errorf("labels of %q map back to %q", s, got)
		}
	}
}

func TestViewSource(t *testing.T) {
	s := "A=1\nDB_PASSWORD=Sup3rS3cretValue\nB=2\n"
	v := viewPrinter().View(s)
	if v.Text != "A=1\nDB_PASSWORD=[hidden]\nB=2\n" {
		t.Fatalf("view %q", v.Text)
	}
	at := func(sub string) (int, int) {
		i := strings.Index(v.Text, sub)
		return i, i + len(sub)
	}
	cases := []struct {
		sub, want string
		ok        bool
	}{
		{"A=1", "A=1", true},
		{"B=2\n", "B=2\n", true},
		{"DB_PASSWORD=[hidden]\n", "DB_PASSWORD=Sup3rS3cretValue\n", true},
		{"[hidden]", "Sup3rS3cretValue", true},
		{"[hid", "", false},
		{"den]\nB", "", false},
	}
	for _, c := range cases {
		a, e := at(c.sub)
		sa, se, ok := v.Source(a, e)
		if ok != c.ok || ok && s[sa:se] != c.want {
			t.Errorf("Source(%q) = %q, %v", c.sub, s[sa:se], ok)
		}
	}
	// a person (no masking, no vault values) sees the text as it is
	if v := (&Printer{}).View(s); v.Text != s {
		t.Fatalf("unmasked view %q", v.Text)
	}
}

// FuzzView: the labels always map back to the original text.
func FuzzView(f *testing.F) {
	for _, s := range []string{"PASSWORD=x VaultedTok3n99", "postgres://a:b@h/d token=VaultedTok3n99", "-----BEGIN RSA PRIVATE KEY-----\nx", "secret=[secret:x]y"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p := viewPrinter()
		v := p.View(s)
		if r := p.Redact(s); r != v.Text {
			t.Fatalf("View(%q)\n= %q\nRedact %q", s, v.Text, r)
		}
		if got := rebuild(v, s); got != s {
			t.Fatalf("labels of %q map back to %q (view %q)", s, got, v.Text)
		}
		for _, m := range v.marks {
			if !HasHidden(v.Text[m.vs:m.ve]) {
				t.Fatalf("mark %q is not a label", v.Text[m.vs:m.ve])
			}
		}
	})
}

// The end of a private key, without its BEGIN line (`fs cat --tail`), is
// hidden too, numbered or not; Hidden returns the values behind the labels.
func TestKeyTailIsHidden(t *testing.T) {
	body := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\nb3BlbnNzaC1rZXk\n-----END RSA PRIVATE KEY-----\n"
	for _, s := range []string{
		body,
		"log line\n" + body,
		"    41\tMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n    42\t-----END PRIVATE KEY-----\n",
	} {
		got := MaskSecrets(s)
		if strings.Contains(got, "MIIE") || strings.Contains(got, "b3Bl") || !strings.Contains(got, "[hidden: private key]") {
			t.Errorf("MaskSecrets(%q) = %q", s, got)
		}
	}
	s := "log line\n" + body
	v := viewPrinter().View(s)
	if h := v.Hidden(s); len(h) != 1 || !strings.HasPrefix(h[0], "MIIE") || !strings.HasSuffix(h[0], "KEY-----") {
		t.Errorf("Hidden = %q", h)
	}
}
