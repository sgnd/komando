package out

import (
	"strings"
	"testing"
)

func TestMaskPersonalHides(t *testing.T) {
	e, p, c, i := PersonalLabel(PersonalEmail), PersonalLabel(PersonalPhone), PersonalLabel(PersonalCard), PersonalLabel(PersonalIBAN)
	for in, want := range map[string]string{
		"contact alice.smith+test@example.co.uk now":           "contact " + e + " now",
		"From: Alice <alice@example.com>":                      "From: Alice <" + e + ">",
		`{"user":"BOB@Example.ORG"}`:                           `{"user":"` + e + `"}`,
		"call +1 415 555 2671 today":                           "call " + p + " today",
		"+44 (20) 7946 0958":                                   p,
		"phone=+6281234567890":                                 "phone=" + p,
		"+49-30-1234567":                                       p,
		"4111 1111 1111 1111":                                  c,
		"card 4111-1111-1111-1111 exp 12/29":                   "card " + c + " exp 12/29",
		"pan=4111111111111111;":                                "pan=" + c + ";",
		"378282246310005":                                      c, // American Express
		"5555555555554444":                                     c, // Mastercard
		"2223003122003222":                                     c, // Mastercard 2-series
		"6011111111111117":                                     c, // Discover
		"GB82 WEST 1234 5698 7654 32":                          i,
		"iban: DE89370400440532013000":                         "iban: " + i,
		"alice@example.com, +1 415 555 2671, 4111111111111111": e + ", " + p + ", " + c,
	} {
		if got := MaskPersonal(in); got != want {
			t.Errorf("MaskPersonal(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func TestMaskPersonalKeeps(t *testing.T) {
	for _, in := range []string{
		"git@github.com:sgnd/komando.git", // a Git remote, not a person
		"noreply@example.com",
		"ubuntu@203.0.113.10", // a server login
		"lodash@4.17.21",      // a package version
		"nginx@sha256:0123abcd",
		"admin@localhost",
		"2026-11-08T10:00:00+07:00", // a time zone
		"TZ +0700",
		"x+12345678901",               // glued to a word
		"1.2+3456789012",              // a version
		"1e+10 +12.5% +1 2",           // numbers, short
		"4111111111111112",            // fails the check digit
		"1234567890123456",            // no card network starts with 1
		"1731052800000",               // a timestamp in ms
		"order 98765432109876543",     // a long ID
		"4111 1111-1111 1111",         // mixed separators
		"GB82 WEST 1234 5698 7654 33", // wrong IBAN check digits
		"10.0.0.1:5432 and 192.168.1.10",
		"[hidden: email] [hidden]",
		"",
	} {
		if got := MaskPersonal(in); got != in {
			t.Errorf("MaskPersonal(%q) = %q, want it unchanged", in, got)
		}
	}
}

func TestMaskPersonalJSON(t *testing.T) {
	in := `{"rows":[["alice@example.com",4111111111111111,"call +1 415 555 2671"]],"alice@example.com":1,"n":12.5}`
	got := string(maskPersonalJSON([]byte(in)))
	want := `{"rows":[["[hidden: email]",4111111111111111,"call [hidden: phone]"]],"alice@example.com":1,"n":12.5}`
	if got != want {
		t.Errorf("maskPersonalJSON\n got %s\nwant %s", got, want)
	}
}

func TestPrinterPersonalNeedsMask(t *testing.T) {
	s := "alice@example.com"
	if got := (&Printer{Personal: true}).Redact(s); got != s {
		t.Errorf("without Mask (a person) the value shows: %q", got)
	}
	if got := (&Printer{Mask: true}).Redact(s); got != s {
		t.Errorf("Mask alone hides secrets, not personal data: %q", got)
	}
	if got := (&Printer{Mask: true, Personal: true}).Redact(s); got != PersonalLabel(PersonalEmail) {
		t.Errorf("Mask and Personal: %q", got)
	}
	b := (&Printer{Mask: true, Personal: true}).redactJSON([]byte(`{"e":"alice@example.com"}`))
	if !strings.Contains(string(b), "[hidden: email]") {
		t.Errorf("JSON: %s", b)
	}
}

func TestHasHiddenLabels(t *testing.T) {
	for s, want := range map[string]bool{
		"x=[hidden]":             true,
		"[hidden: private key]":  true,
		"mail: [hidden: email]":  true,
		"name: [hidden: column]": true,
		"pw=[secret:db-pass]":    true,
		"[hiddenness]":           false,
		"[hidden:email]":         false,
		"alice@example.com":      false,
	} {
		if got := HasHidden(s); got != want {
			t.Errorf("HasHidden(%q) = %v, want %v", s, got, want)
		}
	}
}
