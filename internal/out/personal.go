package out

import (
	"bytes"
	"encoding/json"
	"math/big"
	"regexp"
	"strings"
)

// Personal data masking hides values that identify a person (an email
// address, a phone number, a payment card, a bank account) in the data an
// AI agent reads from servers and resources (Printer.Personal). Each is
// shown as [hidden: KIND], so the agent still sees that a value is there
// and what it is.
//
// The detectors look for shapes that are rarely anything else: a phone
// number needs its international form (+ and a country code), a card
// number needs a card's first digits, length and check digit, an IBAN its
// check digits. Names and street addresses have no such shape; a database
// conn hides them by column (mask_columns).

// Personal kinds, as they appear in [hidden: KIND].
const (
	PersonalEmail  = "email"
	PersonalPhone  = "phone"
	PersonalCard   = "card"
	PersonalIBAN   = "iban"
	PersonalColumn = "column"
)

// PersonalLabel is how a hidden value of kind looks.
func PersonalLabel(kind string) string { return "[hidden: " + kind + "]" }

var (
	email = regexp.MustCompile(`(?i)[a-z0-9][a-z0-9._%+-]*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}\b`)
	// + then 8 to 15 digits, in groups split by one space, dot or dash,
	// the area code maybe in parentheses
	phone = regexp.MustCompile(`\+[1-9]\d{0,3}(?:[ .-]?\(?\d{1,5}\)?){1,6}`)
	card  = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
	iban  = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b`)
)

// MaskPersonal hides email addresses, phone numbers, payment card numbers
// and IBANs in text.
func MaskPersonal(s string) string {
	if s == "" {
		return s
	}
	if strings.IndexByte(s, '@') >= 0 {
		s = email.ReplaceAllStringFunc(s, func(m string) string {
			if notPersonalEmail(m) {
				return m
			}
			return PersonalLabel(PersonalEmail)
		})
	}
	if strings.IndexByte(s, '+') >= 0 {
		s = replaceStandalone(phone, s, func(m string) (string, bool) {
			n := digits(m)
			if len(n) < 8 || len(n) > 15 {
				return m, false
			}
			return PersonalLabel(PersonalPhone), true
		})
	}
	s = card.ReplaceAllStringFunc(s, func(m string) string {
		if !isCard(digits(m)) || mixedSeparators(m) {
			return m
		}
		return PersonalLabel(PersonalCard)
	})
	return iban.ReplaceAllStringFunc(s, func(m string) string {
		if !isIBAN(strings.ReplaceAll(m, " ", "")) {
			return m
		}
		return PersonalLabel(PersonalIBAN)
	})
}

// notPersonalEmail: addresses that name a service, not a person. git@host
// is a Git remote; noreply-style senders belong to no one.
func notPersonalEmail(m string) bool {
	local := strings.ToLower(m[:strings.IndexByte(m, '@')])
	switch local {
	case "git", "noreply", "no-reply", "donotreply", "do-not-reply", "mailer-daemon", "postmaster":
		return true
	}
	return false
}

// replaceStandalone replaces matches of re that stand alone: not glued to
// a letter, digit or dot before them (a time zone "T10:00+07:00", a
// version "1.2+34567890") nor to one after them.
func replaceStandalone(re *regexp.Regexp, s string, f func(string) (string, bool)) string {
	var b strings.Builder
	last := 0
	for _, loc := range re.FindAllStringIndex(s, -1) {
		i, j := loc[0], loc[1]
		if i > 0 && isWordByte(s[i-1]) || j < len(s) && (isWordByte(s[j]) || s[j] == '+') {
			continue
		}
		r, ok := f(s[i:j])
		if !ok {
			continue
		}
		b.WriteString(s[last:i])
		b.WriteString(r)
		last = j
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func isWordByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '.' || c == ':'
}

func digits(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// mixedSeparators: "4111 1111-1111 1111" is not how a card is written.
func mixedSeparators(m string) bool {
	return strings.Contains(m, " ") && strings.Contains(m, "-")
}

// isCard: the first digits and length of a card network, and a valid
// check digit (Luhn).
func isCard(n string) bool {
	l := len(n)
	at := func(k int) int { // the first k digits as a number
		v := 0
		for i := 0; i < k && i < l; i++ {
			v = v*10 + int(n[i]-'0')
		}
		return v
	}
	ok := false
	switch {
	case n[0] == '4': // Visa
		ok = l == 13 || l == 16 || l == 19
	case at(2) >= 51 && at(2) <= 55, at(4) >= 2221 && at(4) <= 2720: // Mastercard
		ok = l == 16
	case at(2) == 34 || at(2) == 37: // American Express
		ok = l == 15
	case at(4) == 6011, at(2) == 65, at(3) >= 644 && at(3) <= 649: // Discover
		ok = l >= 16 && l <= 19
	case at(4) >= 3528 && at(4) <= 3589: // JCB
		ok = l >= 16 && l <= 19
	case at(2) == 62: // UnionPay
		ok = l >= 16 && l <= 19
	case at(2) == 36, at(2) == 38, at(2) == 39, at(3) >= 300 && at(3) <= 305: // Diners Club
		ok = l >= 14 && l <= 19
	}
	return ok && luhn(n)
}

func luhn(n string) bool {
	sum := 0
	for i := len(n) - 1; i >= 0; i-- {
		d := int(n[i] - '0')
		if (len(n)-1-i)%2 == 1 {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// isIBAN checks an IBAN's length and check digits (ISO 13616, mod 97).
func isIBAN(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	var b strings.Builder
	for _, c := range s[4:] + s[:4] {
		switch {
		case c >= '0' && c <= '9':
			b.WriteRune(c)
		case c >= 'A' && c <= 'Z':
			b.WriteString(big.NewInt(int64(c - 'A' + 10)).String())
		default:
			return false
		}
	}
	v, ok := new(big.Int).SetString(b.String(), 10)
	return ok && new(big.Int).Mod(v, big.NewInt(97)).Int64() == 1
}

// maskPersonalJSON applies MaskPersonal to every string value of a JSON
// document (not to object keys), leaving numbers and structure as they
// are.
func maskPersonalJSON(b []byte) []byte {
	var outb bytes.Buffer
	i := 0
	for i < len(b) {
		if b[i] != '"' {
			outb.WriteByte(b[i])
			i++
			continue
		}
		end := stringEnd(b, i)
		lit := b[i:end]
		i = end
		j := i
		for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
			j++
		}
		var s string
		if (j < len(b) && b[j] == ':') || json.Unmarshal(lit, &s) != nil {
			outb.Write(lit) // a key, or not a string komando can read
			continue
		}
		m := MaskPersonal(s)
		if m == s {
			outb.Write(lit)
			continue
		}
		var e bytes.Buffer
		enc := json.NewEncoder(&e)
		enc.SetEscapeHTML(false)
		if enc.Encode(m) != nil {
			outb.Write(lit)
			continue
		}
		outb.Write(bytes.TrimRight(e.Bytes(), "\n"))
	}
	return outb.Bytes()
}
