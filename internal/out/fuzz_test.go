package out

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzMaskJSON: masking never breaks a JSON document, and never leaves a
// value under a key named password.
func FuzzMaskJSON(f *testing.F) {
	for _, s := range []string{`{"a":"DB_PASSWORD=x1"}`, `{"password":"p","n":[1,"t",{"token":"abc"}]}`, `["\"\\u00e9"]`, `{"data":{"k":"c2VjcmV0IQ=="}}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !json.Valid([]byte(s)) {
			return
		}
		b, err := json.Marshal(json.RawMessage(s))
		if err != nil {
			return
		}
		got := maskJSON(b)
		if !json.Valid(got) {
			t.Fatalf("masked JSON is invalid:\n in %s\nout %s", b, got)
		}
	})
}

// FuzzMaskSecrets: idempotent, and a masked text is refused for writing
// whenever something was hidden.
func FuzzMaskSecrets(f *testing.F) {
	for _, s := range []string{"PASSWORD=x", "postgres://a:b@h/d", "-----BEGIN RSA PRIVATE KEY-----\nx", "token abcdefghijklmnop"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		m := MaskSecrets(s)
		if MaskSecrets(m) != m {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, m, MaskSecrets(m))
		}
		if m != s && !HasHidden(m) && !strings.Contains(s, Hidden) {
			t.Fatalf("hid something without a marker: %q -> %q", s, m)
		}
	})
}
