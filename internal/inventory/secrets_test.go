package inventory

import "testing"

func TestRenameURLSecretRefs(t *testing.T) {
	for _, c := range []struct {
		in, from, to, want string
		hit                bool
	}{
		{"registry://u@reg.lan?ca=credential:old", "old", "new", "registry://u@reg.lan?ca=credential:new", true},
		// the other options keep their order and escaping; the fragment stays
		{"x://h/p?a=1&ca=credential%3Aold&b=%2F#f", "old", "new", "x://h/p?a=1&ca=credential:new&b=%2F#f", true},
		{"x://h?ca=credential:old&key=credential:old", "old", "new", "x://h?ca=credential:new&key=credential:new", true},
		// only the exact name
		{"x://h?ca=credential:old-2", "old", "new", "x://h?ca=credential:old-2", false},
		{"x://h?ca=env:old", "old", "new", "x://h?ca=env:old", false},
		{"x://h/credential:old", "old", "new", "x://h/credential:old", false},
		{"x://h#?ca=credential:old", "old", "new", "x://h#?ca=credential:old", false},
		{"x://h", "old", "new", "x://h", false},
		// to "" only looks
		{"x://h?ca=credential:old", "old", "", "x://h?ca=credential:old", true},
	} {
		got, hit := renameURLSecretRefs(c.in, c.from, c.to)
		if got != c.want || hit != c.hit {
			t.Errorf("%s: got %s %v, want %s %v", c.in, got, hit, c.want, c.hit)
		}
	}
	refs := URLSecretRefs("registry://u@h?tls=&ca=credential:reg-ca")
	if len(refs) != 1 || refs[0] != (URLSecretRef{"ca", "reg-ca"}) {
		t.Errorf("refs %+v", refs)
	}
}
