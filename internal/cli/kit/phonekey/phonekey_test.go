package phonekey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// pubLine is a public key line for a new key of this kind.
func pubLine(t *testing.T, kind, comment string) string {
	t.Helper()
	var k any
	var err error
	switch kind {
	case "ecdsa":
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		k = &k.(*ecdsa.PrivateKey).PublicKey
	case "ed25519":
		k, _, err = ed25519.GenerateKey(rand.Reader)
	case "rsa2048":
		var r *rsa.PrivateKey
		r, err = rsa.GenerateKey(rand.Reader, 2048)
		k = &r.PublicKey
	}
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment
}

func TestParse(t *testing.T) {
	line := pubLine(t, "ecdsa", "komando-phone-anna-iphone")
	k, err := Parse([]byte(line + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if k.Name != "komando-phone-anna-iphone" || k.Type != "ecdsa-sha2-nistp256" || !strings.HasPrefix(k.Fingerprint, "SHA256:") || line != k.Type+" "+k.Data+" "+k.Name {
		t.Errorf("%+v", k)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pemKey, _ := ssh.MarshalPrivateKey(priv, "")
	two := pubLine(t, "ed25519", "a") + "\n" + pubLine(t, "ed25519", "b")
	for name, in := range map[string]string{
		"a private key":         string(pem.EncodeToMemory(pemKey)),
		"two keys":              two,
		"no comment":            strings.Fields(line)[0] + " " + strings.Fields(line)[1],
		"a comment with spaces": line + " and more",
		"a bad comment":         strings.Fields(line)[0] + " " + strings.Fields(line)[1] + " -name",
		"options":               `command="/bin/sh" ` + line,
		"restrict":              "restrict " + line,
		"a weak RSA key":        pubLine(t, "rsa2048", "old"),
		"not a key":             "hello world",
		"empty":                 "",
		"too big":               line + strings.Repeat(" ", 20<<10),
	} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestCheckAddress: from= takes addresses, networks and host patterns;
// a value that could end the quoted option or add another one is refused.
func TestCheckAddress(t *testing.T) {
	for in, host := range map[string]bool{
		"10.0.0.7": false, "10.0.0.0/8": false, "10.0.0.0/8,192.168.1.0/24": false, "2001:db8::/32": false, "::1": false,
		"*.example.com": true, "vpn.example.com": true, "10.0.0.*": true,
	} {
		got, err := CheckAddress(in)
		if err != nil || got != host {
			t.Errorf("%q: %v %v, want hostname pattern %v", in, got, err, host)
		}
	}
	for _, in := range []string{"", `10.0.0.1"`, `10.0.0.1",command="sh`, "10.0.0.1 10.0.0.2", "10.0.0.1\n", `a\b`, "!10.0.0.1", "10.0.0.1,,10.0.0.2", ",", strings.Repeat("a", 600)} {
		if _, err := CheckAddress(in); err == nil {
			t.Errorf("%q: accepted", in)
		}
	}
}

// TestLineIsAlwaysGated pins option C: the written line always starts with
// restrict and always forces the server's own gate in server mode, with
// the key's name; from= only when an address is given. Mutant: Line
// without restrict, without --here or without command= turns it red.
func TestLineIsAlwaysGated(t *testing.T) {
	k, err := Parse([]byte(pubLine(t, "ecdsa", "komando-phone-anna")))
	if err != nil {
		t.Fatal(err)
	}
	want := `restrict,command="/usr/local/bin/komando ssh-gate --here --name komando-phone-anna" ` + k.Type + " " + k.Data + " komando-phone-anna"
	if got := Line("/usr/local/bin/komando", k, ""); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	got := Line("/usr/local/bin/komando", k, "10.0.0.0/8")
	if !strings.HasPrefix(got, `restrict,command="/usr/local/bin/komando ssh-gate --here --name komando-phone-anna",from="10.0.0.0/8" `) {
		t.Errorf("with from=: %s", got)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(got)); err != nil {
		t.Errorf("sshd's own parser does not read the line: %v", err)
	}
}

const goodFacts = `uid 1000
home /home/anna
login deploy
komando /usr/local/bin/komando
stat 0 755 /usr/local/bin/komando
stat 0 755 /usr/local/bin
stat 0 755 /usr/local
stat 0 755 /usr
stat 0 755 /
gate yes
syslog yes
`

// TestFactsRefusal pins rule b and the user rule: the gate's binary is
// owned by root, not group or world writable, nor any folder above it,
// and outside the user's home; the user is never uid 0, whatever its name.
func TestFactsRefusal(t *testing.T) {
	f := ParseFacts(goodFacts)
	if code, why := f.Refusal("anna"); code != "" {
		t.Fatalf("%s %s", code, why)
	}
	if f.Komando != "/usr/local/bin/komando" || f.Login != "deploy" || !f.Syslog {
		t.Errorf("%+v", f)
	}
	for name, c := range map[string]struct{ facts, code, word string }{
		"root by uid":           {strings.Replace(goodFacts, "uid 1000", "uid 0", 1), "KEY_USER_INVALID", "uid 0"},
		"no user":               {"user none\n", "KEY_USER_INVALID", "no user"},
		"no komando":            {"uid 1000\nhome /home/anna\nkomando none\n", "KOMANDO_MISSING", "install"},
		"in the home":           {strings.ReplaceAll(goodFacts, "/usr/local/bin/komando", "/home/anna/bin/komando"), "GATE_BINARY_INVALID", "home"},
		"owned by the user":     {strings.Replace(goodFacts, "stat 0 755 /usr/local/bin/komando", "stat 1000 755 /usr/local/bin/komando", 1), "GATE_BINARY_INVALID", "owned by uid 1000"},
		"a writable folder":     {strings.Replace(goodFacts, "stat 0 755 /usr/local/bin\n", "stat 0 775 /usr/local/bin\n", 1), "GATE_BINARY_INVALID", "writable"},
		"world writable":        {strings.Replace(goodFacts, "stat 0 755 /usr/local\n", "stat 0 757 /usr/local\n", 1), "GATE_BINARY_INVALID", "writable"},
		"a folder not checked":  {strings.Replace(goodFacts, "stat 0 755 /usr\n", "", 1), "GATE_BINARY_INVALID", "check"},
		"an unchecked stat":     {strings.Replace(goodFacts, "stat 0 755 /usr\n", "stat ? ? /usr\n", 1), "GATE_BINARY_INVALID", "check"},
		"a path with a space":   {strings.ReplaceAll(goodFacts, "/usr/local/bin/komando", "/opt/my apps/komando"), "GATE_BINARY_INVALID", "path"},
		"no server mode":        {strings.Replace(goodFacts, "gate yes", "gate no", 1), "GATE_UNSUPPORTED", "update"},
		"a relative path":       {strings.ReplaceAll(goodFacts, "komando /usr/local/bin/komando", "komando bin/komando"), "GATE_BINARY_INVALID", "path"},
		"a setuid world binary": {strings.Replace(goodFacts, "stat 0 755 /usr/local/bin/komando", "stat 0 4777 /usr/local/bin/komando", 1), "GATE_BINARY_INVALID", "writable"},
	} {
		code, why := ParseFacts(c.facts).Refusal("anna")
		if code != c.code || !strings.Contains(why, c.word) {
			t.Errorf("%s: %s %q, want %s naming %q", name, code, why, c.code, c.word)
		}
	}
}

func TestUserName(t *testing.T) {
	for _, ok := range []string{"anna", "deploy", "web_ops", "a.b", "svc-1"} {
		if !UserName.MatchString(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "-x", "a b", "a;b", "a$b", "anna\n", strings.Repeat("a", 40), "../x"} {
		if UserName.MatchString(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
