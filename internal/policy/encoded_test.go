package policy

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// b64 is n bytes of data as base64 lines of width w.
func b64(n, w int) []string {
	raw := make([]byte, n)
	for i := range raw {
		raw[i] = byte(i*7 + 3)
	}
	s := base64.StdEncoding.EncodeToString(raw)
	var out []string
	for len(s) > w {
		out = append(out, s[:w])
		s = s[w:]
	}
	return append(out, s)
}

// concat is a+="…" pieces, one per line.
func concat(parts []string) string {
	out := "a=\"\"\n"
	for _, p := range parts {
		out += "a+=\"" + p + "\"\n"
	}
	return out
}

func sha() string {
	return "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
}

func TestScanEncoded(t *testing.T) {
	// the C207 shot case: a 13-line script with 10 base64 lines
	lines := b64(570, 76)
	script := "#!/bin/sh\nset -e\ncat > /tmp/p <<'EOF'\n" + strings.Join(lines, "\n") + "\nEOF\nchmod 600 /tmp/p\n"
	got := ScanEncoded(script)
	if len(got) != 1 || got[0].Kind != "base64" || got[0].First != 4 || got[0].Last != 3+len(lines) {
		t.Fatalf("heredoc block: %+v (%d lines)", got, len(lines))
	}
	if got[0].Chars != len(strings.Join(lines, "")) || got[0].Decoded != 570 {
		t.Errorf("sizes: %+v", got[0])
	}

	cases := []struct {
		name, text, kind string
	}{
		{"one long line", "echo " + strings.Join(b64(60, 200), "") + " > /tmp/x", "base64"},
		{"concatenated run", concat(b64(60, 20)), "base64"},
		{"hex blob", "xxd -r -p > /tmp/a <<EOF\n" + strings.Repeat("4142434445464748", 8) + "\n" + strings.Repeat("494a4b4c4d4e4f50", 8) + "\nEOF", "hex"},
		{"two sha256 joined", "echo " + sha() + sha() + " | sha256sum -c", "hex"},
		{"hex escapes", `printf '` + strings.Repeat(`\x41`, 16) + `'`, "hex escapes"},
		{"octal escapes", `printf '` + strings.Repeat(`\101`, 16) + `'`, "octal escapes"},
		{"base32", "echo " + strings.Repeat("MFRGGZDFMZTWQ2LK", 5) + " | base32 -d", "base32"},
		{"private key", "cat > k <<EOF\n-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Join(b64(300, 70), "\n") + "\n-----END OPENSSH PRIVATE KEY-----\nEOF", "private key"},
	}
	for _, c := range cases {
		got := ScanEncoded(c.text)
		if len(got) == 0 || got[0].Kind != c.kind {
			t.Errorf("%s: want %s, got %+v", c.name, c.kind, got)
		}
	}

	clean := map[string]string{
		"sha256 check": "echo \"" + sha() + "  app.tar.gz\" | sha256sum -c",
		"sha256 field": "EXPECTED=sha256:" + sha(),
		"public cert":  "cat > ca.pem <<EOF\n-----BEGIN CERTIFICATE-----\n" + strings.Join(b64(600, 64), "\n") + "\n-----END CERTIFICATE-----\nEOF",
		"a long path":  "ls /usr/local/share/applications/something/very/long/path/that/keeps/going/on",
		"plain script": "apt-get update && apt-get install -y nginx\nsystemctl restart nginx",
		"short hex":    "echo " + hex.EncodeToString([]byte("0123456789")),
		"uuid":         "id=123e4567-e89b-12d3-a456-426614174000",
	}
	for name, text := range clean {
		if got := ScanEncoded(text); len(got) != 0 {
			t.Errorf("%s: want nothing, got %+v", name, got)
		}
	}
}

func TestHasPrivateKey(t *testing.T) {
	key := "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----"
	if !HasPrivateKey("cat > k <<EOF\n" + key + "\nEOF") {
		t.Error("a private key block was not found")
	}
	// the END line built later or in another heredoc: the BEGIN line is enough
	if !HasPrivateKey("cat > k <<A\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nA\necho \"-----END $T-----\" >> k") {
		t.Error("a BEGIN line without its END was not refused")
	}
	if !HasPrivateKey("cat > k.ppk <<EOF\nPuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nEOF") {
		t.Error("a PuTTY key file was not refused")
	}
	if HasPrivateKey("-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----") {
		t.Error("a public key counted as private")
	}
	if HasPrivateKey("grep -l 'BEGIN PRIVATE KEY' /etc/ssl/*") {
		t.Error("a mention of the header counted as a key")
	}
}
