package cli

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// encLines is n bytes as base64 lines of width w.
func encLines(n, w int) []string {
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

// The window says how much encoded data a script carries and where.
func TestApprovalEncodedRiskLine(t *testing.T) {
	lines := encLines(2259, 76)
	script := "#!/bin/sh\nset -e\ncat > /tmp/p <<'EOF'\n" + strings.Join(lines, "\n") + "\nEOF\n"
	body := "It also sends the script ./p.sh (3200 bytes, 45 lines, SHA-256 abcd), all of it:\n" + script
	v := approvalView{Agent: "Claude Code", Line: "komando host ssh exec web --script ./p.sh", Body: body, Lang: "en"}
	last := 3 + len(lines)
	want := "Risk: Encoded data (base64), 3,012 bytes (about 2,259 decoded) in lines 4–" + strconv.Itoa(last) + "; it cannot be reviewed here"
	if !strings.Contains(v.info(), want) {
		t.Errorf("want %q in:\n%s", want, v.info())
	}
	v.Lang = "id"
	wantID := "Risiko: Data tersandi (base64), 3.012 byte (sekitar 2.259 setelah didekode) di baris 4–" + strconv.Itoa(last) + "; tidak bisa diperiksa di sini"
	if !strings.Contains(v.info(), wantID) {
		t.Errorf("want %q in:\n%s", wantID, v.info())
	}
	if !strings.Contains(v.text(), "Encoded data (base64)") {
		t.Error("the request's text does not name the encoded data")
	}
	cmd := approvalView{Line: "komando host ssh exec web -- echo " + strings.Join(encLines(60, 200), "") + " > /tmp/x", Lang: "en"}
	if !strings.Contains(cmd.info(), "Risk: Encoded data (base64), 80 bytes (about 60 decoded) in the command") {
		t.Errorf("command: %s", cmd.info())
	}
	plain := approvalView{Line: "komando host ssh exec web -- systemctl restart nginx", Body: "It also sends the script ./a.sh (9 bytes, 1 lines, SHA-256 ab), all of it:\nuptime\n", Lang: "en"}
	if strings.Contains(plain.info(), "Encoded") {
		t.Errorf("a plain script got an encoded line: %s", plain.info())
	}
}

// A private key in a script or command is refused, for a person too.
func TestEncodedSecretRefused(t *testing.T) {
	srv := startFakeServer(t)
	f := filepath.Join(t.TempDir(), "k.sh")
	key := "cat > ~/.ssh/id_ed25519 <<EOF\n-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Join(encLines(300, 70), "\n") + "\n-----END OPENSSH PRIVATE KEY-----\nEOF\n"
	if err := os.WriteFile(f, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"script":  {"host", "ssh", "exec", "dev", "--script", f},
		"command": {"host", "ssh", "exec", "dev", "--", "printf '-----BEGIN RSA PRIVATE KEY-----\\nMIIE\\n-----END RSA PRIVATE KEY-----' > k"},
	} {
		err := runRoot(t, args...)
		if e := toErr(err); err == nil || e.Code != "ENCODED_SECRET_INVALID" {
			t.Errorf("%s: want ENCODED_SECRET_INVALID, got %v", name, err)
		}
		if n := len(srv.take()); n != 0 {
			t.Errorf("%s: the server ran it", name)
		}
	}
}

// decode-run stops a script through the usual policy path.
func TestDecodeRunBlocksAScript(t *testing.T) {
	srv := startFakeServer(t)
	f := filepath.Join(t.TempDir(), "d.sh")
	os.WriteFile(f, []byte("base64 -d > /tmp/x <<EOF\nZWNobyBoaQ==\nEOF\nsh /tmp/x\n"), 0o600)
	err := runRoot(t, "host", "ssh", "exec", "dev", "--script", f)
	if e := toErr(err); err == nil || e.Code != "POLICY_BLOCKED" || !strings.Contains(e.Message, "decode-run") {
		t.Errorf("want POLICY_BLOCKED for decode-run, got %v", err)
	}
	if n := len(srv.take()); n != 0 {
		t.Error("the server ran it")
	}
}
