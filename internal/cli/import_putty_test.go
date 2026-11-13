package cli

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

const puttyReg = `Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions]

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Default%20Settings]
"HostName"=""
"PortNumber"=dword:00000016

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Prod%20Web]
"HostName"="deploy@web.example"
"PortNumber"=dword:00000016
"Protocol"="ssh"
"PublicKeyFile"="C:\\Users\\me\\.ssh\\id_ed25519"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\db]
"HostName"="10.0.0.9"
"PortNumber"=dword:000008ae
"UserName"="ops"
"Protocol"="ssh"
"PublicKeyFile"="C:\\keys\\ops.ppk"
"ProxyMethod"=dword:00000006
"ProxyHost"="bastion.example"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\router]
"HostName"="192.168.1.1"
"Protocol"="telnet"
`

// regFile writes text as reg export does: UTF-16 LE with a byte order mark.
func regFile(t *testing.T, text string) string {
	t.Helper()
	u := utf16.Encode([]rune(strings.ReplaceAll(text, "\n", "\r\n")))
	b := []byte{0xff, 0xfe}
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	p := filepath.Join(t.TempDir(), "putty.reg")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// PuTTY's exported sessions: SSH ones become servers (user@host split,
// the port from its hex dword, a key file path kept); a .ppk key, a proxy
// and a telnet session are reported; Default Settings is skipped.
func TestImportPuTTY(t *testing.T) {
	p, err := importPuTTY(regFile(t, puttyReg))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Hosts) != 2 {
		t.Fatalf("hosts %+v", p.Hosts)
	}
	web, db := p.Hosts[0], p.Hosts[1]
	if web.Name != "Prod-Web" && web.Name != "prod-web" || web.Address != "web.example" || web.User != "deploy" || web.Port != 0 || web.Identity != `C:\Users\me\.ssh\id_ed25519` {
		t.Errorf("web %+v", web)
	}
	if db.Address != "10.0.0.9" || db.User != "ops" || db.Port != 2222 || db.Identity != "" {
		t.Errorf("db %+v", db)
	}
	notes := strings.Join(p.Notes, "\n")
	for _, want := range []string{"ops.ppk", "puttygen", "bastion.example", "router: a telnet session"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	// a plain (UTF-8) .reg file works too
	plain := filepath.Join(t.TempDir(), "plain.reg")
	os.WriteFile(plain, []byte(puttyReg), 0o600)
	if p, err := importPuTTY(plain); err != nil || len(p.Hosts) != 2 {
		t.Errorf("plain: %v %v", err, p)
	}
}

// The command: a dry run lists them; FILE is needed.
func TestImportPuTTYCommand(t *testing.T) {
	invHome(t)
	f := regFile(t, puttyReg)
	mustRun(t, "--dry-run", "import", "putty", f)
	mustRun(t, "import", "putty", f)
	st := mustState(t)
	if st.Hosts["db"] == nil || st.Hosts["db"].Port != 2222 {
		t.Errorf("not imported: %v", st.Hosts)
	}
	wantCode(t, "USAGE", "import", "putty")
}
