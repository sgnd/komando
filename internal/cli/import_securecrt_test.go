package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// shaped like SecureCRT 9's File > Export Settings
const crtXMLExport = `<?xml version="1.0" encoding="UTF-8"?>
<VanDyke version="3.0">
  <key name="Sessions">
    <key name="Default">
      <dword name="[SSH2] Port">22</dword>
    </key>
    <key name="web1">
      <string name="Hostname">web.example</string>
      <string name="Username">deploy</string>
      <string name="Protocol Name">SSH2</string>
      <dword name="[SSH2] Port">22</dword>
      <string name="Password V2">02:9f3cTOPSECRETCIPHER</string>
      <string name="Identity Filename V2">C:\keys\web.ppk::rawkey</string>
    </key>
    <key name="Prod">
      <key name="DB">
        <key name="db1">
          <string name="Hostname">10.0.0.9</string>
          <string name="Username">ops</string>
          <string name="Protocol Name">SSH2</string>
          <dword name="[SSH2] Port">2222</dword>
          <string name="Firewall Name">bastion</string>
          <string name="Identity Filename V2">/home/me/.ssh/id_ed25519</string>
        </key>
      </key>
    </key>
    <key name="switch">
      <string name="Hostname">192.168.1.2</string>
      <string name="Protocol Name">Telnet</string>
    </key>
  </key>
</VanDyke>
`

// SSH2 sessions become servers with their folder as a group; a telnet
// session, a firewall and a .ppk key are listed; the stored password is
// never read.
func TestImportSecureCRTXML(t *testing.T) {
	p, err := importSecureCRT(tcl, writeTemp(t, "securecrt.xml", crtXMLExport))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Hosts) != 2 {
		t.Fatalf("hosts %+v notes %v", p.Hosts, p.Notes)
	}
	web, db := p.Hosts[0], p.Hosts[1]
	if web.Name != "web1" || web.Address != "web.example" || web.User != "deploy" || web.Port != 0 || web.Identity != "" || len(web.Groups) != 0 {
		t.Errorf("web %+v", web)
	}
	if db.Address != "10.0.0.9" || db.User != "ops" || db.Port != 2222 || db.Identity != "/home/me/.ssh/id_ed25519" || len(db.Groups) != 1 || db.Groups[0] != "prod-db" {
		t.Errorf("db %+v", db)
	}
	notes := strings.Join(p.Notes, "\n")
	for _, want := range []string{"switch: a Telnet session", "web1: its key C:\\keys\\web.ppk is in PuTTY's format", "db1: SecureCRT reaches it through the firewall or jump host bastion"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q: %v", want, p.Notes)
		}
	}
	if b, _ := json.Marshal(p); strings.Contains(string(b), "TOPSECRET") {
		t.Errorf("the stored password was read: %s", b)
	}
	if v := crtXML([]byte(crtXMLExport)); strings.Contains(strings.Join(func() []string {
		var s []string
		for _, x := range v {
			for k, val := range x.vals {
				s = append(s, k+"="+val)
			}
		}
		return s
	}(), " "), "password") {
		t.Error("a password setting was kept")
	}
}

// SecureCRT's Sessions folder: one .ini file a session, dwords in hex,
// subfolders as groups; its own files are skipped.
func TestImportSecureCRTFolder(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("Default.ini", "S:\"Protocol Name\"=SSH2\r\nS:\"Hostname\"=\r\n")
	write("__FolderData__.ini", "S:\"Folder List\"=Prod\r\n")
	write("web1.ini", "S:\"Hostname\"=web.example\r\nS:\"Username\"=deploy\r\nS:\"Protocol Name\"=SSH2\r\nD:\"[SSH2] Port\"=00000016\r\nS:\"Password V2\"=02:TOPSECRET\r\nZ:\"Port Forward Table V2\"=00000000\r\n")
	write("Prod/db1.ini", "S:\"Hostname\"=10.0.0.9\r\nS:\"Username\"=ops\r\nS:\"Protocol Name\"=SSH2\r\nD:\"[SSH2] Port\"=000008ae\r\nS:\"Firewall Name\"=None\r\n")
	write("Prod/serial1.ini", "S:\"Protocol Name\"=Serial\r\n")
	p, err := importSecureCRT(tcl, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Hosts) != 2 {
		t.Fatalf("hosts %+v notes %v", p.Hosts, p.Notes)
	}
	db, web := p.Hosts[0], p.Hosts[1]
	if db.Address != "10.0.0.9" || db.Port != 2222 || len(db.Groups) != 1 || db.Groups[0] != "prod" {
		t.Errorf("db %+v", db)
	}
	if web.Address != "web.example" || web.User != "deploy" || web.Port != 0 {
		t.Errorf("web %+v", web)
	}
	notes := strings.Join(p.Notes, "\n")
	if !strings.Contains(notes, "Prod/serial1: a Serial session") || strings.Contains(notes, "firewall") {
		t.Errorf("notes %v", p.Notes)
	}
	if b, _ := json.Marshal(p); strings.Contains(string(b), "TOPSECRET") {
		t.Errorf("the stored password was read: %s", b)
	}
	// one session's file on its own
	one, err := importSecureCRT(tcl, filepath.Join(dir, "web1.ini"))
	if err != nil || len(one.Hosts) != 1 || one.Hosts[0].Name != "web1" {
		t.Errorf("one file: %v %+v", err, one)
	}
	// nothing to import says where sessions come from
	empty, err := importSecureCRT(tcl, writeTemp(t, "x.xml", "<VanDyke/>"))
	if err != nil || len(empty.Hosts) != 0 || !strings.Contains(strings.Join(empty.Notes, ""), "Export Settings") {
		t.Errorf("empty: %v %+v", err, empty)
	}
}

// The command: a dry run lists them, the real run adds them; FILE is needed.
func TestImportSecureCRTCommand(t *testing.T) {
	invHome(t)
	f := writeTemp(t, "securecrt.xml", crtXMLExport)
	d := mustRun(t, "--dry-run", "import", "securecrt", f)
	if !strings.Contains(strings.Join(strings.Fields(jsonText(d)), " "), "db1") {
		t.Errorf("dry run: %v", d)
	}
	if st := mustState(t); st.Hosts["db1"] != nil {
		t.Error("the dry run added a server")
	}
	mustRun(t, "import", "securecrt", f)
	st := mustState(t)
	if st.Hosts["db1"] == nil || st.Hosts["db1"].Port != 2222 || st.Hosts["web1"] == nil {
		t.Errorf("not imported: %v", st.Hosts)
	}
	wantCode(t, "USAGE", "import", "securecrt")
}

func jsonText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
