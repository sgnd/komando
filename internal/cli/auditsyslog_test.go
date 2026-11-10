package cli

import (
	"bufio"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

func TestSyslogTarget(t *testing.T) {
	for v, want := range map[string]string{"udp://logs": "udp logs:514", "tcp://10.0.0.5:1514": "tcp 10.0.0.5:1514", "tls://siem.example": "tls siem.example:6514", "off": " ", "": " "} {
		n, a, err := syslogTarget(v)
		if err != nil || n+" "+a != want {
			t.Errorf("%q: %s %s %v", v, n, a, err)
		}
	}
	for _, bad := range []string{"http://x", "udp://", "tcp://x:99999", "udp://u@x", "x:514", "udp://x/path"} {
		if _, _, err := syslogTarget(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// Each audit record goes to the log server as RFC 5424 with the JSON line,
// over UDP and TCP (octet counting).
func TestAuditGoesToSyslog(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tcpGot := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			r := bufio.NewReader(c)
			n, _ := r.ReadString(' ')
			l, _ := strconv.Atoi(strings.TrimSpace(n))
			b := make([]byte, l)
			r.Read(b)
			tcpGot <- string(b)
			c.Close()
		}
	}()
	run := func(args ...string) error {
		root := newRoot()
		root.SetArgs(append([]string{"-o", "json"}, args...))
		return root.Execute()
	}
	if err := run("config", "set", "audit_syslog", "udp://"+pc.LocalAddr().String(), "--yes"); err != nil {
		t.Fatal(err)
	}
	if err := run("host", "add", "web1", "deploy@10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	var msg string
	for !strings.Contains(msg, `"host.add"`) {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("no udp record: %v", err)
		}
		msg = string(buf[:n])
	}
	if !strings.HasPrefix(msg, "<86>1 ") || !strings.Contains(msg, " komando ") {
		t.Errorf("udp record %q", msg)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(msg[strings.Index(msg, "{"):]), &rec); err != nil || rec["command"] != "host.add" || rec["prev"] == nil && !store.Sealed() {
		t.Errorf("record %v %v", rec, err)
	}
	if err := run("config", "set", "audit_syslog", "tcp://"+ln.Addr().String(), "--yes"); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-tcpGot:
		if !strings.Contains(m, `"config.set"`) || !strings.Contains(m, "audit_syslog") {
			t.Errorf("tcp record %q", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no tcp record")
	}
	// changing where the audit goes is a safety change
	if e := toErr(run("config", "set", "audit_syslog", "off")); e == nil || e.Code != "SAFETY_SETTING" {
		t.Errorf("turning it off without --yes: %v", e)
	}
}
