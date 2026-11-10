package sshx

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/store"
)

func TestPSQ(t *testing.T) {
	cases := map[string]string{
		``:                  `''`,
		`plain`:             `'plain'`,
		`it's`:              `'it''s'`,
		`$(Remove-Item C:)`: `'$(Remove-Item C:)'`,
		"a\u2019b":          "'a\u2019\u2019b'",
		"`n$env:X":          "'`n$env:X'",
	}
	for in, want := range cases {
		if got := PSQ(in); got != want {
			t.Errorf("PSQ(%q) = %q, want %q", in, got, want)
		}
	}
	if got := PSArray([]string{"a", "b'c"}); got != `@('a', 'b''c')` {
		t.Errorf("PSArray = %q", got)
	}
}

func TestEncodePS(t *testing.T) {
	b, err := base64.StdEncoding.DecodeString(encodePS("Get-Date é"))
	if err != nil || len(b)%2 != 0 {
		t.Fatal(err)
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	if s := string(utf16.Decode(u)); s != "Get-Date é" {
		t.Errorf("decoded %q", s)
	}
	if len(PSCommandLine) > 8000 {
		t.Errorf("the command line is %d characters; cmd.exe takes at most 8191", len(PSCommandLine))
	}
}

func TestWindowsScript(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	c := &Client{Host: &store.Host{Name: "win1", OS: store.OSWindows, Env: map[string]string{"APP": "it's"}}}
	script, in, err := windowsScript(c, RunRequest{Command: "Get-Service", Dir: `C:\app's`, Env: map[string]string{"MODE": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"$env:APP = 'it''s'\n", "$env:MODE = 'x'\n", "Set-Location -LiteralPath 'C:\\app''s' -ErrorAction Stop\n", "Get-Service\n", "exit $LASTEXITCODE"} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q:\n%s", want, script)
		}
	}
	if len(in) != 0 {
		t.Errorf("no secret values, so no input lines: %q", in)
	}
	if _, _, err := windowsScript(c, RunRequest{Command: "x", Env: map[string]string{"A;B": "1"}}); err == nil {
		t.Error("a bad env name must be refused")
	}
	cmd, _, err := BuildCommand(c, RunRequest{Command: "Get-Date", Sudo: true})
	if err != nil || strings.Contains(cmd, "sudo") || !strings.Contains(cmd, "Get-Date") {
		t.Errorf("BuildCommand on Windows = %q %v", cmd, err)
	}
}

func TestCleanPSError(t *testing.T) {
	in := "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>System.Management.Automation.PSCustomObject</T></TN></Obj>" +
		"<S S=\"Error\">Get-Item : Cannot find path 'C:\\x' because it does not exist._x000D__x000A_</S><S S=\"Error\">At line:1 char:1 &amp; more_x000D__x000A_</S></Objs>"
	got := CleanPSError(in)
	want := "Get-Item : Cannot find path 'C:\\x' because it does not exist.\nAt line:1 char:1 & more\n"
	if got != want {
		t.Errorf("CleanPSError = %q, want %q", got, want)
	}
	if CleanPSError("plain error\n") != "plain error\n" {
		t.Error("plain text must stay as it is")
	}
}

// psSSHD is a stand-in for Windows OpenSSH: it checks that the command is
// komando's PowerShell bootstrap, decodes the script from the first input
// line, prints it and the rest of the input, writes CLIXML on stderr and
// exits 3.
func psSSHD(t *testing.T) *ssh.Client {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(newSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go servePS(raw, cfg)
		}
	}()
	c, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "u", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func servePS(raw net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		ch, creqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go func() {
			for r := range creqs {
				_ = r.Reply(r.Type == "exec", nil)
				if r.Type != "exec" {
					continue
				}
				var p struct{ Cmd string }
				_ = ssh.Unmarshal(r.Payload, &p)
				status := uint32(3)
				if p.Cmd != PSCommandLine {
					_, _ = ch.Stderr().Write([]byte("not the bootstrap: " + p.Cmd))
					status = 127
				} else {
					rd := bufio.NewReader(ch)
					line, _ := rd.ReadString('\n')
					script, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
					rest := new(strings.Builder)
					_, _ = bufio.NewReader(rd).WriteTo(rest)
					_, _ = ch.Write([]byte("SCRIPT:" + string(script) + "INPUT:" + rest.String()))
					_, _ = ch.Stderr().Write([]byte("#< CLIXML\r\n<Objs><S S=\"Error\">boom_x000D__x000A_</S></Objs>"))
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ S uint32 }{status}))
				_ = ch.Close()
			}
		}()
	}
}

func TestRunWindowsOverSSH(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	c := &Client{Client: psSSHD(t), Host: &store.Host{Name: "win1", OS: store.OSWindows}}
	r, err := Run(context.Background(), c, RunRequest{Command: "Get-Date", Stdin: []byte("data\n"), Timeout: 10 * time.Second, MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if r.ExitCode != 3 {
		t.Errorf("exit = %d (stderr %q)", r.ExitCode, r.Stderr)
	}
	if !strings.Contains(r.Stdout, "SCRIPT:Get-Date\n") || !strings.HasSuffix(r.Stdout, "INPUT:data\n") {
		t.Errorf("stdout = %q", r.Stdout)
	}
	if r.Stderr != "boom\n" {
		t.Errorf("stderr = %q, want the CLIXML turned into text", r.Stderr)
	}
	var sb strings.Builder
	code, stderr, err := RunPS(context.Background(), c, "Get-Item x", strings.NewReader("aGk=\n"), &sb)
	if err != nil || code != 3 || stderr != "boom\n" || !strings.Contains(sb.String(), "SCRIPT:Get-Item x") || !strings.HasSuffix(sb.String(), "INPUT:aGk=\n") {
		t.Errorf("RunPS = %d %q %q %v", code, stderr, sb.String(), err)
	}
	if _, _, err := Pipe(context.Background(), c, "cat", nil, &sb); err == nil {
		t.Error("Pipe sends sh: it must refuse a Windows server")
	}
}

// The caller's input is read as UTF-8, like the output: the console's own
// code page (437 or 850 over OpenSSH) would garble any non-ASCII text.
func TestPSBootstrapReadsUTF8(t *testing.T) {
	in := strings.Index(psBootstrap, "[Console]::InputEncoding = New-Object Text.UTF8Encoding $false")
	if in < 0 || in > strings.Index(psBootstrap, "[Console]::In.ReadLine()") {
		t.Errorf("the bootstrap must set the input encoding before it reads:\n%s", psBootstrap)
	}
}
