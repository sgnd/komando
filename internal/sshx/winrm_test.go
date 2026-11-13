package sshx

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

var (
	wsAction  = regexp.MustCompile(`<a:Action[^>]*>[^<]*/([A-Za-z]+)</a:Action>`)
	wsCommand = regexp.MustCompile(`<rsp:Command>([^<]*)</rsp:Command>`)
	wsStdin   = regexp.MustCompile(`<rsp:Stream Name="stdin"[^>]*>([^<]*)</rsp:Stream>`)
)

// winrmServer is a stand-in for a Windows server's WinRM service that
// runs komando's bootstrap the way psSSHD does: it prints the script it
// got on the first input line and exits 4.
func winrmServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var stdin bytes.Buffer
	var commands []string
	ok := func(w http.ResponseWriter, body string) {
		_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body>`+body+`</s:Body></s:Envelope>`)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != "Administrator" || p != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		b, _ := io.ReadAll(r.Body)
		switch string(wsAction.FindSubmatch(b)[1]) {
		case "Create":
			ok(w, `<rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell>`)
		case "Command":
			commands = append(commands, string(wsCommand.FindSubmatch(b)[1]))
			ok(w, `<rsp:CommandResponse><rsp:CommandId>C1</rsp:CommandId></rsp:CommandResponse>`)
		case "Send":
			d, _ := base64.StdEncoding.DecodeString(string(wsStdin.FindSubmatch(b)[1]))
			stdin.Write(d)
			ok(w, `<rsp:SendResponse/>`)
		case "Receive":
			rd := bufio.NewReader(&stdin)
			line, _ := rd.ReadString('\n')
			script, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
			rest, _ := io.ReadAll(rd)
			stdin.Reset()
			outb := base64.StdEncoding.EncodeToString([]byte("SCRIPT:" + string(script) + "INPUT:" + string(rest)))
			ok(w, `<rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="C1">`+outb+`</rsp:Stream>`+
				`<rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>4</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`)
		default:
			ok(w, ``)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &commands
}

func winrmHost(t *testing.T, srv *httptest.Server, opts store.WinRMOpts) *store.Host {
	t.Helper()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	t.Setenv("WINRM_TEST_PW", "pw")
	t.Setenv("WINRM_TEST_CA", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	return &store.Host{Name: "win2", Address: "127.0.0.1", Port: p, User: "Administrator", PasswordRef: "env:WINRM_TEST_PW",
		OS: store.OSWindows, Transport: store.TransportWinRM, WinRMOpts: &opts}
}

func TestRunOverWinRM(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Cleanup(store.Close) // before the folder goes: Windows cannot remove an open file
	srv, commands := winrmServer(t)
	h := winrmHost(t, srv, store.WinRMOpts{Auth: "basic", CA: "env:WINRM_TEST_CA"})
	st := newState(h)
	o := Options{ConnectTimeout: 5 * time.Second, WinRM: true}
	c, err := Dial(context.Background(), st, h, o)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := Run(context.Background(), c, RunRequest{Command: "Get-Date", Stdin: []byte("data\n"), Timeout: 10 * time.Second, MaxOutput: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if r.ExitCode != 4 || !strings.Contains(r.Stdout, "SCRIPT:Get-Date\n") || !strings.HasSuffix(r.Stdout, "INPUT:data\n") {
		t.Errorf("result = %+v", r)
	}
	if len(*commands) != 1 || (*commands)[0] != PSCommandLine {
		t.Errorf("WinRM must run the same bootstrap as SSH: %q", *commands)
	}
	var sb strings.Builder
	if code, _, err := RunPS(context.Background(), c, "Get-Item x", strings.NewReader("aGk=\n"), &sb); err != nil || code != 4 || !strings.Contains(sb.String(), "SCRIPT:Get-Item x") {
		t.Errorf("RunPS = %d %q %v", code, sb.String(), err)
	}
}

func TestWinRMChecksTheCertificate(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Cleanup(store.Close) // before the folder goes: Windows cannot remove an open file
	srv, commands := winrmServer(t)
	h := winrmHost(t, srv, store.WinRMOpts{Auth: "basic"}) // no CA: the test server's certificate is unknown
	c, err := Dial(context.Background(), newState(h), h, Options{ConnectTimeout: 5 * time.Second, WinRM: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = Run(context.Background(), c, RunRequest{Command: "Get-Date", Timeout: 10 * time.Second})
	if e, ok := err.(*out.Error); !ok || e.Code != "WINRM_TLS" {
		t.Errorf("err = %v", err)
	}
	if len(*commands) != 0 {
		t.Error("nothing may run on a server whose certificate is not trusted")
	}
	h.WinRMOpts = &store.WinRMOpts{Auth: "basic", TLS: "skip-verify"}
	c2, _ := Dial(context.Background(), newState(h), h, Options{ConnectTimeout: 5 * time.Second, WinRM: true})
	defer c2.Close()
	if _, err := Run(context.Background(), c2, RunRequest{Command: "Get-Date", Timeout: 10 * time.Second}); err != nil {
		t.Errorf("skip-verify: %v", err)
	}
	t.Setenv("WINRM_TEST_BAD", "wrong")
	h.PasswordRef = "env:WINRM_TEST_BAD"
	h.WinRMOpts = &store.WinRMOpts{Auth: "basic", CA: "env:WINRM_TEST_CA"}
	c3, err := Dial(context.Background(), newState(h), h, Options{ConnectTimeout: 5 * time.Second, WinRM: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	if _, err := Run(context.Background(), c3, RunRequest{Command: "Get-Date", Timeout: 10 * time.Second}); asOutErr(t, err).Code != "AUTH_FAILED" {
		t.Errorf("wrong password: %v", err)
	}
}

func TestWinRMOnlyForPowerShell(t *testing.T) {
	t.Setenv("KOMANDO_HOME", t.TempDir())
	t.Cleanup(store.Close) // before the folder goes: Windows cannot remove an open file
	srv, _ := winrmServer(t)
	h := winrmHost(t, srv, store.WinRMOpts{})
	if _, err := Dial(context.Background(), newState(h), h, Options{ConnectTimeout: time.Second}); asOutErr(t, err).Code != "NOT_SUPPORTED" {
		t.Errorf("a caller that wants SSH: %v", err)
	}
	behind := &store.Host{Name: "web1", Address: "10.0.0.5", Via: "win2"}
	if _, err := Dial(context.Background(), newState(h, behind), behind, Options{ConnectTimeout: time.Second}); asOutErr(t, err).Code != "NOT_SUPPORTED" {
		t.Errorf("a WinRM server as a jump host: %v", err)
	}
	if h.EffectivePort() == 0 || (&store.Host{Transport: store.TransportWinRM}).EffectivePort() != 5986 ||
		(&store.Host{Transport: store.TransportWinRM, WinRMOpts: &store.WinRMOpts{TLS: "off"}}).EffectivePort() != 5985 {
		t.Error("WinRM default ports: 5986, and 5985 for plain HTTP")
	}
}

// A WinRM host with no password fails as AUTH_FAILED with the exit code the
// error catalog gives it (4, a login problem), like a wrong password.
func TestWinRMNoPasswordExit(t *testing.T) {
	for _, h := range []*store.Host{
		{Name: "w1", Address: "10.0.0.9", User: "a", Transport: store.TransportWinRM},
		{Name: "w2", Address: "10.0.0.9", PasswordRef: "env:X", Transport: store.TransportWinRM},
	} {
		_, err := winrmPassword(h)
		if e := asOutErr(t, err); e.Code != "AUTH_FAILED" || e.Exit != out.ExitConnect {
			t.Errorf("%s: %s exit %d, want AUTH_FAILED exit %d", h.Name, e.Code, e.Exit, out.ExitConnect)
		}
	}
}
