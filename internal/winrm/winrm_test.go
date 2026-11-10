package winrm

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWinRM answers the WS-Management calls of one command: it records the
// input the command got and replies with output in two Receives, the
// first one after a timeout fault, as a real server does when a command is
// slow.
type fakeWinRM struct {
	mu       sync.Mutex
	actions  []string
	stdin    bytes.Buffer
	command  string
	exit     int
	receives int
	deleted  bool
	user     string
	pass     string
	fault    string // answer every Create with this fault
}

const soapNS = `xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:f="http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"`

var (
	reAction  = regexp.MustCompile(`<a:Action[^>]*>([^<]+)</a:Action>`)
	reCommand = regexp.MustCompile(`<rsp:Command>([^<]*)</rsp:Command>`)
	reStream  = regexp.MustCompile(`<rsp:Stream Name="stdin"[^>]*>([^<]*)</rsp:Stream>`)
)

func (f *fakeWinRM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u, p, ok := r.BasicAuth()
	if !ok || u != f.user || p != f.pass {
		w.Header().Set("WWW-Authenticate", `Basic realm="WSMAN"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	b, _ := io.ReadAll(r.Body)
	m := reAction.FindSubmatch(b)
	if m == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	action := string(m[1])
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actions = append(f.actions, action[strings.LastIndex(action, "/")+1:])
	w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
	reply := func(body string) {
		_, _ = io.WriteString(w, `<s:Envelope `+soapNS+`><s:Header/><s:Body>`+body+`</s:Body></s:Envelope>`)
	}
	fault := func(code, msg string) {
		w.WriteHeader(http.StatusInternalServerError)
		reply(`<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en-US">The request failed.</s:Text></s:Reason>` +
			`<s:Detail><f:WSManFault Code="` + code + `" Machine="win1"><f:Message>` + msg + `</f:Message></f:WSManFault></s:Detail></s:Fault>`)
	}
	switch {
	case strings.HasSuffix(action, "/Create"):
		if f.fault != "" {
			fault("5", f.fault)
			return
		}
		reply(`<rsp:Shell><rsp:ShellId>SHELL-1</rsp:ShellId></rsp:Shell>`)
	case strings.HasSuffix(action, "/Command"):
		if !bytes.Contains(b, []byte(`<w:Selector Name="ShellId">SHELL-1</w:Selector>`)) || !bytes.Contains(b, []byte("WINRS_CONSOLEMODE_STDIN\">FALSE")) {
			fault("1", "no shell")
			return
		}
		f.command = string(reCommand.FindSubmatch(b)[1])
		reply(`<rsp:CommandResponse><rsp:CommandId>CMD-1</rsp:CommandId></rsp:CommandResponse>`)
	case strings.HasSuffix(action, "/Send"):
		d, _ := base64.StdEncoding.DecodeString(string(reStream.FindSubmatch(b)[1]))
		f.stdin.Write(d)
		reply(`<rsp:SendResponse/>`)
	case strings.HasSuffix(action, "/Receive"):
		f.receives++
		enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
		switch f.receives {
		case 1:
			fault(timedOut, "The WS-Management service cannot complete the operation within the time specified in OperationTimeout.")
		case 2:
			reply(`<rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="CMD-1">` + enc("got: ") + `</rsp:Stream>` +
				`<rsp:Stream Name="stderr" CommandId="CMD-1">` + enc("warn\n") + `</rsp:Stream>` +
				`<rsp:CommandState CommandId="CMD-1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/></rsp:ReceiveResponse>`)
		default:
			reply(`<rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="CMD-1">` + enc(f.stdin.String()) + `</rsp:Stream>` +
				`<rsp:Stream Name="stdout" CommandId="CMD-1" End="true"></rsp:Stream>` +
				`<rsp:CommandState CommandId="CMD-1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>` +
				itoa(f.exit) + `</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`)
		}
	case strings.HasSuffix(action, "/Signal"):
		reply(`<rsp:SignalResponse/>`)
	case strings.HasSuffix(action, "/Delete"):
		f.deleted = true
		reply(``)
	default:
		fault("2", "unknown action")
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func tlsClient(t *testing.T, srv *httptest.Server) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func TestRunOverHTTPS(t *testing.T) {
	f := &fakeWinRM{user: "Administrator", pass: "pw", exit: 3}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	c := New(Config{Endpoint: srv.URL + "/wsman", User: "Administrator", Password: "pw", Basic: true, TLS: tlsClient(t, srv), OperationTimeout: 5 * time.Second})
	defer c.Close()
	input := strings.Repeat("x", 70<<10) + "<&>" // three Sends, and XML characters
	var out, errOut bytes.Buffer
	code, err := c.Run(context.Background(), `powershell -EncodedCommand AAA&<x>`, strings.NewReader(input), &out, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 || out.String() != "got: "+input || errOut.String() != "warn\n" {
		t.Errorf("code %d, stdout %d bytes, stderr %q", code, out.Len(), errOut.String())
	}
	if f.command != "powershell -EncodedCommand AAA&amp;&lt;x&gt;" {
		t.Errorf("command = %q", f.command)
	}
	want := "Create Command Send Send Send Receive Receive Receive Delete"
	if got := strings.Join(f.actions, " "); got != want || !f.deleted {
		t.Errorf("actions = %s, want %s", got, want)
	}
}

func TestCertificateIsChecked(t *testing.T) {
	f := &fakeWinRM{user: "u", pass: "p"}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	c := New(Config{Endpoint: srv.URL + "/wsman", User: "u", Password: "p", Basic: true, TLS: &tls.Config{MinVersion: tls.VersionTLS12}})
	_, err := c.Run(context.Background(), "x", nil, io.Discard, io.Discard)
	var ue x509.UnknownAuthorityError
	if !errors.As(err, &ue) {
		t.Errorf("a certificate from an unknown CA must be refused, got %v", err)
	}
	if len(f.actions) != 0 {
		t.Errorf("nothing may reach the server: %v", f.actions)
	}
	c = New(Config{Endpoint: srv.URL + "/wsman", User: "u", Password: "p", Basic: true, TLS: &tls.Config{InsecureSkipVerify: true}}) //nolint:gosec // the explicit skip-verify option
	if _, err := c.Run(context.Background(), "x", nil, io.Discard, io.Discard); err != nil {
		t.Errorf("skip-verify: %v", err)
	}
}

func TestLoginAndFaults(t *testing.T) {
	f := &fakeWinRM{user: "u", pass: "right"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New(Config{Endpoint: srv.URL + "/wsman", User: "u", Password: "wrong", Basic: true})
	if _, err := c.Run(context.Background(), "x", nil, io.Discard, io.Discard); !errors.Is(err, ErrAuth) {
		t.Errorf("wrong password: %v", err)
	}
	f.fault = "Access is denied."
	c = New(Config{Endpoint: srv.URL + "/wsman", User: "u", Password: "right", Basic: true})
	_, err := c.Run(context.Background(), "x", nil, io.Discard, io.Discard)
	var fe *Error
	if !errors.As(err, &fe) || fe.Code != "5" || fe.Message != "Access is denied." {
		t.Errorf("fault = %#v", err)
	}
}

func TestNTLMIsOffered(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.Header().Add("WWW-Authenticate", "NTLM")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := New(Config{Endpoint: srv.URL + "/wsman", User: `CORP\deploy`, Password: "secret-pw"})
	if _, err := c.Run(context.Background(), "x", nil, io.Discard, io.Discard); !errors.Is(err, ErrAuth) {
		t.Errorf("err = %v", err)
	}
	sawNTLM := false
	for _, h := range got {
		if strings.HasPrefix(h, "Basic") || strings.Contains(h, "secret-pw") {
			t.Errorf("NTLM must never send the password: %q", h)
		}
		sawNTLM = sawNTLM || strings.HasPrefix(h, "NTLM ") || strings.HasPrefix(h, "Negotiate ")
	}
	if !sawNTLM {
		t.Errorf("no NTLM login was tried: %q", got)
	}
}

func TestCancelStopsTheCommand(t *testing.T) {
	block := make(chan struct{})
	var actions []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		a := string(reAction.FindSubmatch(b)[1])
		a = a[strings.LastIndex(a, "/")+1:]
		mu.Lock()
		actions = append(actions, a)
		mu.Unlock()
		switch a {
		case "Create":
			_, _ = io.WriteString(w, `<s:Envelope `+soapNS+`><s:Body><rsp:Shell><rsp:ShellId>S</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>`)
		case "Command":
			_, _ = io.WriteString(w, `<s:Envelope `+soapNS+`><s:Body><rsp:CommandResponse><rsp:CommandId>C</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>`)
		case "Receive":
			select {
			case <-block:
			case <-r.Context().Done():
			}
		default:
			_, _ = io.WriteString(w, `<s:Envelope `+soapNS+`><s:Body/></s:Envelope>`)
		}
	}))
	defer srv.Close()
	defer close(block)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	c := New(Config{Endpoint: srv.URL + "/wsman", User: "u", Password: "p", Basic: true})
	if _, err := c.Run(ctx, "x", nil, io.Discard, io.Discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(actions, " "); !strings.HasSuffix(got, "Signal Delete") {
		t.Errorf("a stopped command must be ended and its shell closed: %s", got)
	}
}

func TestParse(t *testing.T) {
	if _, err := parse([]byte("<html>proxy error</html>")); err == nil {
		t.Error("an answer without a SOAP envelope must be refused")
	}
	r, err := parse([]byte(`<s:Envelope ` + soapNS + `><s:Header><w:SelectorSet><w:Selector Name="ShellId">FROM-SELECTOR</w:Selector></w:SelectorSet></s:Header><s:Body/></s:Envelope>`))
	if err != nil || r.shellID != "FROM-SELECTOR" {
		t.Errorf("shell id from the selector: %+v %v", r, err)
	}
	if _, err := parse([]byte(`<s:Envelope ` + soapNS + `><s:Body><rsp:Stream Name="stdout">not base64!</rsp:Stream></s:Body></s:Envelope>`)); err == nil {
		t.Error("a broken stream must be an error")
	}
}
