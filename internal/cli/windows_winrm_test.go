package cli

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func TestParseWinRMAddress(t *testing.T) {
	h, err := parseWinRMAddress("winrm://Administrator@10.0.0.9:5999?auth=basic&ca=secret:corp-ca")
	if err != nil || h.User != "Administrator" || h.Address != "10.0.0.9" || h.Port != 5999 || h.WinRMOpts.Auth != "basic" || h.WinRMOpts.CA != "secret:corp-ca" || !h.WinRM() || !h.Windows() {
		t.Errorf("%+v %+v %v", h, h.WinRMOpts, err)
	}
	if h, err := parseWinRMAddress("winrm://deploy@corp.local@win.corp.local"); err != nil || h.User != "deploy@corp.local" || h.Address != "win.corp.local" || h.Port != 0 {
		t.Errorf("a UPN user: %+v %v", h, err)
	}
	if h, err := parseWinRMAddress("winrm://[fd00::9]:5986"); err != nil || h.Address != "fd00::9" || h.Port != 5986 {
		t.Errorf("IPv6: %+v %v", h, err)
	}
	for _, bad := range []string{"winrm://", "winrm://h:x", "winrm://h?sudo=1", "winrm://h:99999"} {
		if _, err := parseWinRMAddress(bad); err == nil {
			t.Errorf("%s must be refused", bad)
		}
	}
}

func TestHostAddWinRM(t *testing.T) {
	startFakeServer(t)
	t.Setenv("WIN_PW", "x")
	if err := runRoot(t, "host", "add", "win2", "winrm://Administrator@10.0.0.9?tls=skip-verify", "--password-ref", "env:WIN_PW"); err != nil {
		t.Fatal(err)
	}
	s, _ := store.Load()
	h := s.Hosts["win2"]
	if !h.WinRM() || h.OS != store.OSWindows || h.EffectivePort() != 5986 || h.WinRMOpts.TLS != "skip-verify" {
		t.Errorf("host = %+v %+v", h, h.WinRMOpts)
	}
	for args, code := range map[string][]string{
		"WINRM_INSECURE": {"host", "add", "w3", "winrm://a@10.0.0.10?auth=basic&tls=off"},
		"USAGE":          {"host", "add", "w4", "winrm://a@10.0.0.11?auth=kerberos"},
	} {
		if got := errCode(runRoot(t, code...)); got != args {
			t.Errorf("%v: %s, want %s", code, got, args)
		}
	}
	for _, args := range [][]string{{"shell", "win2"}, {"host", "ssh-command", "win2"}, {"host", "trust", "win2"}} {
		if got := runCode(t, args...); got != "NOT_SUPPORTED" && got != "NEEDS_TERMINAL" {
			t.Errorf("%v: %s", args, got)
		}
	}
	if err := runRoot(t, "host", "edit", "win2", "--address", "winrm://10.0.0.12:5985?tls=off"); err != nil {
		t.Fatal(err)
	}
	s, _ = store.Load()
	if h := s.Hosts["win2"]; h.Address != "10.0.0.12" || h.EffectivePort() != 5985 || h.User != "Administrator" {
		t.Errorf("after edit: %+v", h)
	}
	if err := runRoot(t, "host", "edit", "win2", "--unset", "transport,port"); err != nil {
		t.Fatal(err)
	}
	s, _ = store.Load()
	if h := s.Hosts["win2"]; h.WinRM() || h.WinRMOpts != nil || h.EffectivePort() != 22 || !h.Windows() {
		t.Errorf("back to SSH (still Windows): %+v", h)
	}
}

// TestExecOverWinRM runs exec and test through komando's WinRM client
// against a stand-in WinRM service that prints "hello from winrm".
func TestExecOverWinRM(t *testing.T) {
	startFakeServer(t)
	act := regexp.MustCompile(`<a:Action[^>]*>[^<]*/([A-Za-z]+)</a:Action>`)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := ""
		switch string(act.FindSubmatch(b)[1]) {
		case "Create":
			body = `<rsp:Shell><rsp:ShellId>S</rsp:ShellId></rsp:Shell>`
		case "Command":
			body = `<rsp:CommandResponse><rsp:CommandId>C</rsp:CommandId></rsp:CommandResponse>`
		case "Receive":
			body = `<rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="C">` + base64.StdEncoding.EncodeToString([]byte("hello from winrm\nCORP\\admin\nWIN2\nTrue\n")) +
				`</rsp:Stream><rsp:CommandState CommandId="C" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`
		}
		_, _ = io.WriteString(w, `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body>`+body+`</s:Body></s:Envelope>`)
	}))
	defer srv.Close()
	t.Setenv("WIN_PW", "x")
	if err := runRoot(t, "host", "add", "win2", "winrm://Administrator@"+srv.Listener.Addr().String()+"?tls=skip-verify&auth=basic", "--password-ref", "env:WIN_PW"); err != nil {
		t.Fatal(err)
	}
	got := captureOutput(t, func() error { return runRoot(t, "exec", "win2", "--read-only", "--", "Get-Date") })
	if !strings.Contains(got, "hello from winrm") {
		t.Errorf("exec over WinRM: %s", got)
	}
	got = captureOutput(t, func() error { return runRoot(t, "test", "win2") })
	if !strings.Contains(got, `"server_version":"WinRM"`) || !strings.Contains(got, `"ok":true`) {
		t.Errorf("test over WinRM: %s", got)
	}
}

// --address takes a winrm:// address on add too, as its help says.
func TestHostAddWinRMAddressFlag(t *testing.T) {
	startFakeServer(t)
	t.Setenv("WIN_PW", "x")
	if err := runRoot(t, "host", "add", "win5", "--address", "winrm://Administrator@10.0.0.9:5999?tls=skip-verify", "--password-ref", "env:WIN_PW"); err != nil {
		t.Fatal(err)
	}
	if err := runRoot(t, "host", "add", "win6", "--address", "winrm://Administrator@10.0.0.8", "--user", "ops", "--port", "5990", "--password-ref", "env:WIN_PW"); err != nil {
		t.Fatal(err)
	}
	s, _ := store.Load()
	if h := s.Hosts["win5"]; !h.WinRM() || h.OS != store.OSWindows || h.User != "Administrator" || h.Address != "10.0.0.9" || h.Port != 5999 || h.WinRMOpts.TLS != "skip-verify" {
		t.Errorf("win5 = %+v %+v", h, h.WinRMOpts)
	}
	if h := s.Hosts["win6"]; !h.WinRM() || h.User != "ops" || h.Port != 5990 {
		t.Errorf("win6: --user and --port win over the address: %+v", h)
	}
}

// The CA a WinRM host names is a secret export lists and import checks,
// like the host's password.
func TestWinRMCAExportImport(t *testing.T) {
	invHome(t)
	if err := store.Update(func(s *store.State) error {
		s.Hosts["win7"] = &store.Host{Name: "win7", Address: "10.0.0.9", User: "a", Transport: store.TransportWinRM, OS: store.OSWindows,
			WinRMOpts: &store.WinRMOpts{CA: "secret:corp-ca"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	exp := mustRun(t, "export")
	if n, _ := exp["secrets_needed"].([]any); len(n) != 1 || n[0] != "corp-ca" {
		t.Errorf("export secrets_needed: %v", exp["secrets_needed"])
	}

	invHome(t)
	setSecret(t, "local-ca", "-----BEGIN CERTIFICATE-----")
	file := writeTemp(t, "hosts.json", `{"format":"komando-export/1","hosts":[
		{"name":"w8","address":"10.0.0.8","user":"a","transport":"winrm","os":"windows","winrm":{"ca":"secret:local-ca"}},
		{"name":"w9","address":"10.0.0.9","user":"a","transport":"winrm","os":"windows","winrm":{"ca":"secret:later-ca"}}]}`)
	d := mustRun(t, "import", "komando", file)
	if notes := fmt.Sprint(d["not_imported"], d["notes"]); !strings.Contains(notes, "dropped winrm.ca") {
		t.Errorf("no note for the CA: %s", notes)
	}
	st, _ := store.Load()
	if h := st.Hosts["w8"]; h == nil || h.WinRMOpts.CA != "" {
		t.Errorf("a ref to an existing secret must be dropped: %+v", h)
	}
	if h := st.Hosts["w9"]; h == nil || h.WinRMOpts.CA != "secret:later-ca" {
		t.Errorf("a ref to a secret not set yet may stay: %+v", h)
	}
}

// A WinRM server's CA (winrm://...?ca=secret:NAME) is a reference like any
// other: secret list names the server, secret rm refuses while it is used,
// secret mv points it at the new name, and host rm reports it as unused.
func TestSecretRefInWinRMCA(t *testing.T) {
	invHome(t)
	setSecret(t, "corp-ca", "-----BEGIN CERTIFICATE-----")
	if err := store.Update(func(s *store.State) error {
		s.Hosts = map[string]*store.Host{"win2": {Name: "win2", Address: "10.0.0.9", User: "Administrator",
			Transport: store.TransportWinRM, WinRMOpts: &store.WinRMOpts{CA: "secret:corp-ca"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	d := mustRun(t, "secret", "list")
	row := d["secrets"].([]any)[0].(map[string]any)
	if u := row["used_by"].([]any); len(u) != 1 || u[0] != "host win2" {
		t.Errorf("secret list used_by: %v", row)
	}
	wantCode(t, "SECRET_IN_USE", "secret", "rm", "corp-ca")

	d = mustRun(t, "secret", "mv", "corp-ca", "win-ca")
	if u := d["updated"].([]any); len(u) != 1 || u[0] != "host win2" {
		t.Errorf("mv: %v", d)
	}
	st, _ := loadState()
	if got := st.Hosts["win2"].WinRMOpts.CA; got != "secret:win-ca" {
		t.Errorf("CA after mv: %s", got)
	}

	d = mustRun(t, "host", "rm", "win2")
	if u, _ := d["secrets_unused"].([]any); len(u) != 1 || u[0] != "win-ca" {
		t.Errorf("host rm: %v", d)
	}
}
