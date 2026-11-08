package cli

import (
	"strings"
	"testing"
)

// A company HTTP proxy is a VPN of kind proxy: --via sends any conn or
// server through it.
func TestVpnProxyKind(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "add", "corp", "proxy", "--address", "proxy.corp.example:3128")
	if d := mustRun(t, "vpn", "show", "corp")["vpn"].(map[string]any); d["address"] != "http://proxy.corp.example:3128" {
		t.Errorf("the address is kept as a URL: %v", d)
	}
	mustRun(t, "vpn", "add", "corp-tls", "proxy", "--address", "https://proxy.corp.example")
	for _, bad := range [][]string{
		{"vpn", "add", "x1", "proxy"},                                           // no address
		{"vpn", "add", "x2", "proxy", "--address", "proxy.corp.example"},        // no port
		{"vpn", "add", "x3", "proxy", "--address", "socks5://p:1080"},           // that is a socks VPN
		{"vpn", "add", "x4", "proxy", "--address", "p:3128", "--user", "alice"}, // a user needs its password
	} {
		wantCode(t, "USAGE", bad...)
	}
	mustRun(t, "host", "add", "db1", "admin@10.0.0.5", "--via", "corp")
	d := mustRun(t, "host", "ssh-command", "db1")
	if cmd := strings.Join(toStrings(d["argv"]), " "); !strings.Contains(cmd, "ProxyCommand=nc -X connect -x proxy.corp.example:3128 %h %p") {
		t.Errorf("OpenSSH goes through the proxy too: %s", cmd)
	}
	mustRun(t, "vpn", "edit", "corp", "--address", "proxy2.corp.example:8080")
	if d := mustRun(t, "vpn", "show", "corp")["vpn"].(map[string]any); d["address"] != "http://proxy2.corp.example:8080" {
		t.Errorf("edit keeps the address as a URL: %v", d)
	}
	wantCode(t, "USAGE", "vpn", "edit", "corp", "--address", "socks5://p:1080")
}

func toStrings(v any) []string {
	var s []string
	if a, ok := v.([]any); ok {
		for _, x := range a {
			s = append(s, x.(string))
		}
	}
	return s
}
