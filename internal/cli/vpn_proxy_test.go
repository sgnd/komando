package cli

import "testing"

// A company HTTP proxy is a VPN of kind proxy: --via sends any conn or
// server through it.
func TestVpnProxyKind(t *testing.T) {
	invHome(t)
	mustRun(t, "vpn", "proxy", "add", "corp", "--proxy-address", "proxy.corp.example:3128")
	if d := mustRun(t, "vpn", "proxy", "show", "corp")["vpn"].(map[string]any); d["address"] != "http://proxy.corp.example:3128" {
		t.Errorf("the address is kept as a URL: %v", d)
	}
	mustRun(t, "vpn", "proxy", "add", "corp-tls", "--proxy-address", "https://proxy.corp.example")
	for _, bad := range [][]string{
		{"vpn", "proxy", "add", "x1"},                                                 // no address
		{"vpn", "proxy", "add", "x2", "--proxy-address", "proxy.corp.example"},        // no port
		{"vpn", "proxy", "add", "x3", "--proxy-address", "socks5://p:1080"},           // that is a socks VPN
		{"vpn", "proxy", "add", "x4", "--proxy-address", "p:3128", "--user", "alice"}, // a user needs its password
	} {
		wantCode(t, "USAGE", bad...)
	}
	mustRun(t, "host", "ssh", "add", "db1", "admin@10.0.0.5", "--via", "corp")
	mustRun(t, "vpn", "proxy", "edit", "corp", "--proxy-address", "proxy2.corp.example:8080")
	if d := mustRun(t, "vpn", "proxy", "show", "corp")["vpn"].(map[string]any); d["address"] != "http://proxy2.corp.example:8080" {
		t.Errorf("edit keeps the address as a URL: %v", d)
	}
	wantCode(t, "USAGE", "vpn", "proxy", "edit", "corp", "--proxy-address", "socks5://p:1080")
}
