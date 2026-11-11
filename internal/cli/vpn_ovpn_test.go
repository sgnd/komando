package cli

import (
	"strings"
	"testing"
)

// checkOVPN says why OpenVPN must not get the profile cfg, or nil.
func checkOVPN(cfg string) error {
	_, err := parseOVPN(cfg)
	return err
}

// A profile OpenVPN could read differently from komando is refused, by
// class: escapes, quotes, long lines, odd tags, control characters.
func TestOVPNRefusesWhatOpenVPNReadsDifferently(t *testing.T) {
	long := strings.Repeat("a", 300)
	words17 := "pull-filter ignore" + strings.Repeat(" route", 15)
	for _, c := range []struct{ class, cfg string }{
		{"escape", `remote vpn.example.com\ 1194`},
		{"escape", `verb 3 \`},
		{"escape", `remote "vpn.example.com\"" 1194`},
		{"escape", `\verb 3`},
		{"escape", `setenv NAME 'C:\temp'`},
		{"quote", `remote "vpn.example.com 1194`},
		{"quote", `remote 'vpn.example.com" 1194`},
		{"quote", `remote vpn"example".com 1194`},
		{"quote", `remote "vpn.example.com"1194`},
		{"quote", `remote '' 1194`},
		{"quote", `"setenv" "opt" verb 3`},
		{"long line", "remote " + long + " 1194"},
		{"long line", "<ca>\n" + long + "\n</ca>"},
		{"long line", "<connection>\nremote " + long + "\n</connection>"},
		{"too many words", words17},
		{"tag", "<CA>\nAAAA\n</CA>"},
		{"tag", "< ca>\nAAAA\n</ca>"},
		{"tag", "<ca >\nAAAA\n</ca>"},
		{"tag", "<ca>AAAA\n</ca>"},
		{"tag", "</ca>"},
		{"tag", "<ca>\nAAAA\n</ca> verb 3"},
		{"tag", "<ca>\nAAAA\n</ca>x"},
		{"tag", "<ca>\n<key>\nAAAA\n</key>\n</ca>"},
		{"tag", "<ca>\nAAAA </key>\n</ca>"},
		{"tag", "<ca>\nAAAA\n"},
		{"tag", `"<ca>"` + "\nAAAA\n</ca>"},
		{"tag", "remote <ca>"},
		{"tag", "<auth-user-pass>\nuser\npassword\n</auth-user-pass>"},
		{"tag", "<connection>\n<ca>\nAAAA\n</ca>\n</connection>"},
		{"tag", "<connection>\nremote vpn.example.com 1194\n"},
		{"tag", "<connection>\nverb 3\n</connection>"},
		{"tag", "<connection>\nremote vpn.example.com\n</connection> verb 3"},
		{"control character", "remote vpn.example.com\x00 1194"},
		{"control character", "remote vpn.example.com\v1194"},
		{"control character", "remote vpn.example.com\f1194"},
		{"control character", "remote vpn.example.com\r 1194"},
		{"control character", "remote \"vpn.example.com\t1194\""},
		{"control character", "<ca>\nAA\x00AA\n</ca>"},
		{"not ASCII", "remote vpn.ex\xc3\xa4mple.com 1194"},
		{"name", "UP /etc/openvpn/up.sh"},
		{"name", "---verb 3"},
		{"name", "--config other.conf"},
		{"name", "setenv OPT verb 3"},
	} {
		if err := checkOVPN("client\n" + c.cfg + "\n"); err == nil {
			t.Errorf("%s: %q must be refused", c.class, c.cfg)
		}
	}
}
