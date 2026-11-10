package cli

import (
	"slices"
	"strings"
	"testing"
)

// checkOVPN says why OpenVPN must not get the profile cfg, or nil.
func checkOVPN(cfg string) error {
	_, err := parseOVPN(cfg)
	return err
}

// readAsOpenVPN lists the directives of a profile in the order OpenVPN 2.6
// finds them (options.c: read_config_file, parse_line, read_inline_file):
// a line is read in pieces of at most 256 bytes; words are split on blanks,
// with "..." and '...' quoting and \ escapes outside '...'; # or ; at the
// start of a word ends the line; a line that is the one word <tag> starts
// a block that ends at the first line starting, after blanks, with </tag>.
// A block is listed as <tag>; a <connection> block's directives follow it.
// The tests use it to check what OpenVPN reads in komando's canonical
// profile.
func readAsOpenVPN(text string) []string {
	var names []string
	lines := ovpnPieces(text, 256)
	for i := 0; i < len(lines); i++ {
		w := ovpnParseLineLikeOpenVPN(lines[i])
		if len(w) == 0 {
			continue
		}
		name := w[0]
		if len(name) >= 3 && strings.HasPrefix(name, "--") {
			name = name[2:]
		}
		if len(w) > 1 || !strings.HasPrefix(name, "<") || !strings.HasSuffix(name, ">") {
			names = append(names, name)
			continue
		}
		tag := name[1 : len(name)-1]
		names = append(names, "<"+tag+">")
		var body strings.Builder
		for i++; i < len(lines) && !strings.HasPrefix(strings.TrimLeft(lines[i], " \t\r\v\f"), "</"+tag+">"); i++ {
			body.WriteString(lines[i])
		}
		if tag == "connection" {
			names = append(names, readAsOpenVPN(body.String())...)
		}
	}
	return names
}

// ovpnPieces cuts text the way fgets(buf, max+1) reads it.
func ovpnPieces(text string, max int) []string {
	var out []string
	for text != "" {
		n := strings.IndexByte(text, '\n') + 1
		if n == 0 || n > max {
			n = min(max, len(text))
		}
		out = append(out, text[:n])
		text = text[n:]
	}
	return out
}

// ovpnParseLineLikeOpenVPN is parse_line's reading of one line.
func ovpnParseLineLikeOpenVPN(line string) []string {
	var words []string
	var cur strings.Builder
	inWord, quote, escaped := false, byte(0), false
	end := func() {
		words = append(words, cur.String())
		cur.Reset()
		inWord, quote = false, 0
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == 0 {
			break
		}
		if !escaped && c == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		blank := c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
		switch {
		case !inWord && quote == 0:
			if blank {
				break
			}
			if c == '#' || c == ';' {
				return words
			}
			if !escaped && (c == '"' || c == '\'') {
				quote, inWord = c, true
			} else {
				cur.WriteByte(c)
				inWord = true
			}
		case quote != 0:
			if c == quote && (quote == '\'' || !escaped) {
				end()
			} else {
				cur.WriteByte(c)
			}
		case !escaped && blank:
			end()
		default:
			cur.WriteByte(c)
		}
		escaped = false
	}
	if inWord && quote == 0 {
		end()
	}
	return words
}

// allowedAsRead: a directive or block komando may pass on.
func allowedAsRead(name string) bool {
	if tag, ok := strings.CutPrefix(name, "<"); ok {
		tag = strings.TrimSuffix(tag, ">")
		return tag == "connection" || slices.Contains(ovpnInline, tag)
	}
	return ovpnAllowed[name]
}

// checkCanonical: the canonical profile is stable, keeps every line whole
// for OpenVPN, and OpenVPN reads in it only what komando allows, in the
// order komando read it.
func checkCanonical(t *testing.T, in, got string) {
	t.Helper()
	again, err := canonicalOVPN(got)
	if err != nil || again != got {
		t.Fatalf("%q: written again it changes: %q, %v", in, again, err)
	}
	for _, l := range strings.Split(got, "\n") {
		if len(l) > ovpnMaxLine {
			t.Fatalf("%q: line of %d characters in the output", in, len(l))
		}
	}
	items, _ := parseOVPN(got)
	var want []string
	for _, it := range items {
		switch {
		case it.block:
			want = append(want, "<"+it.name+">")
			for _, c := range it.items {
				want = append(want, c.name)
			}
		default:
			want = append(want, it.name)
		}
	}
	read := readAsOpenVPN(got)
	if !slices.Equal(read, want) {
		t.Fatalf("%q: OpenVPN reads %q, komando checked %q", in, read, want)
	}
	for _, n := range read {
		if !allowedAsRead(n) {
			t.Fatalf("%q: OpenVPN would read %q", in, n)
		}
	}
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

// What komando accepts it writes again in one plain form, and that form is
// what OpenVPN reads: comments, quotes it does not need, a leading -- and
// line ends are gone, and so is anything after a word that starts a comment.
func TestOVPNCanonical(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"client\r\n--remote vpn.example.com 1194 udp   # first server\r\n", "client\nremote vpn.example.com 1194 udp\n"},
		{`remote-cert-eku "TLS Web Server Authentication"`, "remote-cert-eku \"TLS Web Server Authentication\"\n"},
		{`verify-x509-name 'vpn.example.com' name`, "verify-x509-name vpn.example.com name\n"},
		{"\xEF\xBB\xBFclient\n", "client\n"},
		{"verb 3 #up /etc/openvpn/up.sh\n", "verb 3\n"},
		{"verb 3 ;script-security 2\n", "verb 3\n"},
		{"# " + strings.Repeat("x", 300) + "\nclient\n", "client\n"},
		{"; " + strings.Repeat("x", 300) + " up /etc/openvpn/up.sh\nclient\n", "client\n"},
		{"<ca>\n  -----BEGIN CERTIFICATE-----  \nAAAA\n\n   </ca>\n", "<ca>\n-----BEGIN CERTIFICATE-----\nAAAA\n\n</ca>\n"},
		{"  <ca>   # the server's CA\n# not a comment in a block\nAAAA\n</ca>\n", "<ca>\n# not a comment in a block\nAAAA\n</ca>\n"},
		{"<connection>\nremote vpn.example.com 1194\nproto tcp # backup\n</connection>\n", "<connection>\nremote vpn.example.com 1194\nproto tcp\n</connection>\n"},
		{`static-challenge "#PIN" 1`, "static-challenge \"#PIN\" 1\n"},
		{`static-challenge "Enter PIN" 1`, "static-challenge \"Enter PIN\" 1\n"},
		{"ca [inline]\ntls-auth [inline] 1\n", "ca [inline]\ntls-auth [inline] 1\n"},
		{"setenv UV_ID 12ab\n", "setenv UV_ID 12ab\n"},
	} {
		got, err := canonicalOVPN(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
		checkCanonical(t, c.in, got)
		for _, bad := range []string{"up", "script-security"} {
			if slices.Contains(readAsOpenVPN(got), bad) {
				t.Errorf("%q: OpenVPN would read %s in the output", c.in, bad)
			}
		}
	}
}

// The profiles the other OpenVPN tests accept pass through unchanged in
// meaning.
func TestOVPNCanonicalKeepsProfiles(t *testing.T) {
	good := "client\ndev tun\nproto udp\nremote vpn.example 1194\nremote-cert-tls server\nauth-user-pass\n<ca>\nx\n</ca>\n<key>\ny\n</key>\n"
	got, err := canonicalOVPN(good)
	if err != nil || got != good {
		t.Fatalf("a plain profile must stay as it is: %q, %v", got, err)
	}
	checkCanonical(t, good, got)
}

// FuzzCanonicalOVPN: whatever komando accepts, OpenVPN reads in the
// canonical profile exactly the directives komando checked.
func FuzzCanonicalOVPN(f *testing.F) {
	for _, s := range []string{
		"client\nremote vpn.example.com 1194\n<ca>\nAAAA\n</ca>\n",
		"verb 3 # x\n<connection>\nremote a\n</connection>\n",
		`remote-cert-eku "TLS Web Server Authentication"`,
		"static-challenge '#x y' 1\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := canonicalOVPN(s)
		if err != nil {
			return
		}
		checkCanonical(t, s, got)
	})
}
