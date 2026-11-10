package cli

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
)

// An --os-mode OpenVPN profile is run by the openvpn program as root, so
// komando passes on only client settings, and only in a form OpenVPN cannot
// read another way. parseOVPN reads the profile into directives and inline
// blocks and refuses anything OpenVPN's own reader could take differently:
// a backslash (an escape there), a quote inside a word, a line OpenVPN would
// cut in two, a tag that is not alone on its line. canonicalOVPN then writes
// what it read again, from scratch: OpenVPN gets that text, never the file
// the user gave.

// ovpnAllowed are the .ovpn client directives komando passes on. Anything
// that runs programs, writes or reads files by path, or opens a management
// port is refused. Keys and certificates must be inline (<ca>...</ca>),
// never a path.
var ovpnAllowed = map[string]bool{
	"client": true, "dev": true, "dev-type": true, "proto": true, "remote": true, "remote-random": true, "port": true,
	"rport": true, "resolv-retry": true, "nobind": true, "persist-key": true, "persist-tun": true, "float": true,
	"remote-cert-tls": true, "verify-x509-name": true, "ns-cert-type": true, "remote-cert-ku": true, "remote-cert-eku": true, "key-direction": true,
	"cipher": true, "data-ciphers": true, "data-ciphers-fallback": true, "ncp-ciphers": true, "auth": true,
	"tls-client": true, "tls-version-min": true, "tls-version-max": true, "tls-cipher": true, "tls-ciphersuites": true,
	"auth-user-pass": true, "auth-retry": true, "auth-nocache": true, "static-challenge": true,
	"comp-lzo": true, "compress": true, "allow-compression": true, "verb": true, "mute": true, "mute-replay-warnings": true,
	"reneg-sec": true, "tun-mtu": true, "tun-mtu-extra": true, "mssfix": true, "fragment": true, "mtu-disc": true,
	"keepalive": true, "ping": true, "ping-restart": true, "ping-exit": true, "inactive": true, "hand-window": true,
	"pull": true, "pull-filter": true, "route-nopull": true, "route": true, "route-delay": true, "route-metric": true,
	"redirect-gateway": true, "topology": true, "setenv": true, "ignore-unknown-option": true,
	"server-poll-timeout": true, "connect-retry": true, "connect-retry-max": true, "connect-timeout": true,
	"explicit-exit-notify": true, "push-peer-info": true, "sndbuf": true, "rcvbuf": true, "txqueuelen": true,
	"block-outside-dns": true, "dhcp-option": true, "tun-ipv6": true, "replay-window": true, "nice": true,
	// inline only (checked in ovpnDirective)
	"ca": true, "cert": true, "key": true, "tls-auth": true, "tls-crypt": true, "tls-crypt-v2": true,
	"pkcs12": true, "extra-certs": true, "secret": true,
}

var ovpnInline = []string{"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "pkcs12", "extra-certs", "secret"}

// ovpnConnection are the directives a <connection> block may hold: where
// and how to reach one server.
var ovpnConnection = map[string]bool{
	"remote": true, "proto": true, "port": true, "rport": true, "nobind": true, "float": true, "connect-retry": true,
	"connect-retry-max": true, "connect-timeout": true, "server-poll-timeout": true, "explicit-exit-notify": true,
	"tun-mtu": true, "tun-mtu-extra": true, "mssfix": true, "fragment": true, "mtu-disc": true,
}

const (
	// ovpnMaxLine: OpenVPN reads a profile in pieces of at most 255 bytes,
	// so a longer line becomes two lines there. 250 leaves some room.
	ovpnMaxLine = 250
	// ovpnMaxWords: OpenVPN drops the words after the 16th on a line.
	ovpnMaxWords = 16
)

// ovpnTag is a word that is an inline block tag: <ca> or </ca>.
var ovpnTag = regexp.MustCompile(`^</?[A-Za-z0-9_-]+>$`)

// ovpnItem is one directive (name and arguments) or one inline block (tag
// and its lines). A <connection> block holds directives in items.
type ovpnItem struct {
	name  string
	args  []string
	block bool
	lines []string
	items []ovpnItem
}

// canonicalOVPN is the profile OpenVPN gets: what parseOVPN read in cfg,
// written again. It holds only allowed directives and inline blocks, with
// no comments, escapes or quotes OpenVPN could read differently.
func canonicalOVPN(cfg string) (string, error) {
	items, err := parseOVPN(cfg)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	writeOVPN(&b, items)
	text := b.String()
	for _, l := range strings.Split(text, "\n") {
		if len(l) > ovpnMaxLine { // cannot happen: no line grows when written again
			return "", errors.New("a line is too long to pass on")
		}
	}
	return text, nil
}

type ovpnReader struct {
	lines []string
	n     int // lines read so far
}

// next is the next line without its line end (\n, or \r\n), and its number.
func (r *ovpnReader) next() (string, int, bool) {
	if r.n >= len(r.lines) {
		return "", 0, false
	}
	r.n++
	return strings.TrimSuffix(r.lines[r.n-1], "\r"), r.n, true
}

func parseOVPN(cfg string) ([]ovpnItem, error) {
	cfg = strings.TrimPrefix(cfg, "\xEF\xBB\xBF") // OpenVPN skips a UTF-8 BOM too
	r := &ovpnReader{lines: strings.Split(cfg, "\n")}
	return r.items(false)
}

// ovpnComment: the line is blank or only a comment, which is never passed on.
func ovpnComment(line string) bool {
	t := strings.TrimLeft(line, " \t")
	return t == "" || t[0] == '#' || t[0] == ';'
}

// items reads directives and blocks up to the end, or, in a <connection>
// block, up to </connection>.
func (r *ovpnReader) items(inConn bool) ([]ovpnItem, error) {
	var items []ovpnItem
	for {
		line, n, ok := r.next()
		if !ok {
			if inConn {
				return nil, errors.New("<connection> is never closed")
			}
			return items, nil
		}
		if len(line) > ovpnMaxLine && !ovpnComment(line) {
			return nil, fmt.Errorf("line %d is longer than %d characters (OpenVPN would read it as two lines)", n, ovpnMaxLine)
		}
		words, err := ovpnWords(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if len(words) == 0 {
			continue
		}
		if !ovpnTag.MatchString(words[0]) {
			it, err := ovpnDirective(words, inConn)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n, err)
			}
			items = append(items, it)
			continue
		}
		tag := strings.Trim(words[0], "<>") // OpenVPN matches tags case-sensitively
		switch {
		case inConn && tag == "/connection":
			return items, nil
		case strings.HasPrefix(tag, "/"):
			return nil, fmt.Errorf("line %d: <%s> closes a block that is not open", n, tag)
		case inConn:
			return nil, fmt.Errorf("line %d: <%s> inside <connection> is not allowed", n, tag)
		case tag == "connection":
			inner, err := r.items(true)
			if err != nil {
				return nil, err
			}
			items = append(items, ovpnItem{name: tag, block: true, items: inner})
		case slices.Contains(ovpnInline, tag):
			body, err := r.block(tag)
			if err != nil {
				return nil, err
			}
			items = append(items, ovpnItem{name: tag, block: true, lines: body})
		default:
			return nil, fmt.Errorf("line %d: inline block <%s> is not allowed", n, tag)
		}
	}
}

// block reads the lines of an inline block up to its closing tag. OpenVPN
// ends the block at the first line that starts, after blanks, with </tag>,
// and drops the rest of that line, so a rest is refused. A line with < or >
// in it, or one OpenVPN would cut in two, is refused too: either could end
// the block early there.
func (r *ovpnReader) block(tag string) ([]string, error) {
	end := "</" + tag + ">"
	var body []string
	for {
		line, n, ok := r.next()
		if !ok {
			return nil, fmt.Errorf("<%s> is never closed", tag)
		}
		if len(line) > ovpnMaxLine {
			return nil, fmt.Errorf("line %d in <%s> is longer than %d characters (OpenVPN would read it as two lines)", n, tag, ovpnMaxLine)
		}
		for i := 0; i < len(line); i++ {
			if c := line[i]; c != '\t' && (c < 0x20 || c > 0x7e) {
				return nil, fmt.Errorf("line %d in <%s>: a control character or a character that is not ASCII", n, tag)
			}
		}
		t := strings.Trim(line, " \t")
		if rest, closes := strings.CutPrefix(t, end); closes {
			if rest != "" {
				return nil, fmt.Errorf("line %d: text after %s", n, end)
			}
			return body, nil
		}
		if strings.ContainsAny(t, "<>") {
			return nil, fmt.Errorf("line %d: < or > inside <%s>", n, tag)
		}
		body = append(body, t)
	}
}

// ovpnWords splits a line into words the way OpenVPN does: blanks separate
// words, "..." or '...' make one word, and # or ; at the start of a word
// starts a comment. It refuses what OpenVPN could read another way: a
// backslash, a quote inside a word, an empty or unclosed quote, a word
// right after a closing quote, a control character or one that is not
// ASCII, < or > outside a tag alone on its line, and more words than
// OpenVPN keeps.
func ovpnWords(line string) ([]string, error) {
	var words []string
	tag := false
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '#' || c == ';':
			i = len(line)
		case c == '"' || c == '\'':
			j := strings.IndexByte(line[i+1:], c)
			if j < 0 {
				return nil, errors.New("a quote is not closed")
			}
			w := line[i+1 : i+1+j]
			if w == "" {
				return nil, errors.New("an empty quoted word")
			}
			if err := ovpnWordOK(w, true); err != nil {
				return nil, err
			}
			i += j + 2
			if i < len(line) && line[i] != ' ' && line[i] != '\t' {
				return nil, errors.New("text right after a closing quote")
			}
			words = append(words, w)
		default:
			j := i
			for j < len(line) && line[j] != ' ' && line[j] != '\t' {
				j++
			}
			w := line[i:j]
			if ovpnTag.MatchString(w) {
				tag = true
			} else if err := ovpnWordOK(w, false); err != nil {
				return nil, err
			}
			words = append(words, w)
			i = j
		}
	}
	switch {
	case tag && len(words) > 1:
		return nil, errors.New("a tag (<...>) must be alone on its line")
	case len(words) > ovpnMaxWords:
		return nil, fmt.Errorf("more than %d words (OpenVPN drops the rest)", ovpnMaxWords)
	}
	return words, nil
}

// ovpnWordOK checks the characters of one word; a quoted one may hold spaces.
func ovpnWordOK(w string, quoted bool) error {
	for i := 0; i < len(w); i++ {
		switch c := w[i]; {
		case c == '\\':
			return errors.New("a backslash (OpenVPN reads it as an escape)")
		case c == '"' || c == '\'':
			return errors.New("a quote inside a word")
		case c == '<' || c == '>':
			return errors.New("< or > outside a tag")
		case c == ' ' && quoted:
		case c < 0x21 || c > 0x7e:
			return fmt.Errorf("a control character or a character that is not ASCII (byte 0x%02x)", c)
		}
	}
	return nil
}

// ovpnDirective checks one directive line, already split into words.
func ovpnDirective(words []string, inConn bool) (ovpnItem, error) {
	name, args := words[0], words[1:]
	if len(name) >= 3 && strings.HasPrefix(name, "--") {
		name = name[2:] // OpenVPN reads --remote in a profile as remote
	}
	allowed := ovpnAllowed
	if inConn {
		allowed = ovpnConnection
	}
	switch {
	case !allowed[name]:
		return ovpnItem{}, fmt.Errorf("%q is not allowed (komando passes only client settings; nothing that runs programs or reads/writes files)", words[0])
	case slices.Contains(ovpnInline, name) && len(args) > 0 && args[0] != "[inline]":
		return ovpnItem{}, fmt.Errorf("%s must be inline (<%s>...</%s>), not a file path", name, name, name)
	case name == "setenv" && len(args) > 0 && strings.EqualFold(args[0], "opt"):
		// OpenVPN runs "setenv opt X ..." as option X, which would get past this list
		return ovpnItem{}, errors.New(`"setenv opt" is not allowed (OpenVPN runs the rest of the line as an option)`)
	case name == "auth-user-pass" && len(args) > 0:
		return ovpnItem{}, errors.New("auth-user-pass must not name a file; komando passes the login itself")
	}
	return ovpnItem{name: name, args: args}, nil
}

// writeOVPN writes items as OpenVPN reads them: one directive per line, a
// word with a space (or one that would start a comment) in double quotes.
func writeOVPN(b *strings.Builder, items []ovpnItem) {
	for _, it := range items {
		switch {
		case it.block && it.name == "connection":
			b.WriteString("<connection>\n")
			writeOVPN(b, it.items)
			b.WriteString("</connection>\n")
		case it.block:
			b.WriteString("<" + it.name + ">\n")
			for _, l := range it.lines {
				b.WriteString(l + "\n")
			}
			b.WriteString("</" + it.name + ">\n")
		default:
			b.WriteString(it.name)
			for _, a := range it.args {
				if strings.Contains(a, " ") || a[0] == '#' || a[0] == ';' {
					a = `"` + a + `"`
				}
				b.WriteString(" " + a)
			}
			b.WriteString("\n")
		}
	}
}

// ovpnRemotes checks the profile cfg as canonicalOVPN does and lists the
// servers its remote lines name (host, or host:port), for the approval
// window of a login sent there.
func ovpnRemotes(cfg string) (string, error) {
	items, err := parseOVPN(cfg)
	if err != nil {
		return "", err
	}
	var remotes []string
	var walk func([]ovpnItem)
	walk = func(items []ovpnItem) {
		for _, it := range items {
			switch {
			case it.block && it.name == "connection":
				walk(it.items)
			case it.name == "remote" && len(it.args) == 1:
				remotes = append(remotes, it.args[0])
			case it.name == "remote" && len(it.args) > 1:
				remotes = append(remotes, net.JoinHostPort(it.args[0], it.args[1]))
			}
		}
	}
	walk(items)
	return strings.Join(dedupe(remotes), ", "), nil
}
