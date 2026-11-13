package cli

import (
	"bytes"
	"encoding/binary"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/sgnd/komando/internal/store"
)

// importPuTTY reads PuTTY's saved sessions, exported from the Windows
// registry (`reg export HKCU\Software\SimonTatham\PuTTY\Sessions putty.reg`,
// a UTF-16 file). SSH sessions become servers; telnet, serial and raw ones,
// proxies and PuTTY's own key files (.ppk) are reported with what to do.
// PuTTY keeps no passwords, so none are imported.
func importPuTTY(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	p := newPlan()
	sessions, order := puttySessions(regText(b))
	if len(order) == 0 {
		p.Notes = append(p.Notes, path+": no PuTTY sessions (export them with `reg export HKCU\\Software\\SimonTatham\\PuTTY\\Sessions putty.reg`)")
		return p, nil
	}
	for _, label := range order {
		s := sessions[label]
		host := s["HostName"]
		if host == "" {
			continue // Default Settings, or a session with no host
		}
		if proto := s["Protocol"]; proto != "" && proto != "ssh" {
			p.Notes = append(p.Notes, label+": a "+proto+" session; komando imports SSH sessions only")
			continue
		}
		user := s["UserName"]
		if u, h, ok := strings.Cut(host, "@"); ok {
			user, host = u, h
		}
		name := p.name(label)
		h := &store.Host{Name: name, Address: host, User: user}
		if port, err := strconv.ParseUint(strings.TrimPrefix(s["PortNumber"], "dword:"), 16, 32); err == nil && port != 0 && port != 22 {
			h.Port = int(port)
		}
		if k := s["PublicKeyFile"]; k != "" {
			if strings.HasSuffix(strings.ToLower(k), ".ppk") {
				p.Notes = append(p.Notes, name+": its key "+k+" is in PuTTY's format; convert it (`puttygen KEY.ppk -O private-openssh -o KEY`), then `komando key add NAME KEY` and `komando host edit "+name+" --key NAME`")
			} else {
				h.Identity = k
			}
		}
		if m := strings.TrimPrefix(s["ProxyMethod"], "dword:"); m != "" && strings.Trim(m, "0") != "" {
			p.Notes = append(p.Notes, name+": PuTTY reaches it through a proxy ("+s["ProxyHost"]+"); set the way there with `komando host edit "+name+" --via JUMP` or `--proxy-command`")
		}
		p.Hosts = append(p.Hosts, h)
	}
	return p, nil
}

// regText is a .reg file as text: `reg export` writes UTF-16 (little
// endian, with a byte order mark); an older or edited one may be plain.
func regText(b []byte) string {
	if len(b) >= 2 && b[0] == 0xff && b[1] == 0xfe {
		b = b[2:]
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(b[2*i:])
		}
		return string(utf16.Decode(u))
	}
	return string(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")))
}

// puttySessions reads the [...\PuTTY\Sessions\NAME] keys of a .reg file:
// each session's values, with its name decoded (%20 is a space), in the
// file's order.
func puttySessions(text string) (map[string]map[string]string, []string) {
	sessions := map[string]map[string]string{}
	var order []string
	var cur map[string]string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = nil
			key := line[1 : len(line)-1]
			i := strings.LastIndex(strings.ToLower(key), `\putty\sessions\`)
			if i < 0 || strings.HasPrefix(key, "-") {
				continue
			}
			name := key[i+len(`\putty\sessions\`):]
			if dec, err := url.PathUnescape(name); err == nil {
				name = dec
			}
			if name == "" || strings.Contains(name, `\`) {
				continue
			}
			cur = map[string]string{}
			sessions[name] = cur
			order = append(order, name)
			continue
		}
		if cur == nil || !strings.HasPrefix(line, `"`) {
			continue
		}
		k, v, ok := strings.Cut(line[1:], `"=`)
		if !ok {
			continue
		}
		if strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) && len(v) >= 2 {
			v = strings.ReplaceAll(strings.ReplaceAll(v[1:len(v)-1], `\\`, "\x00"), `\"`, `"`)
			v = strings.ReplaceAll(v, "\x00", `\`)
		}
		cur[k] = v
	}
	return sessions, order
}
