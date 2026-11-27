package cli

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// importSecureCRT reads SecureCRT's sessions from one of:
//   - the XML file of File > Export Settings (or Tools > Export Settings),
//   - its Sessions folder (Config/Sessions: one .ini file per session,
//     folders for its session folders),
//   - one session's .ini file.
//
// SSH2 sessions become servers; a session's folder becomes a group.
// Telnet, serial, RDP and other sessions, a firewall (proxy) and a key in
// PuTTY's format are listed with what to do. Stored passwords and key
// passphrases are dropped as they are read: komando never keeps them.
func importSecureCRT(cl *call, path string) (*importPlan, error) {
	p := newPlan()
	var sessions []crtSession
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		s, err := crtFolder(cl, path)
		if err != nil {
			return nil, err
		}
		sessions = s
	} else {
		b, err := readSource(cl, path)
		if err != nil {
			return nil, err
		}
		if t := bytes.TrimSpace(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))); bytes.HasPrefix(t, []byte("<")) {
			sessions = crtXML(b)
		} else {
			label := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			sessions = []crtSession{{label: label, vals: crtINI(regText(b))}}
		}
	}
	found := 0
	for _, s := range sessions {
		host := strings.TrimSpace(s.vals["hostname"])
		proto := strings.TrimSpace(s.vals["protocol name"])
		if host == "" && proto == "" {
			continue // a folder's own settings, or the defaults
		}
		found++
		label := s.label
		if s.folder != "" {
			label = s.folder + "/" + s.label
		}
		if !strings.EqualFold(proto, "ssh2") {
			if proto == "" {
				proto = "unnamed"
			}
			p.Notes = append(p.Notes, label+": a "+proto+" session; komando imports SSH2 sessions only")
			continue
		}
		if host == "" {
			p.Notes = append(p.Notes, label+": no host in the session")
			continue
		}
		name := p.name(s.label)
		h := &store.Host{Name: name, Address: host, User: strings.TrimSpace(s.vals["username"])}
		if port, ok := s.port(); ok && port != 22 {
			h.Port = port
		}
		if s.folder != "" {
			if g := p.groupName(s.folder); g != "" {
				h.Groups = []string{g}
			}
		}
		if k := crtKeyFile(s.vals["identity filename v2"], s.vals["identity filename"]); k != "" {
			if strings.HasSuffix(strings.ToLower(k), ".ppk") {
				p.Notes = append(p.Notes, name+": its key "+k+" is in PuTTY's format; convert it (`puttygen KEY.ppk -O private-openssh -o KEY`), then `komando key add NAME KEY` and `komando host ssh edit "+name+" --key NAME`")
			} else {
				h.Identity = k
			}
		}
		if fw := strings.TrimSpace(s.vals["firewall name"]); fw != "" && !strings.EqualFold(fw, "none") {
			p.Notes = append(p.Notes, name+": SecureCRT reaches it through the firewall or jump host "+fw+"; set the way there with `komando host ssh edit "+name+" --via JUMP` or `--proxy-command`")
		}
		p.Hosts = append(p.Hosts, h)
	}
	if found == 0 {
		p.Notes = append(p.Notes, path+": no SecureCRT sessions (export them with File > Export Settings, or give the Sessions folder of SecureCRT's configuration folder)")
	}
	return p, nil
}

// crtSession is one SecureCRT session: its name, the folder it sits in
// ("Prod/Web", "" at the top) and its settings by lower-case name.
type crtSession struct {
	label, folder string
	vals          map[string]string
	hexPort       bool // .ini files write dwords in hex, the XML export in decimal
}

func (s crtSession) port() (int, bool) {
	v := strings.TrimSpace(s.vals["[ssh2] port"])
	base := 10
	if s.hexPort {
		base = 16
	}
	n, err := strconv.ParseUint(v, base, 16)
	return int(n), err == nil && n != 0
}

// crtSecret is a setting komando never reads: a stored password or a key's
// passphrase (SecureCRT keeps them encrypted, but a copy is still a copy).
func crtSecret(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "password") || strings.Contains(n, "passphrase")
}

// crtKeyFile is a session's own key file. SecureCRT may add "::rawkey" or
// a similar marker after the path.
func crtKeyFile(vals ...string) string {
	for _, v := range vals {
		v, _, _ = strings.Cut(strings.TrimSpace(v), "::")
		if v != "" {
			return v
		}
	}
	return ""
}

// crtINI reads one session file: lines like S:"Hostname"=web1 and
// D:"[SSH2] Port"=00000016. Multi-line values (Z: and B:) and secrets are
// left out.
func crtINI(text string) map[string]string {
	vals := map[string]string{}
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		typ, rest, ok := strings.Cut(strings.TrimSpace(line), `:"`)
		if !ok || (typ != "S" && typ != "D") {
			continue
		}
		k, v, ok := strings.Cut(rest, `"=`)
		if !ok || crtSecret(k) {
			continue
		}
		vals[strings.ToLower(k)] = v
	}
	return vals
}

// crtFolder reads a Sessions folder: every .ini file but SecureCRT's own
// (__FolderData__.ini, Default.ini), with the subfolder as its folder.
func crtFolder(cl *call, root string) ([]crtSession, error) {
	var files []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		base := strings.ToLower(d.Name())
		if !d.IsDir() && strings.HasSuffix(base, ".ini") && base != "__folderdata__.ini" && base != "default.ini" {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, localFileErr("FILE_NOT_FOUND", err, "give SecureCRT's Sessions folder or its exported XML file")
	}
	sort.Strings(files) // the same names on every run
	var list []crtSession
	for _, f := range files {
		b, err := readSource(cl, f)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(root, f)
		folder := filepath.ToSlash(filepath.Dir(rel))
		if folder == "." {
			folder = ""
		}
		list = append(list, crtSession{label: strings.TrimSuffix(filepath.Base(f), filepath.Ext(f)), folder: folder, vals: crtINI(regText(b)), hexPort: true})
	}
	return list, nil
}

// crtXML reads SecureCRT's exported settings: <VanDyke><key
// name="Sessions"> holds a <key> per folder and per session, a session's
// settings as <string name=...> and <dword name=...>.
func crtXML(b []byte) []crtSession {
	type node struct {
		Name string
		Vals map[string]string
		Kids []*node
	}
	dec := xml.NewDecoder(bytes.NewReader(b))
	root := &node{Vals: map[string]string{}}
	stack := []*node{root}
	var field string
	var text strings.Builder
	for {
		tok, err := dec.Token()
		if err == io.EOF || err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := ""
			for _, a := range t.Attr {
				if a.Name.Local == "name" {
					name = a.Value
				}
			}
			if t.Name.Local == "key" {
				n := &node{Name: name, Vals: map[string]string{}}
				top := stack[len(stack)-1]
				top.Kids = append(top.Kids, n)
				stack = append(stack, n)
				continue
			}
			if t.Name.Local == "string" || t.Name.Local == "dword" {
				field = name
				text.Reset()
			}
		case xml.CharData:
			if field != "" {
				text.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "key":
				if len(stack) > 1 {
					stack = stack[:len(stack)-1]
				}
			case "string", "dword":
				if field != "" && !crtSecret(field) {
					stack[len(stack)-1].Vals[strings.ToLower(field)] = text.String()
				}
				field = ""
			}
		}
	}
	var sessionsKey *node
	var find func(n *node)
	find = func(n *node) {
		for _, k := range n.Kids {
			if sessionsKey != nil {
				return
			}
			if strings.EqualFold(k.Name, "sessions") {
				sessionsKey = k
				return
			}
			find(k)
		}
	}
	find(root)
	if sessionsKey == nil {
		return nil
	}
	var out []crtSession
	var walk func(n *node, folder string)
	walk = func(n *node, folder string) {
		for _, k := range n.Kids {
			if len(k.Kids) == 0 || k.Vals["hostname"] != "" || k.Vals["protocol name"] != "" {
				out = append(out, crtSession{label: k.Name, folder: folder, vals: k.Vals})
				continue
			}
			sub := k.Name
			if folder != "" {
				sub = folder + "/" + k.Name
			}
			walk(k, sub)
		}
	}
	walk(sessionsKey, "")
	return out
}
