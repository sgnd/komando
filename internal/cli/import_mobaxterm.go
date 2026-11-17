package cli

import (
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// importMobaXterm reads MobaXterm's exported sessions (.mxtsessions, an
// INI file; also the [Bookmarks] of MobaXterm.ini). Each session is
// NAME=#TYPE#ICON%HOST%PORT%USER%..., where type 109 is SSH; the folder a
// session sits in (SubRep) becomes a group. Other session types are
// listed. MobaXterm keeps passwords apart (encrypted with its master
// password), so none are imported.
func importMobaXterm(cl *call, path string) (*importPlan, error) {
	b, err := readSource(cl, path)
	if err != nil {
		return nil, err
	}
	p := newPlan()
	sections, order := parseINI(regText(b))
	found := 0
	for _, sec := range order {
		if !strings.HasPrefix(strings.ToLower(sec), "bookmarks") {
			continue
		}
		vals := sections[sec]
		group := ""
		if sub := strings.TrimSpace(vals["subrep"]); sub != "" {
			group = p.groupName(sub)
		}
		for _, key := range mapKeys(vals) { // sorted: the same names on every run
			v := vals[key]
			if key == "subrep" || key == "imgnum" || !strings.HasPrefix(v, "#") {
				continue
			}
			found++
			label := key
			f := strings.Split(v, "%")
			kind := strings.Split(strings.TrimPrefix(f[0], "#"), "#")[0]
			if kind != "109" {
				p.Notes = append(p.Notes, label+": not an SSH session (MobaXterm type "+kind+"); komando imports SSH sessions only")
				continue
			}
			if len(f) < 4 || strings.TrimSpace(f[1]) == "" {
				p.Notes = append(p.Notes, label+": no host in the session")
				continue
			}
			name := p.name(label)
			h := &store.Host{Name: name, Address: strings.TrimSpace(f[1]), User: strings.TrimSpace(f[3])}
			if port, err := strconv.Atoi(strings.TrimSpace(f[2])); err == nil && port != 0 && port != 22 {
				h.Port = port
			}
			if group != "" {
				h.Groups = []string{group}
			}
			p.Hosts = append(p.Hosts, h)
		}
	}
	if found == 0 {
		p.Notes = append(p.Notes, path+": no MobaXterm sessions (export them in MobaXterm: right-click User sessions, Export all sessions to file)")
	}
	return p, nil
}

// groupName makes a valid group name from a MobaXterm folder ("Prod\\Web"
// becomes prod-web).
func (p *importPlan) groupName(folder string) string {
	g := strings.ToLower(strings.Trim(unsafeName.ReplaceAllString(strings.ReplaceAll(folder, `\\`, "-"), "-"), "-._"))
	if len(g) > 63 {
		g = g[:63]
	}
	return g
}
