package cli

import (
	"fmt"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// menuEmpty: komando knows nothing yet (names the lists leave out do not
// count).
func menuEmpty(st *store.State) bool {
	return len(menuNames(st.Hosts, "host"))+len(menuNames(st.Conns, "conn"))+len(menuNames(st.Vpns, "vpn")) == 0
}

// menuMainActions is the main menu for this inventory. With nothing added
// yet: Add a server, Bring in my SSH servers (while ~/.ssh/config names
// some komando does not know), Set up my AI agent and Settings and help.
// After that the rows keep a fixed order, so they never move; Running now
// shows above Add something only while something runs.
func menuMainActions(st *store.State, newInSSHConfig int) []menuAction {
	if menuEmpty(st) {
		acts := []menuAction{addServerAction}
		if newInSSHConfig > 0 {
			imp := importAction
			imp.detail = menuCount(newInSSHConfig, "server") + " found in ~/.ssh/config"
			acts = append(acts, imp)
		}
		return append(acts, agentAction, settingsAction)
	}
	sv, se, vp := serversAction, servicesAction, vpnsAction
	sv.detail = menuSome(menuNames(st.Hosts, "host"), "None yet: add one")
	se.detail = menuSome(menuNames(st.Conns, "conn"), "None yet: add a database or another service")
	var vpns []string
	for _, n := range menuNames(st.Vpns, "vpn") {
		if menuVpnUp(st, n) {
			vpns = append(vpns, n+" connected")
		} else {
			vpns = append(vpns, n+" not connected")
		}
	}
	vp.detail = "None yet: add one"
	if len(vpns) > 0 {
		vp.detail = strings.Join(vpns[:min(3, len(vpns))], " · ")
		if len(vpns) > 3 {
			vp.detail += fmt.Sprintf(" and %d more", len(vpns)-3)
		}
	}
	acts := []menuAction{sv, se, vp}
	if n := len(menuRunningRows(st)); n > 0 {
		run := statusAction
		run.name = fmt.Sprintf("Running now (%d)", n)
		acts = append(acts, run)
	}
	return append(acts, addAction, checkAction, historyAction, settingsAction)
}

// menuSome is up to three names and how many more.
func menuSome(names []string, none string) string {
	switch {
	case len(names) == 0:
		return none
	case len(names) <= 3:
		return cleanText(strings.Join(names, ", "))
	}
	return cleanText(strings.Join(names[:3], ", ")) + fmt.Sprintf(" and %d more", len(names)-3)
}

func menuMain(acts []menuAction) *menuList {
	l := &menuList{empty: "nothing to do", hot: menuHot()}
	for _, a := range acts {
		l.rows = append(l.rows, menuRow{label: a.name, detail: a.detail, value: a.name})
	}
	return l
}

// menuItems is the list behind Servers (groups first, then servers),
// Databases and services (by kind), or VPNs.
func menuItems(st *store.State, pick string) *menuList {
	l := &menuList{typing: true}
	switch pick {
	case "servers":
		l.title = "Servers: which one?"
		gl := allGroups(st)
		for _, g := range sortedKeys(gl.Groups) {
			var hosts []string
			for _, m := range gl.Groups[g] {
				if st.Hosts[m] != nil {
					hosts = append(hosts, m)
				}
			}
			if validName("host", g) != nil || len(hosts) == 0 {
				continue // a group of services only is not a group of servers
			}
			l.rows = append(l.rows, menuRow{label: "@" + g, detail: "group of " + menuCount(len(hosts), "server") + ": " + cleanText(strings.Join(hosts, ", ")), value: "@" + g})
		}
		l.rows = append(l.rows, menuHostRows(st)...)
	case "services":
		l.title = "Databases and services: which one?"
		for _, f := range menuFamilies {
			for _, r := range menuConnRows(st, f.family) {
				r.detail = f.word + "  " + r.detail
				l.rows = append(l.rows, r)
			}
		}
	case "vpns":
		l.title = "VPNs: which one?"
		l.rows = menuVpnRows(st)
	}
	return l
}

// menuFamilies is the kinds of service, in the order the list shows them.
var menuFamilies = []struct{ family, word string }{
	{"db", "database"}, {"cache", "cache"}, {"queue", "queue"},
	{"storage", "file storage"}, {"cluster", "cluster"}, {"registry", "registry"},
}

// menuItemKind is what an item is: server, group, vpn, or a conn family.
func menuItemKind(st *store.State, item string) string {
	switch {
	case strings.HasPrefix(item, "@"):
		return "group"
	case st.Hosts[item] != nil:
		return "server"
	case st.Vpns[item] != nil:
		return "vpn"
	case st.Conns[item] != nil:
		return connFamily(st.Conns[item])
	}
	return ""
}

// menuItemTitle is the question above an item's actions, with what it is:
// "web1 (deploy@10.0.0.5): what do you want to do?"
func menuItemTitle(st *store.State, kind, item string) string {
	var what string
	switch kind {
	case "server":
		h := st.Hosts[item]
		what = h.Address
		if h.User != "" {
			what = h.User + "@" + what
		}
	case "group":
		what = menuCount(len(allGroups(st).Groups[strings.TrimPrefix(item, "@")]), "server")
	case "vpn":
		what = "VPN, not connected"
		if menuVpnUp(st, item) {
			what = "VPN, connected"
		}
	default:
		if c := st.Conns[item]; c != nil {
			what = c.Kind
		}
	}
	return cleanText(item+" ("+what+")") + ": what do you want to do?"
}
