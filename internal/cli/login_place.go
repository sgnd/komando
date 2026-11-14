package cli

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// Where a typed password goes. A person types the password of a
// login-ask server or conn into komando's window whenever an AI agent's
// command connects, and it goes to whatever answers at the end of the
// way there. If an agent could choose that way, it could send the person
// to a server it controls and catch the password: the window would name
// the right server and an address the person may not check. So only a
// person sets the way: an AI agent that
//
//   - adds a login-ask server or conn, or turns one to login ask;
//   - changes where one goes (address, port, user, --via, proxy command,
//     WinRM transport; a conn's URL or --via);
//   - changes a server or VPN on the way to one (a jump host's address,
//     a VPN's server), or replaces one with an import
//
// gets NEEDS_PERSON, which no flag lifts (as replacing a pinned host key):
// the person runs that command in their own terminal. A dry run records
// the stop and goes on. A person at a terminal, their scripts and an
// app's calls are not stopped: they choose the way themselves.
//
// The host key adds a second wall for servers: the first connection to a
// login-ask server, whose key nobody has met, goes on only with a person
// (loginNewKey), so even a way changed outside komando (DNS, a VPN of
// this computer) leads to a key the person is shown first.

// loginPlaceStop stops an AI agent's change to where a typed password
// goes; what names each such change. A dry run records it and goes on.
func loginPlaceStop(cl *call, what []string) error {
	if !cl.isAgent() || len(what) == 0 {
		return nil
	}
	sort.Strings(what)
	return cl.policyStop(out.Errf(out.ExitPolicy, "NEEDS_PERSON",
		"ask the user to run `"+commandLine(cl)+"` in their own terminal if they want it; never ask for the password in the chat",
		"%s: a person types that password each time (login ask), so only a person changes where it goes", strings.Join(what, "; ")).NoFlag())
}

// askUsersThrough names the login-ask servers and conns whose way goes
// through step (a server or VPN name), at any depth of --via paths.
func askUsersThrough(s *store.State, step string) []string {
	var users []string
	for _, h := range s.SortedHosts() {
		if h.AskLogin() && h.Name != step && slices.Contains(waySteps(s, h.Via, map[string]bool{}), step) {
			users = append(users, "server "+h.Name)
		}
	}
	for _, c := range sortedConns(s) {
		if c.AskLogin() && slices.Contains(waySteps(s, c.Via, map[string]bool{}), step) {
			users = append(users, "conn "+c.Name)
		}
	}
	return users
}

// waySteps are the names on a --via path and on the paths of its servers.
func waySteps(s *store.State, via string, seen map[string]bool) []string {
	var steps []string
	for _, n := range viaChain(via) {
		if seen[n] {
			continue
		}
		seen[n] = true
		steps = append(steps, n)
		if h, ok := s.Hosts[n]; ok {
			steps = append(steps, waySteps(s, h.Via, seen)...)
		}
	}
	return steps
}

func sortedConns(s *store.State) []*store.Conn {
	names := make([]string, 0, len(s.Conns))
	for n := range s.Conns {
		names = append(names, n)
	}
	sort.Strings(names)
	conns := make([]*store.Conn, 0, len(names))
	for _, n := range names {
		conns = append(conns, s.Conns[n])
	}
	return conns
}

// hostPlaceChanges are the changes, of servers an add, edit or import
// leaves as now (olds: each one before, by name; none for a new one),
// that set where a typed password goes.
func hostPlaceChanges(s *store.State, now []*store.Host, olds map[string]*store.Host) []string {
	var what []string
	for _, h := range now {
		o := olds[h.Name]
		dest := hostPlace(h).dest
		moved := o != nil && hostPlace(o).dest != dest
		switch {
		case h.AskLogin() && o == nil:
			what = append(what, fmt.Sprintf("server %s would log in at %s with a typed password", h.Name, dest))
		case h.AskLogin() && !o.AskLogin():
			what = append(what, fmt.Sprintf("server %s would ask for a typed password for %s", h.Name, dest))
		case h.AskLogin() && moved:
			what = append(what, fmt.Sprintf("server %s would send its typed password to %s instead of %s", h.Name, dest, hostPlace(o).dest))
		}
		if moved {
			if users := askUsersThrough(s, h.Name); len(users) > 0 {
				what = append(what, fmt.Sprintf("server %s, now %s, is on the way to %s", h.Name, dest, strings.Join(users, ", ")))
			}
		}
	}
	return what
}

// connPlaceChanges is hostPlaceChanges for a conn an add, edit or import
// leaves as now (old: nil for a new one).
func connPlaceChanges(old, now *store.Conn) []string {
	if !now.AskLogin() {
		return nil
	}
	dest := connPlace(now).dest
	switch {
	case old == nil:
		return []string{fmt.Sprintf("conn %s would log in at %s with a typed password", now.Name, dest)}
	case !old.AskLogin():
		return []string{fmt.Sprintf("conn %s would ask for a typed password for %s", now.Name, dest)}
	case connPlace(old).dest != dest:
		return []string{fmt.Sprintf("conn %s would send its typed password to %s instead of %s", now.Name, dest, connPlace(old).dest)}
	}
	return nil
}

// vpnPlaceChanges: a VPN an edit, an add --overwrite or an import
// replaces is on the way to the login-ask servers and conns it names
// (changed: the edit changes how it connects).
func vpnPlaceChanges(s *store.State, name string, changed bool) []string {
	if !changed {
		return nil
	}
	if users := askUsersThrough(s, name); len(users) > 0 {
		return []string{fmt.Sprintf("VPN %s is on the way to %s", name, strings.Join(users, ", "))}
	}
	return nil
}

// vpnWayChanged: an edit changes how VPN a connects (anything but its
// groups, tags, labels, notes and protection).
func vpnWayChanged(a, b *store.Vpn) bool {
	x, y := *a, *b
	for _, v := range []*store.Vpn{&x, &y} {
		v.Groups, v.Tags, v.Labels, v.Notes, v.Protected = nil, nil, nil, "", false
	}
	return vpnChanged(&x, &y)
}

// importVpnPlaces stops an AI agent's import that replaces a VPN on the
// way to a login-ask server or conn (loginPlaceStop).
func importVpnPlaces(cl *call, st *store.State, vpns []*store.Vpn) error {
	var replacing []string
	for _, v := range vpns {
		if o, ok := st.Vpns[v.Name]; ok {
			replacing = append(replacing, vpnPlaceChanges(st, v.Name, vpnWayChanged(o, v))...)
		}
	}
	return loginPlaceStop(cl, replacing)
}
