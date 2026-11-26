package cli

import (
	"slices"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// swarmHosts are the servers a selection picks, with the manager in place
// of each swarm service, each once. A swarm service works on its manager
// (Q8): every guard of that server applies, and personal data follows it.
func swarmHosts(cl *call, st *store.State, sel selection) ([]*store.Host, error) {
	hosts := slices.Clone(sel.Hosts)
	var managers []*store.Host
	for _, c := range sel.Conns {
		if c.Kind != "swarm" {
			continue
		}
		h := swarmManagerOf(st, c)
		if h == nil {
			return nil, out.Errf(out.ExitNotFound, "TARGET_EMPTY", "add the server again, or remove the swarm service",
				"swarm service %s: its manager server %s is not in your list", c.Name, c.Manager)
		}
		if !slices.ContainsFunc(hosts, func(o *store.Host) bool { return o.Name == h.Name }) {
			hosts, managers = append(hosts, h), append(managers, h)
		}
	}
	notePersonal(cl, st, managers, nil)
	return hosts, nil
}

// swarmManagerOf is the server a swarm service names as its manager, by
// record ID (a rename keeps it), else by name; nil when it is gone.
func swarmManagerOf(st *store.State, c *store.Conn) *store.Host {
	for _, h := range st.Hosts {
		if c.ManagerID != "" && h.Rec.ID == c.ManagerID {
			return h
		}
	}
	if c.ManagerID == "" {
		return st.Hosts[c.Manager]
	}
	return nil
}

// swarmOf is the swarm service whose manager is h, or nil.
func swarmOf(st *store.State, h *store.Host) *store.Conn {
	for _, c := range st.Conns {
		if c.Kind == "swarm" && swarmManagerOf(st, c) == h {
			return c
		}
	}
	return nil
}
