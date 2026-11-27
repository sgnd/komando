package store

import "slices"

// Removed by the C cluster row, with the --tag swarm line of the swarm form
// (cli swarmForm): until a swarm has its own add path, the swarm tag that
// host add and host edit take becomes a swarm service whose manager is the
// host, as the migration makes it. The host keeps no swarm tag.

// swarmTagged is h's tags without swarm, and whether it had it.
func swarmTagged(tags []string) ([]string, bool) {
	if !slices.Contains(tags, "swarm") {
		return tags, false
	}
	return slices.DeleteFunc(slices.Clone(tags), func(t string) bool { return t == "swarm" }), true
}

// swarmService makes the swarm service of the host stored under id, unless
// one names it as its manager already.
func (w *writer3) swarmService(id string, h *Host) error {
	for _, c := range w.st.conns {
		if c.Provider == "swarm" && c.ManagerID == id {
			return nil
		}
	}
	v := &ServiceV3{Name: w.entries.make(h.Name, "swarm"), Type: "cluster", Provider: "swarm",
		Manager: h.Name, ManagerID: id, CreatedAt: h.UpdatedAt, UpdatedAt: h.UpdatedAt}
	cid, err := w.put(KindConn, "", v)
	if err != nil {
		return err
	}
	w.st.conns[cid] = v
	return nil
}
