package store

import "strings"

// References between records: a server names its key (Key) and the
// servers or VPNs on its way (Via, on servers and conns). Each name has
// the record's ID beside it (KeyID, ViaIDs), so a reference survives a
// rename made somewhere else (a future sync between devices): the
// name is what people and commands read and change; the ID is what a
// rename cannot break.
//
//   - writing: the IDs are set from the names (followNames), so a command
//     changes only names and the IDs follow;
//   - reading: an ID that leads to a record with another name puts that
//     name in (followIDs). An ID that leads nowhere leaves the name as it
//     is: the record is gone, or the ID came from another store (export).

// recIDs maps each server, VPN and key name to its record ID, and back.
func (s *State) recIDs() (byName map[string]string, byID map[string]string) {
	byName, byID = map[string]string{}, map[string]string{}
	add := func(kind, name, id string) {
		if id == "" {
			return
		}
		byName[kind+"/"+name] = id
		byID[id] = name
	}
	for n, h := range s.Hosts {
		add(KindHost, n, h.Rec.ID)
	}
	for n, v := range s.Vpns {
		add(KindVpn, n, v.Rec.ID)
	}
	for n, k := range s.Keys {
		add(KindKey, n, k.Rec.ID)
	}
	return byName, byID
}

// viaSteps splits a --via value into its steps, as the commands do.
func viaSteps(via string) []string {
	var steps []string
	for _, p := range strings.Split(via, ",") {
		if p = strings.TrimSpace(p); p != "" {
			steps = append(steps, p)
		}
	}
	return steps
}

// followNames sets every reference's ID from its name (before a write).
func (s *State) followNames() {
	byName, _ := s.recIDs()
	via := func(v string) []string {
		steps := viaSteps(v)
		if len(steps) == 0 {
			return nil
		}
		ids := make([]string, len(steps))
		known := false
		for i, st := range steps {
			if id := byName[KindHost+"/"+st]; id != "" {
				ids[i], known = id, true
			} else if id := byName[KindVpn+"/"+st]; id != "" {
				ids[i], known = id, true
			}
		}
		if !known {
			return nil
		}
		return ids
	}
	for _, h := range s.Hosts {
		h.KeyID = ""
		if h.Key != "" {
			h.KeyID = byName[KindKey+"/"+h.Key]
		}
		h.ViaIDs = via(h.Via)
	}
	for _, c := range s.Conns {
		c.ViaIDs = via(c.Via)
	}
}

// followIDs puts in the current name of every record an ID leads to
// (after a read): a rename made elsewhere reaches the references.
func (s *State) followIDs() {
	_, byID := s.recIDs()
	via := func(v string, ids []string) string {
		steps := viaSteps(v)
		if len(ids) != len(steps) {
			return v // written by a komando that did not keep them in step
		}
		changed := false
		for i, id := range ids {
			if n, ok := byID[id]; ok && id != "" && n != steps[i] {
				steps[i], changed = n, true
			}
		}
		if !changed {
			return v
		}
		return strings.Join(steps, ",")
	}
	for _, h := range s.Hosts {
		if n, ok := byID[h.KeyID]; ok && h.KeyID != "" && s.Keys[n] != nil {
			h.Key = n
		}
		h.Via = via(h.Via, h.ViaIDs)
	}
	for _, c := range s.Conns {
		c.Via = via(c.Via, c.ViaIDs)
	}
}
