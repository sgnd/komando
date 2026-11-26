package store

import (
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// The format-3 store and the in-memory State (design note
// 2026-11-25-cut-e1-migration-design, section 4; decision Q1). This file
// is the only code that maps the v3 records to State and back: the rest
// of komando reads State. References in State are spelled
// credential:NAME. A write applies only the State fields that changed onto
// the stored v3 record (Audit E1-1), and refuses a change through a host
// or a service to a credential that another entry also uses (Audit E1-2).

// credRef is the reference spelling of a credential name.
func credRef(name string) string {
	if name == "" {
		return ""
	}
	return "credential:" + name
}

// credOfRef is the credential a reference names, or "" for no reference.
// Any other spelling stops: a format-3 store names credentials only.
func credOfRef(entry, field, ref string) (string, error) {
	if ref == "" {
		return "", nil
	}
	if n, ok := strings.CutPrefix(ref, "credential:"); ok && n != "" {
		return n, nil
	}
	return "", out.Errf(out.ExitUsage, "BAD_REFERENCE",
		"save the value as a credential and name it: credential:NAME",
		"%s: field %s must name a credential (credential:NAME)", entry, field)
}

// kindOf3 is the conn kind of a (type, provider), for State.
func kindOf3(typ, provider, url string) string {
	if provider == "ftp" && strings.HasPrefix(strings.ToLower(url), "ftps://") {
		return "ftps"
	}
	for k, tp := range connTypes3 {
		if tp == [2]string{typ, provider} && k != "ftps" {
			return k
		}
	}
	return provider
}

// stored3 is what a format-3 store holds that State does not show as it
// is: the records by ID, so a write merges into them.
type stored3 struct {
	hosts  map[string]*HostV3
	conns  map[string]*ServiceV3
	vpns   map[string]*VpnV3
	creds  map[string]*Credential      // by record ID
	credID map[string]string           // credential name: record ID
	groups map[string]*Group           // by record ID
	stores map[string]*CredentialStore // by record ID
	ver    map[string]uint64           // record ID: its version
}

func (s *stored3) cred(name string) *Credential {
	if id, ok := s.credID[name]; ok {
		return s.creds[id]
	}
	return nil
}

// readStored3 reads the records State is made from.
func readStored3(tx *sealdb.Tx) (*stored3, error) {
	st := &stored3{hosts: map[string]*HostV3{}, conns: map[string]*ServiceV3{}, vpns: map[string]*VpnV3{},
		creds: map[string]*Credential{}, credID: map[string]string{}, groups: map[string]*Group{},
		stores: map[string]*CredentialStore{}, ver: map[string]uint64{}}
	read := func(typ string, mk func(id string) any) error {
		rows, err := tx.List(typ)
		if err != nil {
			return err
		}
		for _, r := range rows {
			st.ver[r.ID] = r.Version
			if err := json.Unmarshal(r.Data, mk(r.ID)); err != nil {
				return fmt.Errorf("%s record %s: %w", typ, r.ID, err)
			}
		}
		return nil
	}
	err := read(KindHost, func(id string) any { v := &HostV3{}; st.hosts[id] = v; return v })
	if err == nil {
		err = read(KindConn, func(id string) any { v := &ServiceV3{}; st.conns[id] = v; return v })
	}
	if err == nil {
		err = read(KindVpn, func(id string) any { v := &VpnV3{}; st.vpns[id] = v; return v })
	}
	if err == nil {
		err = read(KindCredential, func(id string) any { v := &Credential{}; st.creds[id] = v; return v })
	}
	if err == nil {
		err = read(KindGroup, func(id string) any { v := &Group{}; st.groups[id] = v; return v })
	}
	if err == nil {
		err = read(KindCredStore, func(id string) any { v := &CredentialStore{}; st.stores[id] = v; return v })
	}
	if err != nil {
		return nil, err
	}
	for id, c := range st.creds {
		if _, dup := st.credID[c.Name]; dup || c.Name == "" {
			return nil, fmt.Errorf("credential %q: %w", c.Name, sealdb.ErrTampered)
		}
		st.credID[c.Name] = id
	}
	return st, nil
}

// checkRefs3 is the F10 check on load: a reference field that still
// spells secret:NAME stops the store (never the value in the message).
func (st *stored3) checkRefs3() error {
	var recs []record3
	for id, v := range st.hosts {
		recs = append(recs, record3{typ: KindHost, id: id, name: v.Name, data: v})
	}
	for id, v := range st.conns {
		recs = append(recs, record3{typ: KindConn, id: id, name: v.Name, data: v})
	}
	for id, v := range st.vpns {
		recs = append(recs, record3{typ: KindVpn, id: id, name: v.Name, data: v})
	}
	slices.SortFunc(recs, func(a, b record3) int { return strings.Compare(a.typ+a.name, b.typ+b.name) })
	return checkOldRefs3(recs)
}

// groupsOf is the group names whose members hold id, sorted.
func (st *stored3) groupsOf(id string) []string {
	var gs []string
	for _, g := range st.groups {
		if slices.Contains(g.Members, id) {
			gs = append(gs, g.Name)
		}
	}
	slices.Sort(gs)
	return gs
}

// users is every entry that uses credential name, as "host web1".
func (st *stored3) users(name string) []string {
	var us []string
	for _, h := range st.hosts {
		if h.Credential == name || h.SudoCredential == name {
			us = append(us, "host "+h.Name)
		}
	}
	for _, c := range st.conns {
		if c.Credential == name {
			us = append(us, typeWord(c)+" "+c.Name)
		}
	}
	for _, v := range st.vpns {
		if v.Credential == name || v.PSKCredential == name || v.ConfigCredential == name {
			us = append(us, "vpn "+v.Name)
		}
	}
	slices.Sort(us)
	return slices.Compact(us)
}

func typeWord(c *ServiceV3) string {
	if c.Type == "" {
		return "service"
	}
	return c.Type
}

// fillState makes s's inventory from st.
func (st *stored3) fillState(s *State, recipes []sealdb.Record) error {
	for id, c := range st.creds {
		if c.Kind != CredKey || c.Key == nil || c.Key.Agent {
			continue
		}
		s.Keys[c.Name] = &Key{Name: c.Name, Path: c.Key.Path, Type: c.Key.Type, PublicKey: c.Key.PublicKey,
			Fingerprint: c.Key.Fingerprint, PassphraseRef: credRef(c.Key.Passphrase), CertPath: c.Key.CertPath,
			Managed: c.Key.Managed, CreatedAt: c.UpdatedAt, Rec: Rec{ID: id, Version: st.ver[id]}}
	}
	for id, v := range st.hosts {
		if s.Hosts[v.Name] != nil {
			return dupName(KindHost, v.Name)
		}
		h := &Host{Name: v.Name, Address: v.Address, Port: v.Port, Login: v.Login, Via: v.Via, ViaIDs: v.ViaIDs,
			ProxyCommand: v.ProxyCommand, Groups: st.groupsOf(id), Tags: v.Tags, Labels: v.Labels, Env: v.Env,
			Protected: v.Protected, ForwardAgent: v.ForwardAgent, Notes: v.Notes, OS: v.OS, WinRMOpts: v.WinRMOpts,
			SudoRef: credRef(v.SudoCredential), CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt, Rec: Rec{ID: id, Version: st.ver[id]}}
		if v.Provider == "winrm" {
			h.Transport = TransportWinRM
		}
		c := st.creds[v.CredentialID] // a rename made elsewhere keeps the ID
		if c == nil {
			c = st.cred(v.Credential)
		}
		if c != nil {
			h.User = c.User
			switch {
			case c.Kind == CredKey && c.Key != nil && !c.Key.Agent:
				h.Key, h.KeyID = c.Name, st.credID[c.Name]
			case c.Kind == CredKey || c.Ask:
				// ssh-agent, or a password the person types: the user only
			default:
				h.PasswordRef = credRef(c.Name)
			}
		} else if v.Credential != "" {
			return fmt.Errorf("host %s names credential %s, which does not exist: %w", v.Name, v.Credential, sealdb.ErrTampered)
		}
		s.Hosts[v.Name] = h
	}
	for id, v := range st.conns {
		if s.Conns[v.Name] != nil {
			return dupName(KindConn, v.Name)
		}
		c := &Conn{Name: v.Name, Kind: kindOf3(v.Type, v.Provider, v.URL), URL: v.URL, Login: v.Login, Via: v.Via,
			ViaIDs: v.ViaIDs, Groups: st.groupsOf(id), Tags: v.Tags, Labels: v.Labels, Options: v.Options,
			Protected: v.Protected, Notes: v.Notes, TrustedPlugin: v.TrustedPlugin, PluginProgram: v.PluginProgram,
			PluginSearchPath: v.PluginSearchPath, Manager: v.Manager, ManagerID: v.ManagerID,
			CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt, Rec: Rec{ID: id, Version: st.ver[id]}}
		if cr := st.cred(v.Credential); cr != nil {
			if cr.User != "" {
				c.URL = withURLUser(v.URL, cr.User)
			}
			if !cr.Ask {
				c.PasswordRef = credRef(cr.Name)
			}
		}
		s.Conns[v.Name] = c
	}
	for id, v := range st.vpns {
		if s.Vpns[v.Name] != nil {
			return dupName(KindVpn, v.Name)
		}
		s.Vpns[v.Name] = &Vpn{Name: v.Name, Kind: v.Provider, Config: v.Config, ConfigRef: credRef(v.ConfigCredential),
			Address: v.Address, Portal: v.Portal, Service: v.Service, Server: v.Server, User: v.User,
			KeyRef: credRef(v.Credential), PSKRef: credRef(v.PSKCredential), LocalID: v.LocalID, RemoteID: v.RemoteID,
			CA: v.CA, MFA: v.MFA, Protected: v.Protected, Check: v.Check, Groups: st.groupsOf(id), Tags: v.Tags,
			Labels: v.Labels, Notes: v.Notes, LegacyCrypto: v.LegacyCrypto, AllowPAP: v.AllowPAP,
			CreatedAt: v.CreatedAt, UpdatedAt: v.UpdatedAt, Rec: Rec{ID: id, Version: st.ver[id]}}
	}
	for _, r := range recipes {
		v := &Snippet{}
		if err := json.Unmarshal(r.Data, v); err != nil {
			return err
		}
		if v.Name == "" || s.Snippets[v.Name] != nil {
			return dupName(KindRecipe, v.Name)
		}
		v.Rec = Rec{ID: r.ID, Version: r.Version}
		s.Snippets[v.Name] = v
	}
	return nil
}

// withURLUser puts user into a URL that has none.
func withURLUser(raw, user string) string {
	scheme, rest, ok := strings.Cut(raw, "://")
	if !ok || user == "" {
		return raw
	}
	return scheme + "://" + urlEscapeUser(user) + "@" + rest
}

func urlEscapeUser(u string) string {
	r := strings.NewReplacer("%", "%25", "@", "%40", ":", "%3A", "/", "%2F", "?", "%3F", "#", "%23")
	return r.Replace(u)
}

// writer3 applies State's changes onto the stored v3 records in tx.
type writer3 struct {
	tx      *sealdb.Tx
	st      *stored3
	names   *nameMaker        // credential names
	entries *nameMaker        // host, service and VPN names
	ver     map[string]uint64 // record ID: the version its last write gave it
}

// put writes v under typ and id and keeps st in step.
func (w *writer3) put(typ, id string, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	r, err := w.tx.Put(typ, id, b)
	if err == nil {
		w.ver[r.ID] = r.Version
	}
	return r.ID, err
}

// sharedRefusal is Audit E1-2: a change through one entry to a
// credential that others use too.
func (w *writer3) sharedRefusal(entry, what, cred string) error {
	return out.Errf(out.ExitUsage, "CREDENTIAL_SHARED",
		"change it with `komando credential` (it changes it for every entry that uses it), or give this entry its own credential",
		"%s: changing %s would change credential %s, which these entries use: %s; nothing was changed",
		entry, what, cred, strings.Join(w.st.users(cred), ", "))
}

// loginCred makes the credential a host or service logs in with agree
// with what State says: its user and, through a host, its key. A change
// to a credential other entries use is refused (E1-2).
func (w *writer3) loginCred(entry, name, user string, alone func(string) bool) error {
	c := w.st.cred(name)
	if c == nil {
		return fmt.Errorf("%s: credential %s does not exist", entry, name)
	}
	if c.User == user {
		return nil
	}
	if !alone(name) {
		return w.sharedRefusal(entry, "the user", name)
	}
	c.User = user
	_, err := w.put(KindCredential, w.st.credID[name], c)
	return err
}

// newCred makes a credential for entry and returns its name.
func (w *writer3) newCred(base, part string, c *Credential) (string, error) {
	c.Name = w.names.make(base, part)
	id, err := w.put(KindCredential, "", c)
	if err != nil {
		return "", err
	}
	w.st.creds[id], w.st.credID[c.Name] = c, id
	return c.Name, nil
}

// host writes h onto its stored record (E1-1: fields State does not
// carry stay as they are).
func (w *writer3) host(h *Host) error {
	e := "host " + h.Name
	v := w.st.hosts[h.Rec.ID]
	if v == nil {
		v = &HostV3{}
	}
	v.Name, v.Address, v.Port, v.Login, v.Via, v.ViaIDs = h.Name, h.Address, h.Port, h.Login, h.Via, h.ViaIDs
	v.ProxyCommand, v.Tags, v.Labels, v.Env, v.Protected = h.ProxyCommand, h.Tags, h.Labels, h.Env, h.Protected
	v.ForwardAgent, v.Notes, v.OS, v.WinRMOpts, v.CreatedAt, v.UpdatedAt = h.ForwardAgent, h.Notes, h.OS, h.WinRMOpts, h.CreatedAt, h.UpdatedAt
	var swarm bool
	v.Tags, swarm = swarmTagged(h.Tags)
	v.Provider = "ssh"
	if h.Transport == TransportWinRM {
		v.Provider = "winrm"
	}
	sudo, err := refCred(e, "sudo", h.SudoRef)
	if err != nil {
		return err
	}
	v.SudoCredential = sudo
	alone := func(name string) bool {
		us := w.st.users(name)
		return len(us) == 0 || len(us) == 1 && us[0] == e
	}
	// the credential it logs in with
	var cred string
	switch {
	case h.Identity != "":
		// a key file of the person: the key credential that holds that
		// file, or a new one named after it (as the migration does); this
		// host is pointed at it, no other credential changes
		if cred, err = w.keyFileCred(h.Identity, h.User); err != nil {
			return err
		}
	case h.Key != "":
		cred = h.Key
	case h.PasswordRef != "":
		if cred, err = refCred(e, "password", h.PasswordRef); err != nil {
			return err
		}
	case v.Credential != "" && w.st.cred(v.Credential) != nil && (w.st.cred(v.Credential).Ask || isAgent(w.st.cred(v.Credential))):
		cred = v.Credential // ssh-agent or a typed password: State shows the user only
	case h.AskLogin():
		if cred, err = w.newCred(h.Name, "ask", &Credential{Kind: CredPassword, User: h.User, Ask: true}); err != nil {
			return err
		}
	case h.User != "":
		if cred, err = w.newCred(h.Name, "agent", &Credential{Kind: CredKey, User: h.User, Key: &CredentialKey{Agent: true}}); err != nil {
			return err
		}
	}
	v.Credential = cred
	v.CredentialID = w.st.credID[cred]
	if err := refuseOldRefs(e, v); err != nil {
		return err
	}
	id, err := w.put(KindHost, h.Rec.ID, v)
	if err != nil {
		return err
	}
	w.st.hosts[id] = v
	if swarm {
		if err := w.swarmService(id, h); err != nil {
			return err
		}
	}
	if cred != "" {
		if err := w.loginCred(e, cred, h.User, alone); err != nil {
			return err
		}
	}
	return nil
}

// keyFileCred is the key credential that holds the person's key file
// path for user, or a new one named after the file.
func (w *writer3) keyFileCred(path, user string) (string, error) {
	for _, id := range slices.Sorted(maps.Keys(w.st.creds)) {
		c := w.st.creds[id]
		if c.Kind == CredKey && c.Key != nil && !c.Key.Managed && c.Key.Path == path && c.User == user {
			return c.Name, nil
		}
	}
	base := filepath.Base(path)
	if userSlug(base) == "" {
		base = "key"
	}
	return w.newCred(userSlug(base), "", &Credential{Kind: CredKey, User: user, Key: &CredentialKey{Path: path}})
}

func isAgent(c *Credential) bool { return c.Kind == CredKey && c.Key != nil && c.Key.Agent }

// conn writes c onto its stored record; the URL's user goes to its
// credential.
func (w *writer3) conn(c *Conn) error {
	tp, ok := connTypes3[c.Kind]
	if c.Kind == "swarm" {
		tp, ok = [2]string{"cluster", "swarm"}, true
	}
	e := "service " + c.Name
	if !ok {
		return out.Errf(out.ExitUsage, "BAD_KIND", "pick a kind komando knows", "%s: kind %q has no type", e, c.Kind)
	}
	v := w.st.conns[c.Rec.ID]
	if v == nil {
		v = &ServiceV3{}
	}
	user, url := urlUser(c.URL)
	v.Name, v.Type, v.Provider, v.URL, v.Login, v.Via, v.ViaIDs = c.Name, tp[0], tp[1], url, c.Login, c.Via, c.ViaIDs
	v.Tags, v.Labels, v.Options, v.Protected, v.Notes = c.Tags, c.Labels, c.Options, c.Protected, c.Notes
	v.TrustedPlugin, v.PluginProgram, v.PluginSearchPath = c.TrustedPlugin, c.PluginProgram, c.PluginSearchPath
	v.Manager, v.ManagerID, v.CreatedAt, v.UpdatedAt = c.Manager, c.ManagerID, c.CreatedAt, c.UpdatedAt
	alone := func(name string) bool {
		us := w.st.users(name)
		return len(us) == 0 || len(us) == 1 && us[0] == typeWord(v)+" "+v.Name
	}
	cred, err := refCred(e, "password", c.PasswordRef)
	if err != nil {
		return err
	}
	switch {
	case cred != "":
	case v.Credential != "" && w.st.cred(v.Credential) != nil && w.st.cred(v.Credential).Ask:
		cred = v.Credential
	case c.AskLogin():
		if cred, err = w.newCred(c.Name, "ask", &Credential{Kind: CredPassword, User: user, Ask: true}); err != nil {
			return err
		}
	case user != "":
		// a user and no secret: the user stays in the URL
		v.URL = c.URL
	}
	v.Credential = cred
	if err := refuseOldRefs(e, v); err != nil {
		return err
	}
	id, err := w.put(KindConn, c.Rec.ID, v)
	if err != nil {
		return err
	}
	w.st.conns[id] = v
	if cred != "" {
		return w.loginCred(e, cred, user, alone)
	}
	return nil
}

// vpn writes x onto its stored record.
func (w *writer3) vpn(x *Vpn) error {
	e := "vpn " + x.Name
	v := w.st.vpns[x.Rec.ID]
	if v == nil {
		v = &VpnV3{}
	}
	var err error
	if v.Credential, err = refCred(e, "key", x.KeyRef); err != nil {
		return err
	}
	if v.PSKCredential, err = refCred(e, "psk", x.PSKRef); err != nil {
		return err
	}
	if v.ConfigCredential, err = refCred(e, "config", x.ConfigRef); err != nil {
		return err
	}
	v.Name, v.Provider, v.Config, v.Address, v.Portal, v.Service = x.Name, x.Kind, x.Config, x.Address, x.Portal, x.Service
	v.Server, v.User, v.LocalID, v.RemoteID, v.CA, v.MFA = x.Server, x.User, x.LocalID, x.RemoteID, x.CA, x.MFA
	v.Protected, v.Check, v.Tags, v.Labels, v.Notes = x.Protected, x.Check, x.Tags, x.Labels, x.Notes
	v.LegacyCrypto, v.AllowPAP, v.CreatedAt, v.UpdatedAt = x.LegacyCrypto, x.AllowPAP, x.CreatedAt, x.UpdatedAt
	if err := refuseOldRefs(e, v); err != nil {
		return err
	}
	id, err := w.put(KindVpn, x.Rec.ID, v)
	if err == nil {
		w.st.vpns[id] = v
	}
	return err
}

// key writes k onto its key credential. A key's file or passphrase is
// changed only through a credential command, so when another entry uses
// it the change is still the credential's own (`komando credential`).
func (w *writer3) key(k *Key) error {
	c := w.st.creds[k.Rec.ID]
	if c == nil {
		c = &Credential{Kind: CredKey}
	}
	pp, err := refCred("key "+k.Name, "passphrase", k.PassphraseRef)
	if err != nil {
		return err
	}
	c.Name, c.UpdatedAt = k.Name, k.CreatedAt
	c.Key = &CredentialKey{Path: k.Path, Type: k.Type, PublicKey: k.PublicKey, Fingerprint: k.Fingerprint,
		Passphrase: pp, CertPath: k.CertPath, Managed: k.Managed}
	id, err := w.put(KindCredential, k.Rec.ID, c)
	if err == nil {
		w.st.creds[id], w.st.credID[c.Name] = c, id
	}
	return err
}

// groups writes the group records from State's group fields: a member
// joins or leaves; a group with no member stays (v2.7 groups can be
// empty).
func (w *writer3) groups(members map[string][]string) error {
	byName := map[string]string{}
	for id, g := range w.st.groups {
		byName[strings.ToLower(g.Name)] = id
	}
	want := map[string][]string{} // group name (as first written): member IDs
	names := map[string]string{}
	for id, gs := range members {
		for _, g := range gs {
			l := strings.ToLower(g)
			if _, ok := names[l]; !ok {
				names[l] = g
			}
			want[l] = append(want[l], id)
		}
	}
	for l := range byName {
		if _, ok := want[l]; !ok {
			want[l] = nil
		}
	}
	for _, l := range slices.Sorted(maps.Keys(want)) {
		ids := want[l]
		slices.Sort(ids)
		gid, had := byName[l]
		g := w.st.groups[gid]
		if !had {
			g = &Group{Name: names[l]}
		}
		// members that are not entries State shows (snippets) stay
		var keep []string
		for _, m := range g.Members {
			if _, isEntry := members[m]; !isEntry {
				keep = append(keep, m)
			}
		}
		next := append(keep, ids...)
		slices.Sort(next)
		if had && slices.Equal(next, g.Members) {
			continue
		}
		if next == nil {
			next = []string{}
		}
		g.Members = next
		id, err := w.put(KindGroup, gid, g)
		if err != nil {
			return err
		}
		w.st.groups[id] = g
	}
	return nil
}
