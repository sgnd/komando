package store

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// The plan of the format-3 migration: what each format-2 record becomes
// (design sections 2 to 4). It reads no file and writes nothing; the
// migration step writes what it says.

// snapshot2 is what the migration reads from a format-2 store.
type snapshot2 struct {
	state   *State
	secrets map[string]secret2 // by name
	counts  map[string]int     // records per type
}

type secret2 struct {
	id    string
	value SealedValue
}

// connTypes3 is each conn kind's (type, provider) in v2.7. A MariaDB or
// Valkey server stays mysql or redis: its URL does not tell them apart.
var connTypes3 = map[string][2]string{
	"postgres": {"database", "postgres"}, "mysql": {"database", "mysql"}, "sqlserver": {"database", "sqlserver"},
	"oracle": {"database", "oracle"}, "sqlite": {"database", "sqlite"}, "mongodb": {"database", "mongodb"},
	"clickhouse": {"database", "clickhouse"}, "snowflake": {"database", "snowflake"}, "bigquery": {"database", "bigquery"},
	"redis": {"cache", "redis"}, "memcached": {"cache", "memcached"},
	"kafka": {"queue", "kafka"}, "rabbitmq": {"queue", "rabbitmq"}, "nats": {"queue", "nats"}, "sqs": {"queue", "sqs"}, "pubsub": {"queue", "pubsub"},
	"s3": {"storage", "s3"}, "gcs": {"storage", "gcs"}, "azblob": {"storage", "azblob"}, "sftp": {"storage", "sftp"},
	"ftp": {"storage", "ftp"}, "ftps": {"storage", "ftp"}, "smb": {"storage", "smb"}, "webdav": {"storage", "webdav"},
	"k8s":      {"cluster", "kubernetes"},
	"registry": {"registry", "oci"},
}

// plan3 is the migration's work.
type plan3 struct {
	hosts    map[string]*HostV3    // by record ID
	conns    map[string]*ServiceV3 // by record ID
	vpns     map[string]*VpnV3     // by record ID
	swarms   []*ServiceV3          // new entries
	creds    []*credPlan
	stores   []*CredentialStore
	groups   []*Group
	seed     *secret2
	deletes  []string // secret and key record IDs
	expect   map[string]int
	report   migration3Report
	problems []string
}

// credPlan is one credential to write: its value comes from the vault
// secret valueFrom; a key pair komando made is copied from copyKeydata.
type credPlan struct {
	cred        *Credential
	valueFrom   string
	copyKeydata string
}

type migration3Report struct {
	Counts             map[string][2]int `json:"counts"` // type: before, after
	Names              []nameChange      `json:"names,omitempty"`
	Rewritten          []fieldChange     `json:"rewritten,omitempty"`
	KeyAndPassword     []string          `json:"key_and_password,omitempty"`
	SnippetsWithOldRef []string          `json:"snippets_with_old_reference,omitempty"`
	MergedGroups       []string          `json:"merged_groups,omitempty"`
	Backup             string            `json:"backup,omitempty"`
}

// nameChange is an old name and the names that replace it.
type nameChange struct {
	Kind string   `json:"kind"`
	Old  string   `json:"old"`
	New  []string `json:"new"`
}

// fieldChange is a field that names a credential now: no value, only names.
type fieldChange struct {
	Entry      string `json:"entry"`
	Field      string `json:"field"`
	Credential string `json:"credential"`
}

// use is one field that names a secret: a login carries its user.
type use struct {
	entry, field string
	login        bool
	user         string
	kind         string // the credential kind it asks for
	apply        func(credential string)
}

type keyUse struct {
	entry, user string
	apply       func(credential string)
}

type planner struct {
	snap     *snapshot2
	refGuard func(kind, name string) error
	p        *plan3
	entries  *nameMaker
	creds    *nameMaker
	secrets  map[string][]*use // by secret name
	outside  []outsideUse
	keyUses  map[string][]keyUse // by key name, or file:<path>
	keyPass  map[string]string   // key name: its passphrase credential
	deferred []func()            // credentials made after every kept name
	stores   map[string]string   // provider: store name
}

type outsideUse struct {
	provider, item string
	u              *use
}

// planFormat3 is the plan for snap, or STORE_MIGRATION_FAILED naming every
// record and field it cannot move.
func planFormat3(snap *snapshot2, refGuard func(kind, name string) error) (*plan3, error) {
	pl := &planner{
		snap: snap, refGuard: refGuard,
		p:       &plan3{hosts: map[string]*HostV3{}, conns: map[string]*ServiceV3{}, vpns: map[string]*VpnV3{}, report: migration3Report{Counts: map[string][2]int{}}},
		entries: newNameMaker(nil), creds: newNameMaker(nil),
		secrets: map[string][]*use{}, keyUses: map[string][]keyUse{}, keyPass: map[string]string{}, stores: map[string]string{},
	}
	s := snap.state
	for _, n := range slices.Concat(slices.Collect(maps.Keys(s.Hosts)), slices.Collect(maps.Keys(s.Conns)), slices.Collect(maps.Keys(s.Vpns))) {
		pl.entries.keep(n)
	}
	for _, h := range s.SortedHosts() {
		pl.host(h)
	}
	for _, c := range s.SortedConns() {
		pl.conn(c)
	}
	for _, v := range s.SortedVpns() {
		pl.vpn(v)
	}
	for _, k := range slices.Sorted(maps.Keys(s.Keys)) {
		if r := s.Keys[k].PassphraseRef; r != "" {
			key := k
			pl.ref(r, &use{entry: "key " + k, field: "passphrase", kind: CredToken, apply: func(c string) { pl.keyPass[key] = c }})
		}
	}
	split := pl.secretCredentials()
	split = append(split, pl.keyCredentials()...)
	for _, f := range split {
		f()
	}
	for _, f := range pl.deferred {
		f()
	}
	pl.outsideCredentials()
	pl.groups()
	pl.snippets()
	pl.expectCounts()
	if len(pl.p.problems) > 0 {
		return nil, out.Errf(out.ExitPolicy, "STORE_MIGRATION_FAILED",
			"fix each one with komando v0.17.0, then open the store with this komando again; nothing was changed",
			"the store cannot move to format 3: %s", strings.Join(pl.p.problems, "; "))
	}
	return pl.p, nil
}

func (pl *planner) problem(format string, a ...any) {
	pl.p.problems = append(pl.p.problems, fmt.Sprintf(format, a...))
}

// hostUser is the user h logs in as: its own, else the default setting.
func (pl *planner) hostUser(h *Host) string {
	if h.User != "" {
		return h.User
	}
	return pl.snap.state.Settings.DefaultUser
}

func (pl *planner) host(h *Host) {
	v := &HostV3{
		Name: h.Name, Provider: "ssh", Address: h.Address, Port: h.Port, Login: h.Login, Via: h.Via, ViaIDs: h.ViaIDs,
		ProxyCommand: h.ProxyCommand, Tags: slices.DeleteFunc(slices.Clone(h.Tags), func(t string) bool { return t == "swarm" }),
		Labels: h.Labels, Env: maps.Clone(h.Env), Protected: h.Protected, ForwardAgent: h.ForwardAgent, Notes: h.Notes,
		OS: h.OS, CreatedAt: h.CreatedAt, UpdatedAt: h.UpdatedAt,
	}
	if len(v.Tags) == 0 {
		v.Tags = nil
	}
	if h.WinRM() {
		v.Provider = "winrm"
	}
	if h.WinRMOpts != nil {
		o := *h.WinRMOpts
		v.WinRMOpts = &o
	}
	pl.p.hosts[h.Rec.ID] = v
	e, user := "host "+h.Name, pl.hostUser(h)
	setCred := func(c string) { v.Credential = c }
	switch {
	case h.AskLogin():
		pl.made(e, h.Name, "ask", &Credential{Kind: CredPassword, User: user, Ask: true}, setCred)
	case h.Key != "" || h.KeyID != "":
		name := h.Key
		if k := pl.keyByID(h.KeyID); k != "" {
			name = k
		}
		if pl.snap.state.Keys[name] == nil {
			pl.problem("%s: field key names key %s, which does not exist", e, name)
		}
		pl.keyUses[name] = append(pl.keyUses[name], keyUse{e, user, setCred})
	case h.Identity != "":
		pl.keyUses["file:"+h.Identity] = append(pl.keyUses["file:"+h.Identity], keyUse{e, user, setCred})
	case h.PasswordRef != "":
		pl.ref(h.PasswordRef, &use{entry: e, field: "password_ref", login: true, user: user, kind: CredPassword, apply: setCred})
	case user != "":
		pl.made(e, h.Name, "agent", &Credential{Kind: CredKey, User: user, Key: &CredentialKey{Agent: true}}, setCred)
	}
	if (h.Key != "" || h.Identity != "") && h.PasswordRef != "" {
		pl.p.report.KeyAndPassword = append(pl.p.report.KeyAndPassword, h.Name)
	}
	if h.SudoRef != "" {
		pl.ref(h.SudoRef, &use{entry: e, field: "sudo_ref", login: true, user: user, kind: CredPassword, apply: func(c string) { v.SudoCredential = c }})
	}
	for _, k := range slices.Sorted(maps.Keys(h.Env)) {
		if p, _ := parseRef(h.Env[k]); p != "" {
			key := k
			pl.ref(h.Env[k], &use{entry: e, field: "env " + k, kind: CredToken, apply: func(c string) { v.Env[key] = "credential:" + c }})
		}
	}
	if v.WinRMOpts != nil && v.WinRMOpts.CA != "" {
		pl.ref(v.WinRMOpts.CA, &use{entry: e, field: "winrm.ca", kind: CredToken, apply: func(c string) { v.WinRMOpts.CA = "credential:" + c }})
	}
	if slices.Contains(h.Tags, "swarm") {
		pl.p.swarms = append(pl.p.swarms, &ServiceV3{Name: pl.entries.make(h.Name, "swarm"), Type: "cluster", Provider: "swarm",
			Manager: h.Name, ManagerID: h.Rec.ID, CreatedAt: h.CreatedAt, UpdatedAt: h.UpdatedAt})
	}
}

func (pl *planner) keyByID(id string) string {
	for n, k := range pl.snap.state.Keys {
		if id != "" && k.Rec.ID == id {
			return n
		}
	}
	return ""
}

func (pl *planner) conn(c *Conn) {
	tp, ok := connTypes3[c.Kind]
	e := "conn " + c.Name
	if !ok {
		pl.problem("%s: field kind %q has no v2.7 type", e, c.Kind)
	}
	v := &ServiceV3{
		Name: c.Name, Type: tp[0], Provider: tp[1], URL: c.URL, Login: c.Login, Via: c.Via, ViaIDs: c.ViaIDs,
		Tags: c.Tags, Labels: c.Labels, Options: maps.Clone(c.Options), Protected: c.Protected, Notes: c.Notes,
		TrustedPlugin: c.TrustedPlugin, PluginProgram: c.PluginProgram, PluginSearchPath: c.PluginSearchPath,
		CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt,
	}
	pl.p.conns[c.Rec.ID] = v
	if urlPassword(c.URL) {
		pl.problem("%s: field url holds a password in its user part", e)
		return
	}
	var user string
	if c.PasswordRef != "" || c.AskLogin() {
		user, v.URL = urlUser(c.URL)
	}
	setCred := func(n string) { v.Credential = n }
	switch {
	case c.AskLogin():
		pl.made(e, c.Name, "ask", &Credential{Kind: CredPassword, User: user, Ask: true}, setCred)
	case c.PasswordRef != "":
		login, kind := c.Kind != "k8s", CredPassword
		if !login {
			kind = CredToken // a kubeconfig
		}
		pl.ref(c.PasswordRef, &use{entry: e, field: "password_ref", login: login, user: user, kind: kind, apply: setCred})
	}
	mapURLRefs(v.URL, func(opt, val string) string {
		if p, _ := parseRef(val); p != "" {
			o := opt
			pl.ref(val, &use{entry: e, field: "url " + opt, kind: CredToken, apply: func(n string) {
				v.URL = mapURLRefs(v.URL, func(k, x string) string {
					if k == o && x == val {
						return "credential:" + n
					}
					return x
				})
			}})
		}
		return val
	})
	for _, k := range slices.Sorted(maps.Keys(v.Options)) {
		if p, _ := parseRef(v.Options[k]); p != "" {
			key := k
			pl.ref(v.Options[k], &use{entry: e, field: "option " + k, kind: CredToken, apply: func(n string) { v.Options[key] = "credential:" + n }})
		}
	}
}

func (pl *planner) vpn(x *Vpn) {
	v := &VpnV3{
		Name: x.Name, Provider: x.Kind, Config: x.Config, Address: x.Address, Portal: x.Portal, Service: x.Service,
		Server: x.Server, User: x.User, LocalID: x.LocalID, RemoteID: x.RemoteID, CA: x.CA, MFA: x.MFA,
		Protected: x.Protected, Check: x.Check, Tags: x.Tags, Labels: x.Labels, Notes: x.Notes,
		LegacyCrypto: x.LegacyCrypto, AllowPAP: x.AllowPAP, CreatedAt: x.CreatedAt, UpdatedAt: x.UpdatedAt,
	}
	pl.p.vpns[x.Rec.ID] = v
	e := "vpn " + x.Name
	kind := CredToken // a private key or an auth key
	if x.User != "" {
		kind = CredPassword
	}
	if x.KeyRef != "" {
		pl.ref(x.KeyRef, &use{entry: e, field: "key_ref", kind: kind, apply: func(n string) { v.Credential = n }})
	}
	if x.PSKRef != "" {
		pl.ref(x.PSKRef, &use{entry: e, field: "psk_ref", kind: CredToken, apply: func(n string) { v.PSKCredential = n }})
	}
	if x.ConfigRef != "" {
		pl.ref(x.ConfigRef, &use{entry: e, field: "config_ref", kind: CredToken, apply: func(n string) { v.ConfigCredential = n }})
	}
}

// ref files u under the secret or the outside store ref names.
func (pl *planner) ref(ref string, u *use) {
	provider, item := parseRef(ref)
	switch provider {
	case "":
		pl.problem("%s: field %s is no reference", u.entry, u.field)
	case "secret":
		if _, ok := pl.snap.secrets[item]; !ok {
			pl.problem("%s: field %s names secret %s, which does not exist", u.entry, u.field, item)
			return
		}
		if item == ApprovalSeedName {
			pl.problem("%s: field %s names the approval code's seed", u.entry, u.field)
			return
		}
		pl.secrets[item] = append(pl.secrets[item], u)
	default:
		if g := pl.refGuard; g != nil && (provider == "env" || provider == "file") {
			if err := g(provider, item); err != nil {
				pl.problem("%s: field %s: %v", u.entry, u.field, err)
				return
			}
		}
		pl.outside = append(pl.outside, outsideUse{provider, item, u})
	}
}

// made makes a credential named <entry>-<what> once every kept name is
// known, and points the entry at it.
func (pl *planner) made(entry, base, what string, c *Credential, apply func(string)) {
	pl.deferred = append(pl.deferred, func() {
		c.Name = pl.creds.make(base, what)
		pl.p.creds = append(pl.p.creds, &credPlan{cred: c})
		pl.applied(entry, what, c.Name, apply)
	})
}

func (pl *planner) applied(entry, field, cred string, apply func(string)) {
	apply(cred)
	pl.p.report.Rewritten = append(pl.p.report.Rewritten, fieldChange{entry, field, cred})
}

// secretCredentials keeps each secret's name where at most one user logs
// in with it, and returns the work for those two or more users share.
func (pl *planner) secretCredentials() (split []func()) {
	for _, name := range slices.Sorted(maps.Keys(pl.snap.secrets)) {
		sec := pl.snap.secrets[name]
		if name == ApprovalSeedName {
			pl.p.seed = &sec
			pl.p.deletes = append(pl.p.deletes, sec.id)
			continue
		}
		pl.p.deletes = append(pl.p.deletes, sec.id)
		uses := pl.secrets[name]
		users := loginUsers(uses)
		if len(users) <= 1 {
			c := &Credential{Name: pl.creds.keep(name), Kind: kindOf(uses)}
			if len(users) == 1 {
				c.User = users[0]
			}
			pl.p.creds = append(pl.p.creds, &credPlan{cred: c, valueFrom: name})
			for _, u := range uses {
				pl.applied(u.entry, u.field, c.Name, u.apply)
			}
			continue
		}
		var others []*use
		for _, u := range uses {
			if !u.login {
				others = append(others, u)
			}
		}
		if len(others) > 0 {
			// the value keeps its name for the uses that are no login
			c := &Credential{Name: pl.creds.keep(name), Kind: CredToken}
			pl.p.creds = append(pl.p.creds, &credPlan{cred: c, valueFrom: name})
			for _, u := range others {
				pl.applied(u.entry, u.field, c.Name, u.apply)
			}
		}
		split = append(split, func() { pl.splitSecret(name, uses, users) })
	}
	return split
}

func (pl *planner) splitSecret(name string, uses []*use, users []string) {
	ch := nameChange{Kind: "credential", Old: name}
	for _, user := range users {
		c := &Credential{Name: pl.creds.make(name, user), Kind: CredPassword, User: user}
		pl.p.creds = append(pl.p.creds, &credPlan{cred: c, valueFrom: name})
		ch.New = append(ch.New, c.Name)
		for _, u := range uses {
			if u.login && u.user == user {
				pl.applied(u.entry, u.field, c.Name, u.apply)
			}
		}
	}
	slices.Sort(ch.New)
	pl.p.report.Names = append(pl.p.report.Names, ch)
}

func loginUsers(uses []*use) []string {
	var users []string
	for _, u := range uses {
		if u.login && !slices.Contains(users, u.user) {
			users = append(users, u.user)
		}
	}
	slices.Sort(users)
	return users
}

func kindOf(uses []*use) string {
	for _, u := range uses {
		if u.kind == CredPassword {
			return CredPassword
		}
	}
	return CredToken
}

// keyCredentials keeps each key's name where at most one user logs in
// with it (a clash with a secret's name takes <key>-key), and returns the
// work for keys two or more users share.
func (pl *planner) keyCredentials() (split []func()) {
	s := pl.snap.state
	for _, name := range slices.Sorted(maps.Keys(s.Keys)) {
		k := s.Keys[name]
		pl.p.deletes = append(pl.p.deletes, k.Rec.ID)
		uses := pl.keyUses[name]
		users := keyUsers(uses)
		if len(users) > 1 {
			split = append(split, func() { pl.splitKey(name, k, uses, users) })
			continue
		}
		c := pl.keyCred(k)
		if len(users) == 1 {
			c.User = users[0]
		}
		if pl.creds.taken[strings.ToLower(name)] {
			c.Name = pl.creds.make(name, "key")
			pl.p.report.Names = append(pl.p.report.Names, nameChange{Kind: "key", Old: name, New: []string{c.Name}})
		} else {
			c.Name = pl.creds.keep(name)
		}
		pl.p.creds = append(pl.p.creds, &credPlan{cred: c})
		for _, u := range uses {
			pl.applied(u.entry, "key", c.Name, u.apply)
		}
	}
	for _, f := range slices.Sorted(maps.Keys(pl.keyUses)) {
		if path, ok := strings.CutPrefix(f, "file:"); ok {
			uses := pl.keyUses[f]
			split = append(split, func() { pl.identity(path, uses) })
		}
	}
	return split
}

func (pl *planner) keyCred(k *Key) *Credential {
	return &Credential{Kind: CredKey, Key: &CredentialKey{
		Path: k.Path, Type: k.Type, PublicKey: k.PublicKey, Fingerprint: k.Fingerprint,
		Passphrase: pl.keyPass[k.Name], CertPath: k.CertPath, Managed: k.Managed,
	}, UpdatedAt: k.CreatedAt}
}

// splitKey gives each user of k a credential of its own; a key pair
// komando made is copied for every user after the first, so removing or
// rotating one copy leaves the others (Audit Q10).
func (pl *planner) splitKey(name string, k *Key, uses []keyUse, users []string) {
	ch := nameChange{Kind: "key", Old: name}
	for i, user := range users {
		c := pl.keyCred(k)
		c.Name, c.User = pl.creds.make(name, user), user
		cp := &credPlan{cred: c}
		if i > 0 && SealedKey(k) {
			cp.copyKeydata = strings.TrimPrefix(k.Path, sealedKeyPrefix)
		}
		pl.p.creds = append(pl.p.creds, cp)
		ch.New = append(ch.New, c.Name)
		for _, u := range uses {
			if u.user == user {
				pl.applied(u.entry, "key", c.Name, u.apply)
			}
		}
	}
	slices.Sort(ch.New)
	pl.p.report.Names = append(pl.p.report.Names, ch)
}

// identity is a key file a host names with no key record: one credential
// per user, named after the file.
func (pl *planner) identity(path string, uses []keyUse) {
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	users := keyUsers(uses)
	for _, user := range users {
		c := &Credential{Kind: CredKey, User: user, Key: &CredentialKey{Path: path}}
		if len(users) == 1 && madeNameRe.MatchString(base) && !pl.creds.taken[base] {
			c.Name = pl.creds.keep(base)
		} else {
			c.Name = pl.creds.make(base, user)
		}
		pl.p.creds = append(pl.p.creds, &credPlan{cred: c})
		for _, u := range uses {
			if u.user == user {
				pl.applied(u.entry, "identity", c.Name, u.apply)
			}
		}
	}
}

func keyUsers(uses []keyUse) []string {
	var users []string
	for _, u := range uses {
		if !slices.Contains(users, u.user) {
			users = append(users, u.user)
		}
	}
	slices.Sort(users)
	return users
}

// outsideCredentials makes a store per provider and a credential per field
// that named an outside value: <entry>-<field>, its item as written.
func (pl *planner) outsideCredentials() {
	for _, o := range pl.outside {
		store, ok := pl.stores[o.provider]
		if !ok {
			store = o.provider
			pl.stores[o.provider] = store
			pl.p.stores = append(pl.p.stores, &CredentialStore{Name: store, Provider: o.provider})
		}
		entry := o.u.entry[strings.Index(o.u.entry, " ")+1:]
		c := &Credential{Name: pl.creds.make(entry, fieldWord(o.u.field)), Kind: o.u.kind, Store: store, Item: o.item}
		if o.u.login {
			c.User = o.u.user
		}
		pl.p.creds = append(pl.p.creds, &credPlan{cred: c})
		pl.applied(o.u.entry, o.u.field, c.Name, o.u.apply)
	}
}

// fieldWord is the word a made credential name takes for a field.
func fieldWord(field string) string {
	switch field {
	case "password_ref", "key_ref":
		return "credential"
	case "sudo_ref":
		return "sudo"
	case "psk_ref":
		return "psk"
	case "config_ref":
		return "config"
	}
	return field
}

// groups makes one group record per group name, any case merged into the
// spelling that sorts first, with its members' record IDs.
func (pl *planner) groups() {
	s := pl.snap.state
	byLower := map[string]*Group{}
	spellings := map[string][]string{}
	add := func(id string, gs []string) {
		for _, g := range gs {
			l := strings.ToLower(g)
			if byLower[l] == nil {
				byLower[l] = &Group{Name: g}
			}
			if g < byLower[l].Name {
				byLower[l].Name = g
			}
			if !slices.Contains(spellings[l], g) {
				spellings[l] = append(spellings[l], g)
			}
			if !slices.Contains(byLower[l].Members, id) {
				byLower[l].Members = append(byLower[l].Members, id)
			}
		}
	}
	for _, h := range s.Hosts {
		add(h.Rec.ID, h.Groups)
	}
	for _, c := range s.Conns {
		add(c.Rec.ID, c.Groups)
	}
	for _, v := range s.Vpns {
		add(v.Rec.ID, v.Groups)
	}
	for _, l := range slices.Sorted(maps.Keys(byLower)) {
		g := byLower[l]
		slices.Sort(g.Members)
		pl.p.groups = append(pl.p.groups, g)
		if len(spellings[l]) > 1 {
			slices.Sort(spellings[l])
			pl.p.report.MergedGroups = append(pl.p.report.MergedGroups, strings.Join(spellings[l], ", ")+" into "+g.Name)
		}
	}
}

// snippets lists the snippets whose text names secret:, which komando
// never resolved there (Q4).
func (pl *planner) snippets() {
	for _, n := range slices.Sorted(maps.Keys(pl.snap.state.Snippets)) {
		if strings.Contains(pl.snap.state.Snippets[n].Command, "secret:") {
			pl.p.report.SnippetsWithOldRef = append(pl.p.report.SnippetsWithOldRef, n)
		}
	}
}

// expectCounts is how many records of each type the store holds after.
func (pl *planner) expectCounts() {
	p, before := pl.p, pl.snap.counts
	copies := 0
	for _, c := range p.creds {
		if c.copyKeydata != "" {
			copies++
		}
	}
	seed := 0
	if p.seed != nil {
		seed = 1
	}
	p.expect = map[string]int{
		KindHost: len(p.hosts), KindConn: len(p.conns) + len(p.swarms), KindVpn: len(p.vpns),
		KindCredential: len(p.creds), KindCredStore: len(p.stores), KindGroup: len(p.groups), KindApprovalSeed: seed,
		"secret": 0, KindKey: 0, keyDataType: before[keyDataType] + copies,
	}
	for _, typ := range carriedTypes {
		p.expect[typ] = before[typ]
	}
	for typ, n := range p.expect {
		p.report.Counts[typ] = [2]int{before[typ], n}
	}
}

// carriedTypes are records the migration seals again and leaves as they are.
var carriedTypes = []string{KindRecipe, kindSettings, vpnStateType, KindHostCA, KindPin, KindPinRevoked}
