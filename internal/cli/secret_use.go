package cli

import (
	"cmp"
	"fmt"
	"maps"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Where a secret may go when an AI agent asks (docs/features/safety.md).
// komando hides secret values from agents, but a command can still send one
// somewhere: into a file on a server ({{secret:NAME}}), into a command's
// environment (exec --env K=secret:NAME), as a database user's password, or
// as the password of a server or conn, which goes to its address on every
// connection. On a machine the agent controls, the value can come back in
// a form output masking does not know (reversed, hex, cut in pieces). So
// for an agent each of these needs a person's yes: --yes, then komando's
// window names the secret and the place. People and scripts are not asked.

// agentYes is a stop for AI agents only. An agent needs --yes and a
// person's "Allow once" in komando's window, which shows what, then why.
// One answer covers the command.
func agentYes(cl *call, code, msg, what string, why ...string) error {
	if !cl.isAgent() || cl.sess.SafetyApproved(what) {
		return nil
	}
	if cl.yesOKFor(what, why...) {
		cl.sess.ApproveSafety(what)
		return nil
	}
	return cl.policyStop(approvalErr(cl, code, msg))
}

// guardSecretUse stops an AI agent from sending the secrets refs (written
// as references: secret:NAME, env:VAR, vault:PATH#FIELD, ...) to where
// without a person's yes. A reserved secret never goes, for anyone.
func guardSecretUse(cl *call, refs []string, where string) error {
	refs = dedupe(refs)
	if len(refs) == 0 {
		return nil
	}
	if err := reservedRefs(refs); err != nil {
		return err
	}
	what := fmt.Sprintf("%s %s, sent to %s", nouns(len(refs), "the secret"), strings.Join(refs, ", "), where)
	return agentYes(cl, "SECRET_DESTINATION", "an AI agent asked to send "+what+"; that needs a person's yes", what)
}

// reservedRefs refuses a reference to a secret komando keeps for itself.
func reservedRefs(refs []string) error {
	for _, r := range refs {
		if name, ok := strings.CutPrefix(r, "secret:"); ok {
			if err := reservedSecret(name); err != nil {
				return err
			}
		}
	}
	return nil
}

// envSecretRefs are the values of a command's --env pairs that name a
// vault secret (komando reads them from the vault on the way out).
func envSecretRefs(env map[string]string) []string {
	var refs []string
	for _, k := range slices.Sorted(maps.Keys(env)) {
		if v := env[k]; strings.HasPrefix(v, "secret:") {
			refs = append(refs, v)
		}
	}
	return refs
}

// parseEnvTo is parseEnv for a command's --env on hosts: a value that names
// a vault secret goes into that command's environment there, so for an AI
// agent it needs a person's yes (guardSecretUse).
func parseEnvTo(cl *call, pairs []string, hosts []*store.Host) (map[string]string, error) {
	env, err := parseEnv(pairs)
	if err != nil {
		return nil, err
	}
	if err := guardHostEnv(cl, hosts, env); err != nil {
		return nil, err
	}
	refs := envSecretRefs(env)
	if len(refs) == 0 {
		return env, nil
	}
	return env, guardSecretUse(cl, refs, "the command's environment on "+strings.Join(hostNames(hosts), ", "))
}

// A server's own env (host edit --env K=secret:NAME) goes into each
// command komando runs there. In an AI agent's command the agent could
// read the value back in a form masking does not know (printenv K | rev),
// so for an agent those values are left out (sshx.HostSecretEnv) until a
// person says yes: the agent adds --yes to exec or job start, and
// komando's window names the secrets and the servers. Plain env values
// still go.

// hostEnvKey is the approval that lets host h's vault env go out in this call.
func hostEnvKey(h *store.Host) string { return "env of server " + h.Name }

// guardHostEnv: for an agent, the vault values of the hosts' own env go to
// this command only with --yes and a person's yes; without --yes they are
// left out, with a warning. env is the command's own --env: a name it sets
// is not the host's.
func guardHostEnv(cl *call, hosts []*store.Host, env map[string]string) error {
	if !cl.isAgent() {
		return nil
	}
	var refs, names []string
	for _, h := range hosts {
		var hr []string
		for _, k := range slices.Sorted(maps.Keys(h.Env)) {
			if _, own := env[k]; !own && strings.HasPrefix(h.Env[k], "secret:") {
				hr = append(hr, h.Env[k])
			}
		}
		if len(hr) > 0 {
			refs, names = append(refs, hr...), append(names, h.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	if !cl.yes() {
		cl.out.Warn(fmt.Sprintf("the server's env values from the vault (%s on %s) were left out: an AI agent's command gets them only with --yes and the user's yes", strings.Join(dedupe(refs), ", "), strings.Join(names, ", ")))
		return nil
	}
	if err := guardSecretUse(cl, refs, "the command's environment on "+strings.Join(names, ", ")+" (the server's own env)"); err != nil {
		return err
	}
	for _, h := range hosts {
		cl.sess.ApproveSafety(hostEnvKey(h))
	}
	return nil
}

// hostSecretEnv is sshx.HostSecretEnv: yes for people and scripts, and
// for an agent only after guardHostEnv's yes.
func hostSecretEnv(cl *call, c *sshx.Client) bool {
	return !cl.isAgent() || c.Host == nil || cl.sess.SafetyApproved(hostEnvKey(c.Host))
}

// secretPlace is what a server or conn sends on every connection: its
// references (refs) and the place they go to (dest).
type secretPlace struct {
	refs []string
	dest string
}

// loginAskRef stands among a server's references for the password a
// person types for a login-ask server (host add --login ask): komando
// never stores it, but it goes to the server's address on every
// connection, as a stored one does.
const loginAskRef = "the password a person types for it (login ask)"

// hostPlace: a server's password (stored, or typed by a person: login
// ask) and sudo password, and its environment values that name a vault
// secret, go to its user at its address, by the way there and the
// transport (WinRM sends the password as its TLS setting allows).
func hostPlace(h *store.Host) secretPlace {
	refs := append([]string{h.PasswordRef, h.SudoRef}, envSecretRefs(h.Env)...)
	if h.AskLogin() {
		refs = append(refs, loginAskRef)
	}
	dest := net.JoinHostPort(inventory.NormAddr(h.Address), strconv.Itoa(h.EffectivePort()))
	if h.User != "" {
		dest = h.User + "@" + dest
	}
	if h.WinRM() {
		dest = "WinRM " + dest
		if o := h.WinRMOpts; o != nil {
			var set []string
			for _, kv := range [][2]string{{"tls", o.TLS}, {"ca", o.CA}, {"auth", o.Auth}} {
				if kv[1] != "" {
					set = append(set, kv[0]+"="+kv[1])
				}
			}
			if len(set) > 0 {
				dest += " (" + strings.Join(set, ", ") + ")"
			}
		}
	}
	if h.Via != "" {
		dest += " via " + h.Via
	}
	if h.ProxyCommand != "" {
		dest += " through `" + h.ProxyCommand + "`"
	}
	return secretPlace{dedupe(refs), dest}
}

// connPlace: a conn's password and the secrets its URL names go to every
// place its driver logs in at (connPlaces), with the URL's settings that
// decide where and how (connURLSettings), by the way there. A --via path
// counts: the addresses are looked up at its end.
func connPlace(c *store.Conn) secretPlace {
	refs := []string{c.PasswordRef}
	if c.AskLogin() {
		refs = append(refs, loginAskRef)
	}
	for _, r := range inventory.URLSecretRefs(c.URL) {
		refs = append(refs, "secret:"+r.Name)
	}
	dest := strings.Join(connPlaces(c), ",")
	if set := connURLSettings(c.URL); len(set) > 0 {
		dest += " (" + strings.Join(set, "&") + ")"
	}
	if c.Via != "" {
		dest += " via " + c.Via
	}
	return secretPlace{dedupe(refs), dest}
}

// newSends says which references an entry sends to a new place, as a line
// for the approval window, or "": all of them for a new entry (old nil) or
// one that now goes somewhere else, else only those it did not have.
func newSends(label string, old *secretPlace, now secretPlace) (string, error) {
	if err := reservedRefs(now.refs); err != nil {
		return "", err
	}
	send := now.refs
	if old != nil && old.dest == now.dest {
		send = nil
		for _, r := range now.refs {
			if !slices.Contains(old.refs, r) {
				send = append(send, r)
			}
		}
	}
	if len(send) == 0 {
		return "", nil
	}
	return fmt.Sprintf("%s to %s (%s)", strings.Join(send, ", "), now.dest, label), nil
}

// weakTLS lists the settings of a conn URL that turn the network
// protection of a connection down, as the URL writes them: no encryption,
// or no check of the server's certificate. A conn edit also counts a TLS
// scheme or endpoint it drops (old is the URL before; "" for a new conn).
// What a URL leaves out is komando's default, and `komando doctor` reports
// on it; this is about what someone writes in.
func weakTLS(oldURL, newURL string) []string {
	t, err := driver.Parse(newURL)
	if err != nil {
		return nil
	}
	var w []string
	q := url.Values{}
	if u, err := url.Parse(newURL); err == nil {
		q = u.Query()
	}
	switch t.Kind.Name {
	case "postgres":
		if m := q.Get("sslmode"); m == "disable" || m == "allow" || m == "prefer" {
			w = append(w, "sslmode="+m+" (may travel unencrypted)")
		}
	case "mysql":
		switch strings.ToLower(t.TLS) {
		case "false", "preferred":
			w = append(w, "tls="+t.TLS+" (may travel unencrypted)")
		case "skip-verify":
			w = append(w, "tls=skip-verify (the certificate is not checked)")
		}
	case "sqlserver":
		o, _ := driver.ParseSQLServerOptions(q)
		switch {
		case o.Encrypt == "false" || o.Encrypt == "disable":
			w = append(w, "encrypt="+o.Encrypt+" (travels unencrypted)")
		case o.SkipVerify:
			w = append(w, "tls=skip-verify (the certificate is not checked)")
		}
	case "oracle", "clickhouse":
		switch t.TLS {
		case "false":
			w = append(w, "tls=false (travels without TLS)")
		case "skip-verify":
			w = append(w, "tls=skip-verify (the certificate is not checked)")
		}
	case "registry", "ftps":
		switch t.TLS {
		case "false":
			w = append(w, "tls=false (travels unencrypted)")
		case "skip-verify":
			w = append(w, "tls=skip-verify (the certificate is not checked)")
		}
	case "bigquery":
		if !t.Secure {
			w = append(w, "an http:// endpoint (travels unencrypted, the Google token too)")
		}
	case "ftp":
		w = append(w, "insecure=1 (travels unencrypted, passwords too)")
	case "kafka", "rabbitmq", "nats", "sqs", "pubsub":
		if t.TLS == "skip-verify" {
			w = append(w, "tls=skip-verify (the certificate is not checked)")
		}
		if !t.Secure && q.Get("insecure") == "1" {
			w = append(w, "insecure=1 (travels unencrypted, passwords too)")
		}
	case "redis", "memcached", "s3", "gcs", "azblob":
		if !t.Secure && q.Get("insecure") == "1" {
			w = append(w, "insecure=1 (travels unencrypted, passwords too)")
		}
	}
	if old, err := driver.Parse(oldURL); err == nil && old.Kind.Name == t.Kind.Name && old.Secure && !t.Secure {
		w = append(w, "no TLS any more (travels unencrypted)")
	}
	if oldURL != "" { // only what the edit adds
		had := weakTLS("", oldURL)
		w = slices.DeleteFunc(w, func(s string) bool { return slices.Contains(had, s) })
	}
	return w
}

// guardSends asks once for every secret a change sends to a new place
// (sends) and every setting that turns a conn's network protection down
// (weak): an AI agent needs a person's yes for them. why says what else the
// window's answer covers (a change to a protected server).
func guardSends(cl *call, sends, weak []string, why ...string) error {
	empty := func(s string) bool { return s == "" }
	sends, weak = slices.DeleteFunc(sends, empty), slices.DeleteFunc(weak, empty)
	var parts []string
	if len(sends) > 0 {
		parts = append(parts, "sends "+strings.Join(sends, "; "))
	}
	if len(weak) > 0 {
		parts = append(parts, "turns network protection down: "+strings.Join(weak, "; "))
	}
	if len(parts) == 0 {
		return nil
	}
	what := "this change " + strings.Join(parts, "; and it ")
	code := "SECRET_DESTINATION"
	if len(sends) == 0 {
		code = "SAFETY_SETTING"
	}
	return agentYes(cl, code, "an AI agent asked for a change that "+strings.TrimPrefix(what, "this change ")+"; that needs a person's yes", what, why...)
}

// guardConnSends is guardSends for a conn an add or edit leaves as now
// (old is nil for a new one).
func guardConnSends(cl *call, old, now *store.Conn, why ...string) error {
	if what := connPlaceChanges(old, now); cl.isAgent() && len(what) > 0 {
		return loginPlaceStop(cl, what)
	}
	var before *secretPlace
	oldURL := ""
	if old != nil {
		p := connPlace(old)
		if old.PasswordRef != "" {
			p.refs = append(p.refs, loginAskRef) // as for a server (guardHostSends)
		}
		before, oldURL = &p, old.URL
	}
	line, err := newSends("conn "+now.Name, before, connPlace(now))
	if err != nil {
		return err
	}
	var weak []string
	for _, w := range weakTLS(oldURL, now.URL) {
		weak = append(weak, now.Name+": "+w)
	}
	return guardSends(cl, []string{line}, weak, why...)
}

// guardHostSends is guardSends for servers an add, edit or import leaves
// as now; olds holds each one's settings before, by name (none: new). s
// is the inventory: where a typed password goes stops an agent first
// (loginPlaceStop), and what reaches its server through one of them
// counts too (behindSends).
func guardHostSends(cl *call, s *store.State, now []*store.Host, olds map[string]*store.Host, why ...string) error {
	if what := hostPlaceChanges(s, now, olds); cl.isAgent() && len(what) > 0 {
		return loginPlaceStop(cl, what) // no yes lifts it, so no yes to ask for
	}
	lines, err := behindSends(s, now, olds)
	if err != nil {
		return err
	}
	var weak []string
	for _, h := range now {
		var before *secretPlace
		if o, ok := olds[h.Name]; ok && o != nil {
			p := hostPlace(o)
			if o.PasswordRef != "" {
				// a stored password went there already: a person typing
				// it there instead (login ask) sends nothing new
				p.refs = append(p.refs, loginAskRef)
			}
			before = &p
		}
		line, err := newSends("server "+h.Name, before, hostPlace(h))
		if err != nil {
			return err
		}
		lines = append(lines, line)
		weak = append(weak, winrmWeak(olds[h.Name], h)...)
	}
	return guardSends(cl, lines, weak, why...)
}

// behindSends lists what the servers and conns behind a moved hop send by
// the new way: a server in now whose place changed (its address, port,
// --via or proxy command) takes with it every other server and conn whose
// --via names it, and their passwords travel that way on the next
// connection (a conn's database password is typed into the last hop).
func behindSends(st *store.State, now []*store.Host, olds map[string]*store.Host) ([]string, error) {
	if st == nil {
		return nil, nil
	}
	cur := map[string]*store.Host{} // every server as the edit leaves it
	for n, h := range st.Hosts {
		cur[n] = h
	}
	ownLine := map[string]bool{} // a server of the edit whose own place changed: its own line covers it
	moved := map[string]string{} // hop name: where it is now
	for _, h := range now {
		cur[h.Name] = h
		if o := olds[h.Name]; o != nil && hostPlace(o).dest != hostPlace(h).dest {
			moved[h.Name] = hostPlace(h).dest
			ownLine[h.Name] = true
		}
	}
	if len(moved) == 0 {
		return nil, nil
	}
	// a server reached through a moved hop has moved too: what lies behind
	// it goes the new way (mid --via jump, then conn --via mid)
	for changed := true; changed; {
		changed = false
		for n, h := range cur {
			if _, ok := moved[n]; ok {
				continue
			}
			for _, step := range inventory.ViaChain(h.Via) {
				if to, ok := moved[step]; ok {
					moved[n] = hostPlace(h).dest + " (by way of " + step + ", now at " + to + ")"
					changed = true
					break
				}
			}
		}
	}
	var lines []string
	add := func(label, via string, p secretPlace) error {
		for _, step := range inventory.ViaChain(via) {
			to, ok := moved[step]
			if !ok || len(p.refs) == 0 {
				continue
			}
			if err := reservedRefs(p.refs); err != nil {
				return err
			}
			lines = append(lines, fmt.Sprintf("%s to %s (%s), by way of %s, now at %s", strings.Join(p.refs, ", "), p.dest, label, step, to))
			break
		}
		return nil
	}
	for _, n := range slices.Sorted(maps.Keys(cur)) {
		if ownLine[n] {
			continue
		}
		if err := add("server "+n, cur[n].Via, hostPlace(cur[n])); err != nil {
			return nil, err
		}
	}
	for _, n := range slices.Sorted(maps.Keys(st.Conns)) {
		c := st.Conns[n]
		if err := add("conn "+n, c.Via, connPlace(c)); err != nil {
			return nil, err
		}
	}
	return lines, nil
}

// winrmWeak is what now's WinRM settings give up that old's did not: the
// server's certificate is not checked (tls=skip-verify), nothing is
// encrypted (tls=off), the password itself is sent (auth=basic), or a
// server komando knew is checked against another CA certificate (?ca=).
func winrmWeak(old, now *store.Host) []string {
	if !now.WinRM() || now.WinRMOpts == nil {
		return nil
	}
	var was store.WinRMOpts
	if old.WinRM() && old.WinRMOpts != nil {
		was = *old.WinRMOpts
	}
	o := now.WinRMOpts
	var w []string
	if o.TLS != was.TLS {
		switch o.TLS {
		case "skip-verify":
			w = append(w, "server "+now.Name+": WinRM tls=skip-verify (the server's certificate is not checked)")
		case "off":
			w = append(w, "server "+now.Name+": WinRM tls=off (commands, files and the login travel unencrypted)")
		}
	}
	if o.Auth == "basic" && was.Auth != "basic" {
		w = append(w, "server "+now.Name+": WinRM auth=basic (the password itself is sent)")
	}
	// another CA lets another server pass as this one; a new server's own
	// CA, and going back to the system's CAs only, give nothing up
	if old != nil && o.CA != "" && o.CA != was.CA {
		w = append(w, "server "+now.Name+": WinRM is checked against another CA certificate ("+o.CA+")")
	}
	return w
}

// vpnPlace: a VPN's login (its password or auth key, and its pre-shared
// key) goes to its server each time it connects. A WireGuard VPN's keys
// come from its own config file, and a system VPN logs in with this
// computer's settings, so neither sends a reference. servers names an
// OpenVPN VPN's servers (its profile's remote lines), when known.
func vpnPlace(v *store.Vpn, servers string) secretPlace {
	var dest string
	switch v.Kind {
	case "wireguard", "system":
		return secretPlace{}
	case "socks", "proxy":
		dest = v.Address
	case "tailscale":
		dest = cmp.Or(v.Server, "the Tailscale login server")
	case "l2tp", "ipsec", "ikev2":
		dest = v.Server
	case "openvpn":
		dest = cmp.Or(servers, "the servers in its .ovpn profile")
	default: // the SSL VPNs log in at their portal
		dest = v.Portal
	}
	return secretPlace{dedupe([]string{v.KeyRef, v.PSKRef}), dest}
}

// guardTypedLoginMove: a VPN without a stored login gets the one a person
// types (or gives in the browser) at `vpn up`, and that login goes where
// the VPN points. An AI agent that moves it elsewhere (--portal,
// --server, a new OpenVPN profile) would get the person's next login, so
// that is for a person only, as for a server's typed login.
func guardTypedLoginMove(cl *call, old, now *store.Vpn, servers string) error {
	typed := old != nil && (old.KeyRef == "" || old.MFA) // --mfa: a person types the code even with a stored password
	if !typed || !cl.isAgent() || old.Kind == "socks" || old.Kind == "proxy" || vpnPlace(old, "").dest == "" {
		return nil
	}
	moved := vpnPlace(old, "").dest != vpnPlace(now, "").dest || old.Kind == "openvpn" && servers != ""
	if !moved {
		return nil
	}
	return out.Errf(out.ExitPolicy, "NEEDS_PERSON", "ask the user to run this `komando vpn edit` in their own terminal",
		"vpn %s gets the login a person types at `vpn up`; an AI agent may not change where it goes", now.Name).NoFlag()
}

// guardVpnSends is guardSends for a VPN an add or edit leaves as now; old
// is the VPN before (nil: a new one). servers is as for vpnPlace: an
// OpenVPN VPN added again with a new profile may have new servers.
// replaced: an add --overwrite or an import makes the VPN anew, so it
// counts as changed even with the same fields (its profile or key secret
// may be new).
func guardVpnSends(cl *call, s *store.State, old, now *store.Vpn, servers string, replaced bool) error {
	if old != nil && cl.isAgent() {
		if what := vpnPlaceChanges(s, now.Name, replaced || vpnWayChanged(old, now)); len(what) > 0 {
			return loginPlaceStop(cl, what)
		}
	}
	var before *secretPlace
	if old != nil {
		p := vpnPlace(old, "")
		before = &p
	}
	if err := guardTypedLoginMove(cl, old, now, servers); err != nil {
		return err
	}
	line, err := newSends("vpn "+now.Name, before, vpnPlace(now, servers))
	if err != nil {
		return err
	}
	lines := []string{line}
	if old != nil && vpnWayChanged(old, now) {
		behind, err := vpnBehindSends(s, now.Name)
		if err != nil {
			return err
		}
		lines = append(lines, behind...)
	}
	// another CA lets another server pass as this one and get its login
	var weak []string
	if old != nil && old.CA != "" && now.CA != old.CA {
		weak = append(weak, "vpn "+now.Name+" no longer checks its server against the CA certificate it had")
	}
	return guardSends(cl, lines, weak)
}

// vpnBehindSends lists the stored passwords and secrets that travel
// through VPN name (C111): every server and conn whose --via way
// (inventory.WaySteps: jump servers' own --via too) goes through it sends them by
// the VPN's new way, as behindSends has it for a moved jump server. A
// server with only a key sends no secret, so it is not named; a login-ask
// one is stopped before (vpnPlaceChanges).
func vpnBehindSends(st *store.State, name string) ([]string, error) {
	var lines []string
	add := func(label, via string, p secretPlace) error {
		if len(p.refs) == 0 || !slices.Contains(inventory.WaySteps(st, via, map[string]bool{}), name) {
			return nil
		}
		if err := reservedRefs(p.refs); err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s to %s (%s), by way of vpn %s, which moves", strings.Join(p.refs, ", "), p.dest, label, name))
		return nil
	}
	for _, n := range slices.Sorted(maps.Keys(st.Hosts)) {
		if err := add("server "+n, st.Hosts[n].Via, hostPlace(st.Hosts[n])); err != nil {
			return nil, err
		}
	}
	for _, n := range slices.Sorted(maps.Keys(st.Conns)) {
		if err := add("conn "+n, st.Conns[n].Via, connPlace(st.Conns[n])); err != nil {
			return nil, err
		}
	}
	return lines, nil
}

// guardTrustSecret stops an AI agent from giving the vault secret name
// the value now when that value decides whom komando trusts, not only how
// it logs in: an OpenVPN VPN's profile (its servers and CA; the VPN's
// login goes there) and the CA certificate a WinRM server or a conn is
// checked against (?ca=secret:NAME). had is false when the secret is not
// there yet: making a CA an entry already names counts too. A person's
// yes (--yes, then the window) lets it through, as for vpn edit, host
// edit and conn edit making the same change.
//
// nowFrom names where the new value comes from when the agent may not read
// it (secret cp/rename copies another secret): the window then names that
// secret, never the servers in it.
func guardTrustSecret(cl *call, st *store.State, name, old string, had bool, now, nowFrom string) error {
	if !cl.isAgent() || (had && old == now) {
		return nil
	}
	ref := "secret:" + name
	var sends, weak []string
	for _, n := range slices.Sorted(maps.Keys(st.Vpns)) {
		v := st.Vpns[n]
		if v.Kind != "openvpn" || v.ConfigRef != ref {
			continue
		}
		// a login a person types at `vpn up` goes wherever the profile
		// points: moving it is for a person only, as vpn edit has it
		if v.KeyRef == "" || v.MFA {
			return out.Errf(out.ExitPolicy, "NEEDS_PERSON", "ask the user to replace secret "+name+" in their own terminal",
				"secret %s is the profile of vpn %s, which gets the login a person types at `vpn up`; an AI agent may not change where it goes", name, v.Name).NoFlag()
		}
		servers, err := ovpnRemotes(now)
		if err != nil || servers == "" {
			servers = "the servers in the new profile"
		}
		if nowFrom != "" {
			servers = "the servers in the profile " + nowFrom + " holds"
		}
		before := vpnPlace(v, "")
		line, err := newSends("vpn "+v.Name, &before, vpnPlace(v, servers))
		if err != nil {
			return err
		}
		behind, err := vpnBehindSends(st, v.Name)
		if err != nil {
			return err
		}
		sends = append(append(sends, line), behind...)
		weak = append(weak, "vpn "+v.Name+" gets another OpenVPN profile: other servers, checked against another CA certificate, may stand in for it")
	}
	for _, n := range slices.Sorted(maps.Keys(st.Hosts)) {
		h := st.Hosts[n]
		if h.WinRMOpts != nil && h.WinRMOpts.CA == ref {
			weak = append(weak, "server "+h.Name+" is checked against another CA certificate (WinRM): another server may pass as it and get its login")
		}
	}
	for _, n := range slices.Sorted(maps.Keys(st.Conns)) {
		c := st.Conns[n]
		for _, r := range inventory.URLSecretRefs(c.URL) {
			if r.Name == name && caOption(r.Option) {
				weak = append(weak, "conn "+c.Name+" is checked against another CA certificate: another server may pass as it and get its login")
				break
			}
		}
	}
	return guardSends(cl, sends, weak)
}

// guardImportedTrust runs secret set's trust check (guardTrustSecret) for
// every vault secret an import replaces or makes; guardImportSecrets has
// the protected-entry and login-place checks.
func guardImportedTrust(cl *call, st *store.State, values map[string]string) error {
	for _, name := range slices.Sorted(maps.Keys(values)) {
		old, err := vault.Get(name)
		if err := guardTrustSecret(cl, st, name, old, err == nil, values[name], ""); err != nil {
			return err
		}
	}
	return nil
}

// caOption reports whether a conn URL option names a CA certificate.
func caOption(opt string) bool {
	opt = strings.ToLower(opt)
	return opt == "ca" || strings.HasSuffix(opt, "-ca") || strings.HasSuffix(opt, "_ca") || strings.Contains(opt, "rootcert")
}
