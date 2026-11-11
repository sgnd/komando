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
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
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
func agentYes(code, msg, what string, why ...string) error {
	if !isAgent() || sess.SafetyApproved(what) {
		return nil
	}
	if g.yes && personAllowsFor("--yes", what, why...) {
		sess.ApproveSafety(what)
		return nil
	}
	return policyStop(out.Errf(out.ExitPolicy, code, "re-run with --yes after the user agrees", "%s", msg))
}

// guardSecretUse stops an AI agent from sending the secrets refs (written
// as references: secret:NAME, env:VAR, vault:PATH#FIELD, ...) to where
// without a person's yes. A reserved secret never goes, for anyone.
func guardSecretUse(refs []string, where string) error {
	refs = dedupe(refs)
	if len(refs) == 0 {
		return nil
	}
	if err := reservedRefs(refs); err != nil {
		return err
	}
	what := fmt.Sprintf("%s %s, sent to %s", nouns(len(refs), "the secret"), strings.Join(refs, ", "), where)
	return agentYes("SECRET_DESTINATION", "an AI agent asked to send "+what+"; that needs a person's yes", what)
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
func parseEnvTo(pairs []string, hosts []*store.Host) (map[string]string, error) {
	env, err := parseEnv(pairs)
	if err != nil {
		return nil, err
	}
	refs := envSecretRefs(env)
	if len(refs) == 0 {
		return env, nil
	}
	return env, guardSecretUse(refs, "the command's environment on "+strings.Join(hostNames(hosts), ", "))
}

// secretPlace is what a server or conn sends on every connection: its
// references (refs) and the place they go to (dest).
type secretPlace struct {
	refs []string
	dest string
}

// hostPlace: a server's password and sudo password, and its environment
// values that name a vault secret, go to its address, by the way there.
func hostPlace(h *store.Host) secretPlace {
	refs := append([]string{h.PasswordRef, h.SudoRef}, envSecretRefs(h.Env)...)
	dest := net.JoinHostPort(normAddr(h.Address), strconv.Itoa(h.EffectivePort()))
	if h.Via != "" {
		dest += " via " + h.Via
	}
	if h.ProxyCommand != "" {
		dest += " through `" + h.ProxyCommand + "`"
	}
	return secretPlace{dedupe(refs), dest}
}

// connPlace: a conn's password and the secrets its URL names go to its
// address (where ?resolve= points it), by the way there. A --via path
// counts: the address is looked up at its end.
func connPlace(c *store.Conn) secretPlace {
	refs := []string{c.PasswordRef}
	for _, r := range urlSecretRefs(c.URL) {
		refs = append(refs, "secret:"+r.Name)
	}
	dest := c.URL
	if t, err := driver.Parse(c.URL); err == nil {
		dest = t.Address
		if len(t.Brokers) > 1 { // kafka: the login goes to every broker
			dest = strings.Join(t.Brokers, ",")
		}
		if t.Kind.File {
			dest = t.Path
		}
		if t.Resolve != "" && t.Resolve != t.Address {
			dest += " (at " + t.Resolve + ")"
		}
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
	case "redis", "memcached":
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
func guardSends(sends, weak []string, why ...string) error {
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
	return agentYes(code, "an AI agent asked for a change that "+strings.TrimPrefix(what, "this change ")+"; that needs a person's yes", what, why...)
}

// guardConnSends is guardSends for a conn an add or edit leaves as now
// (old is nil for a new one).
func guardConnSends(old, now *store.Conn, why ...string) error {
	var before *secretPlace
	oldURL := ""
	if old != nil {
		p := connPlace(old)
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
	return guardSends([]string{line}, weak, why...)
}

// guardHostSends is guardSends for servers an add, edit or import leaves
// as now; olds holds each one's settings before, by name (none: new).
func guardHostSends(now []*store.Host, olds map[string]*store.Host, why ...string) error {
	var lines []string
	for _, h := range now {
		var before *secretPlace
		if o, ok := olds[h.Name]; ok && o != nil {
			p := hostPlace(o)
			before = &p
		}
		line, err := newSends("server "+h.Name, before, hostPlace(h))
		if err != nil {
			return err
		}
		lines = append(lines, line)
	}
	return guardSends(lines, nil, why...)
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

// guardVpnSends is guardSends for a VPN an add or edit leaves as now; old
// is the VPN before (nil: a new one). servers is as for vpnPlace: an
// OpenVPN VPN added again with a new profile may have new servers.
func guardVpnSends(old, now *store.Vpn, servers string) error {
	var before *secretPlace
	if old != nil {
		p := vpnPlace(old, "")
		before = &p
	}
	line, err := newSends("vpn "+now.Name, before, vpnPlace(now, servers))
	if err != nil {
		return err
	}
	return guardSends([]string{line}, nil)
}
