package cli

import (
	"errors"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// securityCheck is one line of `komando doctor` about security. A warning
// does not fail doctor; a failure does.
type securityCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Warning bool   `json:"warning,omitempty"`
	Detail  string `json:"detail"`
}

func securityChecks(st *store.State) []securityCheck {
	var cs []securityCheck
	add := func(name string, ok, warn bool, detail string) {
		cs = append(cs, securityCheck{Name: "security:" + name, OK: ok || warn, Warning: warn && !ok, Detail: detail})
	}

	// komando's folder and files: this user only (ASVS 14.1, CWE-276)
	loose := looseFiles()
	add("permissions", len(loose) == 0, false, map[bool]string{true: store.Home() + " is private to you",
		false: "others can read " + strings.Join(loose, ", ") + ": run chmod 700 " + store.Home() + " && chmod 600 on the files"}[len(loose) == 0])

	if s, err := vault.Check(); err != nil {
		add("vault", false, false, err.Error())
	} else if !s.NoVaultYet {
		switch {
		case s.Mode == "keyfile":
			add("vault", false, true, "the vault key is a file next to the vault: anyone with a copy of "+store.Home()+" (a backup) can open it. Move it into the OS keychain with `komando secret keychain`, or give the vault a passphrase of 15+ characters with `komando secret passphrase`")
		case s.Mode == "keychain":
			add("vault", true, false, "AES-256-GCM, the key in the OS keychain")
		case s.Mode == "passphrase" && vault.Passphrase() == "":
			add("vault", false, true, "the vault has a passphrase, but KOMANDO_VAULT_PASS is not set here, so komando cannot open it")
		case s.ShortPass:
			add("vault", false, true, "KOMANDO_VAULT_PASS is shorter than 15 characters (NIST SP 800-63B); change it with `komando secret passphrase`")
		case s.OldKDF:
			add("vault", false, true, "the vault uses an older scrypt cost; it moves to the stronger one when you next change a secret or run `komando secret passphrase`")
		default:
			add("vault", true, false, "AES-256-GCM, passphrase with scrypt N=2^17")
		}
	}
	vaultKeyChecks(add)

	if st.Settings.Audit {
		r, err := verifyAudit()
		switch {
		case err != nil:
			add("audit_chain", false, false, err.Error())
		case !r.OK:
			add("audit_chain", false, false, "the audit log was changed outside komando at line "+strconv.Itoa(r.FirstBroken)+" (komando audit verify)")
		default:
			add("audit_chain", true, false, strconv.Itoa(r.Entries)+" entries, chain intact")
		}
	} else {
		add("audit", false, true, "the audit log is off: `komando config set audit on`")
	}
	if st.Settings.HostKeyPolicy == "off" {
		add("host_keys", false, true, "server identity checks are off: `komando config set host_key_policy accept-new`")
	}
	bad := policy.Invalid(st.Settings.ExtraDenyPattern)
	for _, i := range slices.Sorted(maps.Keys(bad)) {
		add("deny_rule:custom-"+strconv.Itoa(i), false, false, bad[i])
	}
	for _, c := range st.SortedConns() {
		if why := plainConn(c); why != "" {
			add("conn:"+c.Name, false, true, why+" (OWASP ASVS 9.2.2)")
		}
	}
	for _, v := range st.SortedVpns() {
		if why := weakVpn(v); why != "" {
			add("vpn:"+v.Name, false, true, why)
		}
	}
	return cs
}

// weakVpn says why a VPN's login is weaker than it looks, or "".
func weakVpn(v *store.Vpn) string {
	var why []string
	if v.Kind == "ipsec" && v.LocalID != "" {
		// komando's built-in client and the OS's both use aggressive mode here
		why = append(why, "Cisco-style IPsec with a group name logs in with IKEv1 aggressive mode: anyone who sees the login can guess the group's pre-shared key offline, and with it pretend to be the server and collect your password; use IKEv2 (kind ikev2) if the server offers it")
	}
	if v.LegacyCrypto {
		why = append(why, "legacy crypto is allowed (3DES, DH groups 2 and 5, which a well-funded attacker can break); once the server offers AES and DH group 14: komando vpn edit "+v.Name+" --legacy-crypto=false")
	}
	if v.AllowPAP {
		why = append(why, "PAP is allowed, which hands the server your password itself; once it offers MS-CHAPv2: komando vpn edit "+v.Name+" --allow-pap=false")
	}
	return strings.Join(why, "; ")
}

// looseFiles lists komando files that other users on this computer can read.
func looseFiles() []string {
	var loose []string
	check := func(p string) {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm()&0o077 != 0 {
			loose = append(loose, p)
		}
	}
	check(store.Home())
	for _, f := range []string{"state.json", "vault.json", "vault.key", "audit.jsonl", "known_hosts"} {
		check(store.Path(f))
	}
	keys, _ := filepath.Glob(store.Path("keys", "*"))
	for _, k := range keys {
		if !strings.HasSuffix(k, ".pub") {
			check(k)
		}
	}
	return loose
}

// vaultKeyChecks: KOMANDO_VAULT_PASS opens a passphrase vault (a changed
// one locks every secret away), and no vault.key the vault does not use is
// left behind (it opens old copies of the vault).
func vaultKeyChecks(add func(name string, ok, warn bool, detail string)) {
	if s, err := vault.Check(); err == nil && s.Mode == "passphrase" && vault.Passphrase() != "" {
		if err := vault.Opens(""); errors.Is(err, vault.ErrWrongKey) {
			add("vault_key", false, false, "KOMANDO_VAULT_PASS does not open the vault. If you changed it, run `komando secret passphrase` in your terminal: it asks for the old passphrase and re-encrypts every secret under the new one")
		}
	}
	if kp := vault.LeftoverKeyFile(); kp != "" {
		add("vault_key_file", false, true, kp+" is left from an earlier key: the vault does not use it, but it opens old copies of the vault (a backup). Remove it")
	}
}

// plainConn says why a conn's traffic may be readable or forged on the
// network, or "". Local addresses and conns reached through an SSH tunnel
// (--via) are left out.
func plainConn(c *store.Conn) string {
	t, err := driver.Parse(c.URL)
	if err != nil || t.Kind.File {
		return ""
	}
	if t.Kind.Name == "registry" && t.TLS == "skip-verify" {
		// flagged with --via too: the tunnel ends at the server on the
		// path, and the registry is often further away (a public address)
		return "encrypted, but the registry's certificate is not checked: store its CA with `komando secret set NAME < ca.crt` and use ?ca=secret:NAME instead of ?tls=skip-verify"
	}
	if !overNetwork(c, t) {
		return ""
	}
	q := url.Values{}
	if u, err := url.Parse(c.URL); err == nil {
		q = u.Query()
	}
	// what to run to fix it: the same URL with verified TLS
	fix := func(why string) string {
		if u := verifiedTLSURL(c.URL, t.Kind.Name); u != "" {
			why += "; to fix it, if the server has TLS: komando conn edit " + c.Name + " --url '" + u + "', or reach it --via an SSH server"
		}
		return why
	}
	const notChecked = "encrypted, but the server's certificate is not checked: anyone on the network path can pretend to be the server and get the password"
	switch t.Kind.Name {
	case "postgres":
		switch q.Get("sslmode") {
		case "verify-full", "verify-ca":
			return ""
		case "require":
			return fix(notChecked)
		case "disable":
			return fix("travels unencrypted (sslmode=disable): anyone on the network path can read the password and the data")
		}
		// libpq's "prefer": TLS without a certificate check, and none at all when the other end says no
		return fix("may travel unencrypted (no sslmode): komando uses TLS when the server offers it, but does not check its certificate and goes on without TLS when told to, so anyone on the network path can read the data and get the password")
	case "mysql":
		switch strings.ToLower(t.TLS) {
		case "true":
			return ""
		case "skip-verify":
			return fix(notChecked)
		case "preferred":
			return fix("may travel unencrypted (tls=preferred): the certificate is not checked, and without TLS on the server the traffic is plain")
		}
		// MySQL 8 (caching_sha2_password) then encrypts the password with a
		// key it sends over the same plain connection
		return fix("travels unencrypted (no tls=true): anyone on the network path can read the data, and can swap the key the MySQL 8 login encrypts the password with, and so read the password")
	case "redis":
		if !t.Secure {
			return fix("travels unencrypted: anyone on the network path can read the password and the data")
		}
	case "memcached":
		if !t.Secure {
			return fix("travels unencrypted: anyone on the network path can read the password and the data")
		}
	case "kafka", "rabbitmq", "nats":
		if t.TLS == "skip-verify" {
			return fix(notChecked)
		}
		if !t.Secure {
			return fix("travels unencrypted: anyone on the network path can read the login and the messages")
		}
	case "ftp":
		return "travels unencrypted (passwords too): use ftps:// or sftp://"
	case "ftps":
		if q.Get("tls") == "skip-verify" {
			return "encrypted, but the server's certificate is not checked"
		}
	case "s3", "sqs":
		if !t.Secure {
			return "travels unencrypted: use an https endpoint"
		}
	case "registry":
		if q.Get("tls") == "false" {
			return "travels unencrypted: drop ?tls=false"
		}
	}
	return ""
}

// overNetwork reports whether c's traffic crosses a network komando does
// not protect: not through an SSH tunnel or VPN (--via), and not only to
// this computer. Every server the URL names counts (kafka:// and nats://
// list several), not just the first.
func overNetwork(c *store.Conn, t driver.Target) bool {
	if c.Via != "" {
		return false
	}
	for _, addr := range append([]string{t.Address}, t.Brokers...) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil || host != "localhost" && (net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback()) {
			return true
		}
	}
	return false
}

// verifiedTLSURL is raw with TLS whose certificate is checked: Postgres
// sslmode=verify-full, MySQL tls=true, rediss://, memcacheds:// and
// amqps:// (on port 5671 when it was 5672), kafka tls=true, nats tls://. It
// is "" for other kinds, or a URL that does not parse. An option the URL
// did not have is added at the end; the rest stays as written.
func verifiedTLSURL(raw, kind string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	key, val := "", ""
	switch kind {
	case "postgres":
		key, val = "sslmode", "verify-full"
	case "mysql":
		key, val = "tls", "true"
	case "redis":
		u.Scheme = "rediss"
	case "memcached":
		u.Scheme = "memcacheds"
	case "kafka":
		key, val = "tls", "true"
	case "rabbitmq":
		u.Scheme = "amqps"
		if u.Port() == "5672" {
			u.Host = net.JoinHostPort(u.Hostname(), "5671")
		}
		q := u.Query()
		if q.Has("tls") || q.Has("insecure") {
			q.Del("tls")
			q.Del("insecure")
			u.RawQuery = q.Encode()
		}
	case "nats":
		u.Scheme = "tls"
		if q := u.Query(); q.Has("tls") || q.Has("insecure") {
			q.Del("tls")
			q.Del("insecure")
			u.RawQuery = q.Encode()
		}
	default:
		return ""
	}
	switch q := u.Query(); {
	case key == "":
	case !q.Has(key) && u.RawQuery == "":
		u.RawQuery = key + "=" + val
	case !q.Has(key):
		u.RawQuery += "&" + key + "=" + val
	default:
		q.Set(key, val)
		u.RawQuery = q.Encode()
	}
	return u.String()
}
