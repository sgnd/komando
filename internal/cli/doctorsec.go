package cli

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/driver"
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
			add("vault", false, true, "the vault key is a file next to the vault: anyone with a copy of "+store.Home()+" (a backup) can open it. Set KOMANDO_VAULT_PASS to a passphrase of 15+ characters before your first secret, or keep backups encrypted")
		case s.ShortPass:
			add("vault", false, true, "KOMANDO_VAULT_PASS is shorter than 15 characters (NIST SP 800-63B); use a longer one")
		case s.OldKDF:
			add("vault", false, true, "the vault uses an older scrypt cost; it moves to the stronger one when you next change a secret")
		default:
			add("vault", true, false, "AES-256-GCM, passphrase with scrypt N=2^17")
		}
	}

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
	for _, c := range st.SortedConns() {
		if why := plainConn(c); why != "" {
			add("conn:"+c.Name, false, true, why+" (OWASP ASVS 9.2.2)")
		}
	}
	return cs
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

// plainConn says why a conn's traffic may be readable or forged on the
// network, or "". Local addresses and conns reached through an SSH tunnel
// (--via) are left out.
func plainConn(c *store.Conn) string {
	if c.Via != "" {
		return ""
	}
	t, err := driver.Parse(c.URL)
	if err != nil || t.Kind.File {
		return ""
	}
	if host, _, err := net.SplitHostPort(t.Address); err == nil {
		if host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback() {
			return ""
		}
	}
	q := url.Values{}
	if u, err := url.Parse(c.URL); err == nil {
		q = u.Query()
	}
	switch t.Kind.Name {
	case "postgres":
		switch q.Get("sslmode") {
		case "verify-full", "verify-ca":
			return ""
		case "require":
			return "encrypted, but the server's certificate is not checked: use sslmode=verify-full"
		}
		return "may travel unencrypted: add ?sslmode=verify-full"
	case "mysql":
		switch strings.ToLower(t.TLS) {
		case "true":
			return ""
		case "skip-verify":
			return "encrypted, but the server's certificate is not checked: use ?tls=true"
		}
		return "may travel unencrypted: add ?tls=true"
	case "redis":
		if !t.Secure {
			return "travels unencrypted: use rediss://"
		}
	case "memcached":
		if !t.Secure {
			return "travels unencrypted: use memcacheds:// (memcached with TLS)"
		}
	case "ftp":
		return "travels unencrypted (passwords too): use ftps:// or sftp://"
	case "ftps":
		if q.Get("tls") == "skip-verify" {
			return "encrypted, but the server's certificate is not checked"
		}
	case "s3":
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
