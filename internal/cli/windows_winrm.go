package cli

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Windows servers over WinRM (docs/features/windows.md). The address says
// it: winrm://[user@]host[:port][?auth=basic&tls=skip-verify|off&ca=secret:NAME].

// isWinRMAddress reports an address written winrm://...
func isWinRMAddress(s string) bool { return strings.HasPrefix(strings.ToLower(s), "winrm://") }

// parseWinRMAddress reads a winrm:// address into a host's address, user,
// port and WinRM settings.
func parseWinRMAddress(s string) (*store.Host, error) {
	bad := func(why string) error {
		return out.Errf(out.ExitUsage, "USAGE", "write it as winrm://USER@HOST[:PORT], for example winrm://Administrator@10.0.0.9 (options: ?auth=basic, ?tls=skip-verify or ?tls=off, ?ca=secret:NAME)",
			"komando cannot read the WinRM address %q: %s", s, why)
	}
	rest := s[len("winrm://"):]
	rest, query, _ := strings.Cut(rest, "?")
	h := &store.Host{Transport: store.TransportWinRM, OS: store.OSWindows, WinRMOpts: &store.WinRMOpts{}}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		h.User, rest = rest[:i], rest[i+1:]
	}
	h.Address = rest
	if strings.Contains(rest, ":") && !(strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]")) {
		a, p, err := net.SplitHostPort(rest)
		if err != nil {
			return nil, bad(err.Error())
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, bad("the port is not a number from 1 to 65535")
		}
		h.Address, h.Port = a, n
	}
	if h.Address == "" {
		return nil, bad("no host")
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return nil, bad(err.Error())
	}
	for k := range q {
		switch k {
		case "auth":
			h.WinRMOpts.Auth = strings.ToLower(q.Get(k))
		case "tls":
			h.WinRMOpts.TLS = strings.ToLower(q.Get(k))
		case "ca":
			h.WinRMOpts.CA = q.Get(k)
		default:
			return nil, bad("unknown option " + k)
		}
	}
	return h, nil
}

// editAddress is host edit --address: a winrm:// address also sets the
// transport and its options (and the user and port it names).
func editAddress(h *store.Host, addr string) error {
	if !isWinRMAddress(addr) {
		h.Address = normAddr(addr)
		return nil
	}
	w, err := parseWinRMAddress(addr)
	if err != nil {
		return err
	}
	h.Address, h.Transport, h.WinRMOpts, h.OS = normAddr(w.Address), w.Transport, w.WinRMOpts, store.OSWindows
	if w.User != "" {
		h.User = w.User
	}
	if w.Port != 0 {
		h.Port = w.Port
	}
	return nil
}

// winrmCA is the vault ref of a WinRM host's CA, or "".
func winrmCA(h *store.Host) string {
	if h.WinRMOpts == nil {
		return ""
	}
	return h.WinRMOpts.CA
}

// checkWinRM checks a WinRM host's settings before it is saved.
func checkWinRM(h *store.Host) error {
	if !h.WinRM() {
		if h.Transport != "" {
			return out.Usage("%q is not a way komando reaches a server: SSH, or WinRM with a winrm:// address", h.Transport)
		}
		h.WinRMOpts = nil
		return nil
	}
	h.OS = store.OSWindows
	if h.WinRMOpts == nil {
		h.WinRMOpts = &store.WinRMOpts{}
	}
	o := h.WinRMOpts
	if o.Auth == "ntlm" {
		o.Auth = ""
	}
	switch {
	case o.Auth != "" && o.Auth != "basic":
		return out.Usage("WinRM auth=%s: use ntlm (the default) or basic", o.Auth)
	case o.TLS != "" && o.TLS != "skip-verify" && o.TLS != "off":
		return out.Usage("WinRM tls=%s: leave it out to check the certificate, or use skip-verify or off", o.TLS)
	case o.CA != "" && !vault.ValidRef(o.CA):
		return out.Usage("WinRM ca=%s: it takes a reference to the CA's PEM, for example ca=secret:NAME (%s)", o.CA, vault.RefHelp())
	case o.Auth == "basic" && o.TLS == "off":
		return out.Errf(out.ExitUsage, "WINRM_INSECURE", "use HTTPS (leave tls=off out), or NTLM (leave auth=basic out), which never sends the password",
			"Basic login over plain HTTP sends the password unencrypted")
	case h.ProxyCommand != "":
		return out.Usage("a WinRM server takes --via, not --proxy-command")
	case h.Key != "" || h.Identity != "":
		return out.Usage("WinRM logs in with a password, not an SSH key: use --password-ref or --ask-password")
	}
	return nil
}

// winrmWarnings say what a WinRM host's settings give up.
func winrmWarnings(h *store.Host) []string {
	if !h.WinRM() {
		return nil
	}
	var w []string
	switch h.WinRMOpts.TLS {
	case "off":
		w = append(w, "tls=off: commands, files and output travel unencrypted over plain HTTP, and the server must allow it (AllowUnencrypted); prefer HTTPS on port 5986")
	case "skip-verify":
		w = append(w, "tls=skip-verify: komando does not check the server's certificate, so it cannot tell the server from an impostor; prefer ca=secret:NAME with its CA")
	}
	if h.PasswordRef == "" {
		w = append(w, "WinRM logs in with a password; give it one with `komando host edit "+h.Name+" --ask-password`")
	}
	return w
}

// sameWinRM reports two hosts with the same WinRM settings.
func sameWinRM(a, b *store.Host) bool {
	var x, y store.WinRMOpts
	if a.WinRMOpts != nil {
		x = *a.WinRMOpts
	}
	if b.WinRMOpts != nil {
		y = *b.WinRMOpts
	}
	return a.Transport == b.Transport && x == y
}
