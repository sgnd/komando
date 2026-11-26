package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Checks for what goes into the inventory, so a bad value is refused when
// it is saved, not later when komando connects.

// checkHost validates a host before it is saved into s: its port, user,
// --via path and identity file.
func checkHost(cl *call, s *store.State, h *store.Host) error {
	if err := inventory.ValidPort(h.Port); err != nil {
		return err
	}
	if h.User != "" {
		if err := inventory.ValidUser(h.User); err != nil {
			return err
		}
	}
	// a leading - would read as an option in the ssh line host ssh-command
	// prints (ssh -oProxyCommand=...), so it is never an address
	if h.Address == "" || strings.HasPrefix(h.Address, "-") || strings.ContainsAny(h.Address, " /@") || inventory.HasControl(h.Address) {
		return out.Errf(out.ExitUsage, "USAGE", "give a host name or IP address, for example 10.0.0.5 or web1.example.com", "%q is not a host name or IP address", h.Address)
	}
	if h.Identity != "" {
		if _, err := os.Stat(inventory.ExpandHome(h.Identity)); err != nil {
			return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "give the path of a private key file, or register it with `komando key add NAME FILE` and use --key",
				"identity file %s: %v", h.Identity, errText(err))
		}
	}
	if err := inventory.CheckLabels(h.Groups, h.Tags, h.Labels); err != nil {
		return err
	}
	return checkHostVia(cl, s, h)
}

// errText is an OS error without the path it repeats.
func errText(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err.Error()
	}
	return err.Error()
}

// checkHostVia: every step of the --via path exists, a VPN comes first,
// the host is not on its own path, and no step's own path leads back.
func checkHostVia(cl *call, s *store.State, h *store.Host) error {
	steps := inventory.ViaChain(h.Via)
	if err := viaTwice(steps); err != nil {
		return err
	}
	for i, step := range steps {
		if strings.EqualFold(step, h.Name) {
			return out.Errf(out.ExitUsage, "VIA_CYCLE", "--via names the servers (or VPN) in front of this one, not the server itself",
				"server %q is in its own --via path", h.Name)
		}
		if _, ok := s.Vpns[step]; ok {
			if i > 0 {
				return out.Errf(out.ExitUsage, "VIA_ORDER", "put the VPN first: --via "+step+","+steps[0], "a VPN can only be the first step of a --via path")
			}
			continue
		}
		if _, ok := s.Hosts[step]; !ok {
			e := out.Errf(out.ExitNotFound, "VIA_NOT_FOUND", "--via takes server and VPN names; see them with `komando list`", "no server or VPN named %q", step)
			if c := closest(step, viaNames(s)); c != "" {
				suggest(cl, e, step, c)
			}
			return e
		}
	}
	// a cycle through other hosts: a -> b -> a
	seen := map[string]bool{h.Name: true}
	var walk func(name string) error
	walk = func(name string) error {
		o, ok := s.Hosts[name]
		if !ok || name == h.Name {
			return nil
		}
		if seen[name] {
			return nil
		}
		seen[name] = true
		for _, step := range inventory.ViaChain(o.Via) {
			if step == h.Name {
				return out.Errf(out.ExitUsage, "VIA_CYCLE", "change one of the --via settings so the path does not lead back",
					"--via loop: %s is reached through %s, which is reached through %s", h.Name, name, h.Name)
			}
			if err := walk(step); err != nil {
				return err
			}
		}
		return nil
	}
	for _, step := range steps {
		if err := walk(step); err != nil {
			return err
		}
	}
	return nil
}

func viaNames(s *store.State) []string {
	var n []string
	for _, h := range s.SortedHosts() {
		n = append(n, h.Name)
	}
	for _, v := range s.SortedVpns() {
		n = append(n, v.Name)
	}
	return n
}

// checkPassphraseRef refuses a passphrase typed where a reference belongs.
func checkPassphraseRef(ref string) error {
	if err := store.CredentialRef("--passphrase-ref", ref); err != nil {
		return err
	}
	if ref != "" && !vault.ValidRef(ref) {
		return out.Errf(out.ExitUsage, "USAGE",
			"store the passphrase with `komando secret set NAME` and pass --passphrase-ref credential:NAME",
			"--passphrase-ref takes a reference, not the passphrase itself")
	}
	return nil
}

// The same server under another name.

// sameAddress reports whether two addresses name the same server as
// written (no DNS); protectedHost also compares the IPs they lead to.
func sameAddress(a, b string) bool { return a != "" && inventory.NormAddr(a) == inventory.NormAddr(b) }

// normConnURL writes the URL's host the normal way (lower case, no root
// dot), so a protected conn cannot be reached as "maria." or "MARIA".
func normConnURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	host := u.Hostname()
	n := inventory.NormAddr(host)
	if n == host {
		return raw
	}
	if p := u.Port(); p != "" {
		u.Host = net.JoinHostPort(n, p)
	} else if strings.Contains(n, ":") {
		u.Host = "[" + n + "]"
	} else {
		u.Host = n
	}
	return u.String()
}

// protectedTwinHost names a protected host that is the same server as h:
// the same address (any case, with or without the root dot) or an address
// that resolves to the same IP, on the same port.
func protectedTwinHost(s *store.State, h *store.Host) string {
	var prot []*store.Host
	for _, o := range s.SortedHosts() {
		if o.Protected && o.Name != h.Name && o.EffectivePort() == h.EffectivePort() {
			if sameAddress(o.Address, h.Address) {
				return o.Name
			}
			prot = append(prot, o)
		}
	}
	if len(prot) == 0 {
		return ""
	}
	// cached: an import checks every host against the same protected ones
	mine := cachedIPs(h.Address)
	if len(mine) == 0 {
		return ""
	}
	for _, o := range prot {
		for _, ip := range cachedIPs(o.Address) {
			if slices.Contains(mine, ip) {
				return o.Name
			}
		}
	}
	return ""
}

// prefetchTwinIPs resolves, a few at a time, the addresses that
// protectedTwinHost will compare for hosts, so a large import does not
// resolve them one by one (while holding the inventory lock, for host
// import). Nothing is looked up when no host in s is protected.
func prefetchTwinIPs(s *store.State, hosts []*store.Host) {
	var names []string
	for _, o := range s.Hosts {
		if o.Protected {
			names = append(names, o.Address)
		}
	}
	if len(names) == 0 {
		return
	}
	for _, h := range hosts {
		if h != nil && h.Address != "" {
			names = append(names, h.Address)
		}
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)
	for _, n := range names {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			cachedIPs(n)
		}()
	}
	wg.Wait()
}

// protectedTwinConn names a protected conn for the same resource as c.
func protectedTwinConn(s *store.State, c *store.Conn) string {
	k := inventory.ConnAddrKey(c)
	if k == "" {
		return ""
	}
	for _, o := range s.SortedConns() {
		if o.Protected && o.Name != c.Name && inventory.ConnAddrKey(o) == k {
			return o.Name
		}
	}
	return ""
}

// hostResult is what host add and edit print: the host, plus warnings.
type hostResult struct {
	*store.Host
	Action   string   `json:"action,omitempty"`  // added | replaced | would_add | would_replace
	Changed  *bool    `json:"changed,omitempty"` // edit: false when the edit changed nothing
	Warnings []string `json:"warnings,omitempty"`
	Next     string   `json:"next,omitempty"` // add: the command to run next
	// SecretsUnused: edit --login ask or agent let go of these stored passwords;
	// they stay in the vault (`komando secret rm NAME`)
	SecretsUnused []string `json:"secrets_unused,omitempty"`
}

// MarshalJSON adds login (ask, password, key or agent) to the server's
// settings, as host show prints it.
func (r hostResult) MarshalJSON() ([]byte, error) {
	type plain hostResult
	if r.Host == nil {
		return json.Marshal(plain(r))
	}
	return json.Marshal(struct {
		plain
		Login string `json:"login"`
	}{plain(r), r.LoginMode()})
}

type connResult struct {
	*store.Conn
	Action   string   `json:"action,omitempty"`  // added | replaced | would_add | would_replace
	Changed  *bool    `json:"changed,omitempty"` // edit: false when the edit changed nothing
	Warnings []string `json:"warnings,omitempty"`
	Next     string   `json:"next,omitempty"` // add: the command to run next
	// SecretsUnused: edit --login ask or none let go of this stored
	// password; it stays in the vault (`komando secret rm NAME`)
	SecretsUnused []string `json:"secrets_unused,omitempty"`
}

// MarshalJSON adds login (ask, password or none) to the conn's settings,
// as conn show prints it.
func (r connResult) MarshalJSON() ([]byte, error) {
	type plain connResult
	if r.Conn == nil {
		return json.Marshal(plain(r))
	}
	return json.Marshal(struct {
		plain
		Login string `json:"login"`
	}{plain(r), r.LoginMode()})
}

// sameTwinWarning is the warning when an entry turns out to be a protected
// one under another name. The entry is protected too.
func sameTwinWarning(kind, name, twin string) string {
	return fmt.Sprintf("%s is the same %s as protected %s, so it is protected too (changes need --yes)", name, kind, twin)
}

// loginClouds are the subcommands of `komando login`: a server with one of
// these names could never be logged in to, so no new server, conn or VPN
// takes one (S-1.5), as none takes "all".
var loginClouds = []string{"aws", "gcp", "azure"}

// reservedCloud is the cloud name n is (any case), or "".
func reservedCloud(n string) string {
	if i := slices.IndexFunc(loginClouds, func(c string) bool { return strings.EqualFold(c, n) }); i >= 0 {
		return loginClouds[i]
	}
	return ""
}

// checkEntryName is inventory.ValidName for the name of a new server, conn or VPN:
// the cloud names are refused too.
func checkEntryName(kind, n string) error {
	if err := inventory.ValidName(kind, n); err != nil {
		return err
	}
	if c := reservedCloud(n); c != "" && (kind == "host" || kind == "conn" || kind == "vpn") {
		word := map[string]string{"host": "server", "conn": "conn", "vpn": "VPN"}[kind]
		return out.Errf(out.ExitUsage, "USAGE", "pick another name, for example "+c+"-1",
			"%q cannot be a %s name: `komando login %s` is the cloud login", n, word, c)
	}
	return nil
}

// checkHostName is checkEntryName for a new server name.
func checkHostName(n string) error { return checkEntryName("host", n) }

// setHostAddress fills h from the positional user@address[:port] (args[1])
// or from --address winrm://USER@HOST. Only the positional address must
// agree with --user and --port; with --address the flags win, as for every
// --address.
func setHostAddress(h *store.Host, args []string, flagAddr string) error {
	arg := flagAddr
	switch {
	case len(args) == 2:
		arg = args[1]
	case !isWinRMAddress(flagAddr):
		return nil
	}
	a, err := parseAddressArg(arg)
	if err != nil {
		return err
	}
	h.Address, h.Transport, h.WinRMOpts = a.Address, a.Transport, a.WinRMOpts
	if len(args) == 2 && a.User != "" && h.User != "" && a.User != h.User {
		return out.Errf(out.ExitUsage, "USAGE", "give the user once, in the address or with --user",
			"user %s in the address and --user %s disagree", a.User, h.User)
	}
	if len(args) == 2 && a.Port != 0 && h.Port != 0 && a.Port != h.Port {
		return out.Errf(out.ExitUsage, "USAGE", "give the port once, in the address or with --port",
			"port %d in the address and --port %d disagree", a.Port, h.Port)
	}
	if a.User != "" && h.User == "" {
		h.User = a.User
	}
	if a.Port != 0 && h.Port == 0 {
		h.Port = a.Port
	}
	return nil
}
