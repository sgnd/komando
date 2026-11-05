package cli

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Checks for what goes into the inventory, so a bad value is refused when
// it is saved, not later when komando connects.

// userRe is a login name: what useradd, Active Directory (user@domain) and
// cloud images use. No spaces, no shell or URL characters.
var userRe = regexp.MustCompile(`^[A-Za-z0-9_.][A-Za-z0-9_.@$-]{0,63}$`)

func validUser(u string) error {
	if !userRe.MatchString(u) {
		return out.Errf(out.ExitUsage, "USAGE", "a login name has letters, digits and . _ - @ $ (no spaces), e.g. --user deploy",
			"invalid user %q", u)
	}
	return nil
}

func validPort(p int) error {
	if p < 0 || p > 65535 {
		return out.Errf(out.ExitUsage, "USAGE", "a port is a number from 1 to 65535; leave it out for 22",
			"invalid port %d", p)
	}
	return nil
}

// validLabelName checks a group or tag name, or a label key: the same rule
// as host names, so every one of them can be written in a selector
// (@GROUP, tag:TAG, label:KEY=VALUE).
func validLabelName(kind, n string) error {
	if !nameRe.MatchString(n) {
		return out.Errf(out.ExitUsage, "USAGE", "use letters, digits and . _ - (max 63), e.g. web or prod-eu",
			"invalid %s name %q", kind, n)
	}
	return nil
}

// checkLabels validates the groups, tags and labels of an inventory entry.
func checkLabels(groups, tags []string, labels map[string]string) error {
	for _, gr := range groups {
		if err := validLabelName("group", gr); err != nil {
			return err
		}
	}
	for _, t := range tags {
		if err := validLabelName("tag", t); err != nil {
			return err
		}
	}
	for k, v := range labels {
		if err := validLabelName("label", k); err != nil {
			return err
		}
		if strings.ContainsAny(v, ",") || hasControl(v) {
			return out.Errf(out.ExitUsage, "USAGE", "a label value cannot hold commas or control characters (it would break label:KEY=VALUE selectors)",
				"invalid value for label %s", k)
		}
	}
	return nil
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0
}

// checkHost validates a host before it is saved into s: its port, user,
// --via path and identity file.
func checkHost(s *store.State, h *store.Host) error {
	if err := validPort(h.Port); err != nil {
		return err
	}
	if h.User != "" {
		if err := validUser(h.User); err != nil {
			return err
		}
	}
	if h.Address == "" || strings.ContainsAny(h.Address, " /@") || hasControl(h.Address) {
		return out.Errf(out.ExitUsage, "USAGE", "give a host name or IP address, e.g. 10.0.0.5 or web1.example.com", "invalid address %q", h.Address)
	}
	if h.Identity != "" {
		if _, err := os.Stat(expandHome(h.Identity)); err != nil {
			return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "give the path of a private key file, or register it with `komando key add NAME PATH` and use --key",
				"identity file %s: %v", h.Identity, errText(err))
		}
	}
	if err := checkLabels(h.Groups, h.Tags, h.Labels); err != nil {
		return err
	}
	return checkHostVia(s, h)
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
func checkHostVia(s *store.State, h *store.Host) error {
	steps := viaChain(h.Via)
	for i, step := range steps {
		if strings.EqualFold(step, h.Name) {
			return out.Errf(out.ExitUsage, "VIA_CYCLE", "--via names the servers (or VPN) in front of this one, not the server itself",
				"host %q cannot reach itself through itself", h.Name)
		}
		if _, ok := s.Vpns[step]; ok {
			if i > 0 {
				return out.Errf(out.ExitUsage, "VIA_ORDER", "put the VPN first: --via "+step+","+steps[0], "a VPN can only be the first step of a --via path")
			}
			continue
		}
		if _, ok := s.Hosts[step]; !ok {
			hint := "--via takes server and VPN names; see `komando list`"
			if c := closest(step, viaNames(s)); c != "" {
				hint = fmt.Sprintf("did you mean %q? (%s)", c, hint)
			}
			return out.Errf(out.ExitNotFound, "VIA_NOT_FOUND", hint, "no server or VPN named %q", step)
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
		for _, step := range viaChain(o.Via) {
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
	if ref != "" && !vault.ValidRef(ref) {
		return out.Errf(out.ExitUsage, "USAGE",
			"store the passphrase with `komando secret set NAME` and pass --passphrase-ref secret:NAME ("+vault.RefHelp()+")",
			"invalid --passphrase-ref: it takes a reference, not the passphrase itself")
	}
	return nil
}

// --- the same server under another name -------------------------------------

// normAddr is a host name the way DNS compares it: lower case, without the
// root dot ("Target." is "target") or IPv6 brackets.
func normAddr(a string) string {
	a = strings.TrimSpace(a)
	a = strings.TrimSuffix(strings.TrimPrefix(a, "["), "]")
	return strings.TrimSuffix(strings.ToLower(a), ".")
}

// sameAddress reports whether two addresses name the same server as
// written (no DNS); protectedHost also compares the IPs they lead to.
func sameAddress(a, b string) bool { return a != "" && normAddr(a) == normAddr(b) }

// normConnURL writes the URL's host the normal way (lower case, no root
// dot), so a protected conn cannot be reached as "maria." or "MARIA".
func normConnURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	host := u.Hostname()
	n := normAddr(host)
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

// lookupHost is the resolver (tests replace it).
var lookupHost = net.DefaultResolver.LookupHost

// lookupIPs resolves a name with a short timeout; an IP is itself.
func lookupIPs(ctx context.Context, host string) []string {
	host = normAddr(host)
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}
	addrs, err := lookupHost(ctx, host)
	if err != nil {
		return nil
	}
	return addrs
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

// connAddrKey is what makes two conns the same resource (as in
// protectedConn): the file, the bucket, or the family and address.
func connAddrKey(c *store.Conn) string {
	t, err := driver.Parse(c.URL)
	if err != nil {
		return ""
	}
	switch {
	case t.Kind.File:
		return "file " + t.Path
	case t.Bucket != "":
		return "bucket " + invHostPort(t.Address) + "/" + t.Bucket
	}
	return t.Kind.Family + " " + invHostPort(t.Address)
}

func invHostPort(a string) string {
	h, p, err := net.SplitHostPort(a)
	if err != nil {
		return normAddr(a)
	}
	return net.JoinHostPort(normAddr(h), p)
}

// protectedTwinConn names a protected conn for the same resource as c.
func protectedTwinConn(s *store.State, c *store.Conn) string {
	k := connAddrKey(c)
	if k == "" {
		return ""
	}
	for _, o := range s.SortedConns() {
		if o.Protected && o.Name != c.Name && connAddrKey(o) == k {
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
}

type connResult struct {
	*store.Conn
	Action   string   `json:"action,omitempty"`  // added | replaced | would_add | would_replace
	Changed  *bool    `json:"changed,omitempty"` // edit: false when the edit changed nothing
	Warnings []string `json:"warnings,omitempty"`
}

// sameTwinWarning is the warning when an entry turns out to be a protected
// one under another name. The entry is protected too.
func sameTwinWarning(kind, name, twin string) string {
	return fmt.Sprintf("%s is the same %s as protected %s, so it is protected too (changes need --yes)", name, kind, twin)
}
