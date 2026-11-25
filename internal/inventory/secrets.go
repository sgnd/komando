package inventory

import (
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// ProtectedUsers are the protected servers, conns and VPNs among users.
func ProtectedUsers(st *store.State, users []string) []string {
	var prot []string
	for _, u := range users {
		kind, name, _ := strings.Cut(u, " ")
		switch {
		case kind == "host" && st.Hosts[name] != nil && st.Hosts[name].Protected,
			kind == "conn" && st.Conns[name] != nil && st.Conns[name].Protected,
			kind == "vpn" && st.Vpns[name] != nil && st.Vpns[name].Protected:
			prot = append(prot, u)
		}
	}
	return prot
}

// SecretUsers lists the servers, conns, keys and VPNs whose references point
// at the vault secret name.
func SecretUsers(st *store.State, name string) []string {
	return walkSecretRefs(st, name, "")
}

// RenameSecretRefs points every reference to credential:from at credential:to and
// returns what it changed.
func RenameSecretRefs(st *store.State, from, to string) []string {
	return walkSecretRefs(st, from, to)
}

// walkSecretRefs finds every reference to credential:name in the state - the
// password, sudo and passphrase refs, a server's environment variables and
// WinRM CA (?ca=credential:NAME), a conn URL's options (?ca=credential:NAME) and
// a VPN's key, preshared key and config - and, when rename is set, points
// it at credential:rename.
func walkSecretRefs(st *store.State, name, rename string) []string {
	ref := "credential:" + name
	now := time.Now().UTC()
	users := map[string]bool{}
	visit := func(user string, touch func(), ps ...*string) {
		hit := false
		for _, p := range ps {
			if *p == ref {
				hit = true
				if rename != "" {
					*p = "credential:" + rename
				}
			}
		}
		if hit {
			users[user] = true
			if rename != "" && touch != nil {
				touch()
			}
		}
	}
	for _, h := range st.Hosts {
		ps := []*string{&h.PasswordRef, &h.SudoRef}
		if h.WinRMOpts != nil {
			ps = append(ps, &h.WinRMOpts.CA) // winrm://...?ca=credential:NAME
		}
		env := make([]string, 0, len(h.Env))
		for k := range h.Env {
			env = append(env, k)
		}
		sort.Strings(env)
		vals := make([]string, len(env))
		for i, k := range env {
			vals[i] = h.Env[k]
			ps = append(ps, &vals[i])
		}
		visit("host "+h.Name, func() { h.UpdatedAt = now }, ps...)
		for i, k := range env {
			h.Env[k] = vals[i]
		}
	}
	for _, c := range st.Conns {
		visit("conn "+c.Name, func() { c.UpdatedAt = now }, &c.PasswordRef)
		// a URL option such as a registry's ?ca=credential:NAME
		if u, hit := renameURLSecretRefs(c.URL, name, rename); hit {
			users["conn "+c.Name] = true
			if rename != "" {
				c.URL, c.UpdatedAt = u, now
			}
		}
	}
	for _, k := range st.Keys {
		visit("key "+k.Name, nil, &k.PassphraseRef)
	}
	for _, v := range st.Vpns {
		visit("vpn "+v.Name, func() { v.UpdatedAt = now }, &v.KeyRef, &v.PSKRef, &v.ConfigRef)
	}
	list := make([]string, 0, len(users))
	for u := range users {
		list = append(list, u)
	}
	sort.Strings(list)
	return list
}

// URLSecretRef is a conn URL option whose value is credential:NAME, such as
// the CA certificate of a registry: ?ca=credential:NAME.
type URLSecretRef struct{ Option, Name string }

// URLSecretRefs lists the options of a conn URL that name a vault secret,
// in the order they are written.
func URLSecretRefs(rawURL string) []URLSecretRef {
	var refs []URLSecretRef
	MapURLSecretRefs(rawURL, func(opt, name string) string {
		refs = append(refs, URLSecretRef{opt, name})
		return name
	})
	return refs
}

// renameURLSecretRefs reports whether an option of the URL says
// credential:from and, when to is set, returns the URL with those options
// saying credential:to. The rest of the URL stays as it was written.
func renameURLSecretRefs(rawURL, from, to string) (string, bool) {
	hit := false
	u := MapURLSecretRefs(rawURL, func(_, name string) string {
		if name != from {
			return name
		}
		hit = true
		if to == "" {
			return name
		}
		return to
	})
	return u, hit
}

// MapURLSecretRefs calls fn for every query option of the URL whose value
// is credential:NAME and writes back the name fn returns. It splits the URL the
// way net/url does (the query runs from the first ? to the #) and edits
// the text in place, so options it does not change keep their order and
// their escaping. Secret names need no escaping (ValidName).
func MapURLSecretRefs(rawURL string, fn func(opt, name string) string) string {
	rest, frag, hasFrag := strings.Cut(rawURL, "#")
	head, query, ok := strings.Cut(rest, "?")
	if !ok || query == "" {
		return rawURL
	}
	parts := strings.Split(query, "&")
	changed := false
	for i, p := range parts {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		val, err := url.QueryUnescape(v)
		if err != nil {
			continue
		}
		name, ok := strings.CutPrefix(val, "credential:")
		if !ok || name == "" {
			continue
		}
		opt, err := url.QueryUnescape(k)
		if err != nil {
			opt = k
		}
		if n := fn(opt, name); n != name {
			parts[i] = k + "=credential:" + n
			changed = true
		}
	}
	if !changed {
		return rawURL
	}
	u := head + "?" + strings.Join(parts, "&")
	if hasFrag {
		u += "#" + frag
	}
	return u
}
