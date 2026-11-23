package store

import (
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// References in the format-2 store and the check that none is left in a
// format-3 store (Audit F10, M8).

// refProviders maps a reference's prefix to its v2.7 provider: secret is
// komando's own vault; the rest are credential store providers (O-08).
var refProviders = []struct{ prefix, provider string }{
	{"secret:", "secret"},
	{"env:", "env"},
	{"file:", "file"},
	{"op://", "onepassword"},
	{"bw://", "bitwarden"},
	{"kdbx:", "keepass"},
	{"vault:", "vault"},
	{"aws-sm:", "aws-sm"},
	{"gcp-sm:", "gcp-sm"},
	{"azure-kv:", "azure-kv"},
}

// parseRef splits a reference into its provider and item; "" for text
// that is no reference.
func parseRef(r string) (provider, item string) {
	for _, p := range refProviders {
		if rest, ok := strings.CutPrefix(r, p.prefix); ok && rest != "" {
			return p.provider, rest
		}
	}
	return "", ""
}

// mapURLRefs writes fn's answer for each query value of rawURL, decoded,
// and leaves the rest of the URL as it was written (cli mapURLSecretRefs).
func mapURLRefs(rawURL string, fn func(opt, val string) string) string {
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
		opt, err := url.QueryUnescape(k)
		if err != nil {
			opt = k
		}
		if n := fn(opt, val); n != val {
			parts[i] = k + "=" + n
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

// urlUser takes the user out of a conn URL: the user, and the URL without
// it. A URL with no user, or no scheme, comes back as it is.
func urlUser(raw string) (user, rest string) {
	scheme, after, ok := strings.Cut(raw, "://")
	if !ok {
		return "", raw
	}
	auth, path, _ := strings.Cut(after, "/")
	at := strings.LastIndex(auth, "@")
	if at < 0 {
		return "", raw
	}
	u, err := url.PathUnescape(auth[:at])
	if err != nil {
		u = auth[:at]
	}
	rest = scheme + "://" + auth[at+1:]
	if strings.Contains(after, "/") {
		rest += "/" + path
	}
	return u, rest
}

// urlPassword reports a URL whose user part holds a password (user:pw@).
func urlPassword(raw string) bool {
	_, after, ok := strings.Cut(raw, "://")
	if !ok {
		return false
	}
	auth, _, _ := strings.Cut(after, "/")
	at := strings.LastIndex(auth, "@")
	return at >= 0 && strings.Contains(auth[:at], ":")
}

// oldRefRe is a value that still names a format-2 vault secret.
var oldRefRe = regexp.MustCompile(`^secret:[A-Za-z0-9._-]+$`)

// record3 is one format-3 record as the checks read it.
type record3 struct {
	typ, id, name string
	data          any
}

// checkOldRefs3 stops at the first reference field that still says
// secret:NAME: credential names, Env, Options and URL query values. Free
// text (snippets, notes, labels, deny patterns, proxy commands) is not
// read, so text that starts with secret: never stops a store. The error
// names the entry and the field, never the value.
func checkOldRefs3(recs []record3) error {
	for _, r := range recs {
		for _, f := range refFields3(r.data) {
			if oldRefRe.MatchString(f.value) {
				return out.Errf(out.ExitPolicy, "STORE_OLD_REFERENCE",
					"open the store with komando v0.17.0, point the field at a saved secret again, then open it with this komando",
					"%s %s: field %s still names a secret the old way", r.typ, r.name, f.field)
			}
		}
	}
	return nil
}

type refField struct{ field, value string }

// refFields3 lists the reference fields of a format-3 record.
func refFields3(v any) []refField {
	var fs []refField
	add := func(field, value string) { fs = append(fs, refField{field, value}) }
	env := func(prefix string, m map[string]string) {
		for _, k := range slices.Sorted(maps.Keys(m)) {
			add(prefix+" "+k, m[k])
		}
	}
	switch r := v.(type) {
	case *HostV3:
		add("credential", r.Credential)
		add("sudo_credential", r.SudoCredential)
		env("env", r.Env)
		if r.WinRMOpts != nil {
			add("winrm.ca", r.WinRMOpts.CA)
		}
	case *ServiceV3:
		add("credential", r.Credential)
		env("option", r.Options)
		mapURLRefs(r.URL, func(opt, val string) string {
			add("url "+opt, val)
			return val
		})
	case *VpnV3:
		add("credential", r.Credential)
		add("psk_credential", r.PSKCredential)
		add("config_credential", r.ConfigCredential)
	case *Credential:
		if r.Key != nil {
			add("key.passphrase", r.Key.Passphrase)
		}
	}
	return fs
}
