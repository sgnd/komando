package driver

import (
	"crypto/x509"
	"errors"
	"net/url"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// A database or cache whose certificate comes from a private CA (a company
// CA, a cloud's own CA such as RDS or Azure) is checked against that CA:
// ?ca=secret:NAME names the vault secret that holds it (PEM), as for a
// registry. The check is a full one: the certificate must be signed by
// that CA and name the server.

// ResolveSecret reads a secret reference; the cli sets it to the vault's.
var ResolveSecret func(ref string) (string, error)

// ErrSecretNotFound is what ResolveSecret wraps for a missing secret.
var ErrSecretNotFound = errors.New("secret not found")

// caKinds are the kinds whose URL takes ?ca= (registry has its own).
var caKinds = map[string]bool{"postgres": true, "mysql": true, "redis": true, "memcached": true, "mongodb": true}

// parseCA reads ?ca=secret:NAME into t.CA.
func parseCA(q url.Values, t *Target) error {
	if !caKinds[t.Kind.Name] || !q.Has("ca") {
		return nil
	}
	ca := q.Get("ca")
	if name, ok := strings.CutPrefix(ca, "secret:"); !ok || name == "" {
		return out.Errf(out.ExitUsage, "USAGE",
			"store the CA certificate with `komando secret set NAME < ca.crt`, then use ?ca=secret:NAME",
			"%s ca option must be secret:NAME, not %q", t.Kind.Name, ca)
	}
	t.CA = ca
	// with a CA the certificate is checked: it needs TLS, and a setting
	// that turns the check off contradicts it
	switch {
	case (t.Kind.Name == "redis" || t.Kind.Name == "memcached") && !t.Secure:
		return out.Usage("?ca= checks a TLS certificate: use %ss:// (TLS)", t.Kind.Name)
	case t.Kind.Name == "mongodb" && !t.Secure:
		return out.Usage("?ca= checks a TLS certificate: add tls=true (or use mongodb+srv://)")
	case t.Kind.Name == "mongodb" && t.TLS == "skip-verify":
		return out.Usage("mongodb ca= and tlsInsecure do not go together: with ca= the certificate is checked against that CA")
	case t.Kind.Name == "postgres" && (q.Get("sslmode") == "disable" || q.Get("sslmode") == "allow"):
		return out.Usage("?ca= checks the server's certificate, so it needs TLS: drop sslmode=%s", q.Get("sslmode"))
	case t.Kind.Name == "mysql" && t.TLS != "" && t.TLS != "true":
		return out.Usage("mysql ca= and tls=%s do not go together: with ca= the certificate is checked against that CA", t.TLS)
	}
	return nil
}

// RootCAs is the pool of the conn's ?ca= certificate, or nil without one.
func (t Target) RootCAs() (*x509.CertPool, error) {
	if t.CA == "" {
		return nil, nil
	}
	if ResolveSecret == nil {
		return nil, errors.New("no secret store to read the CA from")
	}
	pem, err := ResolveSecret(t.CA)
	if err != nil {
		code := "SECRET_UNRESOLVED"
		if errors.Is(err, ErrSecretNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		return nil, out.Errf(out.ExitNotFound, code, "store the CA certificate with `komando secret set NAME < ca.crt`",
			"%s CA %s: %v", t.Kind.Name, t.CA, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pem)) {
		return nil, out.Errf(out.ExitUsage, "BAD_CA", "store the CA certificate (PEM, -----BEGIN CERTIFICATE-----) with `komando secret set NAME < ca.crt`",
			"%s CA %s holds no PEM certificate", t.Kind.Name, t.CA)
	}
	return pool, nil
}

// WithoutCA is a conn URL without its ca= option, for drivers that would
// take it as a setting of their own.
func WithoutCA(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || !u.Query().Has("ca") {
		return raw
	}
	q := u.Query()
	q.Del("ca")
	u.RawQuery = q.Encode()
	return u.String()
}
