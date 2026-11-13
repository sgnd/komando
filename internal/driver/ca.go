package driver

import (
	"crypto/x509"
	"encoding/pem"
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
var caKinds = map[string]bool{"postgres": true, "mysql": true, "redis": true, "memcached": true, "mongodb": true, "kafka": true, "rabbitmq": true, "nats": true, "sqlserver": true, "oracle": true, "clickhouse": true, "snowflake": true, "bigquery": true, "s3": true, "gcs": true, "azblob": true}

// parseCA reads ?ca=secret:NAME into t.CA.
func parseCA(q url.Values, t *Target) error {
	if !caKinds[t.Kind.Name] || !q.Has("ca") {
		return nil
	}
	ca := q.Get("ca")
	if name, ok := strings.CutPrefix(ca, "secret:"); !ok || name == "" {
		return out.Errf(out.ExitUsage, "USAGE",
			"store the CA certificate with `komando secret set NAME < ca.crt`, then use ?ca=secret:NAME",
			"the %s ca option takes secret:NAME, not %q", t.Kind.Name, ca)
	}
	t.CA = ca
	// with a CA the certificate is checked: it needs TLS, and a setting
	// that turns the check off contradicts it
	switch {
	case (t.Kind.Name == "redis" || t.Kind.Name == "memcached") && !t.Secure:
		return out.Usage("?ca= checks a TLS certificate: use %ss:// (TLS)", t.Kind.Name)
	case t.Kind.Name == "mongodb" && !t.Secure:
		return out.Usage("?ca= checks a TLS certificate: add tls=true (or use mongodb+srv://)")
	case t.Kind.Name == "rabbitmq" && !t.Secure:
		return out.Usage("?ca= checks a TLS certificate: use amqps:// (TLS)")
	case t.Kind.Name == "rabbitmq" && t.TLS == "skip-verify":
		return out.Usage("rabbitmq ca= and tls=skip-verify do not go together: with ca= the certificate is checked against that CA")
	case t.Kind.Name == "nats" && !t.Secure:
		return out.Usage("?ca= checks a TLS certificate: use tls:// (TLS)")
	case t.Kind.Name == "nats" && t.TLS == "skip-verify":
		return out.Usage("nats ca= and tls=skip-verify do not go together: with ca= the certificate is checked against that CA")
	case t.Kind.Name == "kafka" && !t.Secure:
		return out.Usage("?ca= checks a TLS certificate: add tls=true")
	case t.Kind.Name == "kafka" && t.TLS == "skip-verify":
		return out.Usage("kafka ca= and tls=skip-verify do not go together: with ca= the certificate is checked against that CA")
	case t.Kind.Name == "mongodb" && t.TLS == "skip-verify":
		return out.Usage("mongodb ca= and tlsInsecure do not go together: with ca= the certificate is checked against that CA")
	case t.Kind.Name == "postgres" && (q.Get("sslmode") == "disable" || q.Get("sslmode") == "allow"):
		return out.Usage("?ca= checks the server's certificate, so it needs TLS: drop sslmode=%s", q.Get("sslmode"))
	case t.Kind.Name == "sqlserver" && !t.Secure:
		return out.Usage("?ca= checks a TLS certificate: add encrypt=true")
	case t.Kind.Name == "sqlserver" && t.TLS == "skip-verify":
		return out.Usage("sqlserver ca= and tls=skip-verify do not go together: with ca= the certificate is checked against that CA")
	case t.Kind.Name == "oracle" && t.TLS != "true":
		return out.Usage("?ca= checks a TLS certificate: use it with tls=true (TCPS), without tls=skip-verify or tls=false")
	case t.Kind.Name == "clickhouse" && t.TLS != "true":
		return out.Usage("?ca= checks a TLS certificate: use it with tls=true (HTTPS), without tls=skip-verify or tls=false")
	case (t.Kind.Name == "bigquery" || t.Kind.Name == "s3" || t.Kind.Name == "gcs" || t.Kind.Name == "azblob") && !t.Secure:
		return out.Usage("?ca= checks a TLS certificate: use an https:// endpoint")
	case t.Kind.Name == "mysql" && t.TLS != "" && t.TLS != "true":
		return out.Usage("mysql ca= and tls=%s do not go together: with ca= the certificate is checked against that CA", t.TLS)
	}
	return nil
}

// RootCAs is the pool of the conn's ?ca= certificate, or nil without one.
func (t Target) RootCAs() (*x509.CertPool, error) {
	certs, err := t.CAPEM()
	if certs == "" || err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(certs))
	return pool, nil
}

// CAPEM is the conn's ?ca= certificates as clean PEM: only the
// CERTIFICATE blocks a pool takes, with no headers, comments or blank
// lines, for a client that reads them from a file (pg_dump, mysqldump).
// "" without a ca=.
func (t Target) CAPEM() (string, error) {
	if t.CA == "" {
		return "", nil
	}
	if ResolveSecret == nil {
		return "", errors.New("no secret store to read the CA from")
	}
	text, err := ResolveSecret(t.CA)
	if err != nil {
		code := "SECRET_UNRESOLVED"
		if errors.Is(err, ErrSecretNotFound) {
			code = "SECRET_NOT_FOUND"
		}
		return "", out.Errf(out.ExitNotFound, code, "store the CA certificate with `komando secret set NAME < ca.crt`",
			"%s CA %s: %v", t.Kind.Name, t.CA, err)
	}
	var b strings.Builder
	for rest := []byte(text); ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		// what x509.CertPool.AppendCertsFromPEM takes
		if blk.Type != "CERTIFICATE" || len(blk.Headers) != 0 {
			continue
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			continue
		}
		_ = pem.Encode(&b, &pem.Block{Type: blk.Type, Bytes: blk.Bytes})
	}
	if b.Len() == 0 {
		return "", out.Errf(out.ExitUsage, "BAD_CA", "store the CA certificate (PEM, -----BEGIN CERTIFICATE-----) with `komando secret set NAME < ca.crt`",
			"%s CA %s holds no PEM certificate", t.Kind.Name, t.CA)
	}
	return b.String(), nil
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
