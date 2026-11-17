package transport

import (
	"crypto/x509"
	"os"
)

// certEnv are the variables Go's crypto/x509 reads, once, to take CAs
// from a file or folder instead of the system's (on macOS and Windows
// too since Go 1.27, unless x509sslcertoverrideplatform=0, which the
// komando program sets as well).
var certEnv = []string{"SSL_CERT_FILE", "SSL_CERT_DIR"}

// The system's CAs are loaded here, with those variables hidden, before
// any connection: every TLS client in the process that leaves RootCAs nil
// then checks against the system's CAs, whatever the environment says.
// The variables come back afterwards, for the programs komando starts.
func init() {
	saved := map[string]string{}
	for _, n := range certEnv {
		if v, ok := os.LookupEnv(n); ok {
			saved[n] = v
			_ = os.Unsetenv(n)
		}
	}
	_, _ = x509.SystemCertPool()
	for n, v := range saved {
		_ = os.Setenv(n, v)
	}
}

// Roots is a copy of the system's CAs, for a client that adds its own CA
// to them (a conn's ?ca=).
func Roots() *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		return x509.NewCertPool()
	}
	return pool
}
