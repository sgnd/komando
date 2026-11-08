package dbx

import (
	"crypto/x509"
	"testing"

	"github.com/jackc/pgx/v5"
)

// With ?ca= every connection attempt uses TLS and checks the certificate
// against that CA and the server's name, also for sslmode=require and the
// default prefer, which would otherwise not check it or try without TLS.
func TestPinCA(t *testing.T) {
	pool := x509.NewCertPool()
	for _, raw := range []string{"postgres://app@db.internal/app", "postgres://app@db.internal/app?sslmode=require"} {
		cfg, err := pgx.ParseConfig(raw)
		if err != nil {
			t.Fatal(err)
		}
		pinCA(cfg, pool)
		tc := cfg.TLSConfig
		if tc == nil || tc.RootCAs != pool || tc.InsecureSkipVerify || tc.ServerName != "db.internal" || tc.VerifyPeerCertificate != nil {
			t.Errorf("%s: TLS %+v", raw, tc)
		}
		for _, fb := range cfg.Fallbacks {
			if fb.TLSConfig == nil {
				t.Errorf("%s: a fallback without TLS is left", raw)
			}
		}
	}
}
