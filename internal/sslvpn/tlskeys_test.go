package sslvpn

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTLS12Exporter checks komando's own RFC 5705 exporter against Go's,
// on TLS 1.2 connections where Go's works (Extended Master Secret), for a
// SHA-256 and a SHA-384 cipher suite.
func TestTLS12Exporter(t *testing.T) {
	tested := 0
	for _, suite := range []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384} {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{suite}}
		srv.StartTLS()
		u, _ := portalURL("https://" + srv.Listener.Addr().String())
		o := Options{CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}
		keys := &tlsKeys{}
		c, err := dialTLSWith(context.Background(), o, u, keys)
		if err != nil {
			srv.Close()
			continue // a suite for the other kind of key than httptest's certificate
		}
		st := c.ConnectionState()
		want, err := st.ExportKeyingMaterial(acPSKLabel, nil, 32)
		if err != nil {
			t.Fatal(err)
		}
		got, err := keys.export(st, acPSKLabel, 32)
		if err != nil || !bytes.Equal(got, want) || st.CipherSuite != suite {
			t.Errorf("%s: exporter %x, want %x (%v)", tls.CipherSuiteName(st.CipherSuite), got, want, err)
		}
		tested++
		c.Close()
		srv.Close()
	}
	if tested != 2 {
		t.Errorf("tested %d suites, want a SHA-256 and a SHA-384 one", tested)
	}
	if _, err := (&tlsKeys{}).export(tls.ConnectionState{Version: tls.VersionTLS12}, acPSKLabel, 32); err == nil {
		t.Error("an exporter without keys")
	}
}
