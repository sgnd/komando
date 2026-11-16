package transport

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// HTTP is a new http.Transport for a client of komando, with the timeouts
// of Go's default one and TLS 1.2 or later. It has no proxy: a client that
// connects straight (no --via path) sets Proxy to Proxy(), or to the
// proxy a person's config file names.
func HTTP() *http.Transport {
	return &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}
