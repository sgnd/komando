package cloud

import (
	"net/http"
	"time"

	"github.com/sgnd/komando/internal/transport"
)

// proxiedClient is an HTTP client for a secret store or cloud API: the
// shared transport, through a person's company proxy (never an AI
// agent's), with the system's CAs.
func proxiedClient(timeout time.Duration) *http.Client {
	tr := transport.HTTP()
	tr.Proxy = transport.Proxy()
	return &http.Client{Transport: tr, Timeout: timeout}
}
