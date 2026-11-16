// SQL Server makes self-signed certificates whose serial number can be
// negative, which Go refuses to parse since 1.23. Parsing them is a
// leniency in the format only: the chain and the host name are still
// checked (TestNegativeSerialCertificate).
//
// SSL_CERT_FILE and SSL_CERT_DIR do not replace the system's CAs on macOS
// and Windows either (Go 1.27 made them do so): an AI agent's environment
// must not choose whom komando trusts (internal/transport, roots.go).
//
//go:debug x509negativeserial=1
//go:debug x509sslcertoverrideplatform=0

// Command komando manages servers, databases, queues, storage, clusters and
// VPNs, for people and AI agents.
package main

import (
	"os"

	"github.com/sgnd/komando/internal/cli"
)

func main() { os.Exit(cli.Execute()) }
