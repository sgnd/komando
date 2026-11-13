// SQL Server makes self-signed certificates whose serial number can be
// negative, which Go refuses to parse since 1.23. Parsing them is a
// leniency in the format only: the chain and the host name are still
// checked (TestNegativeSerialCertificate).
//
//go:debug x509negativeserial=1

// Command komando manages servers, databases, queues, storage, clusters and
// VPNs, for people and AI agents.
package main

import (
	"os"

	"github.com/sgnd/komando/internal/cli"
)

func main() { os.Exit(cli.Execute()) }
