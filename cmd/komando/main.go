// Command komando manages servers, databases, queues, storage, clusters and
// VPNs, for people and AI agents.
package main

import (
	"os"

	"github.com/sgnd/komando/internal/cli"
)

func main() { os.Exit(cli.Execute()) }
