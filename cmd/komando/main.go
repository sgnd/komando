// Command komando is an agent-first SSH and server operations CLI.
package main

import (
	"os"

	"github.com/sgnd/komando/internal/cli"
)

func main() { os.Exit(cli.Execute()) }
