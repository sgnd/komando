//go:build e2elab

package store

import "os"

// The e2e lab (test/e2e/lib.sh) runs komando as an AI agent against a
// throwaway data folder, on a computer whose account home holds a person's
// real ~/.komando. Only a komando built for the lab (go build -tags
// e2elab, which test/e2e/run.sh does, into a folder it removes afterwards) reads the
// account's home folder from KOMANDO_E2E_ACCOUNT_HOME. A released komando
// has no such variable: nothing in an agent's environment moves its home.
func init() { useLabHome() }

func useLabHome() {
	if d := os.Getenv("KOMANDO_E2E_ACCOUNT_HOME"); d != "" {
		AccountHome = func() (string, error) { return d, nil }
	}
}
