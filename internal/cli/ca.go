package cli

import (
	"errors"
	"fmt"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/vault"
)

// A database, cache or queue conn's ?ca=secret:NAME is read from the vault
// where its client is made (dbx, cachex, queuex), for every command that
// opens it.
func init() {
	driver.ResolveSecret = func(ref string) (string, error) {
		v, err := vault.Resolve(ref)
		if errors.Is(err, vault.ErrNotFound) {
			return "", fmt.Errorf("%w: %v", driver.ErrSecretNotFound, err)
		}
		return v, err
	}
}
