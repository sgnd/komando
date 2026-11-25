package inventory

import (
	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/store"
)

// ConnFamily is the command a conn works with: db, cache or storage.
func ConnFamily(c *store.Conn) string {
	k, _ := driver.Lookup(c.Kind)
	return k.Family
}
