package sshx

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
)

// STORE_BUSY says how long komando waited for the store.
func TestStoreBusyNamesTheWait(t *testing.T) {
	busy := fmt.Errorf("%w: could not commit", sealdb.ErrBusy)
	e := storeBusy(busy, 63*time.Second+400*time.Millisecond)
	var oe *out.Error
	if !errors.As(e, &oe) || oe.Code != "STORE_BUSY" || !strings.Contains(oe.Message, "for 1m3s") {
		t.Fatalf("got %v", e)
	}
	if storeBusy(nil, time.Second) != nil {
		t.Error("no error became one")
	}
}
