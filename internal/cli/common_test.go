package cli

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealkey"
	"github.com/sgnd/komando/internal/sealrow"
	"github.com/sgnd/komando/internal/store"
)

// The audit log's os_user is the account komando runs as, on every
// system: Windows has no uid (os.Getuid is -1 there), so it must not read
// "uid -1".
func TestOSUser(t *testing.T) {
	if u := osUser(); u == "" || u == "unknown" || strings.HasPrefix(u, "uid -") {
		t.Fatalf("osUser() = %q", u)
	}
}

// A protected mark taken off with the row key alone (no policy key) stops
// every command with POLICY_MAC_FAILED naming the server: a load, and a
// read of the vault, which reaches the store without a load (toErr).
func TestPolicyMACStopsCommands(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web", "--address", "10.0.0.5", "--protected")
	t.Setenv("PW", "s3cret")
	mustRun(t, "secret", "set", "db-pass", "--from-env", "PW")
	master, err := store.MasterKey()
	if err != nil {
		t.Fatal(err)
	}
	store.Close()
	rk, _ := sealkey.Derive(master, sealkey.Rows)
	k, _ := sealrow.NewKey(rk)
	d, err := sealdb.Open(context.Background(), store.DBPath(), k)
	if err != nil {
		t.Fatal(err)
	}
	err = d.Update(context.Background(), func(tx *sealdb.Tx) error {
		rows, err := tx.List(store.KindHost)
		if err != nil || len(rows) != 1 {
			return fmt.Errorf("hosts %d: %w", len(rows), err)
		}
		_, err = tx.Put(store.KindHost, rows[0].ID, bytes.Replace(rows[0].Data, []byte(`"protected":true`), []byte(`"protected":false`), 1))
		return err
	})
	d.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"list"}, {"secret", "list"}} {
		if e := wantCode(t, "POLICY_MAC_FAILED", args...); !strings.Contains(e.Message, "server web") {
			t.Errorf("%v: %s", args, e.Message)
		}
	}
}
