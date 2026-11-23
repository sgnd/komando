//go:build migratehook

package store

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

// A migration killed after its read-back and before its commit leaves a
// store of format 2 that opens as before, and the next open migrates it.
// The child process dies inside the write step (Audit M10: only a build
// with the migratehook tag can do this).
func TestMigrate3KilledBeforeCommit(t *testing.T) {
	if os.Getenv("KOMANDO_MIGRATE_KILL") == "1" {
		migrateHook = func(step int) error {
			if step == 10 {
				os.Exit(3)
			}
			return nil
		}
		_, err := migrateFormat3(context.Background(), personOpts())
		t.Fatalf("the migration came back: %v", err)
	}
	home := format2Store(t)
	Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMigrate3KilledBeforeCommit$")
	cmd.Env = append(os.Environ(), "KOMANDO_MIGRATE_KILL=1", "KOMANDO_HOME="+home)
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 3 {
		t.Fatalf("the child did not die inside the step: %v", err)
	}
	s, err := Load() // the normal open rolls the half step back
	if err != nil {
		t.Fatalf("the store does not open after the kill: %v", err)
	}
	if len(s.Hosts) != 12 || len(s.Keys) != 2 {
		t.Errorf("%d hosts, %d keys after the kill", len(s.Hosts), len(s.Keys))
	}
	Close()
	if f := formatNow(t); f != "2" {
		t.Fatalf("format %s after the kill", f)
	}
	if _, err := migrateFormat3(context.Background(), personOpts()); err != nil {
		t.Fatalf("the next open: %v", err)
	}
	if f := formatNow(t); f != "3" {
		t.Errorf("format %s after the next open", f)
	}
}
