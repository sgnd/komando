//go:build migratehook

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"github.com/sgnd/komando/internal/sealdb"
)

// T2: a migration killed at each of its steps. Before the commit (step
// 11) the store file is byte for byte as it was and opens as format 2;
// from the commit on it is format 3 and complete. Either way the next
// open by a person ends at format 3, and never two backups of a finished
// store.
func TestMigrate3CrashAtEachStep(t *testing.T) {
	if s := os.Getenv("KOMANDO_MIGRATE_KILL_AT"); s != "" {
		at, _ := strconv.Atoi(s)
		migrateHook = func(step int) error {
			if step == at {
				os.Exit(3)
			}
			return nil
		}
		_, err := migrateFormat3(context.Background(), personOpts())
		t.Fatalf("the migration came back: %v", err)
	}
	for step := 2; step <= 13; step++ {
		t.Run("step "+strconv.Itoa(step), func(t *testing.T) {
			home := format2Store(t)
			if err := UpdateRuntime(Save(), func(s *State) error {
				s.ExecSessions["e1"] = &ExecSession{ID: "e1", Host: "web1", Command: "sleep 1", PID: 42}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			Close()
			before := fileSum(t)
			cmd := exec.Command(os.Args[0], "-test.run=^TestMigrate3CrashAtEachStep$")
			cmd.Env = append(os.Environ(), "KOMANDO_MIGRATE_KILL_AT="+strconv.Itoa(step), "KOMANDO_HOME="+home)
			err := cmd.Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 3 {
				t.Fatalf("the child did not die at step %d: %v", step, err)
			}
			want := "2"
			if step >= 11 {
				want = "3"
			}
			if f := formatNow(t); f != want {
				t.Fatalf("format %s after a kill at step %d, want %s", f, step, want)
			}
			if step >= 11 {
				Close()
				rt, err := ReadRuntime()
				if err != nil || rt.ExecSessions["e1"] == nil {
					t.Errorf("exec session record right after a kill at step %d: %v", step, err)
				}
			}
			if step < 11 {
				format2Reads(t) // the rollback journal undoes a half step
				if step < 9 && fileSum(t) != before {
					t.Errorf("a kill at step %d changed the store file", step)
				}
			}
			Close()
			if _, err := migrateFormat3(context.Background(), personOpts()); err != nil {
				t.Fatalf("the next open after a kill at step %d: %v", step, err)
			}
			if f := formatNow(t); f != "3" {
				t.Errorf("format %s after the next open", f)
			}
			// Q7: the exec session record survives a kill at any step
			rt, err := ReadRuntime()
			if err != nil || rt.ExecSessions["e1"] == nil {
				t.Errorf("exec session record after a kill at step %d: %v %v", step, rt, err)
			}
		})
	}
}

// format2Reads opens the store as v0.17.0 does (format-2 row key, the
// inventory reader) and reads every record.
func format2Reads(t *testing.T) {
	t.Helper()
	Close()
	master, _, err := KeySource(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := keysFor(master, "2")
	if err != nil {
		t.Fatal(err)
	}
	d, err := sealdb.Open(context.Background(), DBPath(), ks.row)
	if err != nil {
		t.Fatalf("format 2 does not open after the kill: %v", err)
	}
	defer d.Close()
	if err := d.SetPolicy(context.Background(), ks.policy); err != nil {
		t.Fatal(err)
	}
	err = d.View(context.Background(), func(tx *sealdb.Tx) error {
		s, err := loadFormat2(tx)
		if err == nil && len(s.Hosts) != 12 {
			err = fmt.Errorf("%d hosts", len(s.Hosts))
		}
		return err
	})
	if err != nil {
		t.Fatalf("format 2 does not read after the kill: %v", err)
	}
}
