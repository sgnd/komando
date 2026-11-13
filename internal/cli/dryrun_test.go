package cli

import (
	"fmt"
	"os"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

// TestDryRunChangesNothing runs inventory commands with --dry-run and checks
// that the state file and the key folder stay as they were.
func TestDryRunChangesNothing(t *testing.T) {
	setHome(t, t.TempDir())
	t.Setenv("KOMANDO_VAULT_PASS", "test")
	defer func() { g.dryRun, store.DryRun = false, false }() // flags are package globals
	run := func(args ...string) error {
		root := newRoot()
		root.SetArgs(append([]string{"-o", "json"}, args...))
		return root.Execute()
	}
	if err := run("host", "add", "web1", "deploy@10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := run("conn", "add", "db1", "postgres://app@10.0.0.2/app"); err != nil {
		t.Fatal(err)
	}
	files := func() string {
		b, _ := os.ReadFile(store.Path("state.json"))
		rt, _ := os.ReadFile(store.Path("runtime.json"))
		return string(b) + "\x00" + string(rt)
	}
	before := files()
	for _, args := range [][]string{
		{"host", "add", "web2", "deploy@10.0.0.3"},
		{"host", "edit", "web1", "--add-tag", "canary"},
		{"host", "rm", "web1"},
		{"conn", "edit", "db1", "--add-tag", "x"},
		{"conn", "rm", "db1"},
		{"group", "add", "web", "web1"},
		{"policy", "deny", "kubectl apply"},
		{"key", "gen", "k1"},
	} {
		if err := run(append([]string{"--dry-run"}, args...)...); err != nil {
			t.Errorf("%v --dry-run: %v", args, err)
		}
		if files() != before {
			t.Fatalf("%v --dry-run changed state.json or runtime.json", args)
		}
	}
	if _, err := os.Stat(store.Path("keys", "k1")); !os.IsNotExist(err) {
		t.Errorf("key gen --dry-run wrote a key file: %v", err)
	}
	store.DryRun = false
}

// A removal's preview says would_remove; removed stays for contract 1.
func TestRmDryRunSaysWouldRemove(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "add", "web1", "u@10.0.0.1")
	d := mustRun(t, "host", "rm", "web1", "--dry-run")
	if fmt.Sprint(d["would_remove"]) != "[web1]" {
		t.Errorf("dry run: %v", d)
	}
	d = mustRun(t, "host", "rm", "web1")
	if _, ok := d["would_remove"]; ok || fmt.Sprint(d["removed"]) != "[web1]" {
		t.Errorf("real run: %v", d)
	}
}
