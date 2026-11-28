package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `secret set NAME --new` stores NAME only when it is not in the vault yet.
func TestSecretSetNew(t *testing.T) {
	invHome(t)
	setSecret(t, "taken", "first")

	// a stored name: SECRET_EXISTS (exit 8), the value stays
	withStdin(t, "second\n", func() {
		e := wantCode(t, "SECRET_EXISTS", "credential", "password", "add", "taken", "--new")
		if e.Exit != out.ExitConflict || !strings.Contains(e.Hint, "--new") || !strings.Contains(e.Message, `"taken"`) {
			t.Errorf("error: %+v", e)
		}
	})
	if v, err := vault.Get("taken"); err != nil || v != "first" {
		t.Fatalf("taken = %q, %v; a refused --new changed it", v, err)
	}

	// the dry run says so too, and is the same error
	withStdin(t, "second\n", func() {
		wantCode(t, "SECRET_EXISTS", "credential", "password", "add", "taken", "--new", "--dry-run")
	})

	// a free name: the dry run stores nothing, the real run stores it
	withStdin(t, "fresh-value\n", func() {
		d := mustRun(t, "credential", "password", "add", "fresh", "--new", "--dry-run")
		if d["action"] != "would_store" || d["replaced"] != false || d["would_set"] != true {
			t.Errorf("dry run: %v", d)
		}
	})
	if _, err := vault.Get("fresh"); err == nil {
		t.Fatal("the dry run stored it")
	}
	withStdin(t, "fresh-value\n", func() {
		d := mustRun(t, "credential", "password", "add", "fresh", "--new")
		if d["action"] != "stored" || d["replaced"] != false || d["ref"] != "credential:fresh" {
			t.Errorf("result: %v", d)
		}
	})
	if v, err := vault.Get("fresh"); err != nil || v != "fresh-value" {
		t.Errorf("fresh = %q, %v", v, err)
	}

	// without --new, set still replaces
	withStdin(t, "third\n", func() {
		if d := mustRun(t, "credential", "password", "add", "taken"); d["replaced"] != true {
			t.Errorf("plain set: %v", d)
		}
	})
	if v, _ := vault.Get("taken"); v != "third" {
		t.Errorf("taken = %q after a plain set", v)
	}
}

// Several komando processes running `secret set NAME --new` at once:
// exactly one stores NAME, every other one stops with SECRET_EXISTS.
func TestSecretSetNewRace(t *testing.T) {
	invHome(t)
	setSecret(t, "other", "x") // the vault and its key exist before the race
	store.Close()              // the children open the store as any other komando does
	const n = 6
	var wg sync.WaitGroup
	results := make([]string, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := exec.Command(os.Args[0], "-test.run=^TestSecretSetNewChild$")
			c.Env = append(vault.SelfEnv(), "KOMANDO_TEST_SETNEW=1", fmt.Sprintf("SETNEW_VALUE=value-%d", i))
			b, _ := c.CombinedOutput()
			results[i] = string(b)
		}(i)
	}
	wg.Wait()
	won, lost := 0, 0
	for _, r := range results {
		switch {
		case strings.Contains(r, "SETNEW=ok"):
			won++
		case strings.Contains(r, "SETNEW=SECRET_EXISTS exit 8"):
			lost++
		default:
			t.Errorf("a child ended otherwise:\n%s", r)
		}
	}
	if won != 1 || lost != n-1 {
		t.Fatalf("%d won and %d got SECRET_EXISTS, want 1 and %d", won, lost, n-1)
	}
	v, err := vault.Get("race")
	if err != nil || !strings.HasPrefix(v, "value-") {
		t.Errorf("race = %q, %v", v, err)
	}
}

// TestSecretSetNewChild is one racing komando of TestSecretSetNewRace.
func TestSecretSetNewChild(t *testing.T) {
	if os.Getenv("KOMANDO_TEST_SETNEW") != "1" {
		t.Skip("a child of TestSecretSetNewRace")
	}
	closeStoreAtEnd(t)
	_, e := invRun(t, "credential", "password", "add", "race", "--new", "--from-env", "SETNEW_VALUE")
	if e == nil {
		fmt.Println("SETNEW=ok")
		return
	}
	fmt.Printf("SETNEW=%s exit %d: %s\n", e.Code, e.Exit, e.Message)
}
