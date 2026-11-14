package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/engine"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// heldWriter is a call's stdout that holds the call at its first write
// until release is closed: the call has done its work and is still
// running.
type heldWriter struct {
	once    sync.Once
	at      chan struct{} // closed at the first write
	release chan struct{}
	mu      sync.Mutex
	buf     bytes.Buffer
}

func newHeldWriter() *heldWriter {
	return &heldWriter{at: make(chan struct{}), release: make(chan struct{})}
}

func (w *heldWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.at); <-w.release })
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *heldWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// waitClosed waits for ch, or fails the test after a while.
func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(30 * time.Second):
		t.Fatalf("%s never happened", what)
	}
}

// A dry run in one call never turns another call's change into a
// preview: the dry run's change is not saved, the other call's is (run
// with -race). The real call has started its command and waits for its
// password while the dry run runs from start to end, so a dry run that
// still reached the store through the process (store.DryRun, before)
// would make the real call's vault and store writes previews.
func TestDryRunBesideARealChange(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	env := map[string]string{"KOMANDO_HOME": home, "USER": "ana"}
	noWindow := func(string) (bool, bool) { t.Error("a call opened a window"); return false, true }
	run := func(c engine.Call, args ...string) (int, string) {
		var o, e bytes.Buffer
		if c.Stdout == nil {
			c.Stdout = &o
		}
		c.Program, c.LookupEnv, c.Stderr, c.Ask = "komando", envOf(env, &sync.Map{}), &e, noWindow
		code := RunCall(context.Background(), c, append([]string{"-o", "json"}, args...))
		return code, o.String() + e.String()
	}

	asking, typed := make(chan struct{}), make(chan struct{})
	saved := readPassword
	t.Cleanup(func() { readPassword = saved })
	readPassword = func(*call, string) (string, error) {
		close(asking)
		<-typed
		return "real-pass", nil
	}
	var realCode int
	var realOut string
	done := make(chan struct{})
	go func() {
		defer close(done)
		realCode, realOut = run(engine.Call{Terminal: true}, "host", "add", "real", "u@10.0.0.1", "--ask-password")
	}()
	waitClosed(t, asking, "the real call's password question")
	if code, o := run(engine.Call{}, "host", "add", "dry", "u@10.0.0.2", "--dry-run"); code != 0 {
		t.Fatalf("the dry run: exit %d: %s", code, o)
	}
	close(typed)
	waitClosed(t, done, "the end of the real call")
	if realCode != 0 {
		t.Fatalf("the real call beside a dry run: exit %d: %s", realCode, realOut)
	}

	// and several at once, in no set order
	const rounds = 6
	var wg sync.WaitGroup
	errs := make(chan error, 2*rounds)
	for i := range rounds {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if code, o := run(engine.Call{}, "host", "add", fmt.Sprintf("dry%d", i), fmt.Sprintf("u@10.0.1.%d", i+1), "--dry-run"); code != 0 {
				errs <- fmt.Errorf("dry run %d: exit %d: %s", i, code, o)
			}
		}()
		go func() {
			defer wg.Done()
			if code, o := run(engine.Call{}, "host", "add", fmt.Sprintf("real%d", i), fmt.Sprintf("u@10.0.2.%d", i+1)); code != 0 {
				errs <- fmt.Errorf("real change %d: exit %d: %s", i, code, o)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	st, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if h := st.Hosts["real"]; h == nil || h.PasswordRef != "secret:real-pass" {
		t.Errorf("the real call's server was not saved: %+v", h)
	}
	if v, err := vault.Get("real-pass"); err != nil || v != "real-pass" {
		t.Errorf("the real call's password was not saved: %q %v", v, err)
	}
	if st.Hosts["dry"] != nil {
		t.Error("the dry run's server was saved")
	}
	for i := range rounds {
		if st.Hosts[fmt.Sprintf("real%d", i)] == nil {
			t.Errorf("real%d was not saved beside a dry run", i)
		}
		if st.Hosts[fmt.Sprintf("dry%d", i)] != nil {
			t.Errorf("dry%d was saved", i)
		}
	}
}

// One call's leave to look at an old copy of the store (a dry run,
// doctor) is its own: a call beside it, without that leave, never opens
// the old copy, nor gets the handle the first call opened (run with
// -race).
func TestOldCopyLookStaysInItsCall(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	if err := store.Update(store.Save, func(st *store.State) error {
		st.Hosts["web"] = &store.Host{Name: "web", Address: "10.0.0.5", User: "u"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	store.Close() // the next open checks the store again
	tcl.leave()   // only the calls below run
	t.Cleanup(tcl.enter)
	// a stand-in keychain that remembers a newer change than the store
	// has: the store is an old copy
	saved := store.GenerationKeeper
	t.Cleanup(func() { store.GenerationKeeper = saved; store.Close() })
	store.GenerationKeeper = store.GenerationKeep{
		Get: func() (uint64, bool, error) { return 1 << 40, true, nil },
		Set: func(uint64) error { return errors.New("the test's keychain is read only") },
		Del: func() {},
	}

	env := map[string]string{"KOMANDO_HOME": home, "USER": "ana"}
	noWindow := func(string) (bool, bool) { t.Error("a call opened a window"); return false, true }
	call := func(stdout io.Writer) engine.Call {
		return engine.Call{Program: "komando", LookupEnv: envOf(env, &sync.Map{}), Stdout: stdout, Stderr: &bytes.Buffer{}, Ask: noWindow}
	}
	oldCopy := func(code int, o string) bool {
		return code == 6 && strings.Contains(o, `"code":"STORE_OLD_COPY"`)
	}

	// alone, a dry run may look; a call after it may not
	var o bytes.Buffer
	if code := RunCall(context.Background(), call(&o), []string{"-o", "json", "list", "--dry-run"}); code != 0 || !strings.Contains(o.String(), `"web"`) {
		t.Fatalf("a dry run alone on an old copy: exit %d: %s", code, o.String())
	}
	o.Reset()
	if code := RunCall(context.Background(), call(&o), []string{"-o", "json", "list"}); !oldCopy(code, o.String()) {
		t.Fatalf("a call after a dry run got the old copy: exit %d: %s", code, o.String())
	}

	// a dry run that has opened the old copy and still runs: the call
	// beside it is refused
	held := newHeldWriter()
	dryCode := make(chan int, 1)
	go func() {
		dryCode <- RunCall(context.Background(), call(held), []string{"-o", "json", "list", "--dry-run"})
	}()
	waitClosed(t, held.at, "the dry run's output")
	o.Reset()
	if code := RunCall(context.Background(), call(&o), []string{"-o", "json", "list"}); !oldCopy(code, o.String()) {
		t.Errorf("a call beside a dry run opened the old copy: exit %d: %s", code, o.String())
	}
	close(held.release)
	if code := <-dryCode; code != 0 || !strings.Contains(held.String(), `"web"`) {
		t.Errorf("the dry run: exit %d: %s", code, held.String())
	}

	// and several at once, in no set order: the dry runs may be refused
	// while a plain call runs (the store asks every running call), a
	// plain call always is
	const rounds = 6
	var wg sync.WaitGroup
	errs := make(chan error, 2*rounds)
	for i := range rounds {
		wg.Add(2)
		go func() {
			defer wg.Done()
			var o bytes.Buffer
			if code := RunCall(context.Background(), call(&o), []string{"-o", "json", "list", "--dry-run"}); code != 0 && !oldCopy(code, o.String()) {
				errs <- fmt.Errorf("dry run %d: exit %d: %s", i, code, o.String())
			}
		}()
		go func() {
			defer wg.Done()
			var o bytes.Buffer
			if code := RunCall(context.Background(), call(&o), []string{"-o", "json", "list"}); !oldCopy(code, o.String()) {
				errs <- fmt.Errorf("plain call %d opened the old copy: exit %d: %s", i, code, o.String())
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
