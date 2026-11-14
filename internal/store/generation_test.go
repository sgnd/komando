package store

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/out"
)

// keychainStore is a sealed home whose key is "in the keychain", with a
// stand-in keychain for the generation.
func keychainStore(t *testing.T) *uint64 {
	t.Helper()
	sealedHome(t)
	oldKS, oldGK := KeySource, GenerationKeeper
	forgetSlowKeychain(t)
	KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
		return bytes.Repeat([]byte{5}, 32), map[string]string{"key_mode": "keychain"}, nil
	}
	var kept uint64
	have := false
	GenerationKeeper = GenerationKeep{
		Get: func() (uint64, bool, error) { return kept, have, nil },
		Set: func(n uint64) error { kept, have = n, true; return nil },
		Del: func() { kept, have = 0, false },
	}
	t.Cleanup(func() {
		KeySource, GenerationKeeper = oldKS, oldGK
		Close()
		OldCopyOK = nil
	})
	return &kept
}

// forgetSlowKeychain starts a test with no keychain marked slow, and
// leaves none marked slow for the next test.
func forgetSlowKeychain(t *testing.T) {
	t.Helper()
	clearSlowKeychain()
	t.Cleanup(clearSlowKeychain)
}

func clearSlowKeychain() {
	slowMu.Lock()
	defer slowMu.Unlock()
	clear(slowUntil)
}

// lookOK is OldCopyOK for a command that may look at an old copy.
func lookOK() bool { return true }

func TestOldCopyIsStopped(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web", Protected: true} })
	if *kept == 0 {
		t.Fatal("the keychain was not told the generation")
	}
	backup, _ := os.ReadFile(Path(StoreFile))
	update(t, func(s *State) { s.Hosts["web"].Protected = false })
	newer := *kept

	// someone puts the old copy back
	Close()
	if err := os.WriteFile(Path(StoreFile), backup, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" || oe.Exit != out.ExitPolicy {
		t.Fatalf("old copy: %v", err)
	}
	if !strings.Contains(oe.Hint, "--accept-old-copy") {
		t.Fatalf("hint %q", oe.Hint)
	}
	if err := Update(Save(), func(s *State) error { return nil }); err == nil {
		t.Fatal("a change went into an old copy")
	}

	// doctor and dry runs may look
	OldCopyOK = lookOK
	if s, err := Load(); err != nil || !s.Hosts["web"].Protected {
		t.Fatalf("allowed look: %v", err)
	}
	OldCopyOK = nil
	Close()
	have, k, guarded, old, err := CopyState()
	if err != nil || !guarded || !old || k != newer || have >= k {
		t.Fatalf("copy state %d %d %v %v %v", have, k, guarded, old, err)
	}

	// the look-only handle is not reused once looking is over
	OldCopyOK = lookOK
	if _, err := DB(false); err != nil {
		t.Fatal(err)
	}
	OldCopyOK = nil
	if _, err := DB(false); err == nil {
		t.Fatal("a handle opened to look at an old copy was handed to a normal command")
	}
	// a write through a look-only handle never lowers the keychain
	OldCopyOK = lookOK
	_ = Update(Save(), func(s *State) error { s.Hosts["x"] = &Host{Name: "x"}; return nil })
	OldCopyOK = nil
	if *kept != newer {
		t.Fatalf("the keychain went down to %d", *kept)
	}
	Close()
	have, _, _, _, _ = CopyState()

	// a person accepts it, the number they saw only
	if _, err := AcceptOldCopy(have + 7); err == nil {
		t.Fatal("accepted a number nobody saw")
	}
	if _, err := AcceptOldCopy(have); err != nil {
		t.Fatal(err)
	}
	Close()
	if _, err := Load(); err != nil {
		t.Fatalf("after accepting: %v", err)
	}
}

// The store ahead of the keychain (a crash between the two writes, a
// keychain that was locked) is normal: the keychain is raised.
func TestKeychainBehindIsRaised(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	update(t, func(s *State) { s.Hosts["b"] = &Host{Name: "b"} })
	want := *kept
	*kept = 1
	Close()
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	if *kept != want {
		t.Fatalf("keychain %d, want %d", *kept, want)
	}
}

// A store with its key in a file has no keychain to compare with.
func TestNoGuardWithoutKeychain(t *testing.T) {
	sealedStore(t) // key_mode "test"
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	if _, _, guarded, _, _ := CopyState(); guarded {
		t.Fatal("guarded without the keychain")
	}
}

// keychainItems gives the stand-in keychain's number and lets a test
// remove it or put rubbish in it.
func TestMissingOrBrokenCountStops(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	_ = kept
	for name, gk := range map[string]GenerationKeep{
		"removed": {Get: func() (uint64, bool, error) { return 0, false, nil }, Set: func(uint64) error { return nil }},
		"rubbish": {Get: func() (uint64, bool, error) { return 0, false, errors.New("not a number") }, Set: func(uint64) error { return nil }},
	} {
		saved := GenerationKeeper
		GenerationKeeper = gk
		Close()
		_, err := Load()
		var oe *out.Error
		if !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" {
			t.Errorf("%s count: %v", name, err)
		}
		GenerationKeeper = saved
	}
	// a slow keychain lets reading go on, never a change
	saved := GenerationKeeper
	GenerationKeeper = GenerationKeep{Get: func() (uint64, bool, error) { return 0, false, ErrKeychainSlow }, Set: func(uint64) error { return nil }}
	Close()
	if _, err := Load(); err != nil {
		t.Errorf("slow keychain: %v", err)
	}
	err := Update(Save(), func(s *State) error { s.Hosts["b"] = &Host{Name: "b"}; return nil })
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "KEYCHAIN_SLOW" {
		t.Errorf("a write with a slow keychain: %v", err)
	}
	if _, _, err := keptCount(); !errors.Is(err, ErrKeychainSlow) {
		t.Errorf("a slow keychain was asked again at once: %v", err)
	}
	GenerationKeeper = saved
	clearSlowKeychain() // a minute later
	Close()
	update(t, func(s *State) { s.Hosts["b"] = &Host{Name: "b"} })
}

// A new store whose key goes into the keychain gets its number there at
// once.
func TestNewStoreStartsItsCount(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	if *kept == 0 {
		t.Fatal("no number for a new store")
	}
	Close()
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
}

// A new store whose change count cannot go into the keychain is not kept:
// on the next run it would be taken for an old copy and never open.
func TestNewStoreCountNotSaved(t *testing.T) {
	kept := keychainStore(t)
	set := GenerationKeeper.Set
	GenerationKeeper.Set = func(uint64) error { return errors.New("keychain locked") }
	err := Update(Save(), func(s *State) error { s.Hosts["a"] = &Host{Name: "a"}; return nil })
	if err == nil || !strings.Contains(err.Error(), "change count") {
		t.Fatalf("a new store without its count: %v", err)
	}
	if _, err := os.Stat(Path(StoreFile)); !os.IsNotExist(err) {
		t.Fatal("the store without a count was kept")
	}
	GenerationKeeper.Set = set
	update(t, func(s *State) { s.Hosts["a"] = &Host{Name: "a"} })
	if *kept == 0 {
		t.Fatal("no number once the keychain works")
	}
}

// A keyfile-era backup put back after the key moved to the keychain: the
// store says "file", but the keychain holds a count, so it is an old copy.
func TestKeyfileBackupAfterKeychainIsStopped(t *testing.T) {
	kept := keychainStore(t)
	KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
		return bytes.Repeat([]byte{5}, 32), map[string]string{"key_mode": "file"}, nil
	}
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
	Close()
	if err := GenerationKeeper.Set(*kept + 50); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" {
		t.Fatalf("keyfile backup: %v", err)
	}
}

// A deleted store.db while the keychain holds a count stops; it never
// starts empty until a person accepts, which forgets the count.
func TestMissingStoreWithCountStops(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
	if *kept == 0 {
		t.Fatal("no count")
	}
	Close()
	if err := os.Remove(Path(StoreFile)); err != nil {
		t.Fatal(err)
	}
	_, err := Load()
	var oe *out.Error
	if !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" || oe.Exit != out.ExitPolicy {
		t.Fatalf("missing store: %v", err)
	}
	if _, err := os.Stat(Path(StoreFile)); err == nil {
		t.Fatal("a fresh store was made")
	}
	have, k, guardedStore, old, err := CopyState()
	if err != nil || have != 0 || k == 0 || !guardedStore || !old {
		t.Fatalf("copy state %d %d %v %v %v", have, k, guardedStore, old, err)
	}
	if _, err := AcceptOldCopy(3); err == nil {
		t.Fatal("accepted a number nobody saw")
	}
	if _, err := AcceptOldCopy(0); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := GenerationKeeper.Get(); ok {
		t.Fatal("the count was not forgotten")
	}
	Close()
	if _, err := Load(); err != nil {
		t.Fatalf("after accepting: %v", err)
	}
}

// A missing store.db while the keychain holds its count: a caller that
// may look at an old copy (a dry run) never makes a store. Making one
// would start empty and lower the keychain's count, and the next plain
// call would run on the empty store.
func TestLookNeverMakesMissingStore(t *testing.T) {
	for name, emptied := range map[string]bool{"store.db gone": false, "folder emptied": true} {
		t.Run(name, func(t *testing.T) {
			kept := keychainStore(t)
			update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
			*kept = 1 << 40
			Close()
			if err := os.Remove(Path(StoreFile)); err != nil {
				t.Fatal(err)
			}
			if emptied {
				ents, _ := os.ReadDir(Home())
				for _, e := range ents {
					os.RemoveAll(Path(e.Name()))
				}
			}
			OldCopyOK = lookOK
			// a read stops (the folder shows it had a store) or sees none
			s, err := Load()
			var oe *out.Error
			if emptied && (err != nil || len(s.Hosts) != 0) || !emptied && (!errors.As(err, &oe) || oe.Code != "STATE_CORRUPT") {
				t.Fatalf("a look at a missing store: %v", err)
			}
			for _, create := range []func() error{
				func() error { _, err := DB(true); return err },                           // the audit log of a dry run
				func() error { return Update(Save(), func(*State) error { return nil }) }, // a change, by mistake
				CheckWritable,
			} {
				if err := create(); !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" {
					t.Errorf("a store made where one went missing: %v", err)
				}
			}
			OldCopyOK = nil
			if _, err := os.Stat(Path(StoreFile)); !os.IsNotExist(err) {
				t.Fatalf("a store was made: %v", err)
			}
			if *kept != 1<<40 {
				t.Fatalf("the keychain's count went down to %d", *kept)
			}
			if _, err := Load(); !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" {
				t.Fatalf("the plain call after the look: %v", err)
			}
		})
	}
}

// A missing store.db and a keychain that cannot say whether it holds a
// count (slow, locked, broken): no store is made, whoever asks. A keychain
// that answers "none", or no keychain at all, is a new home.
func TestMissingStoreKeychainCannotAnswer(t *testing.T) {
	for name, tc := range map[string]struct {
		get  func() (uint64, bool, error)
		code string // "" : a store is made
	}{
		"slow":        {func() (uint64, bool, error) { return 0, false, ErrKeychainSlow }, "KEYCHAIN_SLOW"},
		"locked":      {func() (uint64, bool, error) { return 0, false, errors.New("locked") }, "STORE_OLD_COPY"},
		"no count":    {func() (uint64, bool, error) { return 0, false, nil }, ""},
		"no keychain": {func() (uint64, bool, error) { return 0, false, NoKeychain{errors.New("off")} }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			keychainStore(t)
			// a new home's key in a file: no count to keep
			KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
				return bytes.Repeat([]byte{5}, 32), map[string]string{"key_mode": "file"}, nil
			}
			set := 0
			GenerationKeeper = GenerationKeep{Get: tc.get, Set: func(uint64) error { set++; return nil }, Del: func() {}}
			for _, look := range []bool{false, true} {
				OldCopyOK = func() bool { return look }
				// a read sees no store, as reads go on beside a slow keychain
				if s, err := Load(); err != nil || len(s.Hosts) != 0 {
					t.Errorf("look %v: a read: %v", look, err)
				}
				_, err := DB(true)
				if tc.code == "" {
					if err != nil {
						t.Fatalf("look %v: a new home: %v", look, err)
					}
					Close()
					os.Remove(Path(StoreFile))
					continue
				}
				var oe *out.Error
				if !errors.As(err, &oe) || oe.Code != tc.code {
					t.Errorf("look %v: %v", look, err)
				}
				if _, err := os.Stat(Path(StoreFile)); !os.IsNotExist(err) {
					t.Fatalf("look %v: a store was made: %v", look, err)
				}
				if set != 0 {
					t.Fatalf("look %v: the keychain's count was set", look)
				}
			}
		})
	}
}

// A handle opened to look at an old copy is never closed by a call that
// may not look (it gets STORE_OLD_COPY and its own handle), and takes no
// writes: a write would raise the old copy's change count until it passed
// for the newest.
func TestOldCopyHandleStaysOpenAndTakesNoWrites(t *testing.T) {
	kept := keychainStore(t)
	update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
	*kept += 5
	Close()
	OldCopyOK = lookOK
	d, err := DB(false)
	if err != nil {
		t.Fatal(err)
	}
	have, err := d.Generation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	OldCopyOK = nil
	var oe *out.Error
	if _, err := DB(false); !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" {
		t.Fatalf("a plain call on an old copy: %v", err)
	}
	OldCopyOK = lookOK
	if s, err := Load(); err != nil || s.Hosts["web"] == nil {
		t.Fatalf("the look after a plain call: %v", err)
	}
	if n, err := d.Generation(t.Context()); err != nil || n != have {
		t.Fatalf("the look-only handle after a plain call: %d %v", n, err)
	}
	for i := range 10 {
		err := Update(Save(), func(s *State) error { s.Hosts["x"] = &Host{Name: "x"}; return nil })
		if !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" {
			t.Fatalf("write %d into an old copy: %v", i, err)
		}
	}
	if n, _ := d.Generation(t.Context()); n != have {
		t.Fatalf("the old copy's count went from %d to %d", have, n)
	}
	OldCopyOK = nil

	// doctor looks, then a person accepts the copy: from then on it opens
	// as the newest, and takes writes
	if _, k, guarded, old, err := CopyState(); err != nil || !guarded || !old || k != *kept {
		t.Fatalf("copy state %d %v %v %v", k, guarded, old, err)
	}
	if _, err := AcceptOldCopy(have); err != nil {
		t.Fatal(err)
	}
	OldCopyOK = lookOK
	update(t, func(s *State) { s.Hosts["x"] = &Host{Name: "x"} })
	OldCopyOK = nil
	update(t, func(s *State) { s.Hosts["y"] = &Host{Name: "y"} })
	if *kept <= have {
		t.Fatalf("the keychain was not raised: %d", *kept)
	}
}

// A store whose key is in a key file, beside a keychain that cannot say
// whether it keeps a change count for this folder: it may be a backup from
// before `secret keychain`, so it is read and never changed (a look may
// look). Each write would raise its count until it passed for the newest.
func TestKeyfileStoreKeychainCannotAnswer(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		code string
	}{
		"locked": {errors.New("locked"), "KEYCHAIN_FAILED"},
		"slow":   {ErrKeychainSlow, "KEYCHAIN_SLOW"},
	} {
		t.Run(name, func(t *testing.T) {
			keychainStore(t)
			KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
				return bytes.Repeat([]byte{5}, 32), map[string]string{"key_mode": "keyfile"}, nil
			}
			update(t, func(s *State) { s.Hosts["web"] = &Host{Name: "web"} })
			if err := GenerationKeeper.Set(1 << 30); err != nil { // the keychain remembers a newer store
				t.Fatal(err)
			}
			Close()
			get := GenerationKeeper.Get
			GenerationKeeper.Get = func() (uint64, bool, error) { return 0, false, tc.err }
			d, err := DB(false)
			if err != nil {
				t.Fatal(err)
			}
			have, _ := d.Generation(t.Context())
			if s, err := Load(); err != nil || s.Hosts["web"] == nil {
				t.Fatalf("a read: %v", err)
			}
			var oe *out.Error
			err = Update(Save(), func(s *State) error { s.Hosts["x"] = &Host{Name: "x"}; return nil })
			if !errors.As(err, &oe) || oe.Code != tc.code || !strings.Contains(oe.Message, "nothing was changed") {
				t.Fatalf("a write: %v", err)
			}
			if tc.code == "KEYCHAIN_FAILED" && !strings.Contains(oe.Hint, "KOMANDO_KEYCHAIN=off") {
				t.Errorf("hint %q", oe.Hint)
			}
			clearSlowKeychain()
			if _, _, _, _, err := CopyState(); err == nil || !strings.Contains(err.Error(), "changes nothing") {
				t.Errorf("doctor's copy state: %v", err) // doctor warns
			}
			Close()
			clearSlowKeychain()
			OldCopyOK = lookOK
			if s, err := Load(); err != nil || s.Hosts["web"] == nil {
				t.Fatalf("a look: %v", err)
			}
			if err := Update(Save(), func(*State) error { return nil }); !errors.As(err, &oe) || (oe.Code != "STORE_OLD_COPY" && oe.Code != tc.code) {
				t.Fatalf("a write in a look: %v", err)
			}
			OldCopyOK = nil
			Close()
			d, _ = DB(false)
			if n, _ := d.Generation(t.Context()); n != have {
				t.Fatalf("the count went from %d to %d", have, n)
			}
			// the keychain answers again: the backup is caught
			GenerationKeeper.Get = get
			clearSlowKeychain()
			Close()
			if _, err := Load(); !errors.As(err, &oe) || oe.Code != "STORE_OLD_COPY" {
				t.Fatalf("once the keychain answers: %v", err)
			}
		})
	}
}

// A first store beside a keychain that cannot be read: a person or a
// script gets one, with its key out of the keychain and a note; an agent
// never does, and nobody does in a folder with a trace of a store. A lock
// file left by a refused attempt, or a plain runtime.json, is no trace.
func TestFirstStoreKeychainCannotBeRead(t *testing.T) {
	for _, tc := range []struct {
		who, trace string
		agent      bool
		code       string // "": made
	}{
		{who: "person", code: ""},
		{who: "person beside a lock file and a plain runtime.json", trace: "litter", code: ""},
		{who: "agent", agent: true, code: "STORE_OLD_COPY"},
		{who: "person, store.key left", trace: "store.key", code: "STORE_OLD_COPY"},
		{who: "person, sealed runtime.json left", trace: "runtime.json", code: "STORE_OLD_COPY"},
	} {
		t.Run(tc.who, func(t *testing.T) {
			keychainStore(t)
			var asked map[string]string
			KeySource = func(meta map[string]string, create bool) ([]byte, map[string]string, error) {
				if create {
					asked = meta
				}
				return bytes.Repeat([]byte{5}, 32), map[string]string{"key_mode": "keyfile"}, nil
			}
			set := 0
			GenerationKeeper = GenerationKeep{
				Get: func() (uint64, bool, error) { return 0, false, errors.New("locked") },
				Set: func(uint64) error { set++; return nil },
				Del: func() {},
			}
			savedAgent, savedNotice := AgentCaller, Notice
			t.Cleanup(func() { AgentCaller, Notice = savedAgent, savedNotice })
			AgentCaller = func() bool { return tc.agent }
			var notes []string
			Notice = func(msg string) { notes = append(notes, msg) }
			if err := ensureHome(); err != nil {
				t.Fatal(err)
			}
			switch tc.trace {
			case "litter":
				os.WriteFile(Path(storeLock), nil, 0o600)
				os.WriteFile(runtimePath(), []byte("{}"), 0o600)
			case "runtime.json":
				os.WriteFile(runtimePath(), append(append([]byte{}, runtimeMagic...), "x"...), 0o600)
			case "store.key":
				os.WriteFile(Path("store.key"), make([]byte, 32), 0o600)
			}
			err := Update(Save(), func(s *State) error { s.Hosts["web"] = &Host{Name: "web"}; return nil })
			if tc.code != "" {
				var oe *out.Error
				if !errors.As(err, &oe) || oe.Code != tc.code || !strings.HasPrefix(oe.Hint, "put store.db back") && !strings.HasPrefix(oe.Hint, "if this folder had a store, put store.db back") {
					t.Fatalf("refused: %v", err)
				}
				if tc.agent != strings.Contains(oe.Hint, "KOMANDO_KEYCHAIN=off") {
					t.Errorf("hint %q", oe.Hint)
				}
				if _, err := os.Stat(DBPath()); !os.IsNotExist(err) {
					t.Fatal("a store was made")
				}
				if len(notes) != 0 || set != 0 {
					t.Fatalf("notes %q, count set %d times", notes, set)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if asked["key_mode"] != "keyfile" {
				t.Errorf("the new key was not kept out of the keychain: %v", asked)
			}
			if len(notes) != 1 || !strings.Contains(notes[0], "could not be read (locked)") || !strings.Contains(notes[0], "KOMANDO_KEYCHAIN=off") {
				t.Errorf("notes %q", notes)
			}
			update(t, func(s *State) { s.Hosts["db"] = &Host{Name: "db"} }) // the same run goes on
			if set != 0 {
				t.Errorf("the count was set %d times", set)
			}
		})
	}
}
