package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// The access list komando gives its folder on Windows: this user and
// SYSTEM, full control, passed on to everything inside, nothing taken
// from the folder above.
func TestPrivateSDDL(t *testing.T) {
	got := privateSDDL("S-1-5-21-1-2-3-1001")
	if want := "D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)(A;OICI;FA;;;SY)"; got != want {
		t.Fatalf("privateSDDL = %q, want %q", got, want)
	}
}

func TestStrangers(t *testing.T) {
	const me = "S-1-5-21-1-2-3-1001"
	for _, c := range []struct {
		name    string
		entries []aclEntry
		want    []string
	}{
		{"only me and the system", []aclEntry{{me, true}, {sidSystem, true}}, nil},
		{"administrators and owner stand-ins", []aclEntry{{me, true}, {sidAdmins, true}, {sidCreatorOwner, true}, {sidOwnerRights, true}}, nil},
		{"users of the computer", []aclEntry{{me, true}, {"S-1-5-32-545", true}}, []string{"S-1-5-32-545"}},
		{"authenticated users and everyone, once each", []aclEntry{{"S-1-5-11", true}, {"S-1-1-0", true}, {"S-1-5-11", true}}, []string{"S-1-5-11", "S-1-1-0"}},
		{"another person", []aclEntry{{"S-1-5-21-1-2-3-1002", true}}, []string{"S-1-5-21-1-2-3-1002"}},
		{"a deny entry lets nobody in", []aclEntry{{"S-1-1-0", false}, {me, true}}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := strangers(c.entries, me); !slices.Equal(got, c.want) {
				t.Fatalf("strangers = %q, want %q", got, c.want)
			}
		})
	}
}

// O17: every folder ensureHome makes, the ones above komando's folder
// too, is made private (on Windows, a parent made with the drive root's
// access list lets any user rename it); a folder that was there is left
// as it is, and when one cannot be made private all it made goes again.
func TestEnsureHomeMakesParentsPrivate(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "a", "b", "komando")
	t.Setenv("KOMANDO_HOME", home)
	saved := makePrivate
	t.Cleanup(func() { makePrivate = saved })
	var got []string
	makePrivate = func(d string) error { got = append(got, d); return nil }
	if err := EnsureHome(); err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(base, "a"), filepath.Join(base, "a", "b"), home}
	if !slices.Equal(got, want) {
		t.Fatalf("made private: %q, want %q", got, want)
	}
	for _, d := range want {
		if fi, err := os.Stat(d); err != nil || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, fi.Mode(), err)
		}
	}
	got = nil
	if err := EnsureHome(); err != nil || len(got) != 0 {
		t.Fatalf("a folder that is there: %q %v", got, err)
	}

	home = filepath.Join(base, "c", "d", "komando")
	t.Setenv("KOMANDO_HOME", home)
	makePrivate = func(d string) error {
		if d == filepath.Join(base, "c", "d") {
			return errors.New("no access lists here")
		}
		return nil
	}
	if err := EnsureHome(); err == nil {
		t.Fatal("a folder that cannot be made private was kept")
	}
	if _, err := os.Stat(filepath.Join(base, "c")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the folders it made are still there: %v", err)
	}
}

// A new komando folder is private at once; MkdirPrivate makes the folder
// first when a subfolder is asked for before anything else.
func TestMkdirPrivateMakesHome(t *testing.T) {
	home := filepath.Join(t.TempDir(), "komando")
	t.Setenv("KOMANDO_HOME", home)
	if err := MkdirPrivate("vpn"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{home, filepath.Join(home, "vpn")} {
		fi, err := os.Stat(d)
		if err != nil || !fi.IsDir() {
			t.Fatalf("%s: %v", d, err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o700 {
			t.Errorf("%s has mode %v, want 0700", d, fi.Mode().Perm())
		}
	}
}
