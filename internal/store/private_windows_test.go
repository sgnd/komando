package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// On Windows a new komando folder gets its own access list, and what is
// made inside takes it over: nobody but this user (and SYSTEM) gets in.
func TestPrivateHomeWindows(t *testing.T) {
	home := filepath.Join(t.TempDir(), "komando")
	t.Setenv("KOMANDO_HOME", home)
	if err := MkdirPrivate("vpn"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path("vpn", "a.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(home, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if ctl, _, err := sd.Control(); err != nil || ctl&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("the folder takes entries from the folder above (control %#x, %v)", ctl, err)
	}
	if loose := LooseFiles(); len(loose) != 0 {
		t.Fatalf("LooseFiles = %q, want none", loose)
	}

	// a file someone gave the computer's users: doctor names it and them
	f := Path("vpn", "shared.txt")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err = windows.SecurityDescriptorFromString("D:P(A;;FA;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(f, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	loose := LooseFiles()
	if len(loose) != 1 || !strings.HasPrefix(loose[0], f+" (") || !strings.Contains(loose[0], "Users") {
		t.Fatalf("LooseFiles = %q, want only %s with Users", loose, f)
	}
	if fix := PrivateFix(); !strings.Contains(fix, "icacls \""+home+"\" /inheritance:r") || !strings.Contains(fix, "/reset /T") {
		t.Fatalf("PrivateFix = %q", fix)
	}
}

// A folder that was there before keeps its access list: komando does not
// rewrite a folder it did not make (doctor reports it instead).
func TestEnsureHomeKeepsOldFolderWindows(t *testing.T) {
	home := t.TempDir()
	t.Setenv("KOMANDO_HOME", home)
	before, err := windows.GetNamedSecurityInfo(home, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureHome(); err != nil {
		t.Fatal(err)
	}
	after, err := windows.GetNamedSecurityInfo(home, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("access list changed: %s -> %s", before, after)
	}
}
