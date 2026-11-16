package store

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// An account /etc/passwd does not hold (LDAP, sssd) is asked of getent at
// its fixed path; a getent that knows nothing leaves the lookup's error.
func TestAccountHomeAsksGetent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix only: getent")
	}
	savedL, savedG := lookupID, getentPaths
	t.Cleanup(func() { lookupID, getentPaths = savedL, savedG })
	lookupID = func(string) (*user.User, error) { return nil, errors.New("no such user in /etc/passwd") }
	uid := strconv.Itoa(os.Getuid())
	dir := t.TempDir()
	g := filepath.Join(dir, "getent")
	os.WriteFile(g, []byte("#!/bin/sh\necho \"ldapuser:*:"+uid+":100:LDAP User:/home/ldapuser:/bin/sh\"\n"), 0o755)
	getentPaths = []string{filepath.Join(dir, "missing"), g}
	if d, err := lookupAccountHome(); err != nil || d != "/home/ldapuser" {
		t.Fatalf("got %q %v", d, err)
	}
	os.WriteFile(g, []byte("#!/bin/sh\nexit 2\n"), 0o755)
	if d, err := lookupAccountHome(); err == nil {
		t.Fatalf("no entry anywhere: got %q", d)
	}
	// a line for another uid is not this account's
	os.WriteFile(g, []byte("#!/bin/sh\necho \"x:*:99999:1::/home/x:/bin/sh\"\n"), 0o755)
	if d, err := lookupAccountHome(); err == nil {
		t.Fatalf("another uid: got %q", d)
	}
}
