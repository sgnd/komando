package store

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// userSID is the account ID of the user this komando runs as, from the
// process's own token (never from the environment).
func userSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// privateHome gives the folder h the access list privateSDDL: this user and
// SYSTEM only, passed on to everything made inside it.
func privateHome(h string) error {
	user, err := userSID()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(privateSDDL(user))
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// strangersOf lists who besides this user, SYSTEM and the administrators the
// access list of the file or folder p lets in, by account name where
// Windows knows it. A file with no access list at all lets in everyone.
func strangersOf(p string) ([]string, error) {
	user, err := userSID()
	if err != nil {
		return nil, err
	}
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	if dacl == nil {
		return []string{"Everyone (no access list)"}, nil
	}
	var entries []aclEntry
	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return nil, err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			entries = append(entries, aclEntry{Allow: false})
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			entries = append(entries, aclEntry{SID: sid.String(), Allow: true})
		default:
			// object and callback entries: komando does not read them, so
			// it counts them as letting someone in
			entries = append(entries, aclEntry{SID: fmt.Sprintf("an entry of type %d", ace.Header.AceType), Allow: true})
		}
	}
	names := strangers(entries, user)
	for i, s := range names {
		if sid, err := windows.StringToSid(s); err == nil {
			if acct, dom, _, err := sid.LookupAccount(""); err == nil {
				names[i] = acct
				if dom != "" {
					names[i] = dom + `\` + acct
				}
			}
		}
	}
	return names, nil
}

// LooseFiles lists komando's folder and the files and folders inside it
// that someone else may open, each with who.
func LooseFiles() []string {
	var loose []string
	_ = filepath.WalkDir(Home(), func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if who, err := strangersOf(p); err == nil && len(who) > 0 {
			loose = append(loose, fmt.Sprintf("%s (%s)", p, strings.Join(who, ", ")))
		}
		return nil
	})
	return loose
}

// PrivateFix is the commands that make komando's folder private again on
// Windows: the folder's access list set whole (/reset drops every entry
// written on it, /inheritance:r every entry taken from above, then this
// user and SYSTEM are given full control), then every file and folder
// inside takes it over. /inheritance:r with /grant:r alone keeps an entry
// someone wrote for another account.
func PrivateFix() string {
	user, err := userSID()
	if err != nil {
		user = "%USERNAME%"
	} else {
		user = "*" + user
	}
	h := Home()
	return fmt.Sprintf(`icacls "%s" /reset, then icacls "%s" /inheritance:r /grant:r "%s:(OI)(CI)F" "*%s:(OI)(CI)F", then icacls "%s" /reset /T /C`,
		h, h, user, sidSystem, filepath.Join(h, "*"))
}

// tightenHome: on Windows the access list is set when the folder is made;
// doctor checks and fixes one that was already there.
func tightenHome(string) {}
