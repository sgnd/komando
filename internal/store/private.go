package store

import (
	"os"
	"slices"
)

// Windows keeps a folder private through its access list (DACL), not a
// file mode: 0700 and 0600 do nothing there, and a folder made under C:\
// lets every user of the computer read it. So komando gives its folder an
// access list of its own when it makes it (privateHome), and doctor reads
// the access list of everything inside (LooseFiles on Windows).

// Well-known Windows account IDs (SIDs).
const (
	sidSystem       = "S-1-5-18"     // the operating system itself
	sidAdmins       = "S-1-5-32-544" // the computer's administrators
	sidCreatorOwner = "S-1-3-0"      // stands for whoever makes a file inside
	sidOwnerRights  = "S-1-3-4"      // the owner of the file
)

// privateSDDL is the access list komando's folder gets on Windows, in the
// SDDL text form: full control (FA) for the user whose account ID is user
// and for SYSTEM, passed on to every file (OI) and folder (CI) inside, and
// nothing taken from the folder above (P, protected).
func privateSDDL(user string) string {
	return "D:P(A;OICI;FA;;;" + user + ")(A;OICI;FA;;;SY)"
}

// aclEntry is one entry of an access list: whom it lets in, and whether it
// is an entry that lets in (an allow entry). Deny entries take access
// away, so they never make a file less private.
type aclEntry struct {
	SID   string
	Allow bool
}

// strangers lists the account IDs that entries let in besides user, SYSTEM
// and the administrators (who can take any file anyway), each once and in
// order. CREATOR OWNER and OWNER RIGHTS stand for the file's owner.
func strangers(entries []aclEntry, user string) []string {
	var out []string
	for _, e := range entries {
		if !e.Allow {
			continue
		}
		switch e.SID {
		case user, sidSystem, sidAdmins, sidCreatorOwner, sidOwnerRights:
			continue
		}
		if !slices.Contains(out, e.SID) {
			out = append(out, e.SID)
		}
	}
	return out
}

// MkdirPrivate makes the folder parts inside komando's folder, and
// komando's folder first when it is missing, readable by this user only.
func MkdirPrivate(parts ...string) error {
	if err := ensureHome(); err != nil {
		return err
	}
	return os.MkdirAll(Path(parts...), 0o700)
}
