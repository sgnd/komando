package cloud

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tobischo/gokeepasslib/v3"
)

// KeePass reads one field of an entry in a KeePass or KeePassXC file
// (KDBX 3.1 and 4). ref is FILE#GROUP/.../ENTRY[#FIELD]; the field is the
// password unless named (UserName, URL, Notes, or a custom one). The file is
// opened with KOMANDO_KDBX_PASSWORD and/or the key file KOMANDO_KDBX_KEYFILE.
func KeePass(ref string) (string, error) {
	file, rest, ok := strings.Cut(ref, "#")
	if !ok || rest == "" {
		return "", errors.New("kdbx: references are kdbx:FILE#GROUP/ENTRY or kdbx:FILE#GROUP/ENTRY#FIELD")
	}
	entryPath, field, _ := strings.Cut(rest, "#")
	if field == "" {
		field = "Password"
	}
	if strings.HasPrefix(file, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			file = filepath.Join(home, file[2:])
		}
	}
	pw, keyFile := UnlockEnv("KOMANDO_KDBX_PASSWORD"), UnlockEnv("KOMANDO_KDBX_KEYFILE")
	var creds *gokeepasslib.DBCredentials
	var err error
	switch {
	case pw != "" && keyFile != "":
		creds, err = gokeepasslib.NewPasswordAndKeyCredentials(pw, keyFile)
	case keyFile != "":
		creds, err = gokeepasslib.NewKeyCredentials(keyFile)
	case pw != "":
		creds = gokeepasslib.NewPasswordCredentials(pw)
	default:
		return "", errors.New("kdbx: set KOMANDO_KDBX_PASSWORD (and/or KOMANDO_KDBX_KEYFILE) to open the file")
	}
	if err != nil {
		return "", fmt.Errorf("kdbx: key file: %w", err)
	}
	f, err := os.Open(file)
	if err != nil {
		return "", fmt.Errorf("kdbx: %w", err)
	}
	defer f.Close()
	db := gokeepasslib.NewDatabase()
	db.Credentials = creds
	if err := gokeepasslib.NewDecoder(f).Decode(db); err != nil {
		return "", fmt.Errorf("kdbx: cannot open %s (wrong password or key file?): %v", filepath.Base(file), err)
	}
	if err := db.UnlockProtectedEntries(); err != nil {
		return "", fmt.Errorf("kdbx: %w", err)
	}
	names := strings.Split(strings.Trim(entryPath, "/"), "/")
	if len(names) == 0 || names[len(names)-1] == "" {
		return "", errors.New("kdbx: name the entry: kdbx:FILE#GROUP/ENTRY")
	}
	groups := db.Content.Root.Groups
	// the top group (often the database's name) may be left out
	if len(groups) == 1 && len(names) > 1 && groups[0].Name == names[0] {
		names = names[1:]
	}
	var entries []gokeepasslib.Entry
	if len(groups) == 1 {
		entries, groups = groups[0].Entries, groups[0].Groups
	}
	for _, g := range names[:len(names)-1] {
		found := false
		for _, x := range groups {
			if x.Name == g {
				entries, groups, found = x.Entries, x.Groups, true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("kdbx: no group %q", g)
		}
	}
	title := names[len(names)-1]
	for i := range entries {
		e := &entries[i]
		if e.GetTitle() != title {
			continue
		}
		for _, v := range e.Values {
			if strings.EqualFold(v.Key, field) {
				return v.Value.Content, nil
			}
		}
		return "", fmt.Errorf("kdbx: entry %q has no field %q", title, field)
	}
	return "", fmt.Errorf("kdbx: no entry %q", entryPath)
}
