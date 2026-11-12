package cli

import "strings"

// What a list says on stdout when it shows nothing (S-9.5), in one of two
// forms, so a person reads the same words in every list:
//
//	no SSH keys yet: `komando key gen NAME`
//	no cache keys match "user:*"
//
// JSON keeps its empty array.

// noneYet is the line for an empty list: add is the command that adds one
// ("" for a list komando does not fill), note an aside in brackets.
func noneYet(things, add string, note ...string) string {
	s := "no " + things + " yet"
	if add != "" {
		s += ": `komando " + add + "`"
	}
	return withNote(s, note)
}

// noneMatch is the line for a list a filter left empty.
func noneMatch(things, filter string, note ...string) string {
	return withNote("no "+things+" match "+filter, note)
}

func withNote(s string, note []string) string {
	if n := strings.Join(note, "; "); n != "" {
		s += " (" + n + ")"
	}
	return s + "\n"
}
