package term

import "strings"

// What a list says on stdout when it shows nothing (S-9.5), in one of two
// forms, so a person reads the same words in every list:
//
//	no SSH keys yet: `komando credential key create NAME`
//	no keys match "user:*"
//
// JSON keeps its empty array.

// NoneYet is the line for an empty list: add is the command that adds one
// ("" for a list komando does not fill), note an aside in brackets.
func NoneYet(things, add string, note ...string) string {
	s := "no " + things + " yet"
	if add != "" {
		s += ": `komando " + add + "`"
	}
	return withNote(s, note)
}

// NoneMatch is the line for a list a filter left empty.
func NoneMatch(things, filter string, note ...string) string {
	return withNote("no "+things+" match "+filter, note)
}

func withNote(s string, note []string) string {
	if n := strings.Join(note, "; "); n != "" {
		s += " (" + n + ")"
	}
	return s + "\n"
}
