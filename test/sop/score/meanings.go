package score

import "fmt"

// meanings maps what a task expects (a meaning) to the error codes each
// tree gives for it. It is the one place a rename of a code on the new tree
// is written, and the one table Audit reviews with the cut (Audit E3).
// The "new" column starts as the old codes: the v2.7 cut changes it, in
// the same pull request that renames a code.
var meanings = map[string]map[string][]string{
	"approval:protected": {"old": {"PROTECTED_TARGET"}, "new": {"PROTECTED_TARGET"}},
	"approval:dangerous": {"old": {"POLICY_BLOCKED"}, "new": {"POLICY_BLOCKED"}},
	"flag:write":         {"old": {"WRITE_REQUIRES_FLAG"}, "new": {"WRITE_REQUIRES_FLAG"}},
}

// CodesFor is the error codes a meaning has on a tree ("old" or "new").
func CodesFor(meaning, tree string) ([]string, error) {
	byTree, ok := meanings[meaning]
	if !ok {
		return nil, fmt.Errorf("score: no such meaning %q", meaning)
	}
	codes, ok := byTree[tree]
	if !ok {
		return nil, fmt.Errorf("score: no tree %q for meaning %q", tree, meaning)
	}
	return codes, nil
}
