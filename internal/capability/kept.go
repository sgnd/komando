package capability

// keptUntilPhone (pre-cut, row C369) is today's ssh-gate, kept in v0.18.0
// under today's words and keys: the phone app needs it until its own engine
// ships. The first CLI release after phase 1 of the phone app removes these
// leaves. Their words are outside the closed vocabulary and the top-level
// names on purpose; the vocabulary tests skip only these leaves.
var keptUntilPhone = []Leaf{
	{Key: top("ssh-gate"), Args: []Arg{{Name: "COMMAND", Many: true, Optional: true}}, Today: []string{"ssh-gate"}},
	{Key: own("ssh-gate", "", "line"), Today: []string{"ssh-gate.line"}},
	{Key: own("ssh-gate", "", "status"), Today: []string{"ssh-gate.status"}},
}

// isKeptUntilPhone reports whether k is one of keptUntilPhone's leaves.
func isKeptUntilPhone(k Key) bool {
	for _, l := range keptUntilPhone {
		if l.Key == k {
			return true
		}
	}
	return false
}
