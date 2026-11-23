package capability

import "slices"

// Verb is one word of the closed vocabulary: one word, one meaning.
type Verb struct {
	Name    string
	Class   string // inventory, target, check, run, data, life, setup, settings, about
	Meaning string
}

// Verbs returns the closed vocabulary. The slice is a copy.
func Verbs() []Verb { return slices.Clone(verbs) }

var verbs = []Verb{
	{"add", "inventory", "give komando a thing that exists outside it"},
	{"create", "inventory", "komando or the target makes a new thing"},
	{"edit", "inventory", "change saved details"},
	{"list", "inventory", "the contents of the level you are at"},
	{"show", "inventory", "everything about one thing"},
	{"rename", "inventory", "rename and fix every reference"},
	{"remove", "inventory", "take out of komando's list; the real thing is untouched"},
	{"delete", "target", "destroy inside the target"},
	{"test", "check", "can komando reach it and log in"},
	{"check", "check", "compare against a rule, change nothing"},
	{"exec", "run", "run on a target"},
	{"run", "run", "run on this computer"},
	{"raw", "run", "the target's own command language"},
	{"query", "run", "SQL or a MongoDB query"},
	{"shell", "run", "an interactive session, person only"},
	{"backup", "data", "save a whole database to a file"},
	{"restore", "data", "load a saved database back"},
	{"read", "target", "print an object's content"},
	{"move", "target", "move or rename inside the target"},
	{"link", "target", "a time-limited link"},
	{"copy", "data", "copy bytes or an image"},
	{"prune", "target", "delete old things by a rule"},
	{"info", "target", "a summary of the target"},
	{"start", "life", "begin something that keeps running"},
	{"stop", "life", "end something that keeps running"},
	{"status", "life", "state of something that runs"},
	{"install", "setup", "put files on a place"},
	{"uninstall", "setup", "take files off a place"},
	{"trust", "setup", "pin a server's host key"},
	{"discover", "inventory", "find what an account holds and add it to the list"},
	{"get", "settings", "one setting"},
	{"set", "settings", "one setting"},
	{"export", "data", "komando's own file out"},
	{"import", "data", "komando's own file in"},
	{"update", "about", "komando itself"},
	{"version", "about", "komando itself"},
	{"schema", "about", "komando itself"},
	{"doctor", "about", "komando itself"},
}

// configWords are the noun leaves config keeps as named exceptions.
var configWords = []string{"approval-code", "keychain", "passphrase"}
