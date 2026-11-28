package cli

// The questions for `komando cache redis ...` and `cache memcached ...`:
// the inventory verbs of the table (the same questions conn's verbs ask,
// for caches) and raw, which is today's `cache run`.

func init() {
	hints := map[string]formHint{}
	for _, p := range []struct{ word, kind, what string }{{"redis", "Redis or Valkey", "Redis"}, {"memcached", "Memcached", "Memcached"}} {
		for k, h := range inventoryHints("cache", p.word, "cache", "Caches", p.kind) {
			hints[k] = h
		}
		hints["cache "+p.word+" raw"] = cacheRawHint(p.what, formArg{ask: "Which cache?", pick: "cache",
			help: "A cache from your list. Add one first: komando cache redis add or komando cache memcached add."})
	}
	addFormHints(hints)
}

// inventoryHints are the questions of the seven inventory verbs of one
// provider of a type whose entries are conns: add asks the questions of
// the form group (of one kind when kindLabel is set), the others ask for
// the entry. The pickers offer the conns of the type's family (db for
// database).
func inventoryHints(typ, provider, noun, group, kindLabel string) map[string]formHint {
	fam := familyOfType(typ)
	pick := formArg{ask: "Which " + noun + "?", pick: fam, help: "A " + noun + " from your list. Add one first: komando " + typ + " " + provider + " add."}
	cmd := typ + " " + provider + " "
	edit := invEntryEdit
	edit.args = []formArg{pick}
	return map[string]formHint{
		typ + " " + provider: {},
		cmd + "add": {form: func(cl *call) []formGroup { return formKindOnly(cl, group, kindLabel) },
			next: []string{cmd + "test {}", cmd + "show {}"}},
		cmd + "edit": edit,
		cmd + "list": {args: []formArg{{ask: "Which " + noun + "s? (leave empty for all)", pick: fam, free: true,
			help: "Pick one, or type @group or several names separated by commas."}}},
		cmd + "remove": {args: []formArg{{ask: "Which " + noun + "s should come off your list?", pick: fam, free: true,
			help: "Only komando's list changes; the " + noun + " itself is not touched."}}},
		cmd + "rename": {args: []formArg{{ask: "Which " + noun + " do you want to rename?", pick: fam,
			help: "Groups, notes and everything else that names it are changed too."}, invNewName}},
		cmd + "show": {args: []formArg{pick}},
		cmd + "test": {args: []formArg{{ask: "Which " + noun + "s?", pick: fam, free: true,
			help: "Pick one, or type @group, tag:prod or several names separated by commas."}}, flags: []formFlag{invWait}},
	}
}

func cacheRawHint(what string, pick formArg) formHint {
	return formHint{args: []formArg{pick,
		{ask: "Which " + what + " command?", example: "HGETALL",
			help: "One word, like GET, HGETALL, TTL or EXPIRE. Its arguments come next."},
		{ask: "Its arguments? (leave empty when there are none)", example: "user:42",
			help: "Separate them with spaces, like: leaderboard 0 9 WITHSCORES."}},
		flags: []formFlag{{name: "write", ask: "May it change data?",
			help: "No sends only commands known to just read, so nothing can change. Say yes only for SET, DEL, EXPIRE and the like."}}}
}

// formKindOnly is the Add group of a family with only the kind of one
// provider, so `cache redis add` asks the Redis questions and no others.
func formKindOnly(cl *call, group, kindLabel string) []formGroup {
	if kindLabel == "" {
		return formGroupNamed(cl, group)
	}
	var out []formGroup
	for _, g := range formGroupNamed(cl, group) {
		g.kinds = append([]formKind(nil), g.kinds...)
		for _, k := range g.kinds {
			if k.label == kindLabel {
				g.kinds = []formKind{k}
				out = append(out, g)
			}
		}
	}
	return out
}
