package cli

// The questions for the Cache area: read a key, list keys, see how the
// cache is doing, set or delete keys, send any Redis command. The
// storage, cluster and registry commands have theirs next to their Add
// forms (form_storage.go, form_cluster.go, form_registry.go).

func init() {
	conn := formArg{ask: "Which cache?", pick: "cache",
		help: "A Redis, Valkey or Memcached cache from your list. Add one first: komando cache redis add."}
	key := formArg{ask: "Which key?", example: "session:42",
		help: "Its exact name. `komando cache keys` lists them."}
	addFormHints(map[string]formHint{
		"cache get": {args: []formArg{conn, key},
			flags: []formFlag{{name: "limit", ask: "Show at most how many items of a list, set or hash?", example: "100",
				help: "Only for keys that hold many items. A plain text key is shown whole."}}},
		"cache keys": {args: []formArg{conn, {ask: "Which keys? (leave empty for all)", example: "session:*",
			help: "A pattern: * matches anything, so session:* is every key that starts with session:."}},
			flags: []formFlag{{name: "limit", ask: "Show at most how many keys?", example: "100",
				help: "Big caches hold millions of keys, so keep it small for a first look."}}},
		"cache info": {args: []formArg{conn, {ask: "Only one part? (leave empty for a short summary)", example: "memory",
			help: "server, clients, memory, persistence, stats, replication, cpu or keyspace. Empty shows version, memory, clients and hit rate."}},
			flags: []formFlag{{name: "all", ask: "Show every raw field instead of the summary?",
				help: "Only when you left the part above empty."}}},
		"cache set": {args: []formArg{conn,
			{ask: "Which key to set?", example: "feature:dark-mode",
				help: "Its exact name. An old value under this name is replaced."},
			{ask: "Which value?", example: "on",
				help: "Plain text. Never put a password here; `komando credential password add` keeps one."}},
			flags: []formFlag{{name: "ttl", ask: "Delete it by itself after how long? (leave empty to keep it)", example: "30m, 24h or 7d",
				help: "The key's time to live. Empty keeps it until someone deletes it."}}},
		"cache rm": {args: []formArg{conn, {ask: "Which keys to delete? (several: separate them with spaces)", example: "session:42 session:43",
			help: "Exact names, no patterns. --dry-run shows which exist. Deleting needs --allow-dangerous, a person's extra yes."}}},
	})
}

// Next: lines for the cache commands.
func init() {
	addFormHints(map[string]formHint{
		"cache info": {next: []string{"cache keys {} 'user:*'", "cache info {} memory"}},
		"cache keys": {next: []string{"cache get {} KEY", "cache rm {} KEY --dry-run"}},
		"cache get":  {next: []string{"cache set {} KEY VALUE --dry-run", "cache redis raw {} -- TTL KEY", "cache rm {} KEY --dry-run"}},
		"cache set":  {next: []string{"cache get {} KEY"}},
		"cache rm":   {next: []string{"cache keys {} 'user:*'"}},
	})
}

// The questions for `komando cache redis ...` and `cache memcached ...`:
// the inventory verbs of the table (the same questions conn's verbs ask,
// for caches) and raw, which is today's `cache run`. The reads of one key
// at a time (get, keys, info, set, rm) stay under hints of their own above
// until they are removed with the cut's removal step.

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
	edit := invConnHints["conn edit"]
	edit.hide = nil // the table has no -g and -t on edit: only --add-group and --add-tag
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
		cmd + "test": {args: []formArg{invConns}, flags: []formFlag{invWait}},
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
