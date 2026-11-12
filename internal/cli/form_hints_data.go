package cli

// The questions for the Cache area: read a key, list keys, see how the
// cache is doing, set or delete keys, send any Redis command. The
// storage, cluster and registry commands have theirs next to their Add
// forms (form_storage.go, form_cluster.go, form_registry.go).

func init() {
	conn := formArg{ask: "Which cache?", pick: "cache",
		help: "A Redis, Valkey or Memcached cache from your list. Add one first: komando cache add."}
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
				help: "Plain text. Never put a password here; `komando secret set` keeps one."}},
			flags: []formFlag{{name: "ttl", ask: "Delete it by itself after how long? (leave empty to keep it)", example: "30m, 24h or 7d",
				help: "The key's time to live. Empty keeps it until someone deletes it."}}},
		"cache rm": {args: []formArg{conn, {ask: "Which keys to delete? (several: separate them with spaces)", example: "session:42 session:43",
			help: "Exact names, no patterns. --dry-run shows which exist. Deleting needs --allow-dangerous, a person's extra yes."}}},
		"cache run": {args: []formArg{conn,
			{ask: "Which Redis command?", example: "HGETALL",
				help: "One word, like GET, HGETALL, TTL or EXPIRE. Its arguments come next."},
			{ask: "Its arguments? (leave empty when there are none)", example: "user:42",
				help: "Separate them with spaces, like: leaderboard 0 9 WITHSCORES."}},
			flags: []formFlag{{name: "write", ask: "May it change data?",
				help: "No sends only commands known to just read, so nothing can change. Say yes only for SET, DEL, EXPIRE and the like."}}},
	})
}
