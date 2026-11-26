package capability

// cache: Redis-compatible caches and memcached. raw (today's cache run)
// does everything the removed get, keys, set, rm and info did.

var cacheProviders = []provider{
	{name: "redis", connect: []Option{credentialOpt}, url: "redis://default@10.0.0.7:6379/0", entry: "prod-redis", rawExample: "HGETALL user:42", writeExample: "EXPIRE session:42 3600"},
	{name: "valkey", state: New, connect: []Option{credentialOpt}, url: "redis://default@10.0.0.7:6379/0", entry: "prod-redis", rawExample: "HGETALL user:42", writeExample: "EXPIRE session:42 3600"},
	{name: "memcached", connect: []Option{credentialOpt}, url: "memcached://cache.internal:11211", entry: "app", rawExample: "stats", writeExample: "flush_all"},
}

var cacheLeaves = each(cacheProviders, func(p provider) []Leaf {
	return append(conns("cache", "cache.add").leaves(p), Leaf{
		Key:  Key{Type: "cache", Provider: p.name, Verb: "raw"},
		Args: []Arg{{Name: "NAME"}, {Name: "COMMAND", Many: true, Dash: true}}, Options: []Option{writeOpt},
		Output: TargetData, State: p.state,
		Short:   "Send one " + p.name + " command and show the reply",
		Example: "  komando cache " + p.name + " raw " + p.entry + " -- " + p.rawExample + "\n  komando cache " + p.name + " raw " + p.entry + " --write -- " + p.writeExample + " --dry-run",
		Today:   []string{"cache.run"}, Carries: idsOf("cache", "get", "info", "keys", "rm", "set"),
	})
})
