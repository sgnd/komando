package capability

// cache: Redis-compatible caches and memcached. raw (today's cache run)
// does everything the removed get, keys, set, rm and info did.

var cacheProviders = []provider{
	{name: "redis", connect: []Option{credentialOpt}},
	{name: "valkey", state: New, connect: []Option{credentialOpt}},
	{name: "memcached", connect: []Option{credentialOpt}},
}

var cacheLeaves = each(cacheProviders, func(p provider) []Leaf {
	return append(conns("cache", "cache.add").leaves(p), Leaf{
		Key:  Key{Type: "cache", Provider: p.name, Verb: "raw"},
		Args: []Arg{{Name: "NAME"}, {Name: "COMMAND", Many: true}}, Options: []Option{writeOpt},
		Output: TargetData, State: p.state,
		Today: []string{"cache.run"}, Carries: idsOf("cache", "get", "info", "keys", "rm", "set"),
	})
})
