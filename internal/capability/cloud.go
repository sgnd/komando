package capability

// cloud: a saved cloud account and discover, which adds what the account
// holds to the list. All new work; today only `login aws`
// and the import of AWS servers exist.

var cloudProviders = []provider{
	{name: "alibaba", state: New, connect: []Option{credentialOpt}},
	{name: "aws", state: New, connect: []Option{credentialOpt}},
	{name: "azure", state: New, connect: []Option{credentialOpt}},
	{name: "digitalocean", state: New, connect: []Option{credentialOpt}},
	{name: "gcp", state: New, connect: []Option{credentialOpt}},
	{name: "tencent", state: New, connect: []Option{credentialOpt}},
}

// cloudLogin is today's login command each provider's test carries: the
// person step of cloud sign-in happens in test.
var cloudLogin = map[string]string{"aws": "login.aws", "azure": "login.azure", "gcp": "login.gcp"}

var cloudInventory = inventory{typ: "cloud", guard: "guardProtection"}

var cloudLeaves = each(cloudProviders, func(p provider) []Leaf {
	ls := cloudInventory.leaves(p)
	if id := cloudLogin[p.name]; id != "" {
		for i := range ls {
			if ls[i].Verb == "test" {
				ls[i].Carries = []string{id}
			}
		}
	}
	return append(ls, Leaf{Key: Key{Type: "cloud", Provider: p.name, Verb: "discover"}, Args: oneName, State: New})
})
