package capability

// registry: container registries over the OCI Distribution API. Images
// come from builds, so the image area has delete and no create.

var registryProviders = []provider{{name: "oci", connect: []Option{credentialOpt}}}

var imageVerbs = []areaVerb{
	{"image", "list", "registry.list"}, {"image", "show", "registry.inspect"}, {"image", "copy", "registry.copy"},
	{"image", "delete", "registry.rm"}, {"image", "prune", "registry.prune"},
}

var registryLeaves = each(registryProviders, func(p provider) []Leaf {
	out := conns("registry", "registry.add").leaves(p)
	for _, v := range imageVerbs {
		l := areaLeaf("registry", p.name, v.area, v.verb, v.today)
		if v.verb == "copy" {
			l.Output = TargetData
		}
		out = append(out, l)
	}
	return out
})
