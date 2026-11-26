package capability

// registry: container registries over the OCI Distribution API. Images
// come from builds, so the image area has delete and no create.

var registryProviders = []provider{{name: "oci", connect: []Option{credentialOpt}, entry: "ghcr", url: "registry://myuser@ghcr.io"}}

var imageVerbs = []areaVerb{
	{"image", "list", "registry.list"}, {"image", "show", "registry.inspect"}, {"image", "copy", "registry.copy"},
	{"image", "delete", "registry.rm"}, {"image", "prune", "registry.prune"},
}

var registryLeaves = each(registryProviders, func(p provider) []Leaf {
	out := conns("registry", "registry.add").leaves(p)
	for _, v := range imageVerbs {
		l := areaLeaf("registry", p.name, v.area, v.verb, v.today)
		completeImage(&l, p.entry)
		out = append(out, l)
	}
	return out
})

// completeImage gives an image leaf the arguments, options and texts of
// the command of today it keeps.
func completeImage(l *Leaf, entry string) {
	cmd := "  komando registry oci image " + l.Verb + " "
	switch l.Verb {
	case "list":
		l.Args = []Arg{{Name: "NAME"}, {Name: "REPO", Optional: true}}
		l.Options = []Option{limitOpt}
		l.Short = "List the repositories of a registry, or the tags of one"
		l.Example = cmd + entry + "\n" + cmd + entry + " myorg/api"
	case "show":
		l.Args = []Arg{{Name: "NAME"}, {Name: "IMAGE"}}
		l.Synonyms = []string{"describe"}
		l.Short = "Show an image: its digest, size, platforms and tags"
		l.Example = cmd + entry + " myorg/api:1.4.2\n" + cmd + entry + " myorg/api@sha256:0123 -o json"
	case "copy":
		l.Args = []Arg{{Name: "SRC_CONN:IMAGE"}, {Name: "DST_CONN[:IMAGE]"}}
		l.Output = TargetData
		l.Short = "Copy an image from one registry to another"
		l.Example = cmd + entry + ":myorg/api:1.4.2 harbor:prod/api:1.4.2 --dry-run\n" + cmd + entry + ":myorg/api:1.4.2 harbor:prod/api:1.4.2"
	case "delete":
		l.Args = []Arg{{Name: "NAME"}, {Name: "IMAGE"}}
		l.Short = "Delete an image from a registry"
		l.Example = cmd + entry + " myorg/api:1.3.0 --dry-run\n" + cmd + entry + " myorg/api:1.3.0 --allow-dangerous"
	case "prune":
		l.Args = []Arg{{Name: "NAME"}, {Name: "REPO"}}
		l.Options = []Option{
			{Name: "keep", Kind: Int, Help: "keep the newest N tags"},
			{Name: "match", Kind: String, Help: "only tags that match this pattern"},
			{Name: "older-than", Kind: Duration, Help: "only tags older than this, like 30d"},
		}
		l.Short = "Delete old tags of a repository, keeping the newest"
		l.Example = cmd + entry + " myorg/api --keep 10 --dry-run\n" + cmd + entry + " myorg/api --keep 10 --allow-dangerous"
	}
}
