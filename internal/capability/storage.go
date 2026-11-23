package capability

// storage: buckets and file shares. The object area stays whole; link only where the service makes time-limited links.

var storageProviders = []provider{
	{name: "s3", connect: []Option{credentialOpt}},
	{name: "gcs", connect: []Option{credentialOpt}},
	{name: "azblob", connect: []Option{credentialOpt}},
	{name: "sftp", connect: []Option{credentialOpt}},
	{name: "ftp", connect: []Option{credentialOpt}}, // with ftps
	{name: "smb", connect: []Option{credentialOpt}},
	{name: "webdav", connect: []Option{credentialOpt}},
}

var linkProviders = []string{"s3", "gcs", "azblob"}

var objectVerbs = []areaVerb{
	{"object", "list", "storage.list"}, {"object", "read", "storage.cat"}, {"object", "create", "storage.mkdir"},
	{"object", "move", "storage.mv"}, {"object", "delete", "storage.rm"},
}

var storageLeaves = each(storageProviders, func(p provider) []Leaf {
	out := conns("storage", "storage.add").leaves(p)
	for _, v := range objectVerbs {
		l := areaLeaf("storage", p.name, v.area, v.verb, v.today)
		if v.verb == "move" {
			// chmod rides on move until the open question on --mode is settled
			l.Options = []Option{{Name: "mode", Kind: String, Help: "change the mode, as chmod does"}}
			l.Synonyms = []string{"mv"}
			l.Carries = []string{"storage.chmod"}
		}
		out = append(out, l)
	}
	for _, name := range linkProviders {
		if name == p.name {
			out = append(out, areaLeaf("storage", p.name, "object", "link", "storage.link"))
		}
	}
	return out
})
