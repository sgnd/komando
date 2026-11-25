package capability

// storage: buckets and file shares. The object area stays whole; link only where the service makes time-limited links.

var storageProviders = []provider{
	{name: "s3", connect: []Option{credentialOpt}, entry: "backups", url: "'s3://ACCESS_KEY_ID@my-bucket/backups?region=us-east-1'"},
	{name: "gcs", connect: []Option{credentialOpt}, entry: "backups", url: "gs://my-bucket/backups"},
	{name: "azblob", connect: []Option{credentialOpt}, entry: "backups", url: "azblob://ACCOUNT@my-container/backups"},
	{name: "sftp", connect: []Option{credentialOpt}, entry: "backups", url: "sftp://deploy@files.example.com/uploads"},
	{name: "ftp", connect: []Option{credentialOpt}, entry: "backups", url: "ftps://deploy@files.example.com/public_html"}, // with ftps
	{name: "smb", connect: []Option{credentialOpt}, entry: "backups", url: "smb://alice@fileserver.corp.lan/team/reports"},
	{name: "webdav", connect: []Option{credentialOpt}, entry: "backups", url: "webdavs://alice@cloud.example.com/remote.php/dav/files/alice"},
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
		completeObject(&l, p.name, p.entry)
		if v.verb == "move" {
			// chmod rides on move until the open question on --mode is settled
			l.Options = append(l.Options, Option{Name: "mode", Kind: String, Help: "change the mode, as chmod does"})
			l.Synonyms = []string{"mv"}
			l.Carries = []string{"storage.chmod"}
		}
		out = append(out, l)
	}
	for _, name := range linkProviders {
		if name == p.name {
			l := areaLeaf("storage", p.name, "object", "link", "storage.link")
			completeObject(&l, p.name, p.entry)
			out = append(out, l)
		}
	}
	return out
})

// completeObject gives an object leaf the arguments, options and texts of
// the command of today it keeps.
func completeObject(l *Leaf, provider, entry string) {
	cmd := "  komando storage " + provider + " object " + l.Verb + " "
	switch l.Verb {
	case "list":
		l.Args = []Arg{{Name: "NAME"}, {Name: "PREFIX", Optional: true}}
		l.Options = []Option{
			{Name: "all-versions", Kind: Bool, Help: "S3: every version and delete marker under the prefix"},
			{Name: "limit", Short: "n", Kind: Int, Default: "1000", Help: "the most entries to show"},
			{Name: "recursive", Short: "r", Kind: Bool, Help: "include everything below the prefix, not just one level"},
		}
		l.Short = "List the objects under a folder of a " + provider + " storage"
		l.Example = cmd + entry + " 2026/\n" + cmd + entry + " 2026/ --recursive --limit 50"
	case "read":
		l.Args = []Arg{{Name: "NAME"}, {Name: "OBJECT"}}
		l.Options = []Option{
			{Name: "head", Kind: Int, Help: "only the first N lines"},
			{Name: "tail", Kind: Int, Help: "only the last N lines"},
			{Name: "max-bytes", Kind: Bytes, Default: "1MiB", Help: "read at most this many bytes, like 4MiB"},
		}
		l.Short = "Show the text of an object in " + article(provider) + " storage"
		l.Example = cmd + entry + " logs/app.log --tail 50\n" + cmd + entry + " config/app.env"
	case "create":
		l.Args = []Arg{{Name: "NAME"}, {Name: "PATH"}}
		l.Short = "Make a folder in " + article(provider) + " storage"
		l.Example = cmd + entry + " reports/2026 --dry-run\n" + cmd + entry + " reports/2026"
	case "move":
		l.Args = []Arg{{Name: "NAME"}, {Name: "SRC"}, {Name: "DST"}}
		l.Options = []Option{{Name: "overwrite", Kind: Bool, Help: "replace a file already at DST (never a folder)"}}
		l.Short = "Move or rename an object in " + article(provider) + " storage"
		l.Example = cmd + entry + " old.txt new.txt --dry-run\n" + cmd + entry + " old.txt archive/old.txt"
	case "delete":
		l.Args = []Arg{{Name: "NAME"}, {Name: "OBJECT", Optional: true, Many: true}}
		l.Options = []Option{
			{Name: "all-versions", Kind: Bool, Help: "S3: also remove every old version and delete marker"},
			{Name: "max-remove", Kind: Int, Default: "1000", Help: "refuse when more than this many objects would be removed"},
			{Name: "older-than", Kind: Duration, Help: "with --prefix: only objects older than this, like 30d"},
			{Name: "prefix", Kind: String, Help: "remove everything under this folder (like daily/)"},
		}
		l.Short = "Delete objects from " + article(provider) + " storage"
		l.Example = cmd + entry + " --prefix daily/ --older-than 30d --dry-run\n" + cmd + entry + " old.txt --allow-dangerous"
	case "link":
		l.Args = []Arg{{Name: "NAME"}, {Name: "OBJECT"}}
		l.Options = []Option{
			{Name: "endpoint", Kind: String, Help: "sign the link for this address, like https://files.example.com"},
			{Name: "expires", Kind: Duration, Default: "1h", Help: "how long the link works, like 30m, 24h or 7d (at most 7d)"},
		}
		l.Short = "Make a time-limited link to an object in " + article(provider) + " storage"
		l.Example = cmd + entry + " reports/q3.pdf --dry-run\n" + cmd + entry + " reports/q3.pdf --expires 24h"
	}
}

// article is "a s3" or "an sftp" for the texts of a provider's leaves.
func article(provider string) string {
	if provider[0] == 'a' {
		return "an " + provider
	}
	return "a " + provider
}
