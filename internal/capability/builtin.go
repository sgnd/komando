package capability

// The built-ins about komando and every entry, and the actions that span
// types. Each is a verb at the top: Type is "".

func top(verb string) Key { return Key{Verb: verb} }

var copyOpts = []Option{
	{Name: "sync", Kind: Bool, Help: "send only what changed (compares size, mode and time); the source is a folder"},
	{Name: "delete", Kind: Bool, Needs: []string{"sync"}, Help: "with --sync: also remove files that the source does not have"},
	{Name: "emptied", Kind: String, Repeat: true, Needs: []string{"delete"}, Help: "with --delete: this folder of the source is empty on purpose (repeatable)"},
	{Name: "exclude", Kind: String, Repeat: true, Needs: []string{"sync"}, Help: "with --sync: skip names or paths that match this glob (repeatable)"},
	{Name: "recursive", Short: "r", Kind: Bool, Conflicts: []string{"sync"}, Help: "copy folders (a trailing / on the source copies its contents)"},
	{Name: "sudo", Short: "s", Kind: Bool, Help: "single files: install as root (to a server) or read as root (from one); with --sync, write a folder as root"},
	{Name: "parents", Short: "p", Kind: Bool, Conflicts: []string{"sync"}, Help: "to a server: create missing parent folders"},
	{Name: "mode", Kind: String, Conflicts: []string{"sync"}, Help: "to a server: file mode, like 0755"},
	{Name: "overwrite", Kind: Bool, Conflicts: []string{"sync"}, Help: "to this computer: replace files that already exist"},
	{Name: "progress", Kind: Bool, Help: "show how far the copy is"},
	{Name: "continue", Kind: Bool, Conflicts: []string{"sync"}, Help: "go on with a single file that was cut off"},
	{Name: "size", Kind: Bytes, Conflicts: []string{"sync"}, Help: "from stdin (-): how many bytes it sends, like 10MiB"},
}

var builtinLeaves = []Leaf{
	{Key: top("list"), Args: []Arg{{Name: "SELECTOR", Selector: true, Optional: true}}, LocalRead: true, Today: []string{"list"}},
	{Key: top("test"), Args: []Arg{{Name: "NAME", Selector: true, Optional: true}}, Options: []Option{endOpt},
		Today: []string{"test"}, Carries: []string{"logout.aws"}},
	{Key: top("update"), LeavesHome: true, Today: []string{"update"}},
	{Key: top("version"), LocalRead: true, Today: []string{"version"}},
	{Key: top("schema"), Args: []Arg{{Name: "PATH", Many: true, Optional: true}}, LocalRead: true, Today: []string{"schema"}},
	{Key: top("doctor"), LocalRead: true, Today: []string{"doctor"}},
	{Key: top("copy"), Args: []Arg{{Name: "SOURCE"}, {Name: "DESTINATION"}}, Options: copyOpts,
		Short:   "Copy files between this computer, servers and file storage",
		Example: "  komando copy ./app.tar.gz web1:/tmp/app.tar.gz\n  komando copy ./site @web:/var/www/site --sync --dry-run\n  komando copy web1:/var/log/nginx/error.log ./logs/\n  komando copy ./db.sql.gz backups:2026/db.sql.gz",
		Output:  TargetData, Stops: []string{"localWriteProtected", "protectedFilesOf"},
		Carries: []string{"cp", "upload", "download", "sync", "storage.download", "storage.upload"}},
	{Key: top("import"), Args: []Arg{{Name: "FILE"}}, Stops: []string{"reservedSecret"}, Today: []string{"import"}},
	{Key: top("export"), Args: []Arg{{Name: "FILE"}}, Stops: []string{"localWriteProtected", "reservedSecret"}, Today: []string{"export"},
		Options: []Option{
			{Name: "sealed", Kind: Bool, Help: "seal the file with a passphrase"},
			{Name: "for-phone", Kind: Bool, Help: "a sealed file for the phone app (its fate is open)"},
		}},
	// status shows server sessions too, so it lists what job list did in v0.17
	{Key: top("status"), LocalRead: true, Today: []string{"status"}, Carries: []string{"job.list"}},
}
