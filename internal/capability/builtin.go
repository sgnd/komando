package capability

// The built-ins about komando and every entry, and the actions that span
// types. Each is a verb at the top: Type is "".

func top(verb string) Key { return Key{Verb: verb} }

var copyOpts = []Option{
	{Name: "sync", Kind: Bool, Help: "send only what changed (compares size, mode and time)"},
	{Name: "delete", Kind: Bool, Needs: []string{"sync"}, Help: "delete what the source does not have"},
	{Name: "exclude", Kind: String, Repeat: true, Help: "leave out paths that match"},
}

var builtinLeaves = []Leaf{
	{Key: top("list"), Args: []Arg{{Name: "SELECTOR", Selector: true, Optional: true}}, LocalRead: true, Today: []string{"list"}},
	{Key: top("test"), Args: []Arg{{Name: "NAME", Selector: true, Optional: true}}, Options: []Option{endOpt},
		Today: []string{"test"}, Carries: []string{"logout.aws"}},
	{Key: top("update"), LeavesHome: true, Today: []string{"update"}},
	{Key: top("version"), LocalRead: true, Today: []string{"version"}},
	{Key: top("schema"), Args: []Arg{{Name: "PATH", Many: true, Optional: true}}, LocalRead: true, Today: []string{"schema"}},
	{Key: top("doctor"), LocalRead: true, Today: []string{"doctor"}},
	{Key: top("copy"), Args: []Arg{{Name: "SOURCE", Many: true}, {Name: "DESTINATION"}}, Options: copyOpts,
		Output: TargetData, Stops: []string{"localWriteProtected", "protectedFilesOf"},
		Carries: []string{"cp", "upload", "download", "sync", "storage.download", "storage.upload"}},
	{Key: top("import"), Args: []Arg{{Name: "FILE"}}, Stops: []string{"reservedSecret"}, Today: []string{"import"}},
	{Key: top("export"), Args: []Arg{{Name: "FILE"}}, Stops: []string{"localWriteProtected"}, Today: []string{"export"},
		Options: []Option{
			{Name: "sealed", Kind: Bool, Help: "seal the file with a passphrase"},
			{Name: "for-phone", Kind: Bool, Help: "a sealed file for the phone app (its fate is open)"},
		}},
	// status shows server sessions too, so it lists what job list did
	{Key: top("status"), LocalRead: true, Today: []string{"status"}, Carries: []string{"job.list"}},
}
