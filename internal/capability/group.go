package capability

// group: a name on servers, conns and VPNs; @GROUP picks them all. A group
// exists while something is in it. edit comes with the members option
// (gaps.md, deferred).
var groupLeaves = []Leaf{
	{Key: own("group", "", "create"), Args: []Arg{{Name: "GROUP"}, {Name: "TARGET", Selector: true, Many: true}}, Today: []string{"group.add"},
		Short: "Add servers, conns and VPNs matching TARGET to GROUP",
		Example: "  komando group create web web1,web2 --dry-run\n" +
			"  komando group create web web3 web4\n" +
			"  komando group create prod 'tag:live,!staging-*'"},
	{Key: own("group", "", "edit"), Args: oneName, State: New,
		Options: []Option{{Name: "add", Kind: Entry, Repeat: true}, {Name: "remove", Kind: Entry, Repeat: true}}},
	{Key: own("group", "", "list"), Args: []Arg{{Name: "GROUP", Optional: true}}, LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"group.list"},
		Options: []Option{{Name: "limit", Short: "n", Kind: Int, Help: "show at most this many groups and tags each, or members of GROUP (0 = all)"}},
		Short:   "List groups and tags with their members, or one group's members",
		Example: "  komando group list\n  komando group list web"},
	{Key: own("group", "", "show"), Args: []Arg{{Name: "GROUP"}}, LocalRead: true,
		Short:   "Show the members of one group",
		Example: "  komando group show web\n  komando group show web -o json"},
	{Key: own("group", "", "rename"), Args: []Arg{{Name: "OLD"}, {Name: "NEW"}}, Synonyms: []string{"mv"}, Today: []string{"group.rename"},
		Short:   "Rename a group on every server, conn and VPN in it",
		Example: "  komando group rename prod production --dry-run\n  komando group rename web frontend"},
	{Key: own("group", "", "remove"), Args: []Arg{{Name: "GROUP"}, {Name: "TARGET", Selector: true, Many: true, Optional: true}}, Today: []string{"group.rm"},
		Short: "Take entries out of a group, or delete the group (from komando only)",
		Example: "  komando group remove web web2\n" +
			"  komando group remove old-batch --dry-run   # who would leave it\n" +
			"  komando group remove old-batch --yes"},
}
