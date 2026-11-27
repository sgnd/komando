package capability

// policy: the rules that block destructive commands, built in and your own.
var policyLeaves = []Leaf{
	{Key: own("policy", "", "check"), Args: []Arg{{Name: "COMMAND", Many: true}}, LocalRead: true, Today: []string{"policy.check"},
		Options: []Option{{Name: "conn-kind", Kind: String, Help: "rate the argument for a conn kind instead (a command document as JSON)"}},
		Short:   "Check whether a command would be blocked",
		Example: "  komando policy check 'rm -rf /var/www'\n" +
			"  if komando policy check \"$CMD\" >/dev/null; then echo allowed; fi\n" +
			"  komando policy check --conn-kind postgres 'delete from users'\n" +
			"  komando policy check --conn-kind redis FLUSHALL"},
	{Key: own("policy", "", "create"), Args: []Arg{{Name: "REGEX"}}, Today: []string{"policy.deny"},
		Short:   "Add a deny rule (a Go regular expression)",
		Example: "  komando policy create 'kubectl\\s+delete' --dry-run\n  komando policy create 'kubectl\\s+delete'"},
	{Key: own("policy", "", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"policy.list"},
		Options: []Option{{Name: "limit", Short: "n", Kind: Int, Help: "show at most this many rules of each kind (0 = all)"}},
		Short:   "List the built-in rules and your deny rules",
		Example: "  komando policy list\n  komando policy list -n 5 -o json"},
	{Key: own("policy", "", "show"), Args: []Arg{{Name: "RULE"}}, LocalRead: true, Today: []string{"policy.show"},
		Short:   "Show one rule: what it stops and where it is off",
		Example: "  komando policy show docker-prune\n  komando policy show rm-root -o json"},
	{Key: own("policy", "", "edit"), Args: []Arg{{Name: "RULE"}}, Today: []string{"policy.edit"},
		Options: []Option{{Name: "off", Kind: Bool, Help: "switch the rule off; --off=false switches it on again everywhere"},
			{Name: "add-server", Kind: Entry, Repeat: true, List: true, Help: "with --off: only on these servers"},
			{Name: "add-group", Kind: Entry, Repeat: true, List: true, Help: "with --off: only on the servers in these groups as they are now"},
			{Name: "rm-server", Kind: Entry, Repeat: true, List: true, Help: "switch the rule on again on these servers"},
			{Name: "rm-group", Kind: Entry, Repeat: true, List: true, Help: "switch the rule on again on the servers these groups named"}},
		Short: "Switch a rule off or on, everywhere or on some servers",
		Example: "  komando policy edit docker-prune --off --add-server build1\n" +
			"  komando policy edit pkg-remove-essential --off --add-group lab\n" +
			"  komando policy edit docker-prune --rm-server build1\n" +
			"  komando policy edit docker-prune --off=false"},
	{Key: own("policy", "", "remove"), Args: []Arg{{Name: "RULE"}}, Today: []string{"policy.rm"},
		Short:   "Remove a deny rule you added (from komando only)",
		Example: "  komando policy remove 'kubectl\\s+delete'\n  komando policy remove custom-1a2b3c4d"},
}
