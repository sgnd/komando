package capability

// snippet: saved commands with blanks to fill in, and the built-in ones.
// edit and rename come with the snippet engine's own store (gaps.md,
// deferred).
var (
	readOnlySnippet = Option{Name: "read-only", Kind: Bool, Help: "every step only reads, so protected servers don't need --yes"}
	snippetVar      = Option{Name: "var", Kind: String, Repeat: true, Pairs: true, Help: "fill in a blank: NAME=VALUE (repeatable)"}
)

var snippetLeaves = []Leaf{
	{Key: own("snippet", "", "create"), Args: []Arg{{Name: "NAME"}, {Name: "COMMAND"}}, Today: []string{"recipe.add"},
		Options: []Option{{Name: "desc", Kind: String, Help: "what the snippet does, in a few words (shown in snippet list)"},
			{Name: "needs-sudo", Kind: Bool, Help: "the snippet runs with sudo"},
			readOnlySnippet,
			{Name: "overwrite", Kind: Bool, Help: "replace a snippet with the same name"}},
		Short: "Save a command as a snippet with blanks to fill in",
		Example: "  komando snippet create deploy-app 'cd /srv/{{app}} && git pull && systemctl restart {{app}}' --needs-sudo\n" +
			"  komando snippet create disk-usage 'df -h {{path=/}}' --read-only"},
	{Key: own("snippet", "", "edit"), Args: oneName, State: New, Options: []Option{readOnlySnippet}},
	{Key: own("snippet", "", "exec"), Args: []Arg{{Name: "NAME"}, {Name: "TARGET", Selector: true}},
		Options: []Option{snippetVar, {Name: "no-sudo", Kind: Bool, Help: "do not use sudo even if the snippet asks for it"}},
		Output:  TargetData, Stops: []string{"refuseEncodedSecret"}, Today: []string{"recipe.run"},
		Short: "Run a snippet on servers",
		Example: "  komando snippet exec health @web\n" +
			"  komando snippet exec disk web1\n" +
			"  komando snippet exec deploy-app @web --var app=shop"},
	{Key: own("snippet", "", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"recipe.list"},
		Options: []Option{{Name: "category", Kind: String, Help: "only this category (or \"saved\" for your own)"},
			{Name: "limit", Short: "n", Kind: Int, Help: "show at most this many snippets (0 = all)"}},
		Short:   "List built-in and saved snippets",
		Example: "  komando snippet list\n  komando snippet list --category security"},
	{Key: own("snippet", "", "show"), Args: oneName, LocalRead: true,
		Short:   "Show one snippet: its command, blanks and whether it needs sudo",
		Example: "  komando snippet show health\n  komando snippet show app-logs -o json"},
	{Key: own("snippet", "", "rename"), Args: []Arg{{Name: "NAME"}, {Name: "NEW"}}, State: New},
	{Key: own("snippet", "", "remove"), Args: oneName, Today: []string{"recipe.rm"},
		Short:   "Remove a saved snippet (from komando only)",
		Example: "  komando snippet remove app-logs --dry-run\n  komando snippet remove app-logs"},
}
