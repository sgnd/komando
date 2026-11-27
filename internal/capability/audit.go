package capability

// audit: the sealed log of every change komando made and every attempt it
// blocked. export and the recordings come later (gaps.md, deferred; the
// recordings are paid, row C360).
var auditLeaves = []Leaf{
	{Key: own("audit", "", "list"), LocalRead: true, Synonyms: []string{"ls"}, Today: []string{"audit"},
		Options: []Option{
			{Name: "limit", Short: "n", Kind: Int, Default: "50", Help: "the newest N entries (0 = all; with --since or --until, all unless given)"},
			{Name: "target", Kind: String, Help: "only entries for these servers or conns (a selector, like @prod)"},
			{Name: "command", Kind: String, Help: "only commands that start with this (like exec, fs.)"},
			{Name: "failed", Kind: Bool, Help: "only actions that failed or were blocked"},
			{Name: "actor", Kind: String, Help: "only what this one did: part of the name in KOMANDO_ACTOR, the AI agent (claude, codex ...) or the computer account"},
			{Name: "since", Kind: String, Help: "only entries from this time on: 2h, 7d, today, 2026-11-07 or '2026-11-07 14:30'"},
			{Name: "until", Kind: String, Help: "only entries before this time (the same forms as --since)"}},
		Short: "Show the audit log: who did what, where, and the result",
		Example: "  komando audit list                      # the last 50\n" +
			"  komando audit list -n 0 --target @prod  # everything about @prod\n" +
			"  komando audit list --command host. --failed\n" +
			"  komando audit list --since 2h           # everything in the last two hours\n" +
			"  komando audit list --since yesterday --until today --target @prod\n" +
			"  komando audit list --actor claude --since 7d   # what Claude Code did this week"},
	{Key: own("audit", "", "check"), LocalRead: true, Today: []string{"audit.verify"},
		Short:   "Check that no audit record was changed, added or removed outside komando",
		Example: "  komando audit check\n  komando audit check -o json"},
	{Key: own("audit", "", "export"), State: New},
	{Key: own("audit", "recording", "list"), State: New, LocalRead: true, Synonyms: []string{"ls"}},
	{Key: own("audit", "recording", "show"), Args: oneName, State: New, Output: TargetData},
	{Key: own("audit", "recording", "export"), Args: oneName, State: New, Output: TargetData},
	// remove, not delete: komando's own things use remove
	{Key: own("audit", "recording", "remove"), Args: oneName, State: New},
}
