package capability

var projectOpt = Option{Name: "project", Kind: Bool, Help: "use the current folder instead of your home folder"}

// agent: the komando skill and guard in the AI agents on this computer.
// agent mcp comes with the MCP server (gaps.md, deferred).
var agentLeaves = []Leaf{
	{Key: own("agent", "skill", "install"), LocalRead: true, Today: []string{"guide.install"},
		Options: []Option{projectOpt, {Name: "no-guard", Kind: Bool, Help: "do not add the guard that keeps AI agents away from secret files on this computer"}},
		Short:   "Add the komando skill to Claude Code, Codex, Cursor, Gemini CLI",
		Example: "  komando agent skill install             # for every project on this computer\n" +
			"  komando agent skill install --project   # only for the folder you are in\n" +
			"  komando agent skill install --dry-run   # show where it would go"},
	{Key: own("agent", "skill", "uninstall"), LocalRead: true, Today: []string{"guide.uninstall"},
		Options: []Option{projectOpt},
		Short:   "Take the komando skill and guard out of your AI agents",
		Example: "  komando agent skill uninstall             # from your home folder\n" +
			"  komando agent skill uninstall --project   # from the folder you are in\n" +
			"  komando agent skill uninstall --dry-run   # show what it would remove"},
	{Key: own("agent", "mcp", "start"), State: New},
	{Key: own("agent", "mcp", "stop"), State: New},
}
