package capability

import "slices"

// The fates below exist only until the v0.18.0 cut: with Leaf.Today and
// Leaf.Carries they prove that every command of today has a v2.7 fate.
// The cut deletes them.

// Gone is a command of today that no leaf carries.
type Gone struct {
	Today string // command ID, as in internal/cli/testdata/command_ids.txt
	Why   string // the decision
	Lost  string // the function that goes on purpose, "" when none
}

// Internal is a hidden command of today that komando runs itself, and the
// leaf it serves. A Key with an empty Provider means every provider.
type Internal struct {
	Today string
	For   Key
}

// Gones returns the commands of today that no leaf carries.
func Gones() []Gone { return slices.Clone(gone) }

// Internals returns today's hidden commands and the leaf each serves.
func Internals() []Internal { return slices.Clone(internals) }

// CobraOwn are command IDs cobra makes itself; they stay outside the table.
func CobraOwn() []string { return slices.Clone(cobraOwn) }

// gone are today's commands that no leaf carries, with the decision.
var gone = []Gone{
	{Today: "conn.kinds", Why: "the URL schemes move to each provider's --help and schema"},
	{Today: "environment", Why: "help topics become docs articles"},
	{Today: "exit-codes", Why: "help topics become docs articles"},
	{Today: "output", Why: "help topics become docs articles"},
	{Today: "safety", Why: "help topics become docs articles"},
	{Today: "help", Why: "help is only --help at each level"},
	{Today: "guide", Why: "the agent rules live in the skill file"},
	{Today: "rename", Why: "each provider and noun has its own rename", Lost: "bulk rename (--starts-with, --in-notes, --in-labels): open"},
	{Today: "host.ssh-command", Why: "removed with no replacement", Lost: "a key in ssh-agent for an hour for plain ssh, scp, git"},
	{Today: "secret.check", Why: "removed"},
	{Today: "secret.cp", Why: "removed"},
	{Today: "cert", Why: "moves to paid monitoring in komando-cloud", Lost: "cert check in the CLI until monitoring exists"},
	{Today: "cert.check", Why: "moves to paid monitoring in komando-cloud", Lost: "cert check in the CLI until monitoring exists"},
	{Today: "ssh-gate", Why: "the phone app gets its own engine first"},
	{Today: "ssh-gate.line", Why: "the phone app gets its own engine first"},
	{Today: "ssh-gate.status", Why: "the phone app gets its own engine first"},
}

// internals are hidden commands komando runs itself.
var internals = []Internal{
	{Today: "tunnel.serve", For: Key{Type: "host", Provider: "ssh", Area: "tunnel", Verb: "start"}},
	{Today: "vpn.serve", For: Key{Type: "vpn", Verb: "start"}},
	{Today: "login-holder", For: Key{Type: "host", Provider: "ssh", Verb: "test"}},
	{Today: "guide.guard", For: Key{Type: "agent", Area: "skill", Verb: "install"}},
}

// cobraOwn: the root and cobra's completion commands.
var cobraOwn = []string{"komando", "completion", "completion.bash", "completion.fish", "completion.powershell", "completion.zsh"}
