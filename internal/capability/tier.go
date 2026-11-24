package capability

import "slices"

// Tier is how much a command needs before it runs (the same order as
// today's tiers in internal/cli/risk.go).
type Tier uint8

const (
	Read      Tier = iota // looks only
	Change                // reversible, or only komando's own list
	Protected             // decided by the target's protection
	Dangerous             // cannot be undone, or an outage
	Safety                // weakens komando's own checks
	Person                // only a person at a terminal
)

// TierRow is one row of the v2.7 tier table. It reaches every leaf with
// the same type, area and verb; a row with a Provider reaches only that
// provider (a provider adds a row only where it differs).
type TierRow struct {
	Key
	Tier    Tier
	When    Cond   // zero: always
	What    string // "deletes the keys": the person reads "This deletes the keys."
	Dynamic string // set: the tier holds only when this is so; the command decides
	Bulk    string // set: a bulk confirm the command keeps
}

// Cond is when a row applies. Every flag it names is an Option of every
// leaf the row reaches, so a renamed flag cannot silently stop a row.
type Cond struct {
	Flags []string // all of these options are given
	Value string   // ... and the first one has this value ("false")
	Not   bool     // the row applies when the flags are NOT given
	Words []string // or one of these arguments is given ("0")
}

// Reaches reports whether r applies to leaf k.
func (r TierRow) Reaches(k Key) bool {
	return r.Type == k.Type && r.Area == k.Area && r.Verb == k.Verb &&
		(r.Provider == "" || r.Provider == k.Provider)
}

// Rows returns the tier rows that reach k.
func Rows(k Key) []TierRow {
	var out []TierRow
	for _, r := range tierRows {
		if r.Reaches(k) {
			out = append(out, r)
		}
	}
	return out
}

// TierRows returns every row. The slice is a copy.
func TierRows() []TierRow { return slices.Clone(tierRows) }

// typesWithEdit are the types whose entries a person can protect.
var typesWithEdit = []string{"host", "database", "cache", "queue", "storage", "cluster", "registry", "vpn", "cloud"}

// tierRows is the v2.7 tier table. Inventory and read verbs without a row
// take their class default.
var tierRows = concat2(
	[]TierRow{
		{Key: Key{Type: "queue", Area: "message", Verb: "delete"}, Tier: Dangerous, When: Cond{Flags: []string{"all"}}, What: "deletes every waiting message"},
		{Key: Key{Type: "queue", Area: "topic", Verb: "delete"}, Tier: Dangerous, What: "deletes the topics or queues with their messages"},
		{Key: Key{Type: "storage", Area: "object", Verb: "delete"}, Tier: Dangerous, What: "deletes the files"},
		{Key: Key{Type: "registry", Area: "image", Verb: "delete"}, Tier: Dangerous, What: "deletes the images"},
		{Key: Key{Type: "registry", Area: "image", Verb: "prune"}, Tier: Dangerous, What: "deletes the images"},
		{Key: Key{Type: "database", Verb: "restore"}, Tier: Dangerous, What: "replaces what is in the database now"},
		{Key: own("credential", "password", "remove"), Tier: Dangerous, What: "deletes the saved password"},
		{Key: own("credential", "token", "remove"), Tier: Dangerous, What: "deletes the saved token"},
		{Key: own("credential", "key", "remove"), Tier: Dangerous, When: Cond{Flags: []string{"delete-file"}}, What: "deletes the private key komando keeps"},
		{Key: top("copy"), Tier: Dangerous, When: Cond{Flags: []string{"sync", "delete"}}, What: "deletes the files in the destination that the source does not have"},

		{Key: Key{Type: "host", Verb: "exec"}, Tier: Dangerous, Dynamic: "the command matches a destructive rule"},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "exec"}, Tier: Change, When: Cond{Flags: []string{"stop"}}, What: "stops the session's command"},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "exec"}, Tier: Change, When: Cond{Flags: []string{"remove"}}, What: "removes the session's log from the server"},
		{Key: own("snippet", "", "exec"), Tier: Dangerous, Dynamic: "a step matches a destructive rule"},
		{Key: Key{Type: "cluster", Verb: "exec"}, Tier: Dangerous, Dynamic: "the command matches a destructive rule"},
		{Key: Key{Type: "cluster", Verb: "raw"}, Tier: Dangerous, Dynamic: "the cluster command deletes something or scales to 0"},
		{Key: Key{Type: "cache", Verb: "raw"}, Tier: Dangerous, Dynamic: "the cache command deletes data (DEL, FLUSHALL, ...)"},
		{Key: Key{Type: "database", Verb: "query"}, Tier: Dangerous, Dynamic: "the query deletes data (DROP, DELETE without WHERE, KILL, ...)"},
		{Key: own("credential", "key", "uninstall"), Tier: Dangerous, Dynamic: "it is the key komando logs in with"},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "add"}, Tier: Dangerous, When: Cond{Flags: []string{"proxy-command"}}, Dynamic: "the proxy command matches a destructive rule"},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "edit"}, Tier: Dangerous, When: Cond{Flags: []string{"proxy-command"}}, Dynamic: "the proxy command matches a destructive rule"},
		{Key: top("import"), Tier: Dangerous, Dynamic: "an imported proxy command matches a destructive rule"},

		{Key: own("policy", "", "remove"), Tier: Safety, What: "removes a deny rule"},
		{Key: own("policy", "", "edit"), Tier: Safety, When: Cond{Flags: []string{"on"}, Not: true}, What: "switches a rule off"},
		{Key: own("config", "", "set"), Tier: Safety, Dynamic: "the setting turns a check off"},
		{Key: Key{Type: "vpn", Verb: "edit"}, Tier: Safety, When: Cond{Flags: []string{"mfa"}, Value: "false"}, What: "turns --mfa off (komando may then connect it without a person)"},
		{Key: top("update"), Tier: Safety, Dynamic: "it installs an older version"},
		{Key: Key{Type: "host", Area: "tunnel", Verb: "start"}, Tier: Safety, Dynamic: "it listens on an open address"},
		{Key: Key{Type: "cluster", Area: "tunnel", Verb: "start"}, Tier: Safety, Dynamic: "it listens on an open address"},
		{Key: own("config", "vault", "keychain"), Tier: Safety, Dynamic: "it turns the keychain off"},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "add"}, Tier: Safety, When: Cond{Flags: []string{"proxy-command"}}, Dynamic: "an AI agent runs it (the proxy command runs on this computer)"},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "edit"}, Tier: Safety, When: Cond{Flags: []string{"proxy-command"}}, Dynamic: "an AI agent runs it (the proxy command runs on this computer)"},
		{Key: top("import"), Tier: Safety, Dynamic: "an AI agent imports a server with a proxy command"},
		{Key: own("snippet", "", "create"), Tier: Safety, When: Cond{Flags: []string{"overwrite", "read-only"}}, Dynamic: "it makes an existing snippet read-only"},
		{Key: own("snippet", "", "edit"), Tier: Safety, When: Cond{Flags: []string{"read-only"}}, Dynamic: "it makes an existing snippet read-only"},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "trust"}, Tier: Safety, Dynamic: "an AI agent pins a first host key while host keys are strict"},
		{Key: own("agent", "skill", "uninstall"), Tier: Safety, Dynamic: "it removes komando's guard from an AI agent's settings"},

		{Key: own("config", "", "approval-code"), Tier: Person},
		{Key: own("config", "vault", "passphrase"), Tier: Person},
		{Key: own("config", "vault", "keychain"), Tier: Person, When: Cond{Flags: []string{"off"}, Not: true}, What: "moves the key into the keychain"},
		{Key: Key{Type: "host", Verb: "shell"}, Tier: Person},
		{Key: Key{Type: "database", Verb: "shell"}, Tier: Person},
		{Key: Key{Type: "cluster", Verb: "shell"}, Tier: Person},
		{Key: own("credential", "certificate", "add"), Tier: Person, What: "trusts every server the CA signs"},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "trust"}, Tier: Person, When: Cond{Flags: []string{"reset"}}, What: "replaces a pinned host key"},
		{Key: top("export"), Tier: Person, When: Cond{Flags: []string{"sealed"}}},
		{Key: top("export"), Tier: Person, When: Cond{Flags: []string{"for-phone"}}},
		{Key: top("import"), Tier: Person, Dynamic: "the file is sealed: a person types its passphrase"},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "test"}, Tier: Person, Dynamic: "the server asks for a second factor"},
		{Key: Key{Type: "cloud", Verb: "test"}, Tier: Person, Dynamic: "the cloud asks a person to sign in"},

		{Key: own("group", "", "remove"), Tier: Change, Bulk: "deleting a group of more than 3 members"},
		{Key: Key{Type: "host", Provider: "ssh", Verb: "test"}, Tier: Change, When: Cond{Flags: []string{"end"}}, What: "ends the kept session"},
		{Key: top("test"), Tier: Change, When: Cond{Flags: []string{"end"}}, What: "ends every kept session"},
	},
	protectionOffRows(),
)

// protectionOffRows: turning protection off is a safety step on every
// type a person can protect.
func protectionOffRows() []TierRow {
	var out []TierRow
	for _, typ := range typesWithEdit {
		out = append(out, TierRow{Key: Key{Type: typ, Verb: "edit"}, Tier: Safety,
			When: Cond{Flags: []string{"protected"}, Value: "false"}, What: "turns protection off"})
	}
	return out
}

func concat2(parts ...[]TierRow) []TierRow {
	var out []TierRow
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
