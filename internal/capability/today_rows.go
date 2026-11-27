package capability

import "slices"

// TodayRow (pre-cut) is one row of today's rule table (internal/cli
// risk.go), keyed by today's safety key. Until the cut, internal/cli builds
// its riskRows from these rows; the cut deletes them with the commands
// they are for (cut PR D).
type TodayRow struct {
	Key  TodayKey
	When string // a named condition internal/cli reads ("flag:delete"); "" always
	Cond string // When, in words for `komando schema`
	Tier Tier
	What string // "deletes the keys": the person reads "This deletes the keys."
	// Dynamic set: the tier holds only when this is so; the command decides
	Dynamic string
	Bulk    string // set: a bulk confirm the command keeps
	// Typed and Items: a change row for which a person at the terminal also
	// types the name of what goes; Items says what those are
	Typed, Items string
}

// TodayRows returns today's rows. The slice is a copy.
func TodayRows() []TodayRow { return slices.Clone(todayOnlyRows) }

// todayOnlyRows are today's rows. The order matters only for the text a
// command shows: the highest tier that applies wins.
var todayOnlyRows = []TodayRow{
	// T3: cannot be undone, or an outage. Rows from both old lists.
	{Key: TodayKey{"queue", "message", "delete"}, Tier: Dangerous, What: "deletes every waiting message"},
	{Key: TodayKey{"cache", "", "rm"}, Tier: Dangerous, What: "deletes the keys"},
	{Key: TodayKey{"cluster", "", "rm"}, Tier: Dangerous, What: "deletes it from the cluster"},
	{Key: TodayKey{"cluster", "", "scale"}, When: "word:0,--replicas=0", Cond: "REPLICAS is 0", Tier: Dangerous, What: "stops every copy of the app"},
	{Key: TodayKey{"database", "user", "rm"}, Tier: Dangerous, What: "deletes the database user"},
	{Key: TodayKey{"database", "", "kill"}, Tier: Change, Typed: "ends the session (its client loses the connection)", Items: "sessions"},
	{Key: TodayKey{"host", "file", "rm"}, Tier: Dangerous, What: "deletes the files"},
	{Key: TodayKey{"host", "docker", "rm"}, Tier: Dangerous, What: "deletes the containers"},
	{Key: TodayKey{"host", "docker", "prune"}, Tier: Dangerous, What: "deletes stopped containers and unused images"},
	{Key: TodayKey{"host", "user", "rm"}, When: "flag:remove-home", Cond: "with --remove-home", Tier: Dangerous, What: "deletes the user and their home folder"},
	{Key: TodayKey{"host", "user", "rm"}, Tier: Dangerous, What: "deletes the user"},
	{Key: TodayKey{"credential", "", "remove"}, Tier: Dangerous, What: "deletes the saved passwords"},
	{Key: TodayKey{"host", "package", "rm"}, When: "essential-package", Cond: "a package the server needs (openssh-server, sudo, systemd, ...)", Tier: Dangerous, What: "removes a package the server needs to run or to let you in"},
	{Key: TodayKey{"host", "package", "rm"}, Tier: Change, Typed: "removes the packages", Items: "packages"},
	{Key: TodayKey{"host", "cron", "rm"}, Tier: Change, Typed: "deletes the cron entry", Items: "cron entries"},
	{Key: TodayKey{"host", "", "restart"}, Tier: Dangerous, What: "restarts the server (it is away until it is back)"},
	{Key: TodayKey{"host", "service", "stop"}, When: "ssh-unit", Cond: "the unit is ssh or sshd", Tier: Dangerous, What: "stops sshd (no one can log in remotely)"},
	{Key: TodayKey{"host", "service", "disable"}, When: "ssh-unit", Cond: "the unit is ssh or sshd", Tier: Dangerous, What: "turns sshd off (no one can log in remotely after a restart)"},
	{Key: TodayKey{"", "", "copy"}, When: "flag:delete", Cond: "with --sync --delete", Tier: Dangerous, What: "deletes the files in the destination that the source does not have"},

	// T3 when the command's own check finds it: a policy or classifier hit
	// on what the command runs, decided at run time.
	{Key: TodayKey{"host", "job", "start"}, Tier: Dangerous, Dynamic: "the command matches a destructive rule"},
	{Key: TodayKey{"host", "docker", "exec"}, Tier: Dangerous, Dynamic: "the command matches a destructive rule"},
	{Key: TodayKey{"host", "docker", "raw"}, Tier: Dangerous, Dynamic: "the docker command deletes or stops something"},
	{Key: TodayKey{"host", "docker", "compose"}, Tier: Dangerous, Dynamic: "the compose command deletes or stops something"},
	{Key: TodayKey{"database", "", "explain"}, Cond: "with --analyze", Tier: Dangerous, Dynamic: "the SQL deletes data"},
	{Key: TodayKey{"host", "package", "upgrade"}, When: "flag:security", Cond: "with --security", Tier: Dangerous, Dynamic: "an update would remove a package the server needs"},
	{Key: TodayKey{"host", "", "edit"}, Tier: Dangerous, Dynamic: "--proxy-command matches a destructive rule"},
	{Key: TodayKey{"host", "", "add"}, Tier: Dangerous, Dynamic: "--proxy-command matches a destructive rule"},

	// T3s: weakens komando's own checks.
	{Key: TodayKey{"policy", "", "edit"}, When: "rule-off", Cond: "unless it only switches the rule on", Tier: Safety, What: "switches a rule off"},
	{Key: TodayKey{"conn", "", "edit"}, When: "protection-off", Cond: "with --protected=false", Tier: Safety, What: "turns protection off"},
	// T3s an AI agent meets: a program, file or key this computer would
	// trust from now on, or the agent guard itself (people and scripts are
	// not stopped)
	{Key: TodayKey{"host", "", "add"}, When: "value:proxy-command", Cond: "with --proxy-command", Tier: Safety, Dynamic: "an AI agent runs it (the proxy command runs on this computer)"},
	{Key: TodayKey{"host", "", "edit"}, When: "value:proxy-command", Cond: "with --proxy-command", Tier: Safety, Dynamic: "an AI agent runs it (the proxy command runs on this computer)"},
	{Key: TodayKey{"", "", "import"}, When: "word:kubeconfig", Cond: "SOURCE kubeconfig", Tier: Safety, Dynamic: "an AI agent imports a context whose login runs a program or sends a file of this computer"},

	// T4: only a person at a terminal.
	{Key: TodayKey{"credential", "", "check"}, Tier: Person},
	{Key: TodayKey{"", "", "login"}, Tier: Person},
	{Key: TodayKey{"login", "", "aws"}, Tier: Person},
	{Key: TodayKey{"host", "", "ssh-command"}, Tier: Person},
	{Key: TodayKey{"", "", "import"}, When: "word:komando", Cond: "SOURCE komando", Tier: Person, Dynamic: "the file is sealed (export --sealed): a person types its passphrase"},

	// a bulk change keeps its own confirm (CONFIRM_REQUIRED for an agent)
	{Key: TodayKey{"group", "", "remove"}, When: "one-arg", Cond: "GROUP alone", Tier: Change, Bulk: "deleting a group of more than 3 members"},
}
