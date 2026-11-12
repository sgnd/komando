// Package engine holds what one komando call is: who makes it and the
// state of its approvals. Today the CLI makes one call per process; the
// Mac and iPhone apps will run many calls in one process, for a person and
// for an agent at the same time (docs/design/sync-security.md, phase 0
// track E), so nothing here reads the environment or a global by itself:
// the caller hands it in.
package engine

import "regexp"

// Kind is who makes a call.
type Kind int

const (
	// Person: someone at a terminal or in an app.
	Person Kind = iota
	// Script: no person and no AI agent (a cron job, a pipeline).
	Script
	// Agent: an AI agent, or a key through ssh-gate.
	Agent
)

// Caller is who makes a call.
type Caller struct {
	Kind  Kind
	Agent string // the agent's name, for the approval window and the audit log
	Actor string // who the audit log names (KOMANDO_ACTOR, else the account)
}

// IsAgent reports an AI agent (or an ssh-gate key) as the caller.
func (c Caller) IsAgent() bool { return c.Kind == Agent }

// agentVars are environment variables AI coding agents set in the shells
// they run commands in. KOMANDO_AGENT is for any other agent. A harness
// that sets more than one is listed with each, so clearing one variable
// does not make the agent a script.
var agentVars = []struct{ env, name string }{
	{"CLAUDECODE", "Claude Code"},
	{"CLAUDE_CODE_ENTRYPOINT", "Claude Code"},
	{"GEMINI_CLI", "Gemini CLI"},
	{"CODEX_SANDBOX", "Codex"},
	{"CODEX_THREAD_ID", "Codex"},
	{"CURSOR_AGENT", "Cursor"},
	{"KOMANDO_AGENT", "An AI agent"},
	{"AI_AGENT", "An AI agent"},
	{GateEnv, "An SSH key through ssh-gate"}, // set by ssh-gate, not by the key
}

// AgentVars are the variables that make a process an agent's, for the
// guard hook that refuses shell lines changing them.
func AgentVars() []string {
	out := make([]string, len(agentVars))
	for i, a := range agentVars {
		out[i] = a.env
	}
	return out
}

// GateEnv names the ssh-gate key a command came through.
const GateEnv = "KOMANDO_SSH_GATE"

// GateLabel is what an ssh-gate key's name may look like.
var GateLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// AgentName is the AI agent the environment lookup describes, or "" for a
// person or a script. A variable that is there counts whatever its value,
// also 0, false and empty: an agent told to run `CLAUDECODE=0 komando ...`
// must not turn its own safety stops off.
func AgentName(lookup func(string) (string, bool)) string {
	// a key through ssh-gate is named by the gate, whatever else the
	// environment holds; only a name the gate could have set is shown
	if v, ok := lookup(GateEnv); ok && GateLabel.MatchString(v) {
		return "ssh-gate key " + v
	}
	for _, a := range agentVars {
		if _, ok := lookup(a.env); ok {
			return a.name
		}
	}
	return ""
}

// CallerFrom is the caller an environment lookup describes. terminal says
// whether a person could answer at a terminal (stdin and stderr are one).
func CallerFrom(lookup func(string) (string, bool), terminal bool) Caller {
	c := Caller{Kind: Script}
	if a := AgentName(lookup); a != "" {
		c.Kind, c.Agent = Agent, a
	} else if terminal {
		c.Kind = Person
	}
	if a, _ := lookup("KOMANDO_ACTOR"); a != "" {
		c.Actor = a
	} else if c.Actor, _ = lookup("USER"); c.Actor == "" {
		c.Actor, _ = lookup("USERNAME") // Windows sets only this one
	}
	return c
}
