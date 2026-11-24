package runner

import "strings"

// The shell tool's reach (vault note 2026-11-24-komando-v2-7-test-sop-design,
// section 7, Audit E1). A model's command runs in a lab container on an
// internal network (no route out), with no Docker socket, no host mount
// beyond the run folder, no privileges and an environment allowlist. The
// model key, GITHUB_TOKEN and every ACTIONS_* and GITHUB_* variable live
// only in the runner process. Only the harness, never the tool, cuts the
// task 8 link.

// toolEnvAllow are the variables a command of the tool may see: the lab's
// (test/e2e/lib.sh) and an agent's (A in lib.sh). A name that is not here
// is dropped, so a new secret in the runner's environment never leaks by
// default.
var toolEnvAllow = []string{
	"PATH", "HOME", "USERPROFILE", "TMPDIR", "LANG", "LC_ALL", "TERM",
	"KOMANDO_HOME", "KOMANDO_KEYCHAIN", "KOMANDO_ACTOR", "KOMANDO_NO_DIALOG", "KOMANDO_E2E_ACCOUNT_HOME",
	"XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
	"CLAUDECODE",
}

// ToolEnv keeps only the allowlisted variables of env (NAME=value).
func ToolEnv(env []string) []string {
	var out []string
	for _, e := range env {
		name, _, _ := strings.Cut(e, "=")
		for _, ok := range toolEnvAllow {
			if name == ok {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// ToolContainer is what one tool container needs.
type ToolContainer struct {
	Name    string
	Network string // an internal network the harness made
	RunDir  string // the one host folder the container sees
	Image   string
	Env     []string // already filtered by ToolEnv
}

// ToolContainerArgs is the docker command that runs argv in a locked-down
// container: internal network, all capabilities dropped, no new
// privileges, a read-only root, one mount (the run folder), and the
// environment passed as -e NAME=value, never from a file.
func ToolContainerArgs(c ToolContainer, argv []string) []string {
	args := []string{"docker", "run", "--rm", "--name", c.Name,
		"--network", c.Network, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--read-only", "--tmpfs", "/tmp", "-v", c.RunDir + ":" + c.RunDir, "-w", c.RunDir}
	for _, e := range c.Env {
		args = append(args, "-e", e)
	}
	args = append(args, c.Image)
	return append(args, argv...)
}

// NetworkCreateArgs is the docker command that makes the tool's network:
// internal, so a container on it has no route out.
func NetworkCreateArgs(name string) []string {
	return []string{"docker", "network", "create", "--internal", name}
}
