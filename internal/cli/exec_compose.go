package cli

import (
	"path"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/store"
)

// execComposeReason reads the compose files that docker commands in exec
// text start containers from, with the reader `komando docker compose`
// uses, so a file that hands a service the server stops the text too.
// "" when no command starts containers from a file, or every file stays
// in its containers.
func execComposeReason(cl *call, st *store.State, hosts []*store.Host, command string) string {
	for _, r := range policy.DockerRuns(command) {
		if len(serverComposeFiles(r.Args)) == 0 {
			continue
		}
		if !r.DirKnown {
			return "starts containers from a compose file in a folder komando cannot tell (a cd to a variable, a subshell, COMPOSE_ settings), so komando cannot check what the services get"
		}
		if why := serverComposeReason(cl, st, hosts, composeArgsIn(r.Args, r.Dir)); why != "" {
			return "starts containers from a compose file: " + why
		}
	}
	return ""
}

// execComposeRuns are the docker commands in exec text whose folder
// komando can tell, as their words read from that folder.
func execComposeRuns(command string) [][]string {
	var runs [][]string
	for _, r := range policy.DockerRuns(command) {
		if r.DirKnown {
			runs = append(runs, composeArgsIn(r.Args, r.Dir))
		}
	}
	return runs
}

// composeArgsIn is a docker command's words as run in dir: relative -f,
// --file, -c and --compose-file values and --project-directory are joined
// to dir, and compose gets --project-directory dir when it has none.
func composeArgsIn(args []string, dir string) []string {
	if dir == "" {
		return args
	}
	join := func(p string) string {
		if p == "" || p == "-" || path.IsAbs(p) {
			return p
		}
		return path.Join(dir, p)
	}
	out := make([]string, 0, len(args)+2)
	hasDir := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, glued := strings.Cut(a, "=")
		switch {
		case !oneOf(name, "-f", "--file", "-c", "--compose-file", "--project-directory"):
			out = append(out, a)
		case glued:
			out = append(out, name+"="+join(val))
		case i+1 < len(args):
			out = append(out, a, join(args[i+1]))
			i++
		default:
			out = append(out, a)
		}
		hasDir = hasDir || name == "--project-directory"
	}
	if hasDir {
		return out
	}
	for i, a := range out {
		if strings.EqualFold(a, "compose") {
			return slices.Concat(out[:i+1], []string{"--project-directory", dir}, out[i+1:])
		}
	}
	return out
}
