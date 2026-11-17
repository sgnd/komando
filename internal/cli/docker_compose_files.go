package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// composeFileMax is the most of a compose file on the server komando reads
// to rate it; a larger one is rated as one it cannot check.
const composeFileMax = 1 << 20

// composeDefaultNames are the files `docker compose` looks for, in its
// order, when no -f is given: the first one there is used.
func composeDefaultNames(dir string) []string {
	var names []string
	for _, n := range []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"} {
		if dir != "" {
			n = path.Join(dir, n)
		}
		names = append(names, n)
	}
	return names
}

// serverComposeFiles lists the compose files on the server a docker
// command starts containers from: `stack deploy -c FILE` and `compose -f
// FILE up/create/run/...`. Each group is one file; a group of several is
// compose's default names, of which the first there counts. nil when the
// command starts nothing from a file.
func serverComposeFiles(args []string) [][]string {
	rest, err := skipGlobals(args, dockerGlobalFlags, "docker")
	if err != nil || len(rest) < 2 {
		return nil
	}
	verb, sub := strings.ToLower(rest[0]), strings.ToLower(rest[1])
	switch {
	case verb == "stack" && oneOf(sub, "deploy", "up"):
		return flagFiles(rest[2:], "-c", "--compose-file")
	case verb == "compose":
		return composeFiles(rest[1:])
	}
	return nil
}

// composeFiles reads `docker compose`'s global flags for -f and
// --project-directory, then its subcommand.
func composeFiles(args []string) [][]string {
	var files [][]string
	dir := ""
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		name, val, hasValue := strings.Cut(args[0], "=")
		takes := composeGlobalFlags[name]
		args = args[1:]
		if takes && !hasValue && len(args) > 0 {
			val, args = args[0], args[1:]
		}
		switch name {
		case "-f", "--file":
			files = append(files, []string{val})
		case "--project-directory":
			dir = val
		}
	}
	if len(args) == 0 || !oneOf(strings.ToLower(args[0]), "up", "create", "run", "start", "restart", "pull", "build", "watch", "scale") {
		return nil
	}
	if len(files) == 0 {
		return [][]string{composeDefaultNames(dir)}
	}
	return files
}

// composeGuardArgs is `komando docker compose`'s command line as docker
// compose reads it: --dir is the folder it runs in, so --file is found
// there. The guard rates these words and reads the file they name.
func composeGuardArgs(dir, file string, args []string) []string {
	g := []string{"compose"}
	if dir != "" {
		g = append(g, "--project-directory", dir)
	}
	if file != "" {
		if dir != "" && !path.IsAbs(file) {
			file = path.Join(dir, file)
		}
		g = append(g, "-f", file)
	}
	return append(g, args...)
}

// flagFiles collects the values of a flag given as `-c FILE` or `-c=FILE`.
func flagFiles(args []string, names ...string) [][]string {
	var files [][]string
	for i := 0; i < len(args); i++ {
		name, val, hasValue := strings.Cut(args[i], "=")
		if !oneOf(name, names...) {
			// a short flag glued to its value: -cFILE
			for _, n := range names {
				if len(n) == 2 && strings.HasPrefix(args[i], n) && len(args[i]) > 2 {
					files = append(files, []string{args[i][2:]})
				}
			}
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				break
			}
			i++
			val = args[i]
		}
		files = append(files, []string{val})
	}
	return files
}

// composeFilesRisk reads each compose file with read and says why the
// command must count as destructive: a file that escapes into the host
// (composeEscapes), or one komando cannot read and so cannot check. ""
// when every file is checked and stays in its containers.
func composeFilesRisk(read func(p string) ([]byte, error), groups [][]string) string {
	for _, g := range groups {
		found := false
		for i, p := range g {
			if p == "-" || p == "" {
				return "the compose file comes from standard input, which komando cannot check"
			}
			b, err := read(p)
			if errors.Is(err, os.ErrNotExist) && i < len(g)-1 {
				continue // the next of compose's default names
			}
			if err != nil {
				return fmt.Sprintf("komando cannot read %s on the server (%s), so it cannot check what the services get", p, firstLine(err.Error()))
			}
			if esc := composeEscapes(b); esc != "" {
				return p + ": " + esc
			}
			found = true
			break
		}
		if found && len(g) > 1 {
			if why := composeDefaultsRisk(read, path.Dir(g[0])); why != "" {
				return why
			}
		}
		if !found {
			return "komando found no compose file on the server to check"
		}
	}
	return ""
}

// composeDefaultsRisk checks what compose adds to its own file names when
// no -f is given: the override files it merges, and a COMPOSE_FILE in the
// folder's .env that names other files.
func composeDefaultsRisk(read func(p string) ([]byte, error), dir string) string {
	if dir == "." {
		dir = ""
	}
	for _, n := range []string{"compose.override.yaml", "compose.override.yml", "docker-compose.override.yaml", "docker-compose.override.yml"} {
		p := path.Join(dir, n)
		b, err := read(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Sprintf("komando cannot read %s on the server (%s), so it cannot check what the services get", p, firstLine(err.Error()))
		}
		if esc := composeEscapes(b); esc != "" {
			return p + ": " + esc
		}
	}
	env := path.Join(dir, ".env")
	b, err := read(env)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		return fmt.Sprintf("komando cannot read %s on the server (%s), which may name other compose files", env, firstLine(err.Error()))
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, _, _ := strings.Cut(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "export ")), "=")
		if k == "COMPOSE_FILE" || k == "COMPOSE_PATH_SEPARATOR" {
			return env + " sets " + k + ", so compose reads files komando does not check"
		}
	}
	return ""
}

// serverComposeReason reads the compose files a docker command uses on
// each host (SFTP, at most composeFileMax each, no sudo) and rates them
// with composeFilesRisk. "" when the command uses none or all are safe.
func serverComposeReason(cl *call, st *store.State, hosts []*store.Host, args []string) string {
	groups := serverComposeFiles(args)
	if len(groups) == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, h := range hosts {
		why := ""
		err := withClient(cl, ctx, st, h, func(c *sshx.Client) error {
			sc, err := sftpClient(c)
			if err != nil {
				return err
			}
			defer sc.Close()
			why = composeFilesRisk(func(p string) ([]byte, error) {
				if _, err := sc.Stat(p); err != nil {
					return nil, err
				}
				b, trunc, err := readRemote(cl, ctx, c, sc, p, false, composeFileMax)
				if err == nil && trunc {
					err = fmt.Errorf("larger than %s", humanBytes(composeFileMax))
				}
				return b, err
			}, groups)
			return nil
		})
		if err != nil {
			why = fmt.Sprintf("komando cannot read the compose file on %s (%s), so it cannot check what the services get", h.Name, firstLine(err.Error()))
		}
		if why != "" {
			if len(hosts) > 1 {
				why = "[" + h.Name + "] " + why
			}
			return why
		}
	}
	return ""
}
