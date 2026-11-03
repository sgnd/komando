package cli

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// --------------------------------------------------------------- docker ---

func dockerCmd() *cobra.Command {
	var sudo bool
	c := &cobra.Command{
		Use:     "docker",
		Aliases: []string{"container", "ctr"},
		Short:   "Docker: ps/stats/images (structured), logs, start/stop/restart, exec, compose, raw",
		Long: `Docker on a server over SSH. Reads need nothing; start, stop, restart, pull,
run and compose up change things (protected servers need --yes); rm, prune,
compose down -v and other deletes need --allow-dangerous. The same rules
apply to ` + "`docker raw`" + `, ` + "`docker compose`" + ` and ` + "`cluster run`" + ` on a Swarm manager.`,
	}
	c.PersistentFlags().BoolVarP(&sudo, "sudo", "s", false, "run docker via sudo")
	var all bool
	ps := &cobra.Command{
		Use:   "ps TARGET",
		Short: "Running containers (--all for stopped ones too)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			line := "docker ps"
			if all {
				line += " -a"
			}
			return probe(cmd.Context(), "docker.ps", a[0], line+" --format '{{json .}}'", sudo, dockerTable(
				[]string{"name", "image", "status", "ports", "created"}, []string{"Names", "Image", "Status", "Ports", "RunningFor"}))
		},
	}
	ps.Flags().BoolVarP(&all, "all", "a", false, "stopped containers too")
	stats := &cobra.Command{
		Use:   "stats TARGET",
		Short: "CPU, memory, network and disk use of running containers",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			return probe(cmd.Context(), "docker.stats", a[0], "docker stats --no-stream --format '{{json .}}'", sudo, dockerTable(
				[]string{"name", "cpu", "memory", "mem%", "net i/o", "block i/o", "pids"}, []string{"Name", "CPUPerc", "MemUsage", "MemPerc", "NetIO", "BlockIO", "PIDs"}))
		},
	}
	images := &cobra.Command{
		Use:   "images TARGET",
		Short: "Images on the server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			return probe(cmd.Context(), "docker.images", a[0], "docker images --format '{{json .}}'", sudo, dockerTable(
				[]string{"repository", "tag", "id", "created", "size"}, []string{"Repository", "Tag", "ID", "CreatedSince", "Size"}))
		},
	}
	c.AddCommand(ps, stats, images)
	for _, a := range []string{"start", "stop", "restart", "rm", "pull"} {
		action := a
		c.AddCommand(&cobra.Command{
			Use:   action + " TARGET NAME...",
			Short: "docker " + action,
			Args:  cobra.MinimumNArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				if _, err := guardDocker(append([]string{action}, args[1:]...)); err != nil {
					return err
				}
				return runDocker(cmd.Context(), "docker."+action, args[0], "docker "+action+" "+quoteAll(args[1:]), sudo, true)
			},
		})
	}
	var lo logOpts
	logs := &cobra.Command{
		Use:   "logs TARGET CONTAINER",
		Short: "Same as `komando logs TARGET --container NAME`",
		Long: `The last lines of a container's log (-n, default 200), or new lines as they
come with -f. --since and --until take a duration back from now (10m, 2h,
-1h) or a time (2026-01-02T10:00:00).`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			lo.container = args[1]
			return runLogs(cmd.Context(), "docker.logs", args[0], &lo, sudo)
		},
	}
	lo.bind(logs, false)
	_ = logs.Flags().MarkHidden("sudo")
	_ = logs.Flags().MarkHidden("priority") // journald only
	inspect := &cobra.Command{
		Use:   "inspect TARGET NAME",
		Short: "docker inspect (JSON)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// the exit status travels in stdout so a missing object can say
			// "not found" (exit 3) instead of a bare remote failure
			line := "docker inspect " + sshx.Q(args[1]) + " 2>&1; echo \"" + exitMarker + "$?\""
			return probe(cmd.Context(), "docker.inspect", args[0], line, sudo, func(_ *store.Host, s string) (any, error) {
				body, code := splitExitMarker(s)
				if code != 0 {
					return nil, dockerErr(body, code)
				}
				var v any
				if err := json.Unmarshal([]byte(body), &v); err != nil {
					return body, nil
				}
				return v, nil
			})
		},
	}
	var readOnly bool
	execC := &cobra.Command{
		Use:   "exec TARGET CONTAINER -- COMMAND [ARG...]",
		Short: "Run a command inside a container (its words are passed as given, no shell)",
		Long: `Runs COMMAND in the container with its arguments exactly as written (like
` + "`docker exec`" + `): no shell is added, so the image needs no sh. For pipes or
&& write the shell yourself: -- sh -c 'a | b'. The destructive-command
policy checks the command; --read-only declares that it only looks.`,
		Example: "  komando docker exec app1 api -- php artisan migrate:status\n  komando docker exec app1 api --read-only -- sh -c 'ls /data | wc -l'",
		Args:    cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err == nil {
				// the policy sees the command as typed
				if err := guard(st, nil, strings.Join(args[2:], " "), false); err != nil {
					return err
				}
			}
			return runOne(cmd.Context(), "docker.exec", args[0], dockerExecLine(args[1], args[2:]), sudo, !readOnly)
		},
	}
	execC.Flags().BoolVar(&readOnly, "read-only", false, "declare read-only")
	var file, dir string
	compose := &cobra.Command{
		Use:     "compose TARGET -- ARGS...",
		Short:   "docker compose with -f/--dir (e.g. ps, up -d, pull, logs --tail 50)",
		Example: "  komando docker compose app1 --dir /srv/shop -- up -d --pull always",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mutating, err := guardDocker(append([]string{"compose"}, args[1:]...))
			if err != nil {
				return err
			}
			c := "docker compose"
			if dir != "" {
				c = "cd " + sshx.Q(dir) + " && " + c
			}
			if file != "" {
				c += " -f " + sshx.Q(file)
			}
			c += " " + quoteAll(args[1:]) + " 2>&1"
			return runDocker(cmd.Context(), "docker.compose", args[0], c, sudo, mutating)
		},
	}
	compose.Flags().StringVarP(&file, "file", "f", "", "compose file")
	compose.Flags().StringVar(&dir, "dir", "", "project directory")
	raw := &cobra.Command{
		Use:   "raw TARGET -- DOCKER_ARGS...",
		Short: "Any docker subcommand (policy still applies)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mutating, err := guardDocker(args[1:])
			if err != nil {
				return err
			}
			return runDocker(cmd.Context(), "docker.raw", args[0], "docker "+quoteAll(args[1:]), sudo, mutating)
		},
	}
	c.AddCommand(logs, inspect, execC, compose, raw)
	return c
}

// dockerExecLine runs argv in a container as given: each word quoted for
// the remote shell, none joined into a new shell command line.
func dockerExecLine(container string, argv []string) string {
	return "docker exec -i " + sshx.Q(container) + " " + quoteAll(argv)
}

const exitMarker = "komando-exit:"

// splitExitMarker takes the "komando-exit:N" line off the end of output.
func splitExitMarker(s string) (string, int) {
	s = strings.TrimRight(s, "\n")
	i := strings.LastIndex(s, exitMarker)
	if i < 0 {
		return s, 0
	}
	code, err := strconv.Atoi(strings.TrimSpace(s[i+len(exitMarker):]))
	if err != nil {
		return s, 0
	}
	return strings.TrimRight(s[:i], "\n"), code
}

var dockerNotFound = regexp.MustCompile(`(?i)no such (container|service|object|image|node|task|network|volume|secret|config)|(service|node|task|stack) .* not found|nothing found in stack`)

// dockerErr turns a failed docker command's message into an error with the
// right exit code: a missing object is "not found" (3), the rest remote (5).
// runDocker runs a docker command on servers; when docker fails, its words
// become a typed error (a missing container is NOT_FOUND, exit 3). `docker
// exec` does not use it: there the exit code is the container command's.
func runDocker(ctx context.Context, name, target, command string, sudo, mutating bool) error {
	return runFleet(ctx, name, target, command, nil, execOpts{sudo: sudo, exitMap: func(code int, stderr string) *out.Error {
		if code == 0 {
			return nil
		}
		return dockerErr(stderr, code)
	}}, mutating)
}

func dockerErr(msg string, code int) *out.Error {
	var lines []string
	for _, l := range strings.Split(msg, "\n") {
		l = strings.TrimSpace(l)
		l = strings.TrimPrefix(strings.TrimPrefix(l, "Error response from daemon: "), "Error: ")
		if l != "" && l != "[]" { // docker inspect prints [] before its error
			lines = append(lines, l)
		}
	}
	msg = strings.Join(lines, "\n")
	switch {
	case msg == "" && code == 127:
		return out.Errf(out.ExitNotFound, "DOCKER_MISSING", "install Docker on the server, or pick another server", "docker not found")
	case dockerNotFound.MatchString(msg):
		return out.Errf(out.ExitNotFound, "NOT_FOUND", "list what exists with `komando docker ps TARGET --all` or `komando cluster ls TARGET services`", "%s", firstLine(msg))
	case strings.Contains(msg, "permission denied") && strings.Contains(msg, "docker.sock"):
		return out.Errf(out.ExitRemote, "DOCKER_PERMISSION", "add --sudo, or add the login user to the docker group", "%s", firstLine(msg))
	case msg == "":
		msg = "docker exited " + strconv.Itoa(code)
	}
	return out.Errf(out.ExitRemote, "DOCKER_ERROR", "check that Docker runs there: `komando exec TARGET --read-only -- docker info`", "%s", msg)
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return l
}

// dockerTable parses JSON lines; for a person (-o text) it lays the chosen
// fields out as a table instead (labels and mounts would drown it).
func dockerTable(headers, fields []string) func(*store.Host, string) (any, error) {
	return func(h *store.Host, s string) (any, error) {
		rows, err := parseJSONLines(h, s)
		if err != nil || out.P.Format != "text" {
			return rows, err
		}
		list, ok := rows.([]any)
		if !ok {
			return rows, nil
		}
		var cells [][]string
		for _, r := range list {
			m, _ := r.(map[string]any)
			row := make([]string, len(fields))
			for i, f := range fields {
				row[i] = str(m[f])
			}
			cells = append(cells, row)
		}
		if len(cells) == 0 {
			return "(none)\n", nil
		}
		return textTable(headers, cells), nil
	}
}

func parseJSONLines(_ *store.Host, s string) (any, error) {
	rows := []any{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return s, nil
		}
		rows = append(rows, v)
	}
	return rows, nil
}

// guardDocker rates a docker command line (docker raw, compose, the
// start/stop/rm verbs) with the same rules as `cluster run` on a Swarm
// manager: reads stay reads, changes need --yes on protected servers, and
// deletes and anything that runs arbitrary code need --allow-dangerous.
func guardDocker(args []string) (mutating bool, err error) {
	if len(args) == 0 {
		return true, nil
	}
	if _, err := dockerVerbArgs(args); err != nil {
		return true, err
	}
	risk := classifyDocker(args)
	st, err := loadState()
	if err != nil {
		return true, err
	}
	// the destructive-command policy sees the words as typed
	if hits := policy.Check("docker "+strings.Join(args, " "), st.Settings.ExtraDenyPattern); len(hits) > 0 {
		risk = driver.RiskDestructive
	}
	if risk >= driver.RiskDestructive && !dangerOK() {
		reason := "docker " + strings.Join(args, " ")
		if v, _ := dockerVerbArgs(args); len(v) > 0 && strings.EqualFold(v[0], "exec") {
			reason += " (runs anything in the container; `komando docker exec` checks the command itself)"
		}
		if err := guardConns(st, nil, driver.Verdict{Risk: risk, RuleIDs: []string{"docker"}, Reasons: []string{reason}}); err != nil {
			return true, err
		}
	}
	return risk > driver.RiskRead, nil
}

// Global flags that come before the docker (or docker compose) subcommand,
// and whether they take a value. They are skipped to find the real verb.
var dockerGlobalFlags = map[string]bool{
	"-l": true, "--log-level": true, "-H": true, "--host": true, "-c": true, "--context": true, "--config": true,
	"--tlscacert": true, "--tlscert": true, "--tlskey": true, "--tls": false, "--tlsverify": false, "-D": false, "--debug": false,
}

var composeGlobalFlags = map[string]bool{
	"-p": true, "--project-name": true, "-f": true, "--file": true, "--profile": true, "--env-file": true,
	"--project-directory": true, "--ansi": true, "--parallel": true, "--progress": true,
	"--compatibility": false, "--dry-run": false, "--all-resources": false,
}

// skipGlobals drops leading global flags (and their values). A leading
// flag it does not know is refused: it could hide the verb behind a value.
func skipGlobals(args []string, flags map[string]bool, tool string) ([]string, error) {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		name, _, hasValue := strings.Cut(args[0], "=")
		takes, known := flags[name]
		if !known {
			return nil, out.Usage("put the %s command first (e.g. `-- rm web`): %s before it is not a flag komando knows", tool, name)
		}
		args = args[1:]
		if takes && !hasValue {
			if len(args) == 0 {
				return nil, out.Usage("%s needs a value", name)
			}
			args = args[1:]
		}
	}
	return args, nil
}

// dockerVerbArgs is args without docker's (and compose's) global flags, so
// args[0] is the verb: "-l debug rm x" -> "rm x", "compose -p p down" ->
// "compose down".
func dockerVerbArgs(args []string) ([]string, error) {
	rest, err := skipGlobals(args, dockerGlobalFlags, "docker")
	if err != nil || len(rest) == 0 || !strings.EqualFold(rest[0], "compose") {
		return rest, err
	}
	sub, err := skipGlobals(rest[1:], composeGlobalFlags, "docker compose")
	if err != nil {
		return nil, err
	}
	return append([]string{"compose"}, sub...), nil
}

// classifyDocker rates a docker command by verb, subcommand and flags. It
// is the one rule set for docker raw, docker compose, the docker verbs and
// `cluster run` on a Swarm manager.
func classifyDocker(args []string) driver.Risk {
	args, err := dockerVerbArgs(args)
	if err != nil {
		return driver.RiskDestructive // cannot tell: assume the worst
	}
	if len(args) == 0 {
		return driver.RiskRead // `docker` alone prints its help
	}
	verb, sub := strings.ToLower(args[0]), ""
	if len(args) > 1 {
		sub = strings.ToLower(args[1])
	}
	if verb == "compose" {
		return classifyCompose(sub, args[1:])
	}
	group := oneOf(verb, "service", "stack", "node", "secret", "config", "network", "volume", "container", "image", "system", "swarm", "builder", "buildx", "plugin", "context", "trust", "manifest")
	if verb == "container" && oneOf(sub, "run", "exec", "cp") {
		group, verb, args = false, sub, args[1:]
	}
	switch {
	case !group && oneOf(verb, "ps", "images", "info", "version", "inspect", "logs", "stats", "top", "events", "port", "diff", "history", "search", "help"):
		return driver.RiskRead
	case group && oneOf(sub, "ls", "ps", "inspect", "logs", "services", "df", "info", "events", "list", "history", "top", "port", "diff", "help"):
		return driver.RiskRead
	case verb == "run" && runEscapesHost(args):
		return driver.RiskDestructive // privileged or the host's root: that is the server, not a container
	case verb == "run":
		return driver.RiskWrite // starts a container, like up -d
	case oneOf(sub, "rm", "prune", "leave", "demote", "kill", "down", "remove") || oneOf(verb, "rm", "rmi", "kill", "prune", "exec", "cp") ||
		verb == "swarm" || (verb == "stack" && sub == "deploy" && hasFlag(args, "--prune")) ||
		(verb == "node" && sub == "update" && hasFlag(args, "--availability", "--role")):
		return driver.RiskDestructive // deletes, drains, or runs anything (exec/cp) like kubectl exec
	}
	return driver.RiskWrite
}

// classifyCompose rates `docker compose SUB ...`: down only stops (write),
// down -v / --rmi and rm delete data.
func classifyCompose(sub string, args []string) driver.Risk {
	switch {
	case oneOf(sub, "", "ps", "logs", "config", "ls", "images", "top", "version", "events", "port", "help"):
		return driver.RiskRead
	case sub == "down" && hasFlag(args, "-v", "--volumes", "--rmi"),
		oneOf(sub, "rm", "kill", "exec", "cp"):
		return driver.RiskDestructive
	case sub == "run" && runEscapesHost(args):
		return driver.RiskDestructive
	}
	return driver.RiskWrite
}

// runEscapesHost: docker run flags that hand the container the server.
func runEscapesHost(args []string) bool {
	if hasFlag(args, "--privileged", "--cap-add", "--device", "--security-opt") {
		return true
	}
	for i, a := range args {
		if a == "--" {
			break
		}
		v := ""
		switch {
		case oneOf(a, "-v", "--volume", "--mount", "--pid", "--ipc", "--userns", "--uts") && i+1 < len(args):
			v = a + "=" + args[i+1]
		case strings.HasPrefix(a, "-v=") || strings.HasPrefix(a, "--"):
			v = a
		}
		switch {
		case strings.HasPrefix(v, "--pid=host"), strings.HasPrefix(v, "--ipc=host"), strings.HasPrefix(v, "--userns=host"), strings.HasPrefix(v, "--uts=host"):
			return true
		case strings.HasPrefix(v, "-v=/:"), strings.HasPrefix(v, "--volume=/:"), strings.Contains(v, "source=/,"), strings.HasSuffix(v, "source=/"),
			strings.Contains(v, "docker.sock"):
			return true
		}
	}
	return false
}
