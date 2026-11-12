package cli

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

func dockerCmd() *cobra.Command {
	var sudo bool
	c := &cobra.Command{
		Use:     "docker",
		Aliases: []string{"container", "ctr"},
		Short:   "Docker: containers, images, logs, compose, prune",
		Long: `Docker on a server over SSH. Reads need nothing; start, stop, restart, pull,
compose up and a docker run through ` + "`docker raw`" + ` change things (protected
servers need --yes); rm, prune, compose down -v and other deletes need
--allow-dangerous. The same rules apply to ` + "`docker raw`" + `, ` + "`docker compose`" + ` and ` + "`cluster run`" + ` on a Swarm manager.`,
	}
	c.PersistentFlags().BoolVarP(&sudo, "sudo", "s", false, "run docker with sudo")
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
				[]string{"name", "image", "status", "ports", "created"}, []string{"Names", "Image", "Status", "Ports", "RunningFor"}, "Names"))
		},
	}
	ps.Flags().BoolVarP(&all, "all", "a", false, "stopped containers too")
	stats := &cobra.Command{
		Use:   "stats TARGET",
		Short: "CPU, memory, network and disk use of running containers",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			return probe(cmd.Context(), "docker.stats", a[0], "docker stats --no-stream --format '{{json .}}'", sudo, dockerTable(
				[]string{"name", "cpu", "memory", "mem%", "net i/o", "block i/o", "pids"}, []string{"Name", "CPUPerc", "MemUsage", "MemPerc", "NetIO", "BlockIO", "PIDs"}, "Name"))
		},
	}
	images := &cobra.Command{
		Use:   "images TARGET",
		Short: "Images on the server",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, a []string) error {
			return probe(cmd.Context(), "docker.images", a[0], "docker images --format '{{json .}}'", sudo, dockerTable(
				[]string{"repository", "tag", "id", "created", "size"}, []string{"Repository", "Tag", "ID", "CreatedSince", "Size"}, "Repository", "Tag"))
		},
	}
	c.AddCommand(ps, stats, images)
	for _, a := range []string{"start", "stop", "restart", "rm", "pull"} {
		action := a
		c.AddCommand(&cobra.Command{
			Use:   action + " TARGET " + map[bool]string{true: "IMAGE...", false: "CONTAINER..."}[action == "pull"],
			Short: dockerActionShorts[action],
			Args:  cobra.MinimumNArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				if _, err := guardDocker(args[0], append([]string{action}, args[1:]...)); err != nil {
					return err
				}
				return runDocker(cmd.Context(), "docker."+action, args[0], "docker "+action+" "+quoteAll(args[1:]), sudo, true)
			},
		})
	}
	logs := logsAlias("logs TARGET CONTAINER", "docker.logs", "container")
	logs.Long = `The last lines of a container's log (-n, default 200), or new lines as they
come with -f. --since and --until take a time back from now (10m, 2h, 7d)
or a date (2026-01-02T10:00:00). --sudo runs docker with sudo.`
	inspect := &cobra.Command{
		Use:   "inspect TARGET NAME",
		Short: "Show a container, image or other object in full (docker inspect)",
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
		Short: "Run a command in a container (its words are passed as given, no shell)",
		Long: `Runs COMMAND in the container with its arguments exactly as written (like
` + "`docker exec`" + `): no shell is added, so the image needs no sh. For pipes or
&& write the shell yourself: -- sh -c 'a | b'. The destructive-command
policy checks the command; --read-only declares that it only looks: a
command that clearly changes something is refused, and on a protected
server only commands komando knows read skip --yes.`,
		Example: "  komando docker exec app1 api -- php artisan migrate:status\n  komando docker exec app1 api --read-only -- sh -c 'ls /data | wc -l'",
		Args:    cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return dockerExec(cmd.Context(), args, sudo, readOnly)
		},
	}
	execC.Flags().BoolVar(&readOnly, "read-only", false, "declare that the command only looks (protected servers: no --yes for commands komando knows read)")
	var file, dir string
	compose := &cobra.Command{
		Use:     "compose TARGET -- ARGS...",
		Short:   "docker compose with -f/--dir (e.g. ps, up -d, pull, logs --tail 50)",
		Example: "  komando docker compose app1 --dir /srv/shop -- up -d --pull always",
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mutating, err := guardDocker(args[0], append([]string{"compose"}, args[1:]...))
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
	compose.Flags().StringVarP(&file, "file", "f", "", "the compose file on the server")
	compose.Flags().StringVar(&dir, "dir", "", "the project folder on the server")
	raw := &cobra.Command{
		Use:   "raw TARGET -- DOCKER_ARGS...",
		Short: "Run any docker subcommand (the same safety rules apply)",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mutating, err := guardDocker(args[0], args[1:])
			if err != nil {
				return err
			}
			return runDocker(cmd.Context(), "docker.raw", args[0], "docker "+quoteAll(args[1:]), sudo, mutating)
		},
	}
	c.AddCommand(logs, inspect, execC, compose, raw, dockerPruneCmd(&sudo))
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

// runDocker runs a docker command on servers and turns a docker failure
// into a typed error (dockerErr). `docker exec` does not use it: there the
// exit code is the container command's.
func runDocker(ctx context.Context, name, target, command string, sudo, mutating bool) error {
	return runFleet(ctx, name, target, command, nil, execOpts{sudo: sudo, exitMap: orSudo(soleHost(target), func(rr *sshx.RunResult) *out.Error {
		if rr.ExitCode == 0 {
			return nil
		}
		return dockerErr(rr.Stderr, rr.ExitCode)
	})}, mutating)
}

// dockerActionShorts are the help lines of docker start, stop, restart,
// rm and pull.
var dockerActionShorts = map[string]string{
	"start":   "Start stopped containers (docker start)",
	"stop":    "Stop running containers (docker stop)",
	"restart": "Restart containers (docker restart)",
	"rm":      "Remove containers (docker rm; needs --allow-dangerous)",
	"pull":    "Pull images from their registry (docker pull)",
}

// dockerErr turns a failed docker command's message into an error with the
// right exit code: a missing object, or docker not installed on the
// server, is not found (3); the rest is remote (5).
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

// dockerTable parses JSON lines and sorts the rows by the sortBy fields
// (docker itself puts the newest first). For a person (-o text) it lays the
// chosen fields out as a table instead (labels and mounts would drown it).
func dockerTable(headers, fields []string, sortBy ...string) func(*store.Host, string) (any, error) {
	return func(h *store.Host, s string) (any, error) {
		rows := parseJSONLines(h, s)
		list, ok := rows.([]any)
		if ok {
			key := func(r any) string {
				m, _ := r.(map[string]any)
				k := ""
				for _, f := range sortBy {
					k += str(m[f]) + "\x00"
				}
				return k
			}
			sort.SliceStable(list, func(i, j int) bool { return key(list[i]) < key(list[j]) })
		}
		if out.P.Format != "text" || !ok {
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

func parseJSONLines(_ *store.Host, s string) any {
	rows := []any{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			return s
		}
		rows = append(rows, v)
	}
	return rows
}

// guardDocker rates a docker command line (docker raw, compose, the
// start/stop/rm verbs) with the same rules as `cluster run` on a Swarm
// manager: reads stay reads, changes need --yes on protected servers, and
// deletes and anything that runs arbitrary code need --allow-dangerous. A
// person at a terminal confirms a delete by typing the server's name (the
// number of servers for several), the same answer the server guard
// takes, so a prune is confirmed once and never with a bare "yes".
func guardDocker(target string, args []string) (mutating bool, err error) {
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
		v := driver.Verdict{Risk: risk, RuleIDs: []string{"docker"}, Reasons: []string{reason}}
		hosts, _ := resolveTargets(st, target) // an unknown target fails later, with its own error
		if !dangerOK(fmt.Sprintf("[docker] %s", reason), targetsWhy(st, hosts)) && !confirmDangerous(hostNames(hosts), reason) {
			return true, policyStop(out.Errf(out.ExitPolicy, "POLICY_BLOCKED",
				"only if this is intended: confirm with the user, then re-run with --allow-dangerous (try --dry-run first)",
				"the operation matches destructive rules [docker]: %s", reason).Say(dangerSay(v.Reasons), dangerHint))
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
	if verb == "container" && oneOf(sub, "run", "create", "exec", "cp") {
		group, verb, args = false, sub, args[1:]
	}
	switch {
	case !group && oneOf(verb, "ps", "images", "info", "version", "inspect", "logs", "stats", "top", "events", "port", "diff", "history", "search", "help"):
		return driver.RiskRead
	case group && oneOf(sub, "ls", "ps", "inspect", "logs", "services", "df", "info", "events", "list", "history", "top", "port", "diff", "help"):
		return driver.RiskRead
	case oneOf(verb, "run", "create") && !group && runEscapesHost(args),
		verb == "service" && oneOf(sub, "create", "update") && runEscapesHost(args):
		return driver.RiskDestructive // privileged or the host's root: that is the server, not a container
	case verb == "service" && serviceStops(sub, args):
		return driver.RiskDestructive // 0 replicas is an outage, as with cluster scale
	case verb == "plugin" && oneOf(sub, "install", "upgrade", "create", "enable", "set"):
		return driver.RiskDestructive // a plugin runs as root on the server, with the mounts and devices it asks for
	case verb == "volume" && sub == "create" && volumeEscapesHost(args[2:]):
		return driver.RiskDestructive // a volume that is the host's root or a system folder
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

// serviceStops: `service scale NAME=0` or `service update --replicas 0`
// (any count that reads as 0 or less, or not as a number).
func serviceStops(sub string, args []string) bool {
	switch sub {
	case "scale":
		for _, a := range args[min(2, len(args)):] {
			if _, n, ok := strings.Cut(a, "="); ok && !strings.HasPrefix(a, "-") {
				if c, err := strconv.Atoi(n); err != nil || c <= 0 {
					return true
				}
			}
		}
	case "update":
		for i, a := range args {
			if a == "--" {
				break
			}
			v, ok := strings.CutPrefix(a, "--replicas=")
			if a == "--replicas" && i+1 < len(args) {
				v, ok = args[i+1], true
			}
			if ok {
				if c, err := strconv.Atoi(v); err != nil || c <= 0 {
					return true
				}
			}
		}
	}
	return false
}

// runEscapesHost: docker run, create and service create/update flags that
// hand the container the server: privileges, devices, the host's
// namespaces (or another container's processes), and binds of the host's
// root, its docker socket, its system folders or its credentials, also
// through a volume backed by a host folder or another container's volumes.
func runEscapesHost(args []string) bool {
	if hasFlag(args, "--privileged", "--cap-add", "--device", "--device-cgroup-rule", "--security-opt", "--volumes-from") {
		return true
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, val, hasVal := strings.Cut(a, "=")
		if !strings.HasPrefix(a, "--") {
			name, val, hasVal = shortVolume(a) // -v/:/h, -itv/:/h
		}
		if !hasVal && oneOf(name, "-v", "--volume", "--mount", "--mount-add", "--pid", "--ipc", "--userns", "--uts",
			"--network", "--net", "--network-add", "--cgroupns") && i+1 < len(args) {
			i++
			val, hasVal = args[i], true
		}
		if !hasVal {
			continue
		}
		switch name {
		case "--pid", "--ipc", "--userns", "--uts", "--network", "--net", "--network-add", "--cgroupns":
			if strings.EqualFold(val, "host") || name == "--pid" && strings.HasPrefix(val, "container:") {
				return true
			}
		case "-v", "--volume":
			src, rest, _ := strings.Cut(val, ":")
			opts := ""
			if k := strings.LastIndex(rest, ":"); k >= 0 {
				opts = rest[k+1:]
			}
			ro := false
			for _, o := range strings.Split(opts, ",") {
				ro = ro || o == "ro" || o == "readonly"
			}
			if strings.HasPrefix(src, "/") && hostPathEscapes(src, ro) {
				return true
			}
		case "--mount", "--mount-add":
			if mountEscapesHost(val) {
				return true
			}
		}
	}
	return false
}

// mountEscapesHost reads a --mount value as docker does (one CSV record,
// so "source=/" may be quoted) and checks its host folder: the source of
// a bind, or the device of a volume the local driver binds from the host.
func mountEscapesHost(val string) bool {
	fields, err := csv.NewReader(strings.NewReader(val)).Read()
	if err != nil {
		return true // docker reads it some way komando cannot: assume the worst
	}
	src, ro := "", false
	opts := map[string]string{}
	for _, f := range fields {
		k, v, has := strings.Cut(f, "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "source", "src":
			src = v
		case "readonly", "ro":
			ro = !has || oneOf(strings.ToLower(v), "true", "1")
		case "volume-opt":
			ok, ov, _ := strings.Cut(v, "=")
			opts[strings.ToLower(ok)] = ov
		}
	}
	if strings.HasPrefix(src, "/") && hostPathEscapes(src, ro) {
		return true
	}
	d := opts["device"]
	return strings.HasPrefix(d, "/") && hostPathEscapes(d, ro)
}

// volumeEscapesHost: `volume create --opt device=PATH` (with o=bind or
// type=none) makes a named volume that is a host folder; a later
// `run -v NAME:/h` cannot be told from any other volume, so the create is
// rated by the folder, as a writable bind.
func volumeEscapesHost(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		v, ok := "", false
		switch {
		case oneOf(a, "-o", "--opt") && i+1 < len(args):
			i++
			v, ok = args[i], true
		case strings.HasPrefix(a, "--opt="):
			v, ok = strings.TrimPrefix(a, "--opt="), true
		case strings.HasPrefix(a, "-o") && len(a) > 2:
			v, ok = strings.TrimPrefix(strings.TrimPrefix(a, "-o"), "="), true
		}
		if k, d, _ := strings.Cut(v, "="); ok && strings.EqualFold(k, "device") && strings.HasPrefix(d, "/") && hostPathEscapes(d, false) {
			return true
		}
	}
	return false
}

// shortVolume reads a run of short flags with -v at its end and the
// volume stuck to it (-v/:/h, -v=/:/h, -itv/:/h) the way docker does. name
// is "-v" when the run ends in v (the value may be the next word).
func shortVolume(a string) (name, val string, hasVal bool) {
	for j := 1; j < len(a); j++ {
		switch a[j] {
		case 'd', 'i', 't', 'P': // short flags without a value
		case 'v':
			val = strings.TrimPrefix(a[j+1:], "=")
			return "-v", val, val != ""
		default:
			return "", "", false // another flag, whose value this is
		}
	}
	return "", "", false
}

// hostPathEscapes: a bind of this server folder hands the container the
// server. The root, the docker socket, the folders that hold it, the
// kernel's interfaces and the folders of keys and credentials (root's and
// the users' homes, ssh host keys, the shadow files, the kubelet's and
// Kubernetes' files, etcd) always do; system folders, and folders whose
// programs root runs (cron, /opt), do when written (a read-only
// /etc/localtime is fine). A folder above one of them counts too.
func hostPathEscapes(p string, readOnly bool) bool {
	p = path.Clean(p)
	if p == "/" || strings.Contains(p, "docker.sock") || strings.Contains(p+"/", "/.ssh/") {
		return true
	}
	if p == "/home" || path.Dir(p) == "/home" { // a user's home: ~/.ssh/authorized_keys, private keys
		return true
	}
	under := func(dirs ...string) bool {
		for _, d := range dirs {
			if p == d || strings.HasPrefix(p, d+"/") || strings.HasPrefix(d, p+"/") {
				return true
			}
		}
		return false
	}
	return under("/run", "/var/run", "/var/lib/docker", "/var/lib/containerd", "/proc", "/sys", "/dev",
		"/root", "/etc/shadow", "/etc/gshadow", "/etc/ssh", "/etc/kubernetes", "/var/lib/kubelet", "/var/lib/etcd",
		"/etc/rancher", "/var/lib/rancher") ||
		!readOnly && under("/etc", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/opt", "/var/spool")
}
