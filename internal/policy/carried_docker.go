package policy

import (
	"encoding/csv"
	"path"
	"slices"
	"strconv"
	"strings"
)

// Docker's own rating, as the docker area rates `docker raw` and `docker
// compose` (internal/cli/docker.go classifyDocker, classifyCompose,
// runEscapesHost). The same words through exec stop on the same
// condition. TestDockerRatingMatchesDockerArea in internal/cli keeps the
// two equal while the docker area exists.

// dockerGlobalValued are docker's options before the verb, and whether each takes a value.
var dockerGlobalValued = map[string]bool{
	"-l": true, "--log-level": true, "-H": true, "--host": true, "-c": true, "--context": true, "--config": true,
	"--tlscacert": true, "--tlscert": true, "--tlskey": true, "--tls": false, "--tlsverify": false, "-D": false, "--debug": false,
}

// composeGlobalValued are compose's options before the subcommand.
var composeGlobalValued = map[string]bool{
	"-p": true, "--project-name": true, "-f": true, "--file": true, "--profile": true, "--env-file": true,
	"--project-directory": true, "--ansi": true, "--parallel": true, "--progress": true,
	"--compatibility": false, "--dry-run": false, "--all-resources": false,
}

func dockerRating(c simpleCommand) string {
	switch c.name() {
	case "docker", "podman":
		return DockerRating(c.args[1:])
	case "docker-compose":
		return DockerRating(append([]string{"compose"}, c.args[1:]...))
	}
	return ""
}

// DockerRating says why docker's own rating counts a command (its words
// after `docker`) as destructive: "rm" (deletes), "prune", "kill" (stops
// or changes the swarm) or "host" (hands a container the server); "" when
// it does not. Exec and compose exec are not rated: the command they run
// in the container is checked like any other.
func DockerRating(args []string) string {
	args = skipGlobal(args, dockerGlobalValued)
	if len(args) > 0 && strings.EqualFold(args[0], "compose") {
		args = append([]string{"compose"}, skipGlobal(args[1:], composeGlobalValued)...)
	}
	if len(args) == 0 {
		return ""
	}
	verb, sub := strings.ToLower(args[0]), ""
	if len(args) > 1 {
		sub = strings.ToLower(args[1])
	}
	if verb == "compose" {
		return composeRating(sub, args[1:])
	}
	group := slices.Contains([]string{"service", "stack", "node", "secret", "config", "network", "volume", "container",
		"image", "system", "swarm", "builder", "buildx", "plugin", "context", "trust", "manifest"}, verb)
	if verb == "container" && slices.Contains([]string{"run", "create", "exec", "cp"}, sub) {
		group, verb, args = false, sub, args[1:]
	}
	switch {
	case !group && slices.Contains([]string{"ps", "images", "info", "version", "inspect", "logs", "stats", "top", "events", "port", "diff", "history", "search", "help"}, verb),
		group && slices.Contains([]string{"ls", "ps", "inspect", "logs", "services", "df", "info", "events", "list", "history", "top", "port", "diff", "help"}, sub):
		return ""
	case slices.Contains([]string{"run", "create"}, verb) && !group && runEscapesHost(args),
		verb == "service" && slices.Contains([]string{"create", "update"}, sub) && runEscapesHost(args):
		return "host"
	case verb == "service" && serviceStops(sub, args):
		return "kill"
	case verb == "plugin" && slices.Contains([]string{"install", "upgrade", "create", "enable", "set"}, sub):
		return "host"
	case verb == "volume" && sub == "create" && volumeEscapesHost(args[2:]):
		return "host"
	case verb == "run" || verb == "exec":
		return ""
	case slices.Contains([]string{"rm", "remove"}, sub), slices.Contains([]string{"rm", "rmi"}, verb):
		return "rm"
	case sub == "prune" || verb == "prune":
		return "prune"
	case verb == "cp":
		return "host"
	case slices.Contains([]string{"leave", "demote", "kill", "down"}, sub) || verb == "kill" || verb == "swarm" ||
		verb == "stack" && sub == "deploy" && dockerFlag(args, "--prune") ||
		verb == "node" && sub == "update" && dockerFlag(args, "--availability", "--role"):
		return "kill"
	}
	return ""
}

// composeRating: down only stops (a write); down -v / --rmi and rm
// delete; kill stops; cp writes into the containers; a run that escapes
// into the host is the server.
func composeRating(sub string, args []string) string {
	switch {
	case sub == "down" && dockerFlag(args, "-v", "--volumes", "--rmi"), sub == "rm":
		return "rm"
	case sub == "kill":
		return "kill"
	case sub == "cp", sub == "run" && runEscapesHost(args):
		return "host"
	}
	return ""
}

// skipGlobal drops leading global options and their values.
func skipGlobal(args []string, valued map[string]bool) []string {
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		name, _, glued := strings.Cut(args[0], "=")
		args = args[1:]
		if valued[name] && !glued && len(args) > 0 {
			args = args[1:]
		}
	}
	return args
}

// dockerFlag: one of flags is among args before "--", alone or with =value.
func dockerFlag(args []string, flags ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if name, _, _ := strings.Cut(a, "="); slices.Contains(flags, name) {
			return true
		}
	}
	return false
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
// root, its docker socket, its system folders or its credentials.
func runEscapesHost(args []string) bool {
	if dockerFlag(args, "--privileged", "--cap-add", "--device", "--device-cgroup-rule", "--security-opt", "--volumes-from") {
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
			name, val, hasVal = shortVolume(a)
		}
		if !hasVal && slices.Contains([]string{"-v", "--volume", "--mount", "--mount-add", "--pid", "--ipc", "--userns", "--uts",
			"--network", "--net", "--network-add", "--cgroupns"}, name) && i+1 < len(args) {
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

// mountEscapesHost reads a --mount value as docker does (one CSV record)
// and checks the source of a bind, or the device of a local-driver volume.
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
			ro = !has || slices.Contains([]string{"true", "1"}, strings.ToLower(v))
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

// volumeEscapesHost: `volume create --opt device=PATH` makes a named
// volume that is a host folder, rated as a writable bind of it.
func volumeEscapesHost(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		v, ok := "", false
		switch {
		case (a == "-o" || a == "--opt") && i+1 < len(args):
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
// volume stuck to it (-v/:/h, -v=/:/h, -itv/:/h) the way docker does.
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
// server. Folders of the server's keys, sockets and kernel always do;
// system folders do when written. A folder above one of them counts too.
func hostPathEscapes(p string, readOnly bool) bool {
	p = path.Clean(p)
	if p == "/" || strings.Contains(p, "docker.sock") || strings.Contains(p+"/", "/.ssh/") {
		return true
	}
	if p == "/home" || path.Dir(p) == "/home" {
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
