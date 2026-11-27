package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// No gate key, read-only or not, makes komando read a file on the komando
// computer and send it somewhere: a script, a SQL file, a file to upload or
// a YAML file named by path could be ~/.ssh/id_ed25519 or komando's own
// store, and the server's answer (an error that quotes each line, a file
// the key then reads back) would hand it to the key. Content the key sends
// on its own input ('-') is the key's, and stays allowed.
//
// gateLocalFlags are the flags that name a file on this computer to read,
// by command; gateLocalArgs say why a command's arguments name one, or "".
// TestGateLocalReadsClassified makes every flag and argument a key can
// reach that reads here be in one of them.
var gateLocalFlags = map[string][]string{
	"exec":          {"script", "stdin-file"},
	"job.start":     {"script", "stdin-file"},
	"db.query":      {"file"},
	"db.restore":    {"from"},
	"cluster.apply": {"file"},
	"fs.write":      {"from"},
	"queue.send":    {"from"},
}

var gateLocalArgs = map[string]func(c *cobra.Command) string{
	"copy":        gateLocalSrc,
	"cluster.run": gateKubectlFiles,
}

// gateLocalRead says why c as given reads a file on this computer, or "".
func gateLocalRead(c *cobra.Command, name string) string {
	for _, f := range gateLocalFlags[name] {
		fl := c.Flags().Lookup(f)
		if fl == nil || !fl.Changed {
			continue
		}
		if v := fl.Value.String(); v != "" && v != "-" {
			return "--" + f + " reads " + v + " on this computer"
		}
	}
	if f := gateLocalArgs[name]; f != nil {
		return f(c)
	}
	return ""
}

// gateLocalSrc: copy reads here when SOURCE is not TARGET:PATH.
func gateLocalSrc(c *cobra.Command) string {
	args := c.Flags().Args()
	if len(args) != 2 {
		return "" // a usage error: nothing runs
	}
	if sync, _ := c.Flags().GetBool("sync"); args[0] == "-" && !sync {
		return "" // copy - DESTINATION: the key's own input; with --sync, - is a folder here
	}
	if _, _, remote := splitArg(callOf(c), args[0]); !remote {
		return "its SOURCE " + args[0] + " is on this computer"
	}
	return ""
}

// gateKubectlFiles: kubectl -f FILE, --from-file and cp to a pod read files
// here (kctl's own parse, every spelling).
func gateKubectlFiles(c *cobra.Command) string {
	args := c.Flags().Args()
	if len(args) < 2 {
		return ""
	}
	a, err := parseKargs(args[1:])
	if err != nil {
		return "" // a usage error: nothing runs
	}
	for _, key := range []string{"filename", "from-file"} {
		for _, v := range a.vals[key] {
			if v != "-" {
				return "kubectl " + key + " " + v + " reads a file on this computer"
			}
		}
	}
	if a.verb == "cp" && len(a.pos) == 2 {
		if src := a.pos[0]; strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || !strings.Contains(src, ":") {
			return "kubectl cp from " + src + " reads files on this computer"
		}
	}
	return ""
}

// gateLocalReadErr is the refusal: no flag allows it.
func gateLocalReadErr(name, why string) *out.Error {
	return out.Errf(out.ExitPolicy, "SSH_GATE_REFUSED",
		"send the content on the key's own input instead ('-', for example --script -), or a person runs it on the komando computer itself",
		"komando %s is refused for a key: %s; no key reads files on the komando computer", strings.ReplaceAll(name, ".", " "), why)
}
