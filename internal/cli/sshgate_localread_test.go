package cli

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// No key, read, network or full, makes komando read a file on the komando
// computer: a script, SQL file, upload source or YAML file there could be
// a private key, sent on to a server that echoes it back.
func TestGateLocalReads(t *testing.T) {
	invHome(t)
	gateInventory(t)
	const R = "SSH_GATE_REFUSED"
	refused := []string{
		"exec web --read-only --script /home/u/.ssh/id_ed25519", "exec web --script=.ssh/id_ed25519",
		"exec web --read-only --stdin-file .ssh/id_ed25519 -- cat", "job start web --read-only --script ./x.sh",
		"job start web --stdin-file x -- cat", "database postgres query pg --file /home/u/.ssh/id_ed25519",
		"database postgres restore pg --from ./dump.sql", "cluster apply k8s --file ./x.yaml", "fs write web /tmp/k --from .ssh/id_ed25519",
		"copy .ssh/id_ed25519 s3:",
		"copy .ssh/id_ed25519 web:/tmp/k", "copy .ssh web:/tmp/k --sync", "cluster kubernetes raw k8s -- apply -f /home/u/.ssh/id_ed25519",
		"cluster kubernetes raw k8s -- diff --filename=./x.yaml", "cluster kubernetes raw k8s -- create secret generic x --from-file=.ssh/id_ed25519",
		"cluster kubernetes raw k8s -- cp ./x pod-1:/tmp/x",
	}
	for _, line := range refused {
		for _, key := range []gateKey{readKey, netReadKey, fullKey} {
			words, _ := gateWords(line)
			_, _, e := gateCheck(words, key)
			if e == nil || e.Code != R || !strings.Contains(e.Message, "files on the komando computer") {
				// a read key may stop earlier, as a write or as network
				if key.readOnly && e != nil {
					continue
				}
				t.Errorf("%q %+v: %+v", line, key, e)
			}
		}
	}
	// the key's own input is the key's
	for _, line := range []string{"exec web --read-only --script - ", "database postgres query pg --file -", "cluster kubernetes raw k8s -- apply -f -",
		"exec web --read-only -- uptime", "copy - web:/tmp/x", "copy web:/etc/hosts web:/tmp/hosts"} {
		if got := gateKeyAnswer(t, line, fullKey); got != "" {
			t.Errorf("%q, full key: %q", line, got)
		}
	}
}

// localReadUsage: a flag whose help says it reads a file here.
var localReadUsage = regexp.MustCompile(`(?i)this computer|\('-'|stdin|file to send|from this file`)

// gateLocalNotRead are flags whose help matches localReadUsage but which
// read nothing here, and why.
func init() { // the providers of a moved type share one handler, so one reason
	for _, p := range []string{"s3", "gcs", "azblob", "sftp", "ftp", "smb", "webdav"} {
		gateLocalNotRead["storage."+p+".object.move.SRC"] = "a key in the conn"
	}
}

var gateLocalNotRead = map[string]string{
	"cp.overwrite":   "a download replaces files here: cp to here is refused anyway",
	"sync.sudo":      "writes as root on the servers",
	"fs.mv.SRC":      "a path on the servers",
	"storage.mv.SRC": "a key in the conn",
	"copy.size":      "a number of bytes",
}

// Every flag or argument a key can reach that names a file on this
// computer to read is on gateLocalFlags or gateLocalArgs.
func TestGateLocalReadsClassified(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		name := commandName(c)
		top, _, _ := strings.Cut(name, ".")
		if !c.Runnable() || c.Annotations[groupOnly] == "true" || c.Hidden || c == c.Root() ||
			top == "help" || top == "completion" || gateNeedsPerson[cmdKeys[name]] || gateSavesHere[cmdKeys[name]] != nil && name != "storage.download" && name != "export" {
			return
		}
		if k, ok := kindOf(c); ok && k.Kind != kindRead {
			if _, on := gateOnServers[cmdKeys[name]]; !on {
				return // komando's own setup: refused for every key
			}
		}
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if f.Value.Type() == "bool" || !localReadUsage.MatchString(f.Usage) {
				return
			}
			if _, ok := gateLocalNotRead[name+"."+f.Name]; ok || slices.Contains(gateLocalFlags[name], f.Name) {
				return
			}
			t.Errorf("%s --%s (%q): put it on gateLocalFlags, or on gateLocalNotRead with why", name, f.Name, f.Usage)
		})
		for _, w := range strings.Fields(c.Use)[1:] {
			if strings.HasPrefix(w, "-") {
				break // the words after a flag are its value
			}
			w = strings.Trim(w, "[].")
			if _, ok := gateLocalNotRead[name+"."+w]; ok {
				continue
			}
			if (w == "SRC" || w == "FILE" || w == "LOCAL") && gateLocalArgs[name] == nil {
				t.Errorf("%s: its %s may be a file on this computer; put it on gateLocalArgs", name, w)
			}
		}
	}
	walk(newRoot(tcl))
	for n := range gateLocalFlags {
		if _, ok := commandKinds[cmdKeys[n]]; !ok {
			t.Errorf("gateLocalFlags names %q, which is no command", n)
		}
	}
	for n := range gateLocalArgs {
		if _, ok := commandKinds[cmdKeys[n]]; !ok {
			t.Errorf("gateLocalArgs names %q, which is no command", n)
		}
	}
}
