package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// Import from and export to ~/.ssh/config.

func readFileOrStdin(p string) ([]byte, error) {
	if p == "-" {
		return readAllStdin()
	}
	return readLocalFile(p)
}

// sshUsed are the ssh_config directives komando turns into host settings.
// sshHarmless change nothing komando needs (its own client already behaves
// that way or the option only tunes OpenSSH). Anything else is reported
// after an import, so a setting is never dropped silently.
var sshUsed = set("hostname user port identityfile proxyjump proxycommand")
var sshHarmless = set(`serveraliveinterval serveralivecountmax addkeystoagent usekeychain identitiesonly
stricthostkeychecking userknownhostsfile globalknownhostsfile loglevel compression controlmaster controlpath
controlpersist connecttimeout tcpkeepalive visualhostkey hashknownhosts preferredauthentications
pubkeyauthentication passwordauthentication kbdinteractiveauthentication updatehostkeys canonicalizehostname
checkhostip batchmode`)

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

// sshConfigErr says why the config cannot be read. A new computer, or one
// that reaches its servers with a password, has no ~/.ssh/config at all:
// that is not a wrong path, so the hint is how to add a server instead.
func sshConfigErr(path string, err error) error {
	if errors.Is(err, os.ErrNotExist) && expandHome(path) == expandHome("~/.ssh/config") {
		e := localFileErr("FILE_NOT_FOUND", err, "add a server instead: `komando host add web1 deploy@10.0.0.5`")
		e.Message = "there is no ~/.ssh/config on this computer"
		return e
	}
	return localFileErr("FILE_NOT_FOUND", err, "")
}

// parseSSHConfig reads an OpenSSH config into hosts, following Include;
// wildcard Host patterns become defaults. notes lists what it could not
// carry over (Match blocks, ProxyCommand, ...), per host.
func parseSSHConfig(path string) (hosts []*store.Host, notes []string, err error) {
	type block struct {
		patterns []string
		opts     map[string]string
		raw      map[string]string // directive names as written, for notes
	}
	var blocks []*block
	matches := 0
	var read func(p string, depth int) error
	read = func(p string, depth int) error {
		if depth > 5 {
			return nil
		}
		f, err := os.Open(expandHome(p))
		if err != nil {
			if depth == 0 {
				return sshConfigErr(p, err)
			}
			return nil
		}
		defer f.Close()
		var cur *block
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, val := splitDirective(line)
			switch strings.ToLower(key) {
			case "include":
				for _, inc := range strings.Fields(val) {
					inc = expandHome(inc)
					if !filepath.IsAbs(inc) {
						inc = filepath.Join(filepath.Dir(expandHome(path)), inc)
					}
					matches, _ := filepath.Glob(inc)
					if len(matches) == 0 {
						notes = append(notes, "Include "+inc+": no such file")
					}
					for _, m := range matches {
						_ = read(m, depth+1)
					}
				}
			case "host":
				cur = &block{patterns: strings.Fields(val), opts: map[string]string{}, raw: map[string]string{}}
				blocks = append(blocks, cur)
			case "match":
				cur = nil
				matches++
			default:
				if cur != nil {
					k := strings.ToLower(key)
					if _, set := cur.opts[k]; !set { // first value wins, like ssh
						cur.opts[k] = strings.Trim(val, `"`)
						cur.raw[k] = key
					}
				}
			}
		}
		return sc.Err()
	}
	if err := read(path, 0); err != nil {
		return nil, nil, err
	}
	if matches > 0 {
		notes = append(notes, fmt.Sprintf("%s skipped: komando cannot evaluate Match; add those settings to the hosts with `komando host edit`", countOf(matches, "Match block")))
	}
	for _, b := range blocks {
		for _, pat := range b.patterns {
			if strings.ContainsAny(pat, "*?!") {
				if !strings.HasPrefix(pat, "!") {
					notes = append(notes, "Host "+pat+": used as defaults, not a server")
				}
				continue
			}
			opts := map[string]string{}
			// later wildcard blocks only fill unset values (ssh: first match wins)
			for _, ob := range blocks {
				if !blockMatches(ob.patterns, pat) {
					continue
				}
				for k, v := range ob.opts {
					if _, ok := opts[k]; !ok {
						opts[k] = v
					}
				}
			}
			name := pat
			if !nameRe.MatchString(name) {
				notes = append(notes, fmt.Sprintf("Host %s: not a name komando can use (letters, digits, . _ -)", pat))
				continue
			}
			// HostName may use %h (the name typed) and %% (a literal %)
			hostname := strings.NewReplacer("%h", pat, "%%", "%").Replace(opts["hostname"])
			h := &store.Host{Name: name, Address: hostname, User: opts["user"], Via: opts["proxyjump"]}
			if pc := opts["proxycommand"]; pc != "" && !strings.EqualFold(pc, "none") && h.Via == "" {
				h.ProxyCommand = pc // your own ssh config: the same program runs as with ssh
			}
			if h.Address == "" {
				h.Address = pat
			}
			if p, err := strconv.Atoi(opts["port"]); err == nil {
				h.Port = p
			}
			if id := opts["identityfile"]; id != "" {
				h.Identity = expandHome(id)
			}
			if h.Via == "none" {
				h.Via = ""
			}
			var dropped []string
			for k := range opts {
				if !sshUsed[k] && !sshHarmless[k] {
					dropped = append(dropped, k)
				}
			}
			if len(dropped) > 0 {
				sort.Strings(dropped)
				notes = append(notes, fmt.Sprintf("%s: not carried over: %s", name, strings.Join(dropped, ", ")))
			}
			hosts = append(hosts, h)
		}
	}
	return hosts, notes, nil
}

func blockMatches(patterns []string, host string) bool {
	matched := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		if ok, _ := filepath.Match(p, host); ok {
			if neg {
				return false
			}
			matched = true
		}
	}
	return matched
}

func splitDirective(line string) (string, string) {
	if i := strings.IndexAny(line, " \t="); i > 0 {
		return line[:i], strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
	}
	return line, ""
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, p[2:])
	}
	return p
}
