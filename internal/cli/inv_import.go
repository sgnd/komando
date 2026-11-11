package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/store"
)

// hostVet is what an import may add, and why the rest is left out.
type hostVet struct {
	Add       []*store.Host
	Existing  []string     // same name already there (no --overwrite)
	Protected []string     // would replace a protected host (needs --yes)
	Invalid   []importSkip // names or settings komando refuses
	Notes     []string
}

// vetImportHosts checks imported hosts against s the way host add does:
// names, ports, users, --via paths. The file may come from someone else, so
// its hosts may not use secrets or files of this computer
// (dropForeignHostRefs), unless ownRefs says it is the user's own list (a
// CSV). A proxy command runs on this computer, so it goes through
// guardProxyCommand (an AI agent needs a person's yes). Without --yes (or
// --allow-dangerous) the host is only left out, so the rest still comes
// in; a person who says no in the window stops the whole import. Hosts
// that pass are put into s.
func vetImportHosts(s *store.State, hosts []*store.Host, overwrite, ownRefs bool) (hostVet, error) {
	var v hostVet
	var cand []*store.Host
	later := map[*store.Host][]string{} // what changed on a host; said only if it is added
	for _, h := range hosts {
		if h == nil || h.Name == "" || h.Address == "" {
			continue
		}
		if err := checkHostName(h.Name); err != nil {
			v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(err).Message})
			continue
		}
		if kind, existing, ok := s.FindName(h.Name); ok {
			old, isHost := s.Hosts[h.Name]
			switch {
			case kind != "host" || existing != h.Name || !isHost:
				v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(nameTaken(kind, existing)).Message})
				continue
			case !overwrite:
				v.Existing = append(v.Existing, h.Name)
				continue
			case old.Protected && !yesOK():
				v.Protected = append(v.Protected, h.Name)
				continue
			}
		}
		h.Address = normAddr(h.Address)
		if h.Identity != "" {
			if _, err := os.Stat(expandHome(h.Identity)); err != nil {
				later[h] = append(later[h], h.Name+": its identity file "+h.Identity+" was not found; left out")
				h.Identity = ""
			}
		}
		if !ownRefs {
			later[h] = append(later[h], dropForeignHostRefs(h)...)
		}
		if h.Key != "" {
			if _, ok := s.Keys[h.Key]; !ok {
				// as with an identity file: the server comes in, its key
				// is said, and ssh-agent or a default key may log in
				// meanwhile (a key file is never in an export file)
				later[h] = append(later[h], fmt.Sprintf("%s: its key %s is not on this computer, so it was left out; copy the key file from the old computer, then run `komando key add %s PATH` and `komando host edit %s --key %s`", h.Name, h.Key, h.Key, h.Name, h.Key))
				h.Key = ""
			}
		}
		if err := checkEnvKeys(h.Env); err != nil {
			v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(err).Message})
			continue
		}
		if err := checkHostRefs(h); err != nil {
			v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(err).Message})
			continue
		}
		if r := proxyCommandSkip(h.ProxyCommand); r != "" {
			v.Invalid = append(v.Invalid, importSkip{h.Name, r})
			continue
		}
		if err := guardProxyCommand(h.ProxyCommand); err != nil {
			return v, err
		}
		cand = append(cand, h)
	}
	prev := map[string]*store.Host{} // what --overwrite replaces, put back if the new one is refused
	for _, h := range cand {         // so they can be each other's --via
		if old, ok := s.Hosts[h.Name]; ok {
			prev[h.Name] = old
		}
		s.Hosts[h.Name] = h
	}
	for _, h := range cand {
		if err := checkHost(s, h); err != nil {
			if old, ok := prev[h.Name]; ok {
				s.Hosts[h.Name] = old
			} else {
				delete(s.Hosts, h.Name)
			}
			v.Invalid = append(v.Invalid, importSkip{h.Name, toErr(err).Message})
			continue
		}
		v.Notes = append(v.Notes, later[h]...)
		if !h.Protected { // as host add does: a second name for a protected server
			if twin := protectedTwinHost(s, h); twin != "" {
				h.Protected = true
				v.Notes = append(v.Notes, sameTwinWarning("server", h.Name, twin))
			}
		}
		v.Add = append(v.Add, h)
	}
	return v, guardHostSends(v.Add, prev)
}

// proxyCommandSkip says why an import leaves out a host whose proxy
// command guardProxyCommand would stop and no flag asks to let through.
// With the flag, guardProxyCommand asks the person instead.
func proxyCommandSkip(cmd string) string {
	if cmd == "" {
		return ""
	}
	if hits := policy.Check(cmd, nil); len(hits) > 0 && !g.allowDangerous {
		return "its proxy command matches destructive rules (" + hits[0].Reason + "): import it again with --allow-dangerous once the user confirms it is intended"
	}
	if isAgent() && !g.yes {
		return "its proxy command runs on this computer, so an AI agent needs the user's yes: import it again with --yes after the user confirms"
	}
	return ""
}

// parseHostsJSON reads `host export` output (the envelope or its data), a
// `komando export` file, or a plain list of hosts.
func parseHostsJSON(b []byte) ([]*store.Host, bool) {
	var list []*store.Host
	if json.Unmarshal(b, &list) == nil {
		return list, true
	}
	var doc struct {
		Hosts []*store.Host `json:"hosts"`
		Data  *struct {
			Hosts []*store.Host `json:"hosts"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return nil, false
	}
	if doc.Hosts == nil && doc.Data != nil {
		return doc.Data.Hosts, true
	}
	return doc.Hosts, doc.Hosts != nil
}

func hostImportCmd() *cobra.Command {
	var sshConfig, jsonFile string
	var groups []string
	var overwrite bool
	c := &cobra.Command{
		Use:   "import",
		Short: "Add servers from ~/.ssh/config or a server export (JSON)",
		Long: `Adds servers from an OpenSSH config (like ` + "`komando import ssh-config`" + `) or from
JSON made by ` + "`komando host export`" + `. Existing names are skipped unless
--overwrite; replacing a protected server also needs --yes. Proxy commands
run on this computer, so an AI agent needs a person's yes for them.`,
		Example: `  komando host import --ssh-config ~/.ssh/config --group imported
  komando host import --json fleet.json --overwrite --dry-run`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var hosts []*store.Host
			var notes []string
			switch {
			case jsonFile != "":
				b, err := readFileOrStdin(jsonFile)
				if err != nil {
					return localFileErr("FILE_NOT_FOUND", err, "give the path of a file made by `komando host export`")
				}
				var ok bool
				if hosts, ok = parseHostsJSON(b); !ok {
					return out.Errf(out.ExitUsage, "USAGE", "give a file made by `komando host export` or `komando export`", "cannot read hosts from %s", jsonFile)
				}
			default:
				if sshConfig == "" {
					home, _ := os.UserHomeDir()
					sshConfig = filepath.Join(home, ".ssh", "config")
				}
				var err error
				hosts, notes, err = parseSSHConfig(sshConfig)
				if err != nil {
					return err
				}
			}
			for _, gr := range groups {
				if err := validLabelName("group", gr); err != nil {
					return err
				}
			}
			if st, err := store.Load(); err == nil {
				prefetchTwinIPs(st, hosts) // DNS before the inventory lock, not under it
			}
			var v hostVet
			err := store.Update(func(s *store.State) error {
				var err error
				if v, err = vetImportHosts(s, hosts, overwrite, false); err != nil {
					return err
				}
				now := time.Now().UTC()
				for _, h := range v.Add {
					h.Groups = dedupe(append(h.Groups, groups...))
					if h.CreatedAt.IsZero() {
						h.CreatedAt = now
					}
					h.UpdatedAt = now
				}
				return nil
			})
			if err != nil {
				return err
			}
			added := []string{}
			for _, h := range v.Add {
				added = append(added, h.Name)
			}
			audit(nil, "host.import", added, "", true, nil)
			key := "imported"
			if g.dryRun {
				key = "would_import"
			}
			res := map[string]any{key: added, "skipped_existing": orEmpty(v.Existing)}
			if len(v.Protected) > 0 {
				res["skipped_protected"] = v.Protected
				res["hint"] = "replacing protected hosts needs --yes after the user confirms"
			}
			if len(v.Invalid) > 0 {
				res["skipped_invalid"] = v.Invalid
			}
			if notes = append(notes, v.Notes...); len(notes) > 0 {
				res["notes"] = notes
			}
			incomplete := importIncomplete(len(v.Invalid))
			out.P.Print("host.import", textAs{res, textBlob(hostImportSay(added, v, notes))}, toErr(incomplete))
			if incomplete != nil {
				return exitCode(1)
			}
			return nil
		},
	}
	c.Flags().StringVar(&sshConfig, "ssh-config", "", "OpenSSH config file (default ~/.ssh/config)")
	c.Flags().StringVar(&jsonFile, "json", "", "JSON file made by komando host export (- for stdin)")
	c.Flags().StringSliceVarP(&groups, "group", "g", nil, "put the imported servers in these groups")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace servers that have the same name (protected ones also need --yes)")
	return c
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type hostExport struct {
	Hosts []*store.Host `json:"hosts"`
}

// Text is JSON too: `host import --json` reads what -o text prints.
func (e hostExport) Text() string {
	b, _ := json.MarshalIndent(e, "", "  ")
	return string(b) + "\n"
}

func hostExportCmd() *cobra.Command {
	var target string
	c := &cobra.Command{
		Use:   "export [TARGET]",
		Short: "Servers as JSON for `host import --json` (`komando export` saves everything)",
		Example: `  komando host export @prod > prod-hosts.json
  komando host import --json prod-hosts.json        # on another computer`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			if len(args) == 1 {
				target = args[0]
			}
			hosts := st.SortedHosts()
			if target != "" {
				if hosts, err = resolveTargets(st, target); err != nil {
					return err
				}
			}
			out.P.Print("host.export", hostExport{Hosts: hosts}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&target, "target", "", "same as the TARGET argument")
	_ = c.Flags().MarkHidden("target")
	return c
}

// hostImportSay is host import's text, in the words import says it in.
func hostImportSay(added []string, v hostVet, notes []string) string {
	lines := []string{changeSay("import", joinAnd(added), "")}
	for _, n := range v.Existing {
		lines = append(lines, "skipped "+n+": a server with this name exists (--overwrite replaces it)")
	}
	for _, n := range v.Protected {
		lines = append(lines, "skipped "+n+": it is protected; replacing it needs --yes after the user confirms")
	}
	for _, s := range v.Invalid {
		lines = append(lines, "skipped "+s.Name+": "+s.Reason)
	}
	for _, n := range notes {
		lines = append(lines, "note: "+n)
	}
	return strings.Join(lines, "\n")
}
