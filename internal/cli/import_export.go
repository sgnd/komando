package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// --- export ----------------------------------------------------------------

// exportFile is what `komando export` writes and `komando import komando`
// reads. Secrets stay in the vault; refs are kept, so on a new computer
// the same `komando secret set NAME` makes them work again.
type exportFile struct {
	Format  string           `json:"format"` // komando-export/1
	Hosts   []*store.Host    `json:"hosts"`
	Conns   []*store.Conn    `json:"conns"`
	Vpns    []*store.Vpn     `json:"vpns"`
	Recipes []*store.Snippet `json:"recipes"`
	Secrets []string         `json:"secrets_needed"` // vault names the refs use
	Keys    []string         `json:"keys_needed"`    // keychain keys the hosts use (the key files are not in the file)
}

const exportFormat = "komando-export/1"

func importKomando(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	var f exportFile
	if err := json.Unmarshal(b, &f); err != nil || f.Format == "" {
		var env struct {
			Data exportFile `json:"data"`
		}
		if err2 := json.Unmarshal(b, &env); err2 == nil && env.Data.Format != "" {
			f = env.Data
		} else if hosts, ok := parseHostsJSON(b); ok && len(hosts) > 0 {
			f = exportFile{Format: exportFormat, Hosts: hosts} // `komando host export` output
		} else {
			return nil, out.Errf(out.ExitUsage, "USAGE", "give a file made by `komando export --to FILE` or `komando host export`", "%s is not a komando export file", path)
		}
	}
	if f.Format != exportFormat {
		return nil, out.Usage("%s has format %q; this komando reads %s", path, f.Format, exportFormat)
	}
	p := newPlan()
	p.Hosts, p.Conns, p.Recipes, p.Vpns = f.Hosts, f.Conns, f.Recipes, f.Vpns
	// An export file may come from someone else. Nothing in it may point at
	// secrets or files that are already on this computer (a server of theirs
	// with password_ref secret:prod-db-pass would receive that password),
	// and nothing may skip a safety check.
	// Hosts get the same check in vetImportHosts, for every import.
	ref := func(owner, what string, r *string) {
		if note := dropForeignRef(owner, what, r); note != "" {
			p.Notes = append(p.Notes, note)
		}
	}
	for _, h := range p.Hosts {
		if h.ProxyCommand != "" {
			// a proxy command runs on this computer: never take one from a file
			p.Notes = append(p.Notes, fmt.Sprintf("%s: dropped proxy_command %q (it would run on this computer; set it yourself with `komando host edit %s --proxy-command ...`)", h.Name, h.ProxyCommand, h.Name))
			h.ProxyCommand = ""
		}
	}
	for _, c := range p.Conns {
		ref(c.Name, "password_ref", &c.PasswordRef)
		c.TrustedPlugin = "" // a login program is trusted on this computer only (import kubeconfig)
	}
	var vpns []*store.Vpn
	for _, v := range p.Vpns {
		ref(v.Name, "key_ref", &v.KeyRef)
		ref(v.Name, "psk_ref", &v.PSKRef)
		ref(v.Name, "config_ref", &v.ConfigRef)
		if strings.HasPrefix(v.Portal, "-") || strings.HasPrefix(v.Address, "-") || strings.HasPrefix(v.Service, "-") {
			p.Notes = append(p.Notes, v.Name+": skipped, a setting starts with '-'")
			continue
		}
		vpns = append(vpns, v)
	}
	p.Vpns = vpns
	for _, r := range p.Recipes {
		if r.ReadOnly {
			r.ReadOnly = false
			p.Notes = append(p.Notes, r.Name+": imported as a change; mark it read-only yourself with `recipe add --read-only --overwrite`")
		}
	}
	if len(f.Secrets) > 0 {
		p.Notes = append(p.Notes, "passwords are not in export files; set them with `komando secret set NAME` for: "+strings.Join(f.Secrets, ", "))
	}
	return p, nil
}

// dropForeignRef clears a ref from a file someone else may have written,
// unless it is empty or names a secret that is not set on this computer yet
// (the user sets it after importing). A ref to an existing secret or to a
// file would send this computer's password to the file author's server. It
// returns the note that says what was dropped, or "".
func dropForeignRef(owner, what string, r *string) string {
	name, ok := strings.CutPrefix(*r, "secret:")
	if *r == "" || (ok && name != "") {
		if _, err := vault.Get(name); !ok || errors.Is(err, vault.ErrNotFound) {
			return ""
		}
	}
	note := fmt.Sprintf("%s: dropped %s %q (imports may only name secrets that do not exist yet; set it yourself)", owner, what, *r)
	*r = ""
	return note
}

// dropForeignHostRefs applies dropForeignRef to an imported host's password
// and sudo refs and to its env values that name a secret (komando puts
// those into every command it runs there).
func dropForeignHostRefs(h *store.Host) []string {
	var notes []string
	for _, r := range []struct {
		what string
		ref  *string
	}{{"password_ref", &h.PasswordRef}, {"sudo_ref", &h.SudoRef}} {
		if n := dropForeignRef(h.Name, r.what, r.ref); n != "" {
			notes = append(notes, n)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(h.Env)) {
		v := h.Env[k]
		if !strings.HasPrefix(v, "secret:") {
			continue // a plain value
		}
		if n := dropForeignRef(h.Name, "env "+k, &v); n != "" {
			notes = append(notes, n)
			delete(h.Env, k)
		}
	}
	return notes
}

func exportCmd() *cobra.Command {
	var to string
	var overwrite bool
	c := &cobra.Command{
		Use:   "export [TARGET]",
		Short: "Save servers, conns and recipes to a file (no passwords)",
		Example: `  komando export --to komando-backup.json
  komando export @prod --to prod.json
  komando import komando komando-backup.json      # on the other computer`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			st, err := loadState()
			if err != nil {
				return err
			}
			sel := selection{Hosts: st.SortedHosts(), Conns: st.SortedConns(), Vpns: st.SortedVpns()}
			if len(args) == 1 {
				if sel, err = resolveSelection(st, args[0]); err != nil {
					return err
				}
			}
			need := map[string]bool{}
			f := exportFile{Format: exportFormat, Hosts: sel.Hosts, Conns: sel.Conns, Vpns: sel.Vpns, Recipes: []*store.Snippet{}, Secrets: []string{}, Keys: []string{}}
			for _, v := range sel.Vpns {
				for _, r := range []string{v.KeyRef, v.PSKRef} {
					if n, ok := strings.CutPrefix(r, "secret:"); ok {
						need[n] = true
					}
				}
			}
			keys := map[string]bool{}
			for _, h := range sel.Hosts {
				for _, r := range []string{h.PasswordRef, h.SudoRef} {
					if n, ok := strings.CutPrefix(r, "secret:"); ok {
						need[n] = true
					}
				}
				if k := st.Keys[h.Key]; k != nil {
					keys[h.Key] = true
					if n, ok := strings.CutPrefix(k.PassphraseRef, "secret:"); ok {
						need[n] = true
					}
				}
			}
			var keyFiles []string // what to copy to the other computer, as the export does not
			for _, n := range slices.Sorted(maps.Keys(keys)) {
				f.Keys = append(f.Keys, n)
				keyFiles = append(keyFiles, st.Keys[n].Path)
			}
			for _, c := range sel.Conns {
				if n, ok := strings.CutPrefix(c.PasswordRef, "secret:"); ok {
					need[n] = true
				}
				for _, r := range urlSecretRefs(c.URL) { // ?ca=secret:NAME
					need[r.Name] = true
				}
			}
			for n := range need {
				f.Secrets = append(f.Secrets, n)
			}
			sort.Strings(f.Secrets)
			if len(args) == 0 {
				for _, s := range st.Snippets {
					f.Recipes = append(f.Recipes, s)
				}
				sort.Slice(f.Recipes, func(i, j int) bool { return f.Recipes[i].Name < f.Recipes[j].Name })
			}
			if to == "" {
				out.P.Print("export", f, nil)
				return nil
			}
			if _, err := os.Stat(to); err == nil && !overwrite {
				return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick another file or pass --overwrite", "%s already exists", to)
			}
			b, _ := json.MarshalIndent(f, "", "  ")
			if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
				return err
			}
			if err := writeAtomic(to, func(tmp string) error { return os.WriteFile(tmp, append(b, '\n'), 0o600) }); err != nil {
				return err
			}
			res := map[string]any{"file": to, "hosts": len(f.Hosts), "conns": len(f.Conns), "vpns": len(f.Vpns), "recipes": len(f.Recipes), "secrets_needed": f.Secrets, "keys_needed": f.Keys}
			if len(keyFiles) > 0 {
				res["key_files"] = keyFiles // private keys: copied by hand, never put in an export file
			}
			out.P.Print("export", res, nil)
			return nil
		},
	}
	c.Flags().StringVar(&to, "to", "", "write to this file (0600) instead of printing")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace the file if it exists")
	return c
}
