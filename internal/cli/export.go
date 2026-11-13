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
	"github.com/sgnd/komando/internal/sealfile"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

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
	Keys    []string         `json:"keys_needed"`    // keys from `komando key` the hosts use (the key files are not in the file)
	// whole exports only: your own deny rules and settings, so the safety
	// rules come along (import adds the rules; it only reports settings)
	DenyRules []string          `json:"deny_rules,omitempty"`
	Settings  map[string]string `json:"settings,omitempty"`
}

const exportFormat = "komando-export/1"

// Text is the file itself, as JSON, even with -o text: there is one export
// format, so `komando export -o text > FILE` is a file import reads too.
func (f exportFile) Text() string {
	b, _ := json.MarshalIndent(f, "", "  ")
	return string(b) + "\n"
}

func importKomando(path string) (*importPlan, error) {
	b, err := readSource(path)
	if err != nil {
		return nil, err
	}
	if sealfile.IsSealed(b) {
		return importSealed(path, b)
	}
	var f exportFile
	if err := json.Unmarshal(b, &f); err != nil || f.Format == "" {
		var env struct {
			Data exportFile `json:"data"`
		}
		if err2 := json.Unmarshal(b, &env); err2 == nil && env.Data.Format != "" {
			f = env.Data
		} else {
			return nil, out.Errf(out.ExitUsage, "USAGE", "give a file made by `komando export --to FILE`", "%s is not a komando export file", path)
		}
	}
	if f.Format != exportFormat {
		return nil, out.Usage("%s has format %q; this komando reads %s", path, f.Format, exportFormat)
	}
	p := planFromExport(f)
	if len(f.Secrets) > 0 {
		p.Notes = append(p.Notes, "passwords are not in export files; set them with `komando secret set NAME` for: "+strings.Join(f.Secrets, ", "))
	}
	return p, nil
}

// planFromExport is what an export document adds, with the limits for a
// file that may come from someone else.
func planFromExport(f exportFile) *importPlan {
	p := newPlan()
	p.Hosts, p.Conns, p.Recipes, p.Vpns = f.Hosts, f.Conns, f.Recipes, f.Vpns
	p.DenyRules, p.Settings = f.DenyRules, f.Settings
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
	return p
}

// dropForeignRef clears a ref from a file someone else may have written,
// unless it is empty or names a secret that is not set on this computer yet
// (the user sets it after importing). A ref to an existing secret or to a
// file would send this computer's password to the file author's server. It
// returns the note that says what was dropped, or "".
func dropForeignRef(owner, what string, r *string) string {
	name, ok := strings.CutPrefix(*r, "secret:")
	if ok && carriedSecrets[name] {
		return "" // a sealed file's own secret, with the file's value here
	}
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
// and sudo refs, its WinRM CA, and its env values that name a secret
// (komando puts those into every command it runs there).
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
	if h.WinRMOpts != nil {
		if n := dropForeignRef(h.Name, "winrm.ca", &h.WinRMOpts.CA); n != "" {
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

const exportLong = `Saves your list to a file (komando-export/1, always JSON) that
` + "`komando import komando FILE`" + ` reads on another computer. Passwords and key
files are never in it (only in a sealed file); it lists the secrets and keys
to bring along. With a
TARGET (@prod, kind:host, web1,web2) only those servers, conns and VPNs are
saved; without one also your recipes, deny rules and settings. Without --to
it prints the same JSON.

--sealed writes the same list with the passwords it uses into one sealed
file, for moving to another computer: komando asks for a passphrase twice
(15 or more characters), hidden, and the file opens only with it.
--for-phone seals the file to the iPhone app's key instead: komando asks
for the key file the phone shared and the key check the phone shows. Both
print a check phrase of six words; the phone shows the same words for the
file it got. --with-keys adds the private keys the servers use.

Only a person at a terminal can make a sealed file: an AI agent gets
NEEDS_PERSON, and a dry run says what would be sealed.`

func exportCmd() *cobra.Command {
	var to string
	var overwrite bool
	var seal exportSealOpts
	c := &cobra.Command{
		Use:   "export [TARGET]",
		Short: "Save servers, conns, VPNs, recipes and settings to a file",
		Long:  exportLong,
		Example: `  komando export --to komando-backup.json
  komando export @prod --to prod.json
  komando export kind:host --to servers.json
  komando import komando komando-backup.json      # on the other computer
  komando export --sealed --to move.kmdseal       # with passwords; asks a passphrase
  komando export --for-phone --to phone.kmdseal   # for the iPhone app; asks for its key`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := seal.check(to); err != nil {
				return err
			}
			st, err := loadState()
			if err != nil {
				return err
			}
			f, keyFiles, keysSealed, err := buildExport(st, args)
			if err != nil {
				return err
			}
			if seal.on() {
				return runExportSealed(st, f, seal, to, overwrite)
			}
			if to == "" {
				out.P.Print("export", f, nil)
				return nil
			}
			if err := exportTarget(to, overwrite); err != nil {
				return err
			}
			b, _ := json.MarshalIndent(f, "", "  ")
			if err := writeExport(to, append(b, '\n'), overwrite); err != nil {
				return err
			}
			out.P.Print("export", exportResult{File: to, Hosts: len(f.Hosts), Conns: len(f.Conns), Vpns: len(f.Vpns), Recipes: len(f.Recipes),
				DenyRules: len(f.DenyRules), Settings: len(f.Settings) > 0, SecretsNeeded: f.Secrets, KeysNeeded: f.Keys, KeyFiles: keyFiles, KeysSealed: keysSealed}, nil)
			return nil
		},
	}
	c.Flags().StringVar(&to, "to", "", "write to this file (0600) instead of printing")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace the file if it exists")
	c.Flags().BoolVar(&seal.sealed, "sealed", false, "seal the file with a passphrase, with the passwords in it (a person at a terminal; needs --to)")
	c.Flags().BoolVar(&seal.forPhone, "for-phone", false, "seal the file to the iPhone app's key, with the passwords in it (a person at a terminal; needs --to)")
	c.Flags().BoolVar(&seal.withKeys, "with-keys", false, "with --sealed or --for-phone: also the private keys the servers use")
	return c
}

// exportTarget checks that the export may write to: a file that is not
// there yet (or --overwrite), in a folder that exists or is made.
func exportTarget(to string, overwrite bool) error {
	if _, err := os.Stat(to); err == nil && !overwrite {
		return out.Errf(out.ExitConflict, "FILE_EXISTS", "pick another file or pass --overwrite", "%s already exists", to)
	}
	return os.MkdirAll(filepath.Dir(to), 0o700)
}

// writeExport writes an export file (0600) as a whole: a reader never sees
// half of it. With overwrite, the new file replaces the old one only once
// it is written.
func writeExport(to string, data []byte, overwrite bool) error {
	fill := func(tmp string) error { return os.WriteFile(tmp, data, 0o600) }
	if !overwrite {
		return writeAtomic(to, fill)
	}
	next := to + ".komando-new"
	_ = os.Remove(next)
	if err := writeAtomic(next, fill); err != nil {
		return err
	}
	return os.Rename(next, to)
}

// buildExport is the export document of what args picks (everything
// without one), the key files to copy by hand and the keys komando made.
func buildExport(st *store.State, args []string) (exportFile, []string, []string, error) {
	sel := selection{Hosts: st.SortedHosts(), Conns: st.SortedConns(), Vpns: st.SortedVpns()}
	if len(args) == 1 {
		var err error
		if sel, err = resolveSelection(st, args[0]); err != nil {
			return exportFile{}, nil, nil, err
		}
	}
	need := map[string]bool{}
	use := func(refs ...string) {
		for _, r := range refs {
			if n, ok := strings.CutPrefix(r, "secret:"); ok && n != "" {
				need[n] = true
			}
		}
	}
	f := exportFile{Format: exportFormat, Hosts: sel.Hosts, Conns: sel.Conns, Vpns: sel.Vpns, Recipes: []*store.Snippet{}, Secrets: []string{}, Keys: []string{}}
	for _, v := range sel.Vpns {
		use(v.KeyRef, v.PSKRef, v.ConfigRef)
	}
	keys := map[string]bool{}
	for _, h := range sel.Hosts {
		use(h.PasswordRef, h.SudoRef, winrmCA(h))
		for _, v := range h.Env {
			use(v)
		}
		if k := st.Keys[h.Key]; k != nil {
			keys[h.Key] = true
			use(k.PassphraseRef)
		}
	}
	var keyFiles, keysSealed []string // what to copy to the other computer, as the export does not
	f.Keys, keyFiles, keysSealed = exportKeys(st, keys)
	for _, c := range sel.Conns {
		use(c.PasswordRef)
		for _, r := range urlSecretRefs(c.URL) { // ?ca=secret:NAME
			need[r.Name] = true
		}
	}
	f.Secrets = append(f.Secrets, slices.Sorted(maps.Keys(need))...)
	if len(args) == 0 {
		f.DenyRules = st.Settings.ExtraDenyPattern
		f.Settings = map[string]string{}
		for _, s := range settings {
			f.Settings[s.Key] = s.get(&st.Settings)
		}
		for _, s := range st.Snippets {
			f.Recipes = append(f.Recipes, s)
		}
		sort.Slice(f.Recipes, func(i, j int) bool { return f.Recipes[i].Name < f.Recipes[j].Name })
	}
	return f, keyFiles, keysSealed, nil
}

// exportKeys are the keys the exported servers use, sorted: their files to
// copy by hand, and the keys komando made (sealed in store.db, no file).
func exportKeys(st *store.State, keys map[string]bool) (names, files, sealed []string) {
	names = []string{} // keys_needed is a list, never null
	for _, n := range slices.Sorted(maps.Keys(keys)) {
		names = append(names, n)
		if store.SealedKey(st.Keys[n]) {
			sealed = append(sealed, n)
		} else {
			files = append(files, st.Keys[n].Path)
		}
	}
	return names, files, sealed
}

// exportResult is what `export --to FILE` saved, and what to bring along.
type exportResult struct {
	File          string   `json:"file"`
	Hosts         int      `json:"hosts"`
	Conns         int      `json:"conns"`
	Vpns          int      `json:"vpns"`
	Recipes       int      `json:"recipes"`
	DenyRules     int      `json:"deny_rules"`
	Settings      bool     `json:"settings"` // the settings came along (a whole export)
	SecretsNeeded []string `json:"secrets_needed"`
	KeysNeeded    []string `json:"keys_needed"`
	KeyFiles      []string `json:"key_files,omitempty"` // private keys: copied by hand, never put in an export file
	// KeysSealed are keys komando made (key gen): sealed in store.db, so
	// there is no file to copy; the other computer makes its own
	KeysSealed []string `json:"keys_sealed,omitempty"`
	// A sealed export (--sealed, --for-phone): how it opens (passphrase or
	// recipient), the secrets and keys inside, the check phrase of the
	// file, and for --for-phone the key_id of the phone's key.
	Sealed        string   `json:"sealed,omitempty"`
	SecretsInFile []string `json:"secrets_in_file,omitempty"`
	KeysInFile    []string `json:"keys_in_file,omitempty"`
	CheckPhrase   []string `json:"check_phrase,omitempty"`
	PhoneKeyID    string   `json:"phone_key_id,omitempty"`
	DryRun        bool     `json:"dry_run,omitempty"`
}

func (r exportResult) Text() string {
	if r.Sealed != "" {
		return r.sealedText()
	}
	var what []string
	for _, c := range []struct {
		n    int
		word string
	}{{r.Hosts, "server"}, {r.Conns, "conn"}, {r.Vpns, "VPN"}, {r.Recipes, "recipe"}, {r.DenyRules, "deny rule"}} {
		if c.n > 0 {
			what = append(what, countOf(c.n, c.word))
		}
	}
	if len(what) == 0 {
		what = []string{"nothing"}
	}
	if r.Settings {
		what = append(what, "your settings")
	}
	t := "saved " + strings.Join(what, ", ") + " to " + r.File + " (no passwords)\n"
	if len(r.SecretsNeeded) > 0 {
		t += "set again on the other computer: " + strings.Join(r.SecretsNeeded, ", ") + " (`komando secret set NAME`)\n"
	}
	if len(r.KeyFiles) > 0 {
		t += "copy these key files too: " + strings.Join(r.KeyFiles, ", ") + "\n"
	}
	for _, k := range r.KeysSealed {
		t += "key " + k + " was made by komando and stays sealed here: on the other computer run `komando key gen " + k +
			"`, then put its public key on the servers from here (`komando key deploy FILE.pub TARGET`)\n"
	}
	return t
}
