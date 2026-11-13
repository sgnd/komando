package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// `komando seal` moves a komando folder of before (state.json, vault.json,
// known_hosts, audit.jsonl, keys/) into one sealed store, store.db.
//
// A person at a terminal only. The move holds every lock of the files of
// before from start to end, so no other komando writes them meanwhile, and
// builds the store under another name, so no other komando uses it before
// it is whole. It reads the old files once, writes the store, reads it
// back and compares it with an untouched copy of what it read, writes a
// sealed archive of the old files, puts the store in place, and only then
// replaces each old file with a short note an older komando stops at.
// `komando seal --undo` puts the old files back from the archive.

func sealCmd() *cobra.Command {
	var undo bool
	c := &cobra.Command{
		Use:   "seal",
		Short: "Move this komando folder into one sealed file (store.db)",
		Long: `Moves servers, conns, VPNs, keys, recipes, settings, secrets, remembered
fingerprints and the audit log from the files of an earlier komando into
one sealed file, store.db, the way a new komando folder keeps them. Every
record is sealed, so a copy of the file shows no names.

The old files are kept in a sealed archive (before-seal.archive) and
replaced by a short note, so an older komando stops instead of starting
empty. ` + "`komando seal --undo`" + ` puts them back. Run it yourself in a
terminal; an AI agent cannot.`,
		Example: `  komando seal --dry-run
  komando seal
  komando seal --undo`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if undo {
				return unseal()
			}
			return seal()
		},
	}
	c.Flags().BoolVar(&undo, "undo", false, "put the files of before back from before-seal.archive")
	return c
}

const sealArchive = "before-seal.archive"

// sealConfirm asks the person; tests answer for them.
var sealConfirm = confirmYes

// needsPersonHere stops an agent or a script. A dry run of seal is allowed
// to them (it reads names only); an undo's dry run opens the archive, so
// it is not.
func needsPersonHere(what string, dryRunOK bool) error {
	if g.dryRun && dryRunOK {
		return nil
	}
	if isAgent() || !interactive() {
		return out.Errf(out.ExitPolicy, "NEEDS_PERSON", "a person runs `komando "+what+"` in their own terminal",
			"%s changes where komando keeps everything, so only a person at a terminal can run it", "komando "+what)
	}
	return nil
}

// oldFolder is everything a folder of before holds, read once, read only.
type oldFolder struct {
	st      *store.State // untouched: what the store must read back as
	secrets map[string]vault.Secret
	names   []string // secret names (a dry run reads only these)
	pins    []oldPin
	revoked []ssh.PublicKey // @revoked keys: never trusted again, for any server
	skipped []string        // known_hosts entries komando cannot carry
	keys    map[string]oldKey
	audit   [][]byte
	files   map[string][]byte // the files of before, as read, for the archive
	vaultKC []byte            // a vault key of before kept in the keychain
}

type oldPin struct {
	addr string
	key  ssh.PublicKey
}

type oldKey struct {
	priv, pub []byte
	file      string // under keys/, relative to the folder
}

func readOldFolder(withSecrets bool) (*oldFolder, error) {
	o := &oldFolder{keys: map[string]oldKey{}, files: map[string][]byte{}}
	for _, rel := range oldFiles() {
		b, err := os.ReadFile(store.Path(rel))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		o.files[rel] = b
	}
	var err error
	if o.st, err = store.ReadOldState(); err != nil {
		return nil, err
	}
	if withSecrets {
		if o.secrets, err = vault.ExportFiles(); err != nil {
			return nil, err
		}
		for n := range o.secrets {
			o.names = append(o.names, n)
		}
		if k, ok, _ := vault.KeychainKeyOfOldVault(); ok {
			o.vaultKC = k
		}
	} else if o.names, err = vault.OldNames(); err != nil {
		return nil, err
	}
	o.readPins(o.files["known_hosts"])
	for name, k := range o.st.Keys {
		rel, ok := underKeys(k.Path)
		if !ok || store.SealedKey(k) {
			continue
		}
		o.keys[name] = oldKey{priv: o.files[rel], pub: o.files[rel+".pub"], file: rel}
		if o.keys[name].priv == nil {
			return nil, fmt.Errorf("key %s: %s is missing", name, k.Path)
		}
	}
	for _, line := range bytes.Split(o.files["audit.jsonl"], []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			o.audit = append(o.audit, line)
		}
	}
	return o, nil
}

// underKeys says whether p is a file under this folder's keys/, and its
// path relative to the folder.
func underKeys(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	abs := func(s string) string {
		s = expandHome(s)
		if r, err := filepath.EvalSymlinks(s); err == nil {
			s = r
		} else if r, err := filepath.EvalSymlinks(filepath.Dir(s)); err == nil {
			s = filepath.Join(r, filepath.Base(s))
		}
		a, _ := filepath.Abs(s)
		return a
	}
	dir := abs(store.Path("keys"))
	f := abs(p)
	if filepath.Dir(f) != dir {
		return "", false
	}
	return filepath.Join("keys", filepath.Base(f)), true
}

// readPins reads known_hosts lines komando can carry: plain names, and
// @revoked keys (kept as never-trust); @cert-authority lines and hashed or
// wildcard names are skipped and named.
func (o *oldFolder) readPins(b []byte) {
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 || bytes.HasPrefix(bytes.TrimSpace(line), []byte("#")) {
			continue
		}
		marker, hosts, key, _, _, err := ssh.ParseKnownHosts(line)
		if err == nil && marker == "revoked" {
			o.revoked = append(o.revoked, key)
			continue
		}
		if err != nil || marker != "" {
			o.skipped = append(o.skipped, string(bytes.Fields(line)[0]))
			continue
		}
		for _, h := range hosts {
			if strings.HasPrefix(h, "|") || strings.ContainsAny(h, "*?!") {
				o.skipped = append(o.skipped, h)
				continue
			}
			host, port := h, "22"
			if hh, pp, err := net.SplitHostPort(h); err == nil {
				host, port = hh, pp
			}
			o.pins = append(o.pins, oldPin{net.JoinHostPort(host, port), key})
		}
	}
	// a key that is also revoked is never trusted, as with OpenSSH
	kept := o.pins[:0]
	for _, p := range o.pins {
		if slices.ContainsFunc(o.revoked, func(k ssh.PublicKey) bool { return sshx.SameKey(k, p.key) }) {
			o.skipped = append(o.skipped, p.addr+" (its key is revoked)")
			continue
		}
		kept = append(kept, p)
	}
	o.pins = kept
}

// oldFiles are the files of before the move reads and keeps in the
// archive, relative to the folder.
func oldFiles() []string {
	files := []string{"state.json", "runtime.json", "vault.json", "vault.key", "known_hosts", "audit.jsonl"}
	all, _ := filepath.Glob(store.Path("keys", "*"))
	for _, p := range all {
		files = append(files, filepath.Join("keys", filepath.Base(p)))
	}
	return files
}

type sealResult struct {
	Action   string   `json:"action"`
	Hosts    int      `json:"hosts"`
	Conns    int      `json:"conns"`
	Vpns     int      `json:"vpns"`
	Keys     int      `json:"keys"`
	Recipes  int      `json:"recipes"`
	Secrets  int      `json:"secrets"`
	Pins     int      `json:"pinned_host_keys"`
	Revoked  int      `json:"revoked_host_keys"`
	Audit    int      `json:"audit_records"`
	Archive  string   `json:"archive,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func (r sealResult) Text() string {
	var b strings.Builder
	verb := map[string]string{"sealed": "Sealed", "would_seal": "Would seal"}[r.Action]
	fmt.Fprintf(&b, "%s: %d servers, %d conns, %d VPNs, %d keys, %d recipes, %d secrets, %d pinned host keys, %d revoked host keys, %d audit records\n",
		verb, r.Hosts, r.Conns, r.Vpns, r.Keys, r.Recipes, r.Secrets, r.Pins, r.Revoked, r.Audit)
	if r.Archive != "" {
		fmt.Fprintf(&b, "The files of before are in %s; `komando seal --undo` puts them back.\n", r.Archive)
		b.WriteString("Their old bytes may live on in backups, disk snapshots and the disk itself: change the SSH keys and secrets if that matters.\n")
	}
	for _, w := range r.Warnings {
		b.WriteString("! " + w + "\n")
	}
	return b.String()
}

func seal() error {
	if err := needsPersonHere("seal", true); err != nil {
		return err
	}
	if _, err := os.Stat(store.Path(store.StoreFile)); err == nil {
		return finishSeal()
	}
	if !g.dryRun {
		if err := store.BeginSeal(); err != nil {
			return err
		}
		defer store.EndSeal()
	}
	o, err := readOldFolder(!g.dryRun)
	if err != nil {
		return err
	}
	defer vault.WipeSecrets(o.secrets)
	res := sealResult{Action: "would_seal", Hosts: len(o.st.Hosts), Conns: len(o.st.Conns), Vpns: len(o.st.Vpns), Keys: len(o.st.Keys),
		Recipes: len(o.st.Snippets), Secrets: len(o.names), Pins: len(o.pins), Revoked: len(o.revoked), Audit: len(o.audit)}
	if len(o.skipped) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d known_hosts entries cannot be carried over (hashed or wildcard names, @cert-authority lines; komando never writes them): unless host_key_policy is strict, those servers are pinned again without asking on their next connection, whatever key they show: %s", len(o.skipped), strings.Join(o.skipped, ", ")))
	}
	if g.dryRun {
		out.P.Print("seal", res, nil)
		return nil
	}
	question := fmt.Sprintf("Move %d servers, %d secrets and the rest into one sealed file?", res.Hosts, res.Secrets)
	if len(o.skipped) > 0 {
		question = fmt.Sprintf("%d known_hosts entries (%s) cannot be carried over: those servers are pinned again without asking on their next connection. ", len(o.skipped), strings.Join(o.skipped, ", ")) + question
	}
	if !sealConfirm(question) {
		return policyStop(out.Errf(out.ExitError, "CANCELLED", "run `komando seal` again to be asked again", "%s", "the folder was not sealed; nothing was changed in "+store.Home()))
	}
	store.StartBuilding()
	if err := buildSealed(o); err != nil {
		store.AbortSeal()
		return fmt.Errorf("nothing was changed: %w", err)
	}
	if err := writeArchive(o); err != nil {
		store.AbortSeal()
		return fmt.Errorf("nothing was changed: the archive of the old files could not be written: %w", err)
	}
	if err := store.FinishSeal(); err != nil {
		store.AbortSeal()
		_ = os.Remove(store.Path(sealArchive))
		return fmt.Errorf("nothing was changed: %w", err)
	}
	res.Action, res.Archive = "sealed", store.Path(sealArchive)
	audit(nil, "seal", nil, "", true, map[string]any{"hosts": res.Hosts, "secrets": res.Secrets})
	if left := replaceOldFiles(o); len(left) > 0 {
		out.P.Print("seal", res, out.Errf(out.ExitError, "SEAL_UNFINISHED", "fix what stops it, then run `komando seal` again: it finishes the job",
			"komando now uses the sealed store, but these files of before could not be replaced: %s", strings.Join(left, "; ")))
		return exitCode(out.ExitError)
	}
	out.P.Print("seal", res, nil)
	return nil
}

// finishSeal is `komando seal` on a sealed folder: a move that stopped
// before every old file was replaced is finished; otherwise there is
// nothing to do.
func finishSeal() error {
	if _, err := os.Stat(store.Path(sealArchive)); err != nil || g.dryRun {
		out.P.Print("seal", alreadySealed(), nil)
		return nil
	}
	o := &oldFolder{files: map[string][]byte{}, keys: map[string]oldKey{}}
	for _, rel := range oldFiles() {
		if b, err := os.ReadFile(store.Path(rel)); err == nil && !store.IsMovedNote(store.Path(rel)) {
			o.files[rel] = b
		}
	}
	if st, err := store.Load(); err == nil {
		for name, k := range st.Keys {
			if store.SealedKey(k) {
				o.keys[name] = oldKey{file: filepath.Join("keys", name)}
			}
		}
	}
	if left := replaceOldFiles(o); len(left) > 0 {
		return out.Errf(out.ExitError, "SEAL_UNFINISHED", "fix what stops it, then run `komando seal` again",
			"these files of before could not be replaced: %s", strings.Join(left, "; "))
	}
	out.P.Print("seal", alreadySealed(), nil)
	return nil
}

// buildSealed makes the store (under its building name) and puts
// everything of o in it, then reads it back and compares.
func buildSealed(o *oldFolder) error {
	if _, err := store.DB(true); err != nil {
		return err
	}
	var want store.State // what the store must read back as
	b, _ := json.Marshal(o.st)
	if err := json.Unmarshal(b, &want); err != nil {
		return err
	}
	paths := map[string]string{}
	for name, k := range o.keys {
		p, err := store.WriteManagedKey(name, k.priv, k.pub)
		if err != nil {
			return fmt.Errorf("key %s: %w", name, err)
		}
		paths[name] = p
	}
	follow := func(s *store.State) {
		for name, p := range paths {
			old := o.keys[name].file
			s.Keys[name].Path = p
			for _, h := range s.Hosts {
				if r, ok := underKeys(h.Identity); ok && r == old {
					h.Identity, h.Key = "", name // a server given the key file itself follows the key
				}
			}
		}
	}
	follow(&want)
	err := store.Update(func(s *store.State) error {
		var fresh store.State
		_ = json.Unmarshal(b, &fresh)
		s.Hosts, s.Conns, s.Vpns, s.Keys, s.Snippets, s.Settings = fresh.Hosts, fresh.Conns, fresh.Vpns, fresh.Keys, fresh.Snippets, fresh.Settings
		follow(s)
		s.Runtime = o.st.Runtime
		return nil
	})
	if err != nil {
		return err
	}
	if err := vault.ImportSealed(o.secrets); err != nil {
		return err
	}
	if err := sshx.RevokeHostKeys(o.revoked); err != nil {
		return fmt.Errorf("revoked host keys: %w", err)
	}
	for _, p := range o.pins {
		if _, err := sshx.PinHostKey(p.addr, p.key, false); err != nil {
			return fmt.Errorf("pinned key of %s: %w", p.addr, err)
		}
	}
	if err := store.AppendAuditLines(o.audit); err != nil {
		return err
	}
	return compareSealed(o, &want, paths)
}

// alreadySealed is seal's result for a folder that is sealed already.
func alreadySealed() textAs {
	p := store.Path(store.StoreFile)
	return textAs{map[string]any{"action": "already_sealed", "store": p}, textFn(func() string {
		return "the komando folder is sealed already: " + p + "\n"
	})}
}
