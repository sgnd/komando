package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// compareSealed reads the store back and checks it holds what the folder
// of before held: want is an untouched copy, with the key paths the move
// gave.
func compareSealed(o *oldFolder, want *store.State, paths map[string]string) error {
	st, err := store.Load()
	if err != nil {
		return err
	}
	same := func(what string, a, b any) error {
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		empty := func(j []byte) []byte { // none at all reads as an empty map
			if string(j) == "null" {
				return []byte("{}")
			}
			return j
		}
		if !bytes.Equal(empty(ja), empty(jb)) {
			return fmt.Errorf("the store does not read back the same %s", what)
		}
		return nil
	}
	for _, c := range []struct {
		what string
		a, b any
	}{{"servers", want.Hosts, st.Hosts}, {"conns", want.Conns, st.Conns}, {"VPNs", want.Vpns, st.Vpns},
		{"keys", want.Keys, st.Keys}, {"recipes", want.Snippets, st.Snippets}, {"settings", want.Settings, st.Settings},
		{"runtime data", o.st.Runtime, st.Runtime}} {
		if err := same(c.what, c.a, c.b); err != nil {
			return err
		}
	}
	list, err := vault.List()
	if err != nil || len(list) != len(o.secrets) {
		return fmt.Errorf("the store does not read back the secrets (%d of %d)", len(list), len(o.secrets))
	}
	for _, i := range list {
		s := o.secrets[i.Name]
		v, err := vault.Get(i.Name)
		if err != nil || v != string(s.Value) || !i.UpdatedAt.Equal(s.UpdatedAt) {
			return fmt.Errorf("the store does not read back secret %s", i.Name)
		}
	}
	for _, p := range o.pins {
		keys, err := sshx.PinnedKeys(p.addr)
		found := false
		for _, k := range keys {
			found = found || sshx.SameKey(k, p.key)
		}
		if err != nil || !found {
			return fmt.Errorf("the store does not read back the pinned key of %s", p.addr)
		}
	}
	for name := range paths {
		b, err := store.ReadPrivateKey(st.Keys[name])
		if err != nil || !bytes.Equal(b, o.keys[name].priv) {
			return fmt.Errorf("the store does not read back key %s", name)
		}
	}
	var got [][]byte
	if err := eachAudit(func(_ int, b []byte) error { got = append(got, bytes.Clone(b)); return nil }); err != nil {
		return err
	}
	if len(got) < len(o.audit) {
		return fmt.Errorf("the store does not read back the audit log (%d of %d)", len(got), len(o.audit))
	}
	for i, line := range o.audit {
		if !bytes.Equal(got[i], line) {
			return fmt.Errorf("the store does not read back audit record %d", i+1)
		}
	}
	return nil
}

// archiveFile is the archive's content: the files of before as they were
// read, the store's audit count at the move (an undo carries the records
// written after), and a vault key of before that lived in the keychain.
type archiveFile struct {
	Files      map[string][]byte `json:"files"`
	AuditCount int64             `json:"audit_count"`
	VaultKC    []byte            `json:"vault_keychain_key,omitempty"`
}

// writeArchive keeps the files of before, as the move read them, in one
// archive sealed with a key the store keeps for it. It stays until a
// person deletes it.
func writeArchive(o *oldFolder) error {
	n, err := store.AuditCount()
	if err != nil {
		return err
	}
	b, err := json.Marshal(archiveFile{Files: o.files, AuditCount: n, VaultKC: o.vaultKC})
	if err != nil {
		return err
	}
	sealed, err := store.SealArchive(b)
	clear(b)
	if err != nil {
		return err
	}
	p := store.Path(sealArchive)
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("%s is already there", p)
	}
	if err := store.WriteFileAtomic(p, sealed, 0o600); err != nil {
		return err
	}
	// read back: the archive is the only way back
	back, err := os.ReadFile(p)
	if err == nil {
		var a *archiveFile
		if a, err = openArchive(back); err == nil && len(a.Files) != len(o.files) {
			err = errors.New("the archive does not read back whole")
		}
	}
	if err != nil {
		os.Remove(p)
	}
	return err
}

func openArchive(b []byte) (*archiveFile, error) {
	plain, err := store.OpenArchive(b)
	if err != nil {
		return nil, err
	}
	var a archiveFile
	err = json.Unmarshal(plain, &a)
	clear(plain)
	return &a, err
}

// replaceOldFiles puts the note in place of each file of before the store
// now holds, and returns what it could not replace. The note goes in by a
// rename, so a file is never left half written; a private key's or the
// vault's old bytes are then overwritten through a handle kept open. Key
// files under keys/ that the store did not take stay as they are.
func replaceOldFiles(o *oldFolder) []string {
	moved := map[string]bool{}
	for _, k := range o.keys {
		moved[k.file], moved[k.file+".pub"] = true, true
	}
	var left []string
	rels := make([]string, 0, len(o.files))
	for rel := range o.files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		p := store.Path(rel)
		secret := rel == "vault.json" || rel == "vault.key" || (filepath.Dir(rel) == "keys" && filepath.Ext(rel) != ".pub")
		switch {
		case filepath.Dir(rel) == "keys" && !moved[rel]:
			continue
		case rel == "runtime.json":
			if err := store.UpdateRuntime(func(*store.State) error { return nil }); err != nil {
				left = append(left, rel+": "+err.Error())
			}
			continue
		}
		var old *os.File
		if secret {
			old, _ = os.OpenFile(p, os.O_WRONLY, 0)
		}
		var err error
		if rel == "vault.key" {
			err = os.Remove(p)
		} else {
			err = store.WriteFileAtomic(p, []byte(store.MovedNote), 0o600)
		}
		if old != nil {
			if fi, ferr := old.Stat(); ferr == nil && err == nil {
				_, _ = old.WriteAt(make([]byte, fi.Size()), 0)
				_ = old.Sync()
			}
			old.Close()
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			left = append(left, rel+": "+err.Error())
		}
	}
	return left
}

// unseal is `komando seal --undo`: the files of before come back from the
// archive, with the audit records written since, and store.db goes aside
// (renamed, never deleted). It puts back an older state of everything, so
// it is for a person only, with a yes.
func unseal() error {
	if err := needsPersonHere("seal --undo", false); err != nil {
		return err
	}
	b, err := os.ReadFile(store.Path(sealArchive))
	if errors.Is(err, os.ErrNotExist) {
		return out.Errf(out.ExitNotFound, "FILE_NOT_FOUND", "there is nothing to undo: this folder was not sealed by `komando seal`", "%s is not there", store.Path(sealArchive))
	}
	if err != nil {
		return err
	}
	a, err := openArchive(b)
	if err != nil {
		return fmt.Errorf("%s does not open: %w", sealArchive, err)
	}
	if g.dryRun {
		out.P.Print("seal.undo", map[string]any{"action": "would_undo", "files": len(a.Files)}, nil)
		return nil
	}
	if !sealConfirm("Put the files of before back? Changes made since `komando seal`, other than the audit log, stay only in the store, which is kept aside.") {
		return policyStop(out.Errf(out.ExitError, "CANCELLED", "nothing was changed in "+store.Home(), "the folder was not unsealed"))
	}
	// the same locks as seal: no komando writes the files of before while
	// they come back
	if err := store.BeginSeal(); err != nil {
		return err
	}
	defer store.EndSeal()
	if a.VaultKC != nil {
		if err := vault.RestoreKeychainKey(a.VaultKC); err != nil {
			return fmt.Errorf("the vault key of before cannot go back into the keychain: %w (nothing was changed)", err)
		}
	}
	// what stays only in the store otherwise: the audit records since the
	// move, and the runtime data, plain (the folder of before cannot open
	// a sealed runtime.json)
	since, _ := store.AuditAfter(a.AuditCount)
	rt, rtErr := store.OpenRuntimeFile()
	files := a.Files
	if len(since) > 0 {
		files["audit.jsonl"] = append(bytes.TrimRight(files["audit.jsonl"], "\n"), append([]byte("\n"), append(bytes.Join(since, []byte("\n")), '\n')...)...)
	}
	if rtErr == nil {
		files["runtime.json"] = rt
	}
	// keys first, state.json last: until state.json is back the folder
	// stays on the store, so a stop halfway changes nothing komando uses;
	// running it again finishes it
	rels := make([]string, 0, len(files))
	for rel := range files {
		if rel != "state.json" {
			rels = append(rels, rel)
		}
	}
	sort.Strings(rels)
	rels = append(rels, "state.json")
	for _, rel := range rels {
		data, ok := files[rel]
		if !ok {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(store.Path(rel)), 0o700); err != nil {
			return err
		}
		if err := store.WriteFileAtomic(store.Path(rel), data, 0o600); err != nil {
			return fmt.Errorf("putting back %s: %w; komando still uses the store, and `komando seal --undo` again finishes it", rel, err)
		}
	}
	_ = os.Remove(store.Path("runtime.pids"))
	ts := time.Now().UTC().Format("20060102T150405")
	aside := store.StoreFile + ".undone-" + ts
	if err := store.RemoveStore(aside); err != nil {
		return fmt.Errorf("the files of before are back, but %s could not be set aside (%w): rename it yourself, or komando goes on using it", store.Path(store.StoreFile), err)
	}
	_ = os.Rename(store.Path("store.key"), store.Path("store.key.undone-"+ts))
	_ = os.Rename(store.Path(sealArchive), store.Path(sealArchive+".used-"+ts))
	for rel := range a.Files {
		clear(a.Files[rel])
	}
	out.P.Print("seal.undo", map[string]any{"action": "undone", "files": len(a.Files), "store_kept_as": store.Path(aside)}, nil)
	return nil
}
