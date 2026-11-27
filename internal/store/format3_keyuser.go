package store

import (
	"bytes"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"
)

// O-42 for new writes (coordinator, 2026-11-27; Audit to confirm, see
// TestFormat3KeyForAnotherUser): a server that logs in with a key another
// server uses under another user gets that user's own key credential, as
// the migration makes them. A key pair komando made is copied, sealed as
// the original is; the two are separate from then on (rotating or removing
// one leaves the other). The audit log names the copy.

// keyFor is the key credential entry logs in with for user: name itself
// when it is that user's or nobody else's, else user's copy of it.
func (w *writer3) keyFor(entry, name, user string, alone func(string) bool) (string, error) {
	c := w.st.cred(name)
	if c == nil || c.Kind != CredKey || c.Key == nil || c.User == user || alone(name) {
		return name, nil
	}
	for _, id := range slices.Sorted(maps.Keys(w.st.creds)) {
		o := w.st.creds[id]
		if o.Kind == CredKey && o.Key != nil && o.User == user && w.samePair(o.Key, c.Key) {
			return o.Name, nil
		}
	}
	k := *c.Key
	if id, ok := strings.CutPrefix(k.Path, sealedKeyPrefix); ok {
		r, err := w.tx.Get(id)
		if err != nil {
			return "", err
		}
		nr, err := w.tx.Put(keyDataType, "", r.Data)
		if err != nil {
			return "", err
		}
		k.Path = sealedKeyPrefix + nr.ID
	}
	cp := &Credential{Name: w.names.make(name, user), Kind: CredKey, User: user, Key: &k, UpdatedAt: time.Now().UTC()}
	id, err := w.put(KindCredential, "", cp)
	if err != nil {
		return "", err
	}
	w.st.creds[id], w.st.credID[cp.Name] = cp, id
	entryJSON, err := json.Marshal(map[string]any{
		"ts": time.Now().UTC().Format(time.RFC3339Nano), "command": "credential.copy", "ok": true, "dry_run": false,
		"actor": "komando", "from": name, "to": cp.Name, "user": user, "for": entry,
	})
	if err != nil {
		return "", err
	}
	return cp.Name, w.tx.AppendAudit(entryJSON)
}

// samePair reports whether a and b are the same key: by fingerprint, by the
// stored key pair of a key komando made, else by the key file.
func (w *writer3) samePair(a, b *CredentialKey) bool {
	if a.Fingerprint != "" || b.Fingerprint != "" {
		return a.Fingerprint == b.Fingerprint
	}
	ia, sa := strings.CutPrefix(a.Path, sealedKeyPrefix)
	ib, sb := strings.CutPrefix(b.Path, sealedKeyPrefix)
	if sa != sb {
		return false
	}
	if !sa {
		return a.Path == b.Path
	}
	ra, err := w.tx.Get(ia)
	if err != nil {
		return false
	}
	rb, err := w.tx.Get(ib)
	return err == nil && bytes.Equal(ra.Data, rb.Data)
}
