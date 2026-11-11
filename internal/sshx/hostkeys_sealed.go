package sshx

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/store"
)

// sealedHostKeys keeps pins in the sealed store: one record of type "pin"
// per server address (host:port, normalised as known_hosts does), holding
// its keys as authorized_keys lines. A check answers exactly as
// knownhosts does for the lines komando writes: by the host name the
// connection was made to, else by the remote address.
type sealedHostKeys struct{}

const pinType = "pin"

type pinRecord struct {
	Addr string   `json:"addr"`
	Keys []string `json:"keys"`
}

func (sealedHostKeys) view(ctx context.Context, fn func(hostKeyTx) error) error {
	d, err := store.DB(false)
	if errors.Is(err, store.ErrNoStore) {
		return fn(&sealedTx{}) // no store yet: no pins
	}
	if err != nil {
		return err
	}
	return storeBusy(d.View(ctx, func(tx *sealdb.Tx) error { return fn(&sealedTx{tx: tx}) }))
}

func (sealedHostKeys) update(ctx context.Context, fn func(hostKeyTx) error) error {
	d, err := store.DB(true)
	if err != nil {
		return err
	}
	return storeBusy(d.Update(ctx, func(tx *sealdb.Tx) error { return fn(&sealedTx{tx: tx}) }))
}

// storeBusy turns "another komando process holds the store" into its own
// error, so a connection that waited for the store does not read like a
// server that did not answer.
func storeBusy(err error) error {
	if err == nil || !isBusy(err) {
		return err
	}
	return out.Errf(out.ExitConflict, "STORE_BUSY",
		"another komando process is writing komando's store; a long `komando seal` or a stuck komando: wait for it to finish, then run it again",
		"komando's store stayed busy for %s, so the server's host key could not be checked: %v", sealdb.BusyTimeout, err)
}

// isBusy: SQLite gave up waiting for another writer's lock.
func isBusy(err error) bool {
	m := err.Error()
	return strings.Contains(m, "SQLITE_BUSY") || strings.Contains(m, "database is locked")
}

type sealedTx struct {
	tx      *sealdb.Tx // nil: no store yet
	idx     map[string]sealedPin
	revoked *sealedPin // the one record of revoked keys; nil until read
}

// revokedType is the record of host keys never to trust, for any server:
// the @revoked lines of a known_hosts that `komando seal` moved.
const revokedType = "pinrevoked"

func (t *sealedTx) revokedKeys() (*sealedPin, error) {
	if t.revoked != nil {
		return t.revoked, nil
	}
	t.revoked = &sealedPin{}
	if t.tx == nil {
		return t.revoked, nil
	}
	rows, err := t.tx.List(revokedType)
	if err != nil {
		return nil, err
	}
	switch len(rows) {
	case 0:
	case 1:
		if err := json.Unmarshal(rows[0].Data, &t.revoked.rec); err != nil {
			return nil, err
		}
		t.revoked.id = rows[0].ID
	default:
		return nil, sealdb.ErrTampered
	}
	return t.revoked, nil
}

// isRevoked reports key on the never-trust list.
func (t *sealedTx) isRevoked(key ssh.PublicKey) (bool, error) {
	r, err := t.revokedKeys()
	if err != nil {
		return false, err
	}
	for _, line := range r.rec.Keys {
		if k, ok := parsePinLine(line); ok && SameKey(k, key) {
			return true, nil
		}
	}
	return false, nil
}

// errRevoked: a key on the never-trust list.
func errRevoked(key ssh.PublicKey) error {
	return &knownhosts.RevokedError{Revoked: knownhosts.KnownKey{Key: key, Filename: store.StoreFile}}
}

type sealedPin struct {
	id  string
	rec pinRecord
}

// index reads every pin record once per step (names are sealed, so a pin
// is found by opening them).
func (t *sealedTx) index() (map[string]sealedPin, error) {
	if t.idx != nil {
		return t.idx, nil
	}
	t.idx = map[string]sealedPin{}
	if t.tx == nil {
		return t.idx, nil
	}
	rows, err := t.tx.List(pinType)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		var p pinRecord
		if err := json.Unmarshal(r.Data, &p); err != nil {
			return nil, err
		}
		if _, dup := t.idx[p.Addr]; dup || p.Addr == "" {
			return nil, sealdb.ErrTampered
		}
		t.idx[p.Addr] = sealedPin{r.ID, p}
	}
	return t.idx, nil
}

func parsePinLine(line string) (ssh.PublicKey, bool) {
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	return k, err == nil
}

func (t *sealedTx) Check(hostname string, remote net.Addr, key ssh.PublicKey) error {
	target := hostname
	if target == "" {
		target = remote.String()
	}
	// as knownhosts: a host name without a port is an error, not a match
	if _, _, err := net.SplitHostPort(target); err != nil {
		return err
	}
	if rev, err := t.isRevoked(key); err != nil || rev {
		if err != nil {
			return err
		}
		return errRevoked(key)
	}
	idx, err := t.index()
	if err != nil {
		return err
	}
	ke := &knownhosts.KeyError{}
	norm := knownhosts.Normalize(target)
	for i, line := range idx[norm].rec.Keys {
		k, ok := parsePinLine(line)
		if !ok {
			// a pin that cannot be read is never "no pin": that would let
			// any new key in on first use
			return out.Errf(out.ExitConnect, "HOSTKEY_UNREADABLE",
				"a person checks the server's key and runs `komando host trust` for it in their own terminal",
				"the pinned host key for %s cannot be read", norm)
		}
		ke.Want = append(ke.Want, knownhosts.KnownKey{Key: k, Filename: store.StoreFile, Line: i + 1})
		if SameKey(k, key) {
			return nil
		}
	}
	return ke
}

func (t *sealedTx) Pins(addr string) ([]ssh.PublicKey, int, error) {
	idx, err := t.index()
	if err != nil {
		return nil, 0, err
	}
	p := idx[knownhosts.Normalize(addr)]
	var keys []ssh.PublicKey
	for _, line := range p.rec.Keys {
		if k, ok := parsePinLine(line); ok {
			keys = append(keys, k)
		}
	}
	return keys, len(p.rec.Keys), nil
}

func (t *sealedTx) put(addr string, keys []string) error {
	if t.tx == nil {
		return errors.New("sshx: no store to pin in")
	}
	idx, err := t.index()
	if err != nil {
		return err
	}
	norm := knownhosts.Normalize(addr)
	rec := pinRecord{Addr: norm, Keys: keys}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	r, err := t.tx.Put(pinType, idx[norm].id, b)
	if err != nil {
		return err
	}
	idx[norm] = sealedPin{r.ID, rec}
	return nil
}

func pinLine(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func (t *sealedTx) Add(addr string, key ssh.PublicKey) error {
	if rev, err := t.isRevoked(key); err != nil || rev {
		if err != nil {
			return err
		}
		return errRevoked(key)
	}
	idx, err := t.index()
	if err != nil {
		return err
	}
	keys := append([]string{}, idx[knownhosts.Normalize(addr)].rec.Keys...)
	return t.put(addr, append(keys, pinLine(key)))
}

func (t *sealedTx) Replace(addr string, key ssh.PublicKey) error {
	if rev, err := t.isRevoked(key); err != nil || rev {
		if err != nil {
			return err
		}
		return errRevoked(key)
	}
	return t.put(addr, []string{pinLine(key)})
}

// RevokeHostKeys puts keys on the never-trust list: no server is reached
// with them, and none can be pinned (`komando seal` carries a known_hosts
// file's @revoked lines here).
func RevokeHostKeys(keys []ssh.PublicKey) error {
	if len(keys) == 0 {
		return nil
	}
	return sealedHostKeys{}.update(context.Background(), func(ht hostKeyTx) error {
		t := ht.(*sealedTx)
		r, err := t.revokedKeys()
		if err != nil {
			return err
		}
		lines := append([]string{}, r.rec.Keys...)
		for _, k := range keys {
			if rev, _ := t.isRevoked(k); !rev {
				lines = append(lines, pinLine(k))
			}
		}
		b, err := json.Marshal(pinRecord{Addr: "*", Keys: lines})
		if err != nil {
			return err
		}
		rec, err := t.tx.Put(revokedType, r.id, b)
		if err != nil {
			return err
		}
		t.revoked = &sealedPin{rec.ID, pinRecord{Addr: "*", Keys: lines}}
		return nil
	})
}

// HostKeyRevoked reports key on the never-trust list.
func HostKeyRevoked(key ssh.PublicKey) (bool, error) {
	var rev bool
	err := sealedHostKeys{}.view(context.Background(), func(ht hostKeyTx) error {
		var err error
		rev, err = ht.(*sealedTx).isRevoked(key)
		return err
	})
	return rev, err
}
