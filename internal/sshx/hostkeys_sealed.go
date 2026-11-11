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
	tx  *sealdb.Tx // nil: no store yet
	idx map[string]sealedPin
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
	idx, err := t.index()
	if err != nil {
		return err
	}
	ke := &knownhosts.KeyError{}
	norm := knownhosts.Normalize(target)
	for i, line := range idx[norm].rec.Keys {
		k, ok := parsePinLine(line)
		if !ok {
			continue
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
	idx, err := t.index()
	if err != nil {
		return err
	}
	keys := append([]string{}, idx[knownhosts.Normalize(addr)].rec.Keys...)
	return t.put(addr, append(keys, pinLine(key)))
}

func (t *sealedTx) Replace(addr string, key ssh.PublicKey) error {
	return t.put(addr, []string{pinLine(key)})
}
