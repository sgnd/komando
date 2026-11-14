package syncproto

import (
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
)

// genKeys is one account key generation with its personal vault key
// (SS 7.1).
type genKeys struct {
	KeyGen
	acct  []byte
	vault []byte
}

// newGen makes account key gen and its vault key. The account sealing key
// (an X-Wing pair) is derived from the account key, so every device of the
// account has its private half without another sealed copy.
func newGen(gen uint32) (genKeys, error) {
	g := genKeys{acct: randomBytes(32), vault: randomBytes(32)}
	g.Gen = gen
	g.KeyID = keyID(g.acct)
	sk, err := xwing.DeriveKeyPair(derive(g.acct, labelSealingKey, 32))
	if err != nil {
		return g, err
	}
	g.SealingPub = sk.PublicKey().Bytes()
	return g, nil
}

func keyHex(id [16]byte) string { return hex.EncodeToString(id[:]) }

// Blob names. They carry the key ID, not the generation, so two devices
// racing to start the same generation never overwrite each other.
func blobDeviceKey(kid [16]byte, dev DeviceID) string { return "k/" + keyHex(kid) + "/" + hexID(dev) }
func blobKitKey(kid [16]byte, kit KitRecord) string {
	h := sum(labelSealKit, kit.SignPub)
	return "kk/" + keyHex(kid) + "/" + hex.EncodeToString(h[:16])
}
func blobVault(kid [16]byte) string   { return "v/" + keyHex(kid) }
func blobHistory(kid [16]byte) string { return "h/" + keyHex(kid) }

// The HPKE info values: the sealed account key is bound to the account,
// the generation and the receiver (SS 7.1).
func infoDevice(account Hash, gen uint32, dev DeviceID) []byte {
	var e enc
	e.raw([]byte(labelSealDevice))
	e.raw(account[:])
	e.u32(gen)
	e.raw(dev[:])
	return e.b
}

func infoKit(account Hash, gen uint32, kit KitRecord) []byte {
	var e enc
	e.raw([]byte(labelSealKit))
	e.raw(account[:])
	e.u32(gen)
	e.bytes(kit.SignPub)
	return e.b
}

func placeOf(label string, account Hash, gen uint32) []byte {
	var e enc
	e.raw([]byte(label))
	e.raw(account[:])
	e.u32(gen)
	return e.b
}

func (d *Device) installGen(g genKeys) {
	d.acctKeys[g.Gen] = g.acct
	d.vaultKeys[g.Gen] = g.vault
}

// uploadGen seals a new generation to every listed device and kit, puts
// the vault key under it, and puts every older account key under it, so a
// holder of the new key can still open old writes (SS 7.1).
func (d *Device) uploadGen(g genKeys) error {
	for id, m := range d.list.Members {
		ct, err := sealTo(m.Rec.UnwrapPub, infoDevice(d.account, g.Gen, id), g.acct)
		if err != nil {
			return err
		}
		if err := d.srv.Put(d.id, blobDeviceKey(g.KeyID, id), ct); err != nil {
			return err
		}
	}
	for _, k := range d.list.Kits {
		if err := d.sealToKit(g, k); err != nil {
			return err
		}
	}
	v, err := sealRecord(g.acct, placeOf(labelVaultKey, d.account, g.Gen), g.vault)
	if err != nil {
		return err
	}
	if err := d.srv.Put(d.id, blobVault(g.KeyID), v.bytes()); err != nil {
		return err
	}
	var e enc
	for _, gen := range slices.Sorted(maps.Keys(d.acctKeys)) {
		if gen < g.Gen {
			e.u32(gen)
			e.raw(d.acctKeys[gen])
		}
	}
	h, err := sealRecord(g.acct, placeOf(labelHistory, d.account, g.Gen), e.b)
	if err != nil {
		return err
	}
	return d.srv.Put(d.id, blobHistory(g.KeyID), h.bytes())
}

func (d *Device) sealToKit(g genKeys, k KitRecord) error {
	ct, err := sealTo(k.SealPub, infoKit(d.account, g.Gen, k), g.acct)
	if err != nil {
		return err
	}
	return d.srv.Put(d.id, blobKitKey(g.KeyID, k), ct)
}

// loadKeys opens the current generation sealed to this device, if it does
// not hold it yet, then its vault key and the older keys. Every opened
// account key is compared with the key ID in the signed list.
func (d *Device) loadKeys() error {
	g := d.list.Gen
	if d.acctKeys[g.Gen] != nil {
		return nil
	}
	ct, err := d.srv.Get(d.id, blobDeviceKey(g.KeyID, d.id))
	if err != nil {
		return err
	}
	if ct == nil {
		return ErrNoKey
	}
	acct, err := d.keys.Unwrap.Open(infoDevice(d.account, g.Gen, d.id), ct)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoKey, ErrOpen)
	}
	return d.installOpened(g, acct)
}

// installOpened checks an opened account key against the list, then opens
// the vault key and the history under it.
func (d *Device) installOpened(g KeyGen, acct []byte) error {
	if keyID(acct) != g.KeyID {
		return ErrKeyMismatch
	}
	vb, err := d.srv.Get(d.id, blobVault(g.KeyID))
	if err != nil {
		return err
	}
	vs, err := parseSealed(vb)
	if err != nil {
		return ErrNoKey
	}
	vault, err := openRecord(acct, placeOf(labelVaultKey, d.account, g.Gen), vs)
	if err != nil {
		return fmt.Errorf("%w: vault key: %v", ErrNoKey, err)
	}
	hb, err := d.srv.Get(d.id, blobHistory(g.KeyID))
	if err != nil {
		return err
	}
	hs, err := parseSealed(hb)
	if err != nil {
		return ErrNoKey
	}
	hist, err := openRecord(acct, placeOf(labelHistory, d.account, g.Gen), hs)
	if err != nil {
		return fmt.Errorf("%w: key history: %v", ErrNoKey, err)
	}
	if err := d.installHistory(hist); err != nil {
		return err
	}
	d.installGen(genKeys{KeyGen: g, acct: acct, vault: vault})
	return nil
}

// installHistory installs older account keys and their vault keys, each
// checked against the key ID in the list.
func (d *Device) installHistory(hist []byte) error {
	r := dec{b: hist}
	for len(r.b) > 0 && r.err == nil {
		gen := r.u32()
		acct := r.take(32)
		old, ok := d.list.Gens[gen]
		if r.err != nil || !ok || keyID(acct) != old.KeyID {
			return ErrKeyMismatch
		}
		if d.acctKeys[gen] != nil {
			continue
		}
		vb, err := d.srv.Get(d.id, blobVault(old.KeyID))
		if err != nil {
			return err
		}
		vs, err := parseSealed(vb)
		if err != nil {
			return ErrNoKey
		}
		vault, err := openRecord(acct, placeOf(labelVaultKey, d.account, gen), vs)
		if err != nil {
			return ErrNoKey
		}
		d.installGen(genKeys{KeyGen: old, acct: append([]byte{}, acct...), vault: vault})
	}
	return r.err
}
