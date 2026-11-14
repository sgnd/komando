package syncproto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Joiner is a new device waiting to be let in by a device the account
// already has (SS 6.3, spec 5.3). It holds a one-time 128-bit secret,
// shown as a QR code or 26 characters, good for 10 minutes and one try.
type Joiner struct {
	dev     *Device
	secret  []byte
	created time.Time
	used    bool
}

// ErrDeclined: the person said no to "Add this device?".
var ErrDeclined = errors.New("syncproto: the person declined")

func mailbox(secret []byte) string {
	return "pair/" + hex.EncodeToString(derive(secret, labelPairBox, 16))
}

// StartJoin makes the secret and posts the new device's keys and name,
// sealed under a key from the secret: the AEAD tag is the check code, so
// the server can neither read nor swap them. It returns the 26 characters.
func StartJoin(dev *Device) (*Joiner, string, error) {
	j := &Joiner{dev: dev, secret: randomBytes(16), created: dev.now()}
	sigs, err := joinSigs(dev.keys, &dev.rec, 0)
	if err != nil {
		return nil, "", err
	}
	var e enc
	dev.rec.encode(&e)
	e.str(dev.Name)
	e.u64(uint64(j.created.Unix()))
	e.u32(uint32(len(sigs)))
	for _, s := range sigs {
		e.u8(uint8(s.Role))
		e.raw(s.Sig[:])
	}
	box := oneTimeBox(derive(j.secret, labelPairReq, 32), []byte(labelPairReq), e.b)
	if err := dev.srv.Put(dev.id, mailbox(j.secret)+"/req", box); err != nil {
		return nil, "", err
	}
	return j, encode32(j.secret), nil
}

type joinRequest struct {
	rec     DeviceRecord
	name    string
	created time.Time
	sigs    []EntrySig
}

func openJoinRequest(secret, box []byte) (*joinRequest, error) {
	p, err := oneTimeOpen(derive(secret, labelPairReq, 32), []byte(labelPairReq), box)
	if err != nil {
		return nil, ErrCheckCode
	}
	d := dec{b: p}
	r := &joinRequest{rec: decodeDeviceRecord(&d), name: d.str(), created: time.Unix(int64(d.u64()), 0)}
	id := r.rec.ID()
	for range d.count(2) {
		s := EntrySig{Role: SigRole(d.u8()), Device: id}
		d.fixed(s.Sig[:])
		r.sigs = append(r.sigs, s)
	}
	if err := d.done(); err != nil || !r.rec.valid() {
		return nil, ErrCheckCode
	}
	return r, nil
}

// AcceptJoin is the existing device's side: read the code, check it,
// ask the person ("Add Budi's iPad?"), sign the entry with the authority
// key, seal the account key to the new device, and reply under the same
// secret with the account, the newest entry and a fresh summary.
func (d *Device) AcceptJoin(code string, confirm func(name string) bool) error {
	if d.keys.Authority == nil {
		return ErrNoAuthority
	}
	secret, err := decode32(code, 16)
	if err != nil {
		return ErrCheckCode
	}
	box, err := d.srv.Get(d.id, mailbox(secret)+"/req")
	if err != nil || len(box) == 0 {
		return ErrCheckCode
	}
	req, err := openJoinRequest(secret, box)
	if err != nil {
		return err
	}
	if age := d.now().Sub(req.created); age > PairingWindow || age < -PairingWindow {
		return ErrPairingExpired
	}
	// One try: the request is gone once read with the right code.
	if err := d.srv.Put(d.id, mailbox(secret)+"/req", nil); err != nil {
		return err
	}
	probe := &Entry{Body: Body{Action: ActAddDevice, Devices: []DeviceRecord{req.rec}}, Sigs: req.sigs}
	if !joinSigned(probe, &probe.Body) {
		return ErrCheckCode
	}
	if !confirm(req.name) {
		return ErrDeclined
	}
	if err := d.refreshList(); err != nil {
		return err
	}
	en := d.nextEntry(probe.Body)
	en.Sigs = req.sigs
	if err := en.signEntry(d.keys.Authority, RoleAuthority, d.id, 0); err != nil {
		return err
	}
	if err := d.appendEntry(en); err != nil {
		return err
	}
	if err := d.sealCurrentTo(req.rec); err != nil {
		return err
	}
	if _, err := d.pull(); err != nil {
		return err
	}
	if err := d.publishSummary(); err != nil {
		return err
	}
	var e enc
	e.raw(d.account[:])
	e.u32(d.head)
	e.raw(d.headHash[:])
	e.bytes(d.summaries[d.id].Marshal())
	reply := oneTimeBox(derive(secret, labelPairReply, 32), []byte(labelPairReply), e.b)
	return d.srv.Put(d.id, mailbox(secret)+"/reply", reply)
}

// sealCurrentTo seals the current account key to one device.
func (d *Device) sealCurrentTo(rec DeviceRecord) error {
	g := d.list.Gen
	ct, err := sealTo(rec.UnwrapPub, infoDevice(d.account, g.Gen, rec.ID()), d.acctKeys[g.Gen])
	if err != nil {
		return err
	}
	return d.srv.Put(d.id, blobDeviceKey(g.KeyID, rec.ID()), ct)
}

// Finish is the new device's side. It checks everything before trusting
// anything (SS 6.3 step 5): the reply opens under the secret, the chain
// leads from that account ID to that entry and lists this device, and the
// opened account key matches the key ID in the signed list.
func (j *Joiner) Finish() (*Device, error) {
	d := j.dev
	if j.used {
		return nil, ErrPairingUsed
	}
	if d.now().Sub(j.created) > PairingWindow {
		j.used = true
		return nil, ErrPairingExpired
	}
	box, err := d.srv.Get(d.id, mailbox(j.secret)+"/reply")
	if err != nil {
		return nil, err
	}
	if len(box) == 0 {
		return nil, ErrWaiting // not answered yet; this is not the one try
	}
	j.used = true
	defer clear(j.secret)
	p, err := oneTimeOpen(derive(j.secret, labelPairReply, 32), []byte(labelPairReply), box)
	if err != nil {
		return nil, ErrCheckCode
	}
	r := dec{b: p}
	var account, headHash Hash
	r.fixed(account[:])
	head := r.u32()
	r.fixed(headHash[:])
	sumBytes := r.bytes()
	if err := r.done(); err != nil {
		return nil, ErrCheckCode
	}
	if err := d.adopt(account, head, headHash); err != nil {
		return nil, err
	}
	if err := d.loadKeys(); err != nil {
		return nil, err
	}
	if err := d.CheckPeer(sumBytes); err != nil && !errors.Is(err, ErrMissingWrites) {
		return nil, fmt.Errorf("pairing summary: %w", err)
	}
	return d, d.writeInfo()
}

// adopt takes the account a pairing reply names, after checking the list
// from entry 1 leads to the named entry and lists this device.
func (d *Device) adopt(account Hash, head uint32, headHash Hash) error {
	d.account, d.trustUpTo = account, head
	if err := d.refreshList(); err != nil {
		return err
	}
	if d.head < head || d.list.Hashes[head-1] != headHash {
		return fmt.Errorf("%w: the list does not lead to the entry the pairing device named", ErrFork)
	}
	if m := d.list.Members[d.id]; m == nil || m.AddedAt > head {
		return fmt.Errorf("%w: this device is not on the list", ErrCheckCode)
	}
	d.joined = true
	return nil
}
