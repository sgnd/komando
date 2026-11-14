package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// XAUTH and Mode Config.

const (
	cfgReq = 1
	cfgRep = 2
	cfgSet = 3
	cfgAck = 4

	xauthType   = 16520
	xauthUser   = 16521
	xauthPass   = 16522
	xauthCode   = 16523
	xauthMsg    = 16524
	xauthChal   = 16525
	xauthDomain = 16526
	xauthStatus = 16527
	xauthNext   = 16528
	xauthAnswer = 16529

	cfgIP4Addr = 1
	cfgIP4Mask = 2
	cfgIP4DNS  = 3
)

func attrPayload(typ byte, id uint16, attrs []byte) v1Payload {
	b := []byte{typ, 0}
	b = binary.BigEndian.AppendUint16(b, id)
	return v1Payload{typ: plAttr, body: append(b, attrs...)}
}

// xauth answers the server's login requests until it says yes or no.
func (k *ikeV1) xauth(ctx context.Context) error {
	tries := 0
	for {
		var m v1msg
		select {
		case m = <-k.txn:
		case <-ctx.Done():
			return ctx.Err()
		case <-k.t.done:
			return fmt.Errorf("the connection ended: %v", k.t.err)
		case <-time.After(30 * time.Second):
			if tries == 0 {
				k.o.logf("IKEv1: the server asked for no XAUTH login")
				return nil
			}
			return errors.New("the XAUTH login got no answer")
		}
		ap := find(m.ps, plAttr)
		if ap == nil || len(ap.body) < 4 || !k.verify(m, nil) {
			continue
		}
		typ, id := ap.body[0], binary.BigEndian.Uint16(ap.body[2:])
		as := parseAttrs(ap.body[4:])
		k.o.logf("IKEv1: XAUTH message %d from the server", typ)
		switch typ {
		case cfgReq:
			tries++
			if tries > 3 {
				return &AuthError{Msg: "the server keeps asking for the XAUTH login"}
			}
			var reply []byte
			for _, a := range as {
				switch a.t {
				case xauthType:
					reply = append(reply, attrTV(xauthType, uint16(a.num()))...)
				case xauthUser:
					reply = append(reply, attrTLV(xauthUser, []byte(k.o.User))...)
				case xauthPass:
					reply = append(reply, attrTLV(xauthPass, []byte(k.o.Password))...)
				case xauthCode, xauthAnswer, xauthNext:
					if k.o.Prompt == nil {
						return ErrNeedsPerson
					}
					label := "One-time code"
					if msg := attrString(as, xauthMsg); msg != "" {
						label = msg
					}
					code, err := k.o.Prompt(label, a.t != xauthNext)
					if err != nil {
						return err
					}
					reply = append(reply, attrTLV(a.t, []byte(code))...)
				}
			}
			out, err := k.protected(exTxn, m.mid, []v1Payload{attrPayload(cfgRep, id, reply)})
			if err != nil {
				return err
			}
			k.sendLast(m.mid, out)
		case cfgSet:
			out, err := k.protected(exTxn, m.mid, []v1Payload{attrPayload(cfgAck, id, attrTV(xauthStatus, uint16(attrNum(as, xauthStatus))))})
			if err != nil {
				return err
			}
			k.sendLast(m.mid, out)
			if attrNum(as, xauthStatus) != 1 {
				return &AuthError{Msg: "the VPN refused the login (XAUTH): check the user name and password"}
			}
			return nil
		}
	}
}

func attrString(as []attr, t uint16) string {
	for _, a := range as {
		if a.t == t {
			return clean(string(a.v))
		}
	}
	return ""
}

func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7f && b.Len() < 200 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (k *ikeV1) sendLast(mid uint32, out []byte) {
	k.mu.Lock()
	k.lastOut[mid] = out
	k.mu.Unlock()
	k.t.sendIKE(out)
}

// modeConfig asks for an address and DNS servers (pull), or takes the
// ones the server pushes.
func (k *ikeV1) modeConfig(ctx context.Context) error {
	mid := newMID()
	req := append(attrTLV(cfgIP4Addr, nil), attrTLV(cfgIP4Mask, nil)...)
	req = append(req, attrTLV(cfgIP4DNS, nil)...)
	out, err := k.protected(exTxn, mid, []v1Payload{attrPayload(cfgReq, 1, req)})
	if err != nil {
		return err
	}
	// a push may already be waiting
	select {
	case m := <-k.txn:
		if ok, err := k.takeConfig(m); ok || err != nil {
			return err
		}
	default:
	}
	m, err := k.roundTrip(ctx, mid, out)
	if err != nil {
		return fmt.Errorf("mode config: %v", err)
	}
	_, err = k.takeConfig(m)
	return err
}

func (k *ikeV1) takeConfig(m v1msg) (bool, error) {
	ap := find(m.ps, plAttr)
	if ap == nil || len(ap.body) < 4 || !k.verify(m, nil) {
		return false, nil
	}
	typ := ap.body[0]
	if typ != cfgRep && typ != cfgSet {
		return false, nil
	}
	var addr netip.Addr
	for _, a := range parseAttrs(ap.body[4:]) {
		if len(a.v) != 4 {
			continue
		}
		v := netip.AddrFrom4([4]byte(a.v))
		switch a.t {
		case cfgIP4Addr:
			addr = v
		case cfgIP4DNS:
			if !slices.Contains(k.s.DNS, v) {
				k.s.DNS = append(k.s.DNS, v)
			}
		}
	}
	if addr.IsValid() {
		if k.s.Address.IsValid() && k.s.Address != addr {
			return true, fmt.Errorf("the server gave another address (%s, before %s) to the new IKE SA", addr, k.s.Address)
		}
		k.s.Address = addr
	}
	if typ == cfgSet {
		out, err := k.protected(exTxn, m.mid, []v1Payload{attrPayload(cfgAck, binary.BigEndian.Uint16(ap.body[2:]), nil)})
		if err == nil {
			k.sendLast(m.mid, out)
		}
	}
	if !k.s.Address.IsValid() {
		return true, errors.New("the server gave no address (mode config)")
	}
	return true, nil
}
