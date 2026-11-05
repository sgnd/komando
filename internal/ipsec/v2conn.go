package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// v2Conn keeps an IKEv2 connection up: liveness checks, the rekeys the
// server starts, new CHILD SAs when the server drops one, and a new IKE SA
// when the server asks for reauthentication (AUTH_LIFETIME).
type v2Conn struct {
	s *Session
	o *Options

	mu  sync.Mutex
	ike *ikeV2
}

func (c *v2Conn) current() *ikeV2 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ike
}

// establish makes a new IKE SA with its first CHILD SA.
func (c *v2Conn) establish(ctx context.Context) (*ikeV2, error) {
	k := newIKEv2(c.s.t, c.s, c.o, c)
	msg1, msg2, ni, nr, err := k.saInit(ctx)
	if err == nil {
		c.o.logf("IKEv2: IKE SA up (%s, PRF %s, DH %d)", k.suite.enc.name, k.suite.prf.name, k.suite.group)
		if err = c.s.t.startNATT(); err == nil {
			err = k.auth(ctx, msg1, msg2, ni, nr)
		}
	}
	if err != nil {
		// tell the server only once the IKE SA is up (after IKE_AUTH started)
		k.close(k.authStarted)
		return nil, err
	}
	return k, nil
}

func (c *v2Conn) start(ctx context.Context) error {
	k, err := c.establish(ctx)
	if err != nil {
		return err
	}
	c.ike = k
	c.s.closers = append(c.s.closers, func() { c.current().close(true) })
	go c.keepUp()
	return nil
}

// renew replaces the IKE SA (and its CHILD SA) with a new one.
func (c *v2Conn) renew(ctx context.Context) error {
	addr := c.s.Address
	c.s.Address = netip0
	k, err := c.establish(ctx)
	if err != nil {
		c.s.Address = addr
		return err
	}
	if got := c.s.Address; got != addr {
		k.close(true)
		c.s.Address = addr
		return fmt.Errorf("the server gave another address (%s, before %s) on reauthentication", got, addr)
	}
	c.mu.Lock()
	old := c.ike
	c.ike = k
	c.mu.Unlock()
	old.close(true)
	return nil
}

func (c *v2Conn) keepUp() {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	born := time.Now()
	espBorn := time.Now()
	life := c.o.Lifetime
	if life <= 0 {
		life = time.Hour
	}
	for {
		select {
		case <-c.s.done:
			return
		case <-tick.C:
		}
		k := c.current()
		k.mu.Lock()
		quiet := time.Since(k.alive)
		authLife := k.authLife
		k.mu.Unlock()
		if out := c.s.currentOut(); out != nil && out.born.After(espBorn) {
			espBorn = out.born // the server rekeyed
		}
		switch {
		case authLife > 0 && time.Since(born) > max(authLife-time.Minute, authLife*9/10):
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			err := c.renew(ctx)
			cancel()
			if err != nil {
				c.s.end(fmt.Errorf("could not log in again when the server asked (AUTH_LIFETIME): %v", err))
				return
			}
			born, espBorn = time.Now(), time.Now()
			c.o.logf("IKEv2: logged in again (reauthentication)")
		case time.Since(espBorn) > life*8/10:
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			err := k.newChild(ctx, true)
			cancel()
			if err != nil {
				c.s.end(fmt.Errorf("could not rekey the CHILD SA: %v", err))
				return
			}
			espBorn = time.Now()
		case quiet > 30*time.Second:
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			_, _, err := k.roundTrip(ctx, exInfo2, nil, true)
			cancel()
			if err != nil {
				if c.current() == k {
					c.s.end(errors.New("the VPN server stopped answering (liveness check)"))
				}
				return
			}
		}
	}
}

// ---- requests from the server

func (k *ikeV2) respond(m *v2msg, ps []v1Payload) {
	out, err := k.seal(m.exch, m.id, true, ps)
	if err != nil {
		return
	}
	k.mu.Lock()
	k.resps[m.id] = out
	delete(k.resps, m.id-8)
	k.mu.Unlock()
	k.t.sendIKE(out)
}

func (k *ikeV2) request(m *v2msg) {
	k.mu.Lock()
	switch {
	case m.id < k.peerID:
		out := k.resps[m.id]
		k.mu.Unlock()
		if out != nil {
			k.t.sendIKE(out) // our answer got lost
		}
		return
	case m.id > k.peerID:
		k.mu.Unlock()
		return
	}
	k.peerID++
	k.mu.Unlock()
	switch m.exch {
	case exInfo2:
		k.informational(m)
	case exChild:
		k.createChild(m)
	default:
		k.respond(m, []v1Payload{notify(7, nil)}) // INVALID_SYNTAX
	}
}

func (k *ikeV2) informational(m *v2msg) {
	var reply []v1Payload
	endIKE := false
	for _, p := range m.ps {
		if p.typ != pDelete || len(p.body) < 4 {
			continue
		}
		proto, spiLen, n := p.body[0], int(p.body[1]), int(binary.BigEndian.Uint16(p.body[2:]))
		if proto == 1 {
			endIKE = true
			continue
		}
		if proto != 3 || spiLen != 4 || len(p.body) < 4+4*n {
			continue
		}
		var ours []byte
		current := false
		for i := 0; i < n; i++ {
			spiOut := binary.BigEndian.Uint32(p.body[4+4*i:])
			if in, ok := k.s.inFor(spiOut); ok {
				ours = binary.BigEndian.AppendUint32(ours, in)
			}
			current = k.s.remove(spiOut) || current
		}
		if len(ours) > 0 {
			d := []byte{3, 4, 0, 0}
			binary.BigEndian.PutUint16(d[2:], uint16(len(ours)/4))
			reply = append(reply, v1Payload{typ: pDelete, body: append(d, ours...)})
		}
		if current {
			// the server dropped the SA in use without a new one: ask for one
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				if err := k.newChild(ctx, false); err != nil {
					k.s.end(fmt.Errorf("the server closed the tunnel (%v)", err))
				}
			}()
		}
	}
	k.respond(m, reply)
	if endIKE {
		if k.c != nil && k.c.current() == k {
			k.s.end(errors.New("the server ended the session"))
		}
		k.close(false)
	}
}

// createChild answers the server's CREATE_CHILD_SA: a CHILD SA rekey, or
// a rekey of the IKE SA itself.
func (k *ikeV2) createChild(m *v2msg) {
	sa, nonce := find(m.ps, pSA), find(m.ps, pNonce)
	if sa == nil || nonce == nil {
		k.respond(m, []v1Payload{notify(7, nil)})
		return
	}
	ni := nonce.body
	nr := random(32)
	ps := parseProposals(sa.body)
	if len(ps) > 0 && ps[0].proto == 1 {
		k.rekeyIKE(m, sa.body, ni, nr)
		return
	}
	suite, prop, ts, group, ok := pickESP(sa.body)
	if !ok {
		k.respond(m, []v1Payload{notify(nNoProposal, nil)})
		return
	}
	var gir []byte
	reply := []v1Payload{}
	spi := random(4)
	reply = append(reply, v1Payload{typ: pSA, body: proposalV2(prop.num, 3, spi, ts, true)}, v1Payload{typ: pNonce, body: nr})
	if group != 0 {
		ke := find(m.ps, pKE)
		if ke == nil || len(ke.body) < 4 || binary.BigEndian.Uint16(ke.body) != group {
			k.respond(m, []v1Payload{notify(nInvalidKE, binary.BigEndian.AppendUint16(nil, group))})
			return
		}
		dh, err := newDH(group)
		if err != nil {
			return
		}
		if gir, err = dh.Shared(ke.body[4:]); err != nil {
			k.respond(m, []v1Payload{notify(7, nil)})
			return
		}
		reply = append(reply, v1Payload{typ: pKE, body: append(binary.BigEndian.AppendUint16(nil, group), append([]byte{0, 0}, dh.Public()...)...)})
	}
	for _, p := range m.ps {
		if p.typ == pTSi || p.typ == pTSr {
			reply = append(reply, v1Payload{typ: p.typ, body: p.body})
		}
	}
	k.mu.Lock()
	ir, ri := k.childKeys(suite, gir, ni, nr)
	k.mu.Unlock()
	// the server started this exchange: initiator->responder is inbound
	esp, err := newESP(suite, binary.BigEndian.Uint32(spi), binary.BigEndian.Uint32(prop.spi), ir, ri)
	if err != nil {
		return
	}
	k.respond(m, reply)
	k.s.install(esp)
	k.o.logf("IKEv2: the server rekeyed ESP (%s, SPI %08x/%08x)", suite, esp.spiIn, esp.spiOut)
}

func (k *ikeV2) rekeyIKE(m *v2msg, sa, ni, nr []byte) {
	suite, prop, ts, ok := pickIKE(sa)
	if !ok {
		k.respond(m, []v1Payload{notify(nNoProposal, nil)})
		return
	}
	ke := find(m.ps, pKE)
	if ke == nil || len(ke.body) < 4 || binary.BigEndian.Uint16(ke.body) != suite.group {
		k.respond(m, []v1Payload{notify(nInvalidKE, binary.BigEndian.AppendUint16(nil, suite.group))})
		return
	}
	dh, err := newDH(suite.group)
	if err != nil {
		return
	}
	gir, err := dh.Shared(ke.body[4:])
	if err != nil {
		k.respond(m, []v1Payload{notify(7, nil)})
		return
	}
	spi := random(8)
	reply := []v1Payload{{typ: pSA, body: proposalV2(prop.num, 1, spi, ts, true)}, {typ: pNonce, body: nr},
		{typ: pKE, body: append(binary.BigEndian.AppendUint16(nil, suite.group), append([]byte{0, 0}, dh.Public()...)...)}}
	// the new IKE SA: the server, which started the rekey, is its initiator
	n := &ikeV2{t: k.t, s: k.s, o: k.o, c: k.c, spiI: prop.spi, spiR: spi, weInit: false, suite: suite,
		resps: map[uint32][]byte{}, pending: map[uint32]chan v2msg{}, frags: map[uint32]*fragSet{},
		alive: time.Now(), stop: make(chan struct{}), tsi: k.tsi, tsr: k.tsr, serverID: k.serverID}
	k.mu.Lock()
	seed := k.suite.prf.prf(k.skD, gir, ni, nr)
	k.mu.Unlock()
	n.derive(seed, ni, nr, prop.spi, spi)
	n.in = k.t.route(prop.spi)
	go n.run()
	k.respond(m, reply)
	if k.c != nil {
		k.c.mu.Lock()
		if k.c.ike == k {
			k.c.ike = n
		}
		k.c.mu.Unlock()
	}
	k.o.logf("IKEv2: the server rekeyed the IKE SA (%s, PRF %s, DH %d)", suite.enc.name, suite.prf.name, suite.group)
	// the server deletes the old IKE SA next; stop it after a while anyway
	time.AfterFunc(30*time.Second, func() { k.close(false) })
}

// newChild makes a new CHILD SA (rekey: and deletes the one in use).
func (k *ikeV2) newChild(ctx context.Context, rekey bool) error {
	old := k.s.currentOut()
	spi := random(4)
	ni := random(32)
	var ps []v1Payload
	if rekey && old != nil {
		ps = append(ps, v1Payload{typ: pNotify, body: binary.BigEndian.AppendUint32([]byte{3, 4, byte(nRekeySA >> 8), byte(nRekeySA & 0xff)}, old.spiIn)})
	}
	tsi, tsr := k.tsi, k.tsr
	if tsi == nil {
		tsi = tsAll()
	}
	if tsr == nil {
		tsr = tsAll()
	}
	ps = append(ps, v1Payload{typ: pSA, body: espProposals(spi, 0)}, v1Payload{typ: pNonce, body: ni},
		v1Payload{typ: pTSi, body: tsi}, v1Payload{typ: pTSr, body: tsr})
	r, _, err := k.roundTrip(ctx, exChild, ps, true)
	if err != nil {
		return err
	}
	if code, ok := r.errorNotify(); ok {
		return v2Error(code)
	}
	sa, nr := find(r.ps, pSA), find(r.ps, pNonce)
	if sa == nil || nr == nil {
		return errors.New("the server's CREATE_CHILD_SA answer is incomplete")
	}
	suite, peerSPI, _, err := chosenESP(sa.body)
	if err != nil {
		return err
	}
	k.mu.Lock()
	ir, ri := k.childKeys(suite, nil, ni, nr.body)
	k.mu.Unlock()
	esp, err := newESP(suite, binary.BigEndian.Uint32(spi), binary.BigEndian.Uint32(peerSPI), ri, ir)
	if err != nil {
		return err
	}
	k.s.install(esp)
	k.o.logf("IKEv2: new CHILD SA (%s, SPI %08x/%08x)", suite, esp.spiIn, esp.spiOut)
	if rekey && old != nil {
		d := binary.BigEndian.AppendUint32([]byte{3, 4, 0, 1}, old.spiIn)
		go func() {
			time.Sleep(time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			k.roundTrip(ctx, exInfo2, []v1Payload{{typ: pDelete, body: d}}, true)
			k.s.remove(old.spiOut)
		}()
	}
	return nil
}

// close stops the IKE SA; tell sends the server a Delete first.
func (k *ikeV2) close(tell bool) {
	k.mu.Lock()
	if k.ended {
		k.mu.Unlock()
		return
	}
	k.ended = true
	keys := k.skD != nil
	k.mu.Unlock()
	if tell && keys {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		k.roundTrip(ctx, exInfo2, []v1Payload{{typ: pDelete, body: []byte{1, 0, 0, 0}}}, true)
		cancel()
	}
	close(k.stop)
	k.t.unroute(k.spiI)
}

// DialIKEv2 connects an IKEv2 VPN: with a pre-shared key, or with an EAP
// login (User, Password) after checking the server's certificate.
func DialIKEv2(ctx context.Context, o Options) (*Session, error) {
	if o.PSK == "" && o.User == "" {
		return nil, errors.New("IKEv2 needs a pre-shared key or a user name")
	}
	t, err := newTransport(ctx, o.Server)
	if err != nil {
		return nil, err
	}
	s := newSession(t)
	c := &v2Conn{s: s, o: &o}
	if err := c.start(ctx); err != nil {
		s.end(err)
		return nil, err
	}
	return s, nil
}
