package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// v1Conn keeps an IKEv1 connection up: dead peer detection, and new SAs
// before the old ones expire.
type v1Conn struct {
	s   *Session
	o   *Options
	tun bool

	mu      sync.Mutex
	ike     *ikeV1
	renewMu sync.Mutex // one renewal at a time
}

// phase1 runs main mode (or aggressive mode with a group name) and, for
// Cisco-style IPsec, XAUTH and mode config.
func (c *v1Conn) phase1(ctx context.Context, first bool) (*ikeV1, error) {
	if c.o.ID == "" {
		k := newIKEv1(c.s.t, c.s, c.o, c.tun)
		if err := k.mainMode(ctx); err != nil {
			c.s.t.unroute(k.ic)
			return nil, legacyHint(c.o, err)
		}
		return c.finish(ctx, k)
	}
	if first {
		c.o.logf("IKEv1: warning: aggressive mode (a group name and pre-shared key) lets anyone who sees the login guess the group key offline, and with the key pretend to be this server; use IKEv2 if the server offers it")
	}
	groups := []uint16{14} // one DH group per offer in aggressive mode
	if c.o.LegacyCrypto {
		groups = append(groups, 2, 5)
	}
	var err error
	for _, g := range groups {
		k := newIKEv1(c.s.t, c.s, c.o, c.tun)
		if err = k.aggressiveOnce(ctx, g); err == nil {
			return c.finish(ctx, k)
		}
		c.s.t.unroute(k.ic)
		var ae *AuthError
		if errors.As(err, &ae) || ctx.Err() != nil || !strings.Contains(err.Error(), "accepted none") {
			return nil, err
		}
		c.o.logf("IKEv1: DH group %d refused, trying another", g)
	}
	return nil, legacyHint(c.o, err)
}

func (c *v1Conn) finish(ctx context.Context, k *ikeV1) (*ikeV1, error) {
	k.onDelete = func() { c.serverDeleted(k) }
	k.onESPLost = func() { c.replaceESP(k) }
	c.o.logf("IKEv1: IKE SA up (%s/%s, DH %d)", k.suite.enc.name, k.suite.hash.name, k.suite.group)
	if k.suite.weak() {
		c.o.logf("IKEv1: warning: the server chose %s, which is weak (allowed because legacy crypto is on for this VPN); ask its admin for AES and DH group 14 or higher", k.suite)
	}
	if c.tun {
		if c.o.User != "" {
			if err := k.xauth(ctx); err != nil {
				k.deleteIKE()
				c.s.t.unroute(k.ic)
				return nil, err
			}
		}
		// every IKE SA asks for the address again: the server ties it to
		// the IKE SA and refuses a quick mode for an address it did not give
		if err := k.modeConfig(ctx); err != nil {
			k.deleteIKE()
			c.s.t.unroute(k.ic)
			return nil, err
		}
	}
	return k, nil
}

func (c *v1Conn) current() *ikeV1 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ike
}

// serverDeleted: the server ended the IKE SA. The ESP SAs may live on;
// komando starts a new IKE SA so rekeys and DPD keep working.
func (c *v1Conn) serverDeleted(k *ikeV1) {
	if c.current() != k || !c.renewMu.TryLock() {
		return // replaced already, or a renewal is under way (it is what the server answers)
	}
	c.renewMu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := c.renew(ctx); err != nil {
			c.s.end(fmt.Errorf("the server ended the IPsec session (%v)", err))
		}
	}()
}

// replaceESP makes a new ESP SA after the server deleted the one in use
// (its lifetime ran out without a rekey); failing that, a new IKE SA.
func (c *v1Conn) replaceESP(k *ikeV1) {
	if c.current() != k {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	err := k.quickMode(ctx)
	if err != nil {
		c.o.logf("IKEv1: new ESP SA failed (%v); making a new IKE SA", err)
		err = c.renew(ctx)
	}
	if err != nil {
		c.s.end(fmt.Errorf("the server ended the ESP SA and a new one failed: %v", err))
	}
}

// renew makes a new IKE SA and new ESP SAs, then drops the old IKE SA.
func (c *v1Conn) renew(ctx context.Context) error {
	c.renewMu.Lock()
	defer c.renewMu.Unlock()
	if c.o.Prompt != nil && c.tun && c.o.User != "" {
		// a one-time code cannot be asked again in the background
		c.o.Prompt = nil
	}
	k, err := c.phase1(ctx, false)
	if err != nil {
		return err
	}
	if err := k.quickMode(ctx); err != nil {
		c.s.t.unroute(k.ic)
		return err
	}
	c.mu.Lock()
	old := c.ike
	c.ike = k
	c.mu.Unlock()
	if old != nil {
		old.mu.Lock()
		gone := old.ended
		old.ended = true
		old.mu.Unlock()
		if !gone {
			b := append([]byte{0, 0, 0, 1, 1, 16, 0, 1}, old.ic...)
			old.info([]v1Payload{{typ: plDelete, body: append(b, old.rc...)}})
		}
		time.AfterFunc(10*time.Second, func() { c.s.t.unroute(old.ic) })
	}
	return nil
}

// keepUp runs until the session ends: DPD every 30 seconds, ESP rekeys
// at 80% of their lifetime, a new IKE SA at 80% of its own.
func (c *v1Conn) keepUp() {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	ikeBorn, espBorn := time.Now(), time.Now()
	missed, lastDPD := 0, time.Now()
	for {
		select {
		case <-c.s.done:
			return
		case <-tick.C:
		}
		k := c.current()
		k.mu.Lock()
		ikeLife, espLife := k.life, k.childLife
		k.mu.Unlock()
		if ikeLife <= 0 {
			ikeLife = 8 * time.Hour
		}
		if espLife <= 0 {
			espLife = time.Hour
		}
		switch {
		case time.Since(ikeBorn) > ikeLife*8/10:
			c.o.logf("IKEv1: the IKE SA is %s old; making a new one", time.Since(ikeBorn).Round(time.Second))
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			err := c.renew(ctx)
			cancel()
			if err != nil {
				c.s.end(fmt.Errorf("could not renew the IKE SA: %v", err))
				return
			}
			ikeBorn, espBorn = time.Now(), time.Now()
			c.o.logf("IKEv1: new IKE SA")
		case time.Since(espBorn) > espLife*8/10:
			old := c.s.currentOut()
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			err := k.quickMode(ctx)
			cancel()
			if err != nil {
				c.o.logf("IKEv1: ESP rekey failed: %v; making a new IKE SA", err)
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				err = c.renew(ctx)
				cancel()
				if err != nil {
					c.s.end(fmt.Errorf("could not rekey: %v", err))
					return
				}
				ikeBorn = time.Now()
			}
			espBorn = time.Now()
			if old != nil {
				b := []byte{0, 0, 0, 1, 3, 4, 0, 1}
				time.AfterFunc(5*time.Second, func() {
					c.current().info([]v1Payload{{typ: plDelete, body: binary.BigEndian.AppendUint32(b, old.spiIn)}})
				})
			}
		case k.dpd && time.Since(lastDPD) >= 30*time.Second:
			// the answer to the check sent 30 seconds ago
			k.mu.Lock()
			acked := k.dpdAck
			k.dpdAck = false
			k.mu.Unlock()
			if acked {
				missed = 0
			} else if time.Since(ikeBorn) > 40*time.Second {
				missed++
			}
			if missed >= 5 {
				c.s.end(errors.New("the VPN server stopped answering (dead peer detection)"))
				return
			}
			k.mu.Lock()
			k.dpdSeq++
			seq := binary.BigEndian.AppendUint32(nil, k.dpdSeq)
			k.mu.Unlock()
			k.info([]v1Payload{{typ: plNotify, body: k.dpdBody(36136, seq)}})
			lastDPD = time.Now()
		}
	}
}

func (c *v1Conn) start(ctx context.Context) error {
	k, err := c.phase1(ctx, true)
	if err != nil {
		return err
	}
	if err := k.quickMode(ctx); err != nil {
		k.deleteSAs() // the server must not keep the IKE SA we give up on
		return err
	}
	c.ike = k
	c.s.closers = append(c.s.closers, func() { c.current().deleteSAs() })
	go c.keepUp()
	return nil
}

// DialL2TP sets up the IPsec part of L2TP/IPsec: ESP in transport mode for
// UDP port 1701, with a pre-shared key. The caller runs L2TP over it.
func DialL2TP(ctx context.Context, o Options) (*Session, error) {
	if o.PSK == "" {
		return nil, errors.New("L2TP/IPsec needs the pre-shared key")
	}
	o.ID = ""
	return dialV1(ctx, &o, false)
}

// DialCisco connects Cisco-style IPsec (IKEv1 with XAUTH and mode config,
// as in Cisco ASA/IOS, MikroTik, strongSwan and the "IPSec" type of macOS
// and iOS): ESP in tunnel mode; Address and DNS are the server's.
func DialCisco(ctx context.Context, o Options) (*Session, error) {
	if o.PSK == "" {
		return nil, errors.New("IPsec needs the group's pre-shared key")
	}
	return dialV1(ctx, &o, true)
}

func dialV1(ctx context.Context, o *Options, tun bool) (*Session, error) {
	t, err := newTransport(ctx, o.Server)
	if err != nil {
		return nil, err
	}
	s := newSession(t)
	s.log = o.logf
	c := &v1Conn{s: s, o: o, tun: tun}
	if err := c.start(ctx); err != nil {
		s.end(err)
		return nil, err
	}
	return s, nil
}
