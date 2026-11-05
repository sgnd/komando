package netx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/sgnd/komando/internal/ipsec"
	"github.com/sgnd/komando/internal/l2tp"
	"github.com/sgnd/komando/internal/ppp"
	"github.com/sgnd/komando/internal/store"
)

// L2TP/IPsec, Cisco-style IPsec and IKEv2 run inside komando
// (internal/ipsec, internal/l2tp): ESP rides in UDP and feeds a userspace
// network stack, so no admin rights are needed and the computer's network
// is not changed.

func ipsecOptions(v *store.Vpn) (ipsec.Options, error) {
	o := ipsec.Options{Server: v.Server, User: v.User, ID: v.LocalID, RemoteID: v.RemoteID, CA: []byte(v.CA),
		Log: func(f string, a ...any) { log.Printf(f, a...) }}
	if v.PSKRef != "" {
		psk, err := secret(v, v.PSKRef)
		if err != nil {
			return o, err
		}
		o.PSK = psk
	}
	if v.User != "" {
		o.Password = SessionSecret
		if o.Password == "" {
			if v.KeyRef == "" {
				return o, LoginRequired(v)
			}
			pw, err := secret(v, v.KeyRef)
			if err != nil {
				return o, err
			}
			o.Password = pw
		}
	}
	o.Debug = os.Getenv("KOMANDO_IPSEC_DEBUG") != ""
	// tests make the SAs short-lived to check rekeying
	if d, err := time.ParseDuration(os.Getenv("KOMANDO_IPSEC_LIFETIME")); err == nil && d > 0 {
		o.Lifetime = d
	}
	return o, nil
}

func openIPsec(ctx context.Context, v *store.Vpn, timeout time.Duration) (Dialer, io.Closer, error) {
	o, err := ipsecOptions(v)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, max(timeout, 60*time.Second))
	defer cancel()
	switch v.Kind {
	case "l2tp":
		s, err := ipsec.DialL2TP(ctx, o)
		if err != nil {
			return nil, nil, ipsecErr(v, err)
		}
		t, err := l2tp.Dial(ctx, s.L2TP(), v.User, o.Password, o.Log)
		if err != nil && errors.Is(err, l2tp.ErrNoAnswer) && ctx.Err() == nil {
			// often the server still holds the session that just dropped
			// (one session per user): it was told to end it; try once more
			o.Log("L2TP: %v; trying once more", err)
			time.Sleep(3 * time.Second)
			t, err = l2tp.Dial(ctx, s.L2TP(), v.User, o.Password, o.Log)
		}
		if err != nil {
			s.Close()
			return nil, nil, ipsecErr(v, err)
		}
		return stackDialer(v, l2tpTun{t, s}, t.Addresses(), t.DNS(), t.MTU())
	case "ipsec":
		s, err := ipsec.DialCisco(ctx, o)
		if err != nil {
			return nil, nil, ipsecErr(v, err)
		}
		t := s.Tunnel()
		return stackDialer(v, t, t.Addresses(), t.DNS(), t.MTU())
	case "ikev2":
		s, err := ipsec.DialIKEv2(ctx, o)
		if err != nil {
			return nil, nil, ipsecErr(v, err)
		}
		t := s.Tunnel()
		return stackDialer(v, t, t.Addresses(), t.DNS(), t.MTU())
	}
	return nil, nil, configErr(v, fmt.Errorf("unknown kind %q", v.Kind))
}

// l2tpTun is L2TP over its IPsec session; closing it ends both.
type l2tpTun struct {
	*l2tp.Tunnel
	s *ipsec.Session
}

func (t l2tpTun) Close() error {
	t.Tunnel.Close()
	return t.s.Close()
}

func ipsecErr(v *store.Vpn, err error) error {
	var ae *ipsec.AuthError
	var pe *ppp.AuthError
	switch {
	case errors.Is(err, ipsec.ErrNeedsPerson):
		return LoginRequired(v)
	case errors.As(err, &ae), errors.As(err, &pe):
		return Down(v, fmt.Errorf("%v (check `komando vpn show %s`: the pre-shared key, --user and the password)", err, v.Name))
	}
	return Down(v, err)
}
