package cli

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/vault"
)

// Opening a conn.

// access is what every conn command needs: the parsed URL, the password and
// a dialer that goes through the --via host (nil Dial = connect directly).
type access struct {
	Target   driver.Target
	Password string
	Dial     func(ctx context.Context, network, addr string) (net.Conn, error)
	ssh      *sshx.Client
	vpn      io.Closer
}

func (a *access) Close() {
	if a.ssh != nil {
		a.ssh.Close()
	}
	if a.vpn != nil {
		a.vpn.Close()
	}
}

func openAccess(cl *call, ctx context.Context, st *store.State, c *store.Conn) (*access, error) {
	t, err := driver.Parse(c.URL)
	if err != nil {
		return nil, err
	}
	if err := guardConnFile(cl, c); err != nil {
		return nil, err
	}
	password, err := resolvePassword(cl, st, c)
	if err != nil {
		return nil, err
	}
	a := &access{Target: t, Password: password}
	// ?resolve=IP: connections to the URL's address go to that IP, from the
	// end of the --via path set up below
	defer func() { a.Dial = pinDial(a.Dial, t.Address, t.Resolve) }()
	if c.Via == "" {
		a.Dial = gateDialFor(cl, sshOpts(cl, st).ConnectTimeout)
		return a, nil
	}
	h, vpn, err := resolveVia(st, c.Via)
	if err != nil {
		return nil, err
	}
	if vpn != nil {
		d, closer, err := netx.Open(ctx, vpn, sshOpts(cl, st).ConnectTimeout)
		if err != nil {
			return nil, err
		}
		a.Dial, a.vpn = d, closer
		return a, nil
	}
	cctx, cancel := context.WithTimeout(ctx, sshOpts(cl, st).ConnectTimeout)
	defer cancel()
	if a.ssh, err = sshx.Dial(cctx, st, h, sshOpts(cl, st)); err != nil {
		return nil, err
	}
	a.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := a.ssh.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return sshx.WithDeadlines(c), nil
	}
	return a, nil
}

// resolvePassword is c's password: from the vault, or typed by a person
// for this command (login ask).
func resolvePassword(cl *call, st *store.State, c *store.Conn) (string, error) {
	if c.AskLogin() {
		return connLoginPassword(cl, st, c)
	}
	p, err := vault.Resolve(c.PasswordRef)
	if err == nil {
		return p, nil
	}
	hint := netx.SecretHint(c.PasswordRef) + ", or point the conn elsewhere: `komando conn edit " + c.Name + " --password-ref ...`"
	if errors.Is(err, vault.ErrNotFound) {
		return "", out.Errf(out.ExitNotFound, "SECRET_NOT_FOUND", hint, "password reference %s: %v", c.PasswordRef, err)
	}
	return "", out.Errf(out.ExitNotFound, "SECRET_UNRESOLVED", hint, "password reference %s: %v", c.PasswordRef, err)
}
