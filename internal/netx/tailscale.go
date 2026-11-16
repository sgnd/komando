package netx

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"

	"github.com/sgnd/komando/internal/store"
)

// Tailscale and Headscale run inside komando (tsnet, Tailscale's own Go
// library) in user-space mode: no tailscaled, no admin rights, and the
// computer's network is not changed. The node's state (its keys) is sealed
// in the store (tailscale_state.go); ~/.komando/vpn/NAME-tailscale holds
// only tsnet's other files.

// TailscaleDir is tsnet's folder for the VPN (no keys: see sealedTSState).
func TailscaleDir(v *store.Vpn) string { return store.Path("vpn", v.Name+"-tailscale") }

func newTailscale(v *store.Vpn) (*tsnet.Server, error) {
	key := ""
	if v.KeyRef != "" {
		var err error
		if key, err = secret(v, v.KeyRef); err != nil {
			return nil, err
		}
	}
	if err := store.MkdirPrivate("vpn", v.Name+"-tailscale"); err != nil {
		return nil, err
	}
	quiet := func(string, ...any) {}
	for _, n := range tsEnv {
		_ = os.Unsetenv(n)
	}
	return &tsnet.Server{
		Dir:        TailscaleDir(v),
		Store:      &sealedTSState{id: tsStateID(v)},
		Hostname:   "komando-" + v.Name,
		AuthKey:    key,
		ControlURL: cmp.Or(v.Server, ipn.DefaultControlURL),
		Logf:       quiet,
		UserLogf:   quiet,
	}, nil
}

// tsEnv are the variables tsnet would read where a field is empty: the
// login server, a login key or a forced login. The VPN's own settings
// decide those, never the environment (an AI agent's TS_CONTROL_URL would
// send the stored auth key to its own server).
var tsEnv = []string{"TS_CONTROL_URL", "TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET", "TS_CLIENT_ID",
	"TS_ID_TOKEN", "TS_AUDIENCE", "TSNET_FORCE_LOGIN"}

// openTailscale joins the tailnet and dials through it. It needs a node
// that is logged in (an auth key, or an earlier `komando vpn up`).
func openTailscale(ctx context.Context, v *store.Vpn, timeout time.Duration) (Dialer, io.Closer, error) {
	srv, err := newTailscale(v)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, max(timeout, time.Minute))
	defer cancel()
	if v.KeyRef == "" {
		// without a key, Up would wait for a browser login nobody sees
		if err := srv.Start(); err != nil {
			return nil, nil, Down(v, fmt.Errorf("tailscale: %v", err))
		}
		if state, _ := tailscaleState(ctx, srv); state == "NeedsLogin" {
			srv.Close()
			return nil, nil, LoginRequired(v)
		}
	}
	if _, err := srv.Up(ctx); err != nil {
		srv.Close()
		return nil, nil, Down(v, fmt.Errorf("tailscale: %v", err))
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return srv.Dial(ctx, network, addr)
	}, srv, nil
}

// TailscaleLogin logs the node in through the browser: show gets the
// login page. It returns once the node is connected; its state is kept, so
// later sessions start without a login until the key expires.
func TailscaleLogin(ctx context.Context, v *store.Vpn, show func(url string)) error {
	srv, err := newTailscale(v)
	if err != nil {
		return err
	}
	defer srv.Close()
	if err := srv.Start(); err != nil {
		return Down(v, fmt.Errorf("tailscale: %v", err))
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	shown := ""
	for {
		state, url := tailscaleState(ctx, srv)
		if state == "Running" {
			return nil
		}
		if url != "" && url != shown {
			show(url)
			shown = url
		}
		select {
		case <-ctx.Done():
			return Down(v, errors.New("tailscale: the login was not finished in time"))
		case <-time.After(time.Second):
		}
	}
}

// tailscaleState is the node's backend state and, when it waits for a
// person, the login page. It waits a moment for the state to settle.
func tailscaleState(ctx context.Context, srv *tsnet.Server) (string, string) {
	lc, err := srv.LocalClient()
	if err != nil {
		return "", ""
	}
	for i := 0; i < 20; i++ {
		st, err := lc.StatusWithoutPeers(ctx)
		if err == nil && st.BackendState != "NoState" && st.BackendState != "Starting" {
			return st.BackendState, st.AuthURL
		}
		if err == nil && st.AuthURL != "" {
			return st.BackendState, st.AuthURL
		}
		time.Sleep(250 * time.Millisecond)
	}
	return "", ""
}
