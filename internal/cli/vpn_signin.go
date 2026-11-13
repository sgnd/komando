package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sgnd/komando/internal/browserx"
	"github.com/sgnd/komando/internal/netx"
	"github.com/sgnd/komando/internal/sslvpn"
	"github.com/sgnd/komando/internal/store"
	"github.com/sgnd/komando/internal/tmpclean"
)

// sslLogin logs in to a built-in SSL VPN. With a person at the terminal
// (interactive) the login may ask them: a code, or a browser sign-in.
func sslLogin(cl *call, ctx context.Context, v *store.Vpn, interactive bool) (string, error) {
	if !interactive {
		return netx.SSLVPNLogin(ctx, v, nil, nil, nil)
	}
	w := &signInWindow{cl: cl}
	defer w.close()
	return netx.SSLVPNLogin(ctx, v, func(label string, secret bool) (string, error) { return loginPrompt(cl, label, secret) }, w.show, cl.out.Err)
}

// signInWindow is the browser window of one VPN login. A login may sign
// in twice (the portal, then a gateway); the same window shows both, so
// the second passes on the first one's session without typing again.
type signInWindow struct {
	cl *call // the call it works for
	b  *browserx.Browser
}

func (w *signInWindow) close() {
	if w.b != nil {
		w.b.Close()
	}
}

// show shows a VPN's browser sign-in to the person at the terminal and
// returns the address it ends on (globalprotectcallback:...), which
// carries the login. With Chrome, Edge, Brave or Chromium on the computer
// komando opens its own window and reads that address itself; without
// one, the page opens in the person's browser and they paste the address.
func (w *signInWindow) show(ctx context.Context, p sslvpn.BrowserPage) (string, error) {
	const wait = 10 * time.Minute
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	if exe := browserx.Find(); exe != "" {
		if w.b == nil {
			sayLine(w.cl, "komando: a browser window opens for the sign-in. Finish it there (password, one-time code); the window closes by itself.")
			var err error
			if w.b, err = browserx.Open(exe); err != nil {
				return "", err
			}
		}
		back, err := w.b.SignIn(ctx, browserx.Page{URL: p.URL, HTML: p.HTML}, sslvpn.GPCallback, sslvpn.GPCallbackOK)
		var st *browserx.Stopped
		if errors.As(err, &st) && (errors.Is(err, browserx.ErrClosed) || errors.Is(err, context.DeadlineExceeded)) {
			why := st.Err.Error()
			if errors.Is(err, context.DeadlineExceeded) {
				why = "the sign-in was not finished within " + humanAge(wait)
			}
			if st.At != "" {
				why += "; the window was at " + st.At
			}
			return "", &sslvpn.LoginError{Msg: why}
		}
		return back, err
	}
	target := p.URL
	if target == "" {
		tmpclean.Sweep(os.TempDir(), "komando-signin-", "")
		dir, err := os.MkdirTemp("", "komando-signin-")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(dir)
		defer tmpclean.Add(dir)()
		target = filepath.Join(dir, "sign-in.html")
		if err := os.WriteFile(target, []byte(p.HTML), 0o600); err != nil {
			return "", err
		}
	}
	fmt.Fprintln(w.cl.out.Err, "komando: the sign-in opens in your browser. komando can read the result by\n"+
		"  itself only from Chrome, Edge, Brave or Chromium, and found none. When the\n"+
		"  sign-in is done, the last page has a link or button that opens GlobalProtect.\n"+
		"  Copy that link's address (it starts with "+sslvpn.GPCallback+")\n"+
		"  and paste it here.")
	if p.URL != "" {
		fmt.Fprintln(w.cl.out.Err, "komando: sign in at "+cleanText(p.URL))
	}
	openBrowser(ctx, target)
	return loginSecret(w.cl, "Address from the last page: ")
}
