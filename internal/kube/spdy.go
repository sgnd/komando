package kube

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/moby/spdystream"

	"github.com/sgnd/komando/internal/proxyx"
)

// SPDY/3.1 is how Kubernetes before 1.30 streams exec and port-forward
// (and what kubectl falls back to). The request is upgraded to SPDY; then
// each part of the exchange is its own stream, named by a "streamType"
// header: error, stdin, stdout, stderr and resize for exec (protocol
// v4.channel.k8s.io), error and data per connection for port-forward
// (portforward.k8s.io). A stream can be half-closed, which is how stdin
// ends.

const streamWait = 30 * time.Second

// dialSPDY upgrades a request on the API server to SPDY, through the same
// dialer, TLS settings and credentials as the client's requests.
func (c *Client) dialSPDY(ctx context.Context, path string, q url.Values, protocols []string) (*spdystream.Connection, string, error) {
	u := *c.Base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = q.Encode()
	addr := u.Host
	if u.Port() == "" {
		port := "443"
		if u.Scheme == "http" {
			port = "80"
		}
		addr = net.JoinHostPort(u.Hostname(), port)
	}
	dial := proxyx.Dialer((&net.Dialer{Timeout: streamWait}).DialContext)
	tr, _ := c.http.Transport.(*http.Transport)
	if tr != nil && tr.DialContext != nil {
		dial = tr.DialContext
	}
	var pick proxyx.Func
	if tr != nil {
		pick = tr.Proxy // nil through a --via path
	}
	conn, err := proxyx.Dial(ctx, pick, dial, &u, addr)
	if err != nil {
		return nil, "", err
	}
	if u.Scheme == "https" {
		tc := &tls.Config{MinVersion: tls.VersionTLS12}
		if tr != nil && tr.TLSClientConfig != nil {
			tc = tr.TLSClientConfig.Clone()
		}
		tc.NextProtos = []string{"http/1.1"} // the upgrade needs HTTP/1.1
		if tc.ServerName == "" {
			tc.ServerName = u.Hostname()
		}
		tconn := tls.Client(conn, tc)
		if err := tconn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, "", err
		}
		conn = tconn
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", u.String(), nil)
	req.Header.Set("User-Agent", "komando")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "SPDY/3.1")
	for _, p := range protocols {
		req.Header.Add("X-Stream-Protocol-Version", p)
	}
	if err := c.authorize(ctx, req.Header); err != nil {
		conn.Close()
		return nil, "", err
	}
	conn.SetDeadline(time.Now().Add(streamWait))
	br := bufio.NewReader(conn)
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, "", err
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, "", fmt.Errorf("SPDY upgrade: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer conn.Close()
		return nil, "", upgradeRefused(resp)
	}
	conn.SetDeadline(time.Time{})
	sc, err := spdystream.NewConnection(&bufferedConn{Conn: conn, r: br}, false)
	if err != nil {
		conn.Close()
		return nil, "", err
	}
	go sc.Serve(func(s *spdystream.Stream) { s.Refuse() }) // the server opens no streams
	go func() {
		select {
		case <-ctx.Done():
			sc.Close()
		case <-sc.CloseChan():
		}
	}()
	return sc, resp.Header.Get("X-Stream-Protocol-Version"), nil
}

// bufferedConn reads first what the upgrade answer left in its buffer.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// openStream opens one named stream and waits until the server takes it.
func openStream(sc *spdystream.Connection, h http.Header) (*spdystream.Stream, error) {
	s, err := sc.CreateStream(h, nil, false)
	if err != nil {
		return nil, err
	}
	if err := s.WaitTimeout(streamWait); err != nil {
		return nil, fmt.Errorf("the cluster did not open the %s stream: %w", h.Get("streamType"), err)
	}
	return s, nil
}

func (c *Client) execSPDY(ctx context.Context, o ExecOptions, path string, q url.Values) error {
	sc, proto, err := c.dialSPDY(ctx, path, q, []string{"v4.channel.k8s.io"})
	if err != nil {
		return err
	}
	defer sc.Close()
	if proto != "v4.channel.k8s.io" {
		return fmt.Errorf("exec: the cluster offers no exec protocol komando speaks (%q)", proto)
	}
	stream := func(typ string) (*spdystream.Stream, error) {
		return openStream(sc, http.Header{"Streamtype": {typ}})
	}
	// the streams the query asked for, error first
	errS, err := stream("error")
	if err != nil {
		return err
	}
	var stdin, stdout, stderr, resize *spdystream.Stream
	if o.Stdin != nil {
		if stdin, err = stream("stdin"); err != nil {
			return err
		}
	}
	if stdout, err = stream("stdout"); err != nil {
		return err
	}
	if !o.TTY {
		if stderr, err = stream("stderr"); err != nil {
			return err
		}
	} else if resize, err = stream("resize"); err != nil {
		return err
	}
	status := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(io.LimitReader(errS, 1<<20))
		status <- b
	}()
	if stdin != nil {
		go func() {
			io.Copy(stdin, o.Stdin)
			stdin.Close() // half-close: the command sees the end of its input
		}()
	}
	if resize != nil && o.Resize != nil {
		go func() {
			enc := json.NewEncoder(resize)
			for s := range o.Resize {
				if enc.Encode(map[string]uint16{"Width": s.Width, "Height": s.Height}) != nil {
					return
				}
			}
		}()
	}
	var wg sync.WaitGroup
	copyOut := func(w io.Writer, s *spdystream.Stream) {
		if s == nil {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			io.Copy(orDiscard(w), s)
		}()
	}
	copyOut(o.Stdout, stdout)
	copyOut(o.Stderr, stderr)
	wg.Wait()
	select {
	case b := <-status:
		if len(strings.TrimSpace(string(b))) == 0 {
			return nil
		}
		return execStatus(b)
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(streamWait):
		return errors.New("exec: the cluster sent no status")
	}
}

// forwardSPDY carries one connection to port on a pod over SPDY.
func (c *Client) forwardSPDY(ctx context.Context, path string, port int, conn net.Conn) error {
	sc, proto, err := c.dialSPDY(ctx, path, nil, []string{"portforward.k8s.io"})
	if err != nil {
		return err
	}
	defer sc.Close()
	if proto != "portforward.k8s.io" {
		return fmt.Errorf("port-forward: the cluster offers no protocol komando speaks (%q)", proto)
	}
	h := http.Header{"Streamtype": {"error"}, "Port": {strconv.Itoa(port)}, "Requestid": {"0"}}
	errS, err := openStream(sc, h)
	if err != nil {
		return err
	}
	errS.Close() // komando writes nothing on it
	h.Set("Streamtype", "data")
	data, err := openStream(sc, h)
	if err != nil {
		return err
	}
	done := make(chan error, 3)
	go func() {
		b, _ := io.ReadAll(io.LimitReader(errS, 1<<20))
		if m := strings.TrimSpace(string(b)); m != "" {
			done <- fmt.Errorf("port-forward: %s", m)
		}
	}()
	go func() {
		io.Copy(data, conn)
		data.Close() // half-close: the pod sees the end
	}()
	go func() {
		io.Copy(conn, data)
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return nil
	}
}
