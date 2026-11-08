package kube

import (
	"bytes"
	"context"
	"encoding/binary"
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

	"github.com/gorilla/websocket"
)

// exec, attach and port-forward speak the Kubernetes streaming protocols
// over WebSocket, so kubectl is not needed; clusters before 1.30 get SPDY
// instead (spdy.go). Each WebSocket message starts
// with a channel byte: 0 stdin, 1 stdout, 2 stderr, 3 status, 4 resize
// (exec); for port-forward, channel 0 is data and 1 errors, and each
// channel's first message is the port.

// ExecOptions describe one command in a container.
type ExecOptions struct {
	Namespace, Pod, Container string
	Command                   []string
	Stdin                     io.Reader
	Stdout, Stderr            io.Writer
	TTY                       bool
	Resize                    <-chan TermSize // only with TTY
}

// TermSize is a terminal's size in characters.
type TermSize struct{ Width, Height uint16 }

// ExitError is a command that ended with a non-zero exit code.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return "exit " + strconv.Itoa(e.Code) }

// dialWS opens a WebSocket to path on the API server, through the same
// dialer, TLS settings and credentials as the client's requests.
func (c *Client) dialWS(ctx context.Context, path string, q url.Values, protocols []string) (*websocket.Conn, string, error) {
	u := *c.Base
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	u.RawQuery = q.Encode()
	tr, _ := c.http.Transport.(*http.Transport)
	d := websocket.Dialer{Subprotocols: protocols, HandshakeTimeout: 30 * time.Second}
	if tr != nil {
		d.TLSClientConfig = tr.TLSClientConfig.Clone()
		d.TLSClientConfig.NextProtos = nil // WebSocket needs HTTP/1.1
		d.NetDialContext = tr.DialContext
		d.Proxy = tr.Proxy // nil through a --via path
	}
	h := http.Header{"User-Agent": {"komando"}}
	if err := c.authorize(ctx, h); err != nil {
		return nil, "", err
	}
	ws, resp, err := d.DialContext(ctx, u.String(), h)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
			return nil, "", upgradeRefused(resp)
		}
		return nil, "", err
	}
	return ws, ws.Subprotocol(), nil
}

// authorize sets the Authorization header a streaming request needs.
func (c *Client) authorize(ctx context.Context, h http.Header) error {
	tok, err := c.bearer(ctx)
	if err != nil {
		return err
	}
	if tok != "" {
		h.Set("Authorization", "Bearer "+tok)
	} else if c.ctx.User.Username != "" {
		r := &http.Request{Header: http.Header{}}
		r.SetBasicAuth(c.ctx.User.Username, c.ctx.User.Password)
		h.Set("Authorization", r.Header.Get("Authorization"))
	}
	return nil
}

// upgradeRefused turns the answer to a refused upgrade into an APIError.
func upgradeRefused(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var st struct{ Reason, Message string }
	_ = json.Unmarshal(b, &st)
	if st.Message == "" {
		st.Message = strings.TrimSpace(string(b))
	}
	return &APIError{Code: resp.StatusCode, Reason: firstNonEmpty(st.Reason, http.StatusText(resp.StatusCode)), Message: st.Message}
}

// errOldProtocol: the WebSocket was opened, but not with a protocol
// version komando uses there.
var errOldProtocol = errors.New("the cluster offers only an older WebSocket protocol")

// trySPDY reports whether a failed WebSocket should be retried over SPDY,
// as kubectl does: the cluster answered, but would not upgrade. Kubernetes
// 1.29 refuses a v5 WebSocket with a bare 403, so any refused upgrade is
// retried; where the refusal is real (no access, no such pod), SPDY gets
// the same answer, and that is what is reported.
func trySPDY(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) || errors.Is(err, errOldProtocol) || errors.Is(err, websocket.ErrBadHandshake)
}

// Exec runs a command in a container and waits for it. A non-zero exit
// comes back as *ExitError.
func (c *Client) Exec(ctx context.Context, o ExecOptions) error {
	q := url.Values{"command": o.Command, "stdout": {"true"}}
	if o.Container != "" {
		q.Set("container", o.Container)
	}
	if o.Stdin != nil {
		q.Set("stdin", "true")
	}
	if o.TTY {
		q.Set("tty", "true") // a terminal joins stderr into stdout
	} else {
		q.Set("stderr", "true")
	}
	path := "/api/v1/namespaces/" + url.PathEscape(o.Namespace) + "/pods/" + url.PathEscape(o.Pod) + "/exec"
	// v5 is the first WebSocket version that can end stdin (Kubernetes
	// 1.30); an older cluster gets the same command over SPDY.
	ws, proto, err := c.dialWS(ctx, path, q, []string{"v5.channel.k8s.io"})
	if err == nil && proto != "v5.channel.k8s.io" {
		ws.Close()
		err = errOldProtocol
	}
	if trySPDY(err) {
		return c.execSPDY(ctx, o, path, q)
	}
	if err != nil {
		return err
	}
	defer ws.Close()
	var wmu sync.Mutex
	send := func(ch byte, b []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return ws.WriteMessage(websocket.BinaryMessage, append([]byte{ch}, b...))
	}
	go func() { <-ctx.Done(); ws.Close() }()
	if o.Stdin != nil {
		go func() {
			buf := make([]byte, 32<<10)
			for {
				n, err := o.Stdin.Read(buf)
				if n > 0 && send(0, buf[:n]) != nil {
					return
				}
				if err != nil {
					_ = send(255, []byte{0}) // v5: close stdin
					return
				}
			}
		}()
	}
	if o.TTY && o.Resize != nil {
		go func() {
			for s := range o.Resize {
				b, _ := json.Marshal(map[string]uint16{"Width": s.Width, "Height": s.Height})
				if send(4, b) != nil {
					return
				}
			}
		}()
	}
	stdout, stderr := orDiscard(o.Stdout), orDiscard(o.Stderr)
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				return nil
			}
			return fmt.Errorf("exec stream: %w", err)
		}
		if len(msg) == 0 {
			continue
		}
		switch msg[0] {
		case 1:
			stdout.Write(msg[1:])
		case 2:
			stderr.Write(msg[1:])
		case 3:
			return execStatus(msg[1:])
		}
	}
}

// execStatus reads the status message that ends an exec.
func execStatus(b []byte) error {
	var st struct {
		Status, Message, Reason string
		Details                 struct {
			Causes []struct{ Reason, Message string }
		}
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("exec: %s", bytes.TrimSpace(b))
	}
	if st.Status == "Success" {
		return nil
	}
	for _, c := range st.Details.Causes {
		if c.Reason == "ExitCode" {
			if n, err := strconv.Atoi(c.Message); err == nil {
				return &ExitError{Code: n}
			}
		}
	}
	return fmt.Errorf("exec: %s", firstNonEmpty(st.Message, st.Reason, "failed"))
}

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// PortForward connects conn to port on a pod, until either side closes.
// One WebSocket carries one connection.
func (c *Client) PortForward(ctx context.Context, namespace, pod string, port int, conn net.Conn) error {
	defer conn.Close()
	path := "/api/v1/namespaces/" + url.PathEscape(namespace) + "/pods/" + url.PathEscape(pod) + "/portforward"
	ws, _, err := c.dialWS(ctx, path, url.Values{"ports": {strconv.Itoa(port)}}, []string{"v4.channel.k8s.io"})
	if trySPDY(err) {
		return c.forwardSPDY(ctx, path, port, conn)
	}
	if err != nil {
		return err
	}
	defer ws.Close()
	// the first message on each channel (data, then error) is its port
	for i := 0; i < 2; i++ {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			return fmt.Errorf("port-forward: %w", err)
		}
		if len(msg) < 3 || binary.LittleEndian.Uint16(msg[1:3]) != uint16(port) {
			return errors.New("port-forward: unexpected first message")
		}
	}
	done := make(chan error, 2)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, append([]byte{0}, buf[:n]...)); werr != nil {
					done <- werr
					return
				}
			}
			if err != nil {
				done <- nil
				return
			}
		}
	}()
	go func() {
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				done <- nil
				return
			}
			if len(msg) < 2 {
				continue
			}
			switch msg[0] {
			case 0:
				if _, err := conn.Write(msg[1:]); err != nil {
					done <- nil
					return
				}
			case 1:
				done <- fmt.Errorf("port-forward: %s", bytes.TrimSpace(msg[1:]))
				return
			}
		}
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return nil
	}
}
