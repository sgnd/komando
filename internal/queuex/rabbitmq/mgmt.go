package rabbitmq

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"

	"github.com/sgnd/komando/internal/out"
)

// The management HTTP API (the rabbitmq_management plugin), on the port
// ?management= names, on the conn's own host and its own path (--via):
// HTTPS with the same certificate check for amqps://. komando only reads
// from it (GET), logged in as the conn's user.

// maxMgmtBody caps an answer of the management API.
const maxMgmtBody = 64 << 20

// mgmt GETs path (already escaped) into v. what names the queue (or "")
// for a 404.
func (r *Rabbit) mgmt(ctx context.Context, path, what string, v any) error {
	scheme := "http"
	if r.tls != nil {
		scheme = "https"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+r.t.Management+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(r.user, r.password)
	req.Header.Set("Accept", "application/json")
	resp, err := r.httpClient().Do(req)
	if err != nil {
		return mgmtErr(r.t.Management, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMgmtBody))
	if err != nil {
		return mgmtErr(r.t.Management, err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return out.Errf(out.ExitConnect, "QUEUE_AUTH", "the management API takes users with the management, monitoring or administrator tag: ask the server's admin to add one (`rabbitmqctl set_user_tags USER management`), or drop ?management= from the URL",
			"the management API refused the login of %s", r.user)
	case resp.StatusCode == http.StatusForbidden:
		return out.Errf(out.ExitRemote, "QUEUE_DENIED", "the user lacks the management API permission for this vhost; ask the server's admin", "the management API refused %s", path)
	case resp.StatusCode == http.StatusNotFound && what != "":
		return queueNotFound(what)
	case resp.StatusCode == http.StatusNotFound:
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "check the vhost in the URL's path (%2F is the default vhost \"/\") and that ?management= names the management API's port", "the management API has no %s", path)
	case resp.StatusCode != http.StatusOK:
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "read the management API's words above", "the management API answered %s: %s", resp.Status, short(body))
	}
	if err := json.Unmarshal(body, v); err != nil {
		return out.Errf(out.ExitRemote, "QUEUE_ERROR", "check that ?management= names the management API's port (usually 15672, or 15671 for HTTPS)", "the management API's answer is not JSON: %v", err)
	}
	return nil
}

func (r *Rabbit) httpClient() *http.Client {
	tr := &http.Transport{
		DialContext:     func(ctx context.Context, network, addr string) (net.Conn, error) { return r.dial(ctx, network, addr) },
		TLSClientConfig: r.tls,
		Proxy:           nil, // the conn's own path (--via), never a proxy from the environment
	}
	return &http.Client{Transport: tr, Timeout: r.timeout}
}

func mgmtErr(addr string, err error) error {
	if isTimeout(err) {
		return out.Errf(out.ExitTimeout, "TIMEOUT", "check ?management=PORT, or raise --timeout", "the management API at %s did not answer in time", addr)
	}
	return out.Errf(out.ExitConnect, "QUEUE_CONNECT", "check ?management=PORT in the conn's URL (15672, or 15671 for HTTPS) and that the rabbitmq_management plugin is on (`rabbitmq-plugins enable rabbitmq_management`)",
		"cannot reach the management API at %s: %v", addr, err)
}

// short is the start of an error body, for a message.
func short(b []byte) string {
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}

// vhostPath is "/api/KIND/VHOST[/NAME]" with both parts escaped (the
// default vhost "/" is %2F).
func (r *Rabbit) vhostPath(kind, name string) string {
	p := fmt.Sprintf("/api/%s/%s", kind, url.PathEscape(r.t.Database))
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	return p
}
