package storex

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// The storage kinds that speak HTTP (GCS, Azure Blob, WebDAV) share this:
// one client, and one way to turn an answer into komando's errors.

// webClient is an HTTP client for one conn. It goes through HTTPS_PROXY
// like the S3 client, unless dial (a --via path) is the way out.
func webClient(dial DialFunc, timeout time.Duration, skipVerify bool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = timeout
	if skipVerify {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} //nolint:gosec // only when the conn URL says ?tls=skip-verify
	}
	if dial != nil {
		tr.DialContext = dial
		tr.Proxy = nil // the --via host is the way out
	}
	return &http.Client{Transport: tr, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("storage redirected to another host (%s); komando does not follow it with your credentials", req.URL.Host)
		}
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		return nil
	}}
}

// webErr turns a failed request or an error status into komando's error.
// what names the service ("gcs", "azure", "webdav") in messages.
func webErr(what string, resp *http.Response, err error) error {
	if err == nil && resp == nil {
		return nil
	}
	if err != nil {
		var oe *out.Error
		switch {
		case errors.As(err, &oe):
			return oe
		case errors.Is(err, context.DeadlineExceeded):
			return out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout, or leave it unset for large transfers", "storage did not answer in time")
		}
		if e := tlsErr(err, what); e != nil {
			return e
		}
		var ne net.Error
		if errors.As(err, &ne) || strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
			return out.Errf(out.ExitConnect, "STORAGE_CONNECT", "run `komando conn test NAME` to check reachability", "%v", err)
		}
		return out.Errf(out.ExitRemote, "STORAGE_ERROR", "run `komando conn test NAME` to check the conn", "%v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	msg := strings.TrimSpace(string(body))
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	switch resp.StatusCode {
	case http.StatusNotFound:
		return out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list objects with `komando storage ls CONN [PREFIX]`", "object not found")
	case http.StatusUnauthorized, http.StatusForbidden:
		return out.Errf(out.ExitConnect, "STORAGE_AUTH", "check the conn's user, key or token reference; it may lack permission for this action",
			"%s: %s %s", what, resp.Status, msg)
	}
	return out.Errf(out.ExitRemote, "STORAGE_ERROR", "run `komando conn test NAME` to check the conn", "%s: %s %s", what, resp.Status, msg)
}

// do sends req and returns the answer when its status is one of ok;
// otherwise the body is read for the error and closed.
func do(c *http.Client, what string, req *http.Request, ok ...int) (*http.Response, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, webErr(what, nil, err)
	}
	for _, s := range ok {
		if resp.StatusCode == s {
			return resp, nil
		}
	}
	defer resp.Body.Close()
	return nil, webErr(what, resp, nil)
}

// pathEscape escapes each part of an object key, keeping the slashes.
func pathEscape(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = escapeSegment(p)
	}
	return strings.Join(parts, "/")
}

func escapeSegment(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}
