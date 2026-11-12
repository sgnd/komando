package driver

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/sgnd/komando/internal/out"
)

// folderOf is a URL path as a storage prefix: no leading /, a trailing /
// unless empty.
func folderOf(p string) string {
	p = strings.Trim(p, "/")
	if p != "" {
		p += "/"
	}
	return p
}

// endpointOf reads an ?endpoint= URL (an emulator, another cloud) into
// t.Address and t.Secure, with def when there is none.
func endpointOf(q url.Values, kind, def string, t *Target) error {
	e := q.Get("endpoint")
	if e == "" {
		e = def
	}
	u, err := url.Parse(e)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return out.Usage("%s endpoint must be a URL like https://storage.example.com", kind)
	}
	t.Secure = u.Scheme == "https"
	port := u.Port()
	if port == "" {
		port = map[bool]string{true: "443", false: "80"}[t.Secure]
	}
	t.Address = net.JoinHostPort(u.Hostname(), port)
	t.Path = strings.Trim(u.Path, "/") // an emulator's path, such as Azurite's account
	return nil
}

func onlyOptions(q url.Values, kind string, known ...string) error {
	for k := range q {
		ok := false
		for _, n := range known {
			ok = ok || k == n
		}
		if !ok {
			return out.Usage("unknown %s URL option %q (known: %s)", kind, k, strings.Join(known, ", "))
		}
	}
	return nil
}

// parseGCS reads gs://bucket/folder[?endpoint=URL][&ca=secret:NAME]. The login is a service
// account key from --password-ref, or else gcloud's (application default
// credentials).
func parseGCS(u *url.URL, t Target) (Target, error) {
	t.Bucket = u.Host
	if t.Bucket == "" || strings.Contains(t.Bucket, ":") || u.User != nil {
		return Target{}, out.Usage("gcs URL is gs://bucket/folder (no user: the login is gcloud's, or a key in --password-ref)")
	}
	t.Prefix = folderOf(u.Path)
	q := u.Query()
	if err := onlyOptions(q, "gcs", "endpoint", "ca", "insecure"); err != nil {
		return Target{}, err
	}
	if err := endpointOf(q, "gcs", "https://storage.googleapis.com", &t); err != nil {
		return Target{}, err
	}
	return t, parseCA(q, &t)
}

// parseAzure reads azblob://ACCOUNT@container/folder[?endpoint=URL][&ca=secret:NAME]. The
// account key or a SAS token comes from --password-ref.
func parseAzure(u *url.URL, t Target) (Target, error) {
	t.User, t.Bucket = u.User.Username(), u.Host
	if t.User == "" || t.Bucket == "" || strings.Contains(t.Bucket, ":") {
		return Target{}, out.Usage("azblob URL is azblob://ACCOUNT@container/folder, e.g. %s", t.Kind.Example)
	}
	t.Prefix = folderOf(u.Path)
	q := u.Query()
	if q.Has("sig") || q.Has("sv") {
		// a SAS token pasted into the URL: it is a password
		return Target{}, out.Errf(out.ExitUsage, "URL_HAS_PASSWORD",
			"remove the SAS token from the URL, store it with `komando secret set NAME`, then pass --password-ref secret:NAME",
			"conn URLs must not contain a password")
	}
	if err := onlyOptions(q, "azblob", "endpoint", "ca", "insecure"); err != nil {
		return Target{}, err
	}
	if err := endpointOf(q, "azblob", "https://"+t.User+".blob.core.windows.net", &t); err != nil {
		return Target{}, err
	}
	return t, parseCA(q, &t)
}

// parseWebDAV reads webdavs://user@host[:port]/path (webdav:// is plain
// HTTP and needs ?insecure=1, as plain FTP does).
func parseWebDAV(u *url.URL, t Target) (Target, error) {
	if u.Hostname() == "" {
		return Target{}, out.Usage("webdav URL needs a host, e.g. %s", t.Kind.Example)
	}
	t.Secure = strings.EqualFold(u.Scheme, "webdavs")
	port := map[bool]int{true: 443, false: 80}[t.Secure]
	if p := u.Port(); p != "" {
		var err error
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return Target{}, out.Usage("invalid port %q in conn URL", p)
		}
	}
	t.Address = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	t.User = u.User.Username()
	t.Prefix = folderOf(u.Path)
	q := u.Query()
	if err := onlyOptions(q, "webdav", "tls", "insecure"); err != nil {
		return Target{}, err
	}
	if t.Secure {
		if t.TLS = q.Get("tls"); t.TLS != "" && t.TLS != "skip-verify" {
			return Target{}, out.Usage("webdav tls option must be skip-verify (or left out to verify the certificate)")
		}
	} else if q.Get("insecure") != "1" {
		return Target{}, out.Errf(out.ExitUsage, "INSECURE_PROTOCOL",
			"use webdavs:// (HTTPS); otherwise add ?insecure=1 to accept that the password and files travel unencrypted",
			"webdav:// sends the password unencrypted")
	}
	return t, nil
}

// parseSMB reads smb://[DOMAIN;]user@host[:port]/share/folder[?domain=D]
// (cifs:// is the same). The first part of the path is the share; the rest
// is the folder keys are relative to. The domain may come from either
// place, not both.
func parseSMB(u *url.URL, t Target) (Target, error) {
	if u.Hostname() == "" {
		return Target{}, out.Usage("smb URL needs a host, e.g. %s", t.Kind.Example)
	}
	port := 445
	if p := u.Port(); p != "" {
		var err error
		if port, err = strconv.Atoi(p); err != nil || port < 1 || port > 65535 {
			return Target{}, out.Usage("invalid port %q in conn URL", p)
		}
	}
	t.Address = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	q := u.Query()
	if err := onlyOptions(q, "smb", "domain"); err != nil {
		return Target{}, err
	}
	t.User, t.Domain = u.User.Username(), q.Get("domain")
	if d, user, ok := strings.Cut(t.User, ";"); ok {
		if t.Domain != "" && !strings.EqualFold(t.Domain, d) {
			return Target{}, out.Usage("smb URL names two domains (%q before the user and %q in ?domain=): keep one", d, t.Domain)
		}
		t.Domain, t.User = d, user
	}
	if t.User == "" {
		return Target{}, out.Errf(out.ExitUsage, "USAGE",
			"add the user name, e.g. smb://alice@host/share; a guest login is refused because it cannot sign what the server sends",
			"smb URL needs a user name")
	}
	share, folder, _ := strings.Cut(strings.Trim(u.Path, "/"), "/")
	if share == "" || strings.ContainsAny(share, `\:*?"<>|`) {
		return Target{}, out.Usage("smb URL needs a share after the host, e.g. %s", t.Kind.Example)
	}
	// Secure stays false: it means TLS (cert check, doctor), and SMB signs
	// its messages instead; storex.OpenSMB always asks for that
	t.Bucket, t.Prefix = share, folderOf(folder)
	return t, nil
}
