package storex

import (
	"cmp"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// gcsBucket is a bucket (and folder) on Google Cloud Storage, through its
// JSON API. The login is a service account key, or gcloud's application
// default credentials; an emulator (?endpoint=) may need none.
type gcsBucket struct {
	c      *http.Client
	base   string // https://storage.googleapis.com, or an emulator's URL
	bucket string
	prefix string
	signer *gcsSigner // nil: no service account key, so no links
}

const gcsScope = "https://www.googleapis.com/auth/devstorage.read_write"

// gcsDefaultCredentials finds application default credentials; tests
// replace it.
var gcsDefaultCredentials = func(ctx context.Context) (*google.Credentials, error) {
	return google.FindDefaultCredentials(ctx, gcsScope)
}

// OpenGCS prepares a client; it does not contact the bucket. key is a
// service account key (JSON) from the vault, or "" for gcloud's login.
func OpenGCS(_ context.Context, t driver.Target, key string, dial DialFunc, timeout time.Duration) (Bucket, error) {
	scheme := map[bool]string{true: "https", false: "http"}[t.Secure]
	b := &gcsBucket{base: scheme + "://" + hostOf(t), bucket: t.Bucket, prefix: t.Prefix}
	if t.Path != "" {
		b.base += "/" + t.Path
	}
	plain := webClient(dial, timeout, false)
	onGoogle := t.Address == "storage.googleapis.com:443"
	var creds *google.Credentials
	var err error
	tctx := context.WithValue(context.Background(), oauth2.HTTPClient, plain) // tokens too go the conn's way
	if key != "" {
		creds, err = google.CredentialsFromJSONWithType(tctx, []byte(key), google.ServiceAccount, gcsScope)
		if err != nil {
			return nil, out.Errf(out.ExitUsage, "STORAGE_AUTH", "the --password-ref of a gcs conn holds a service account key (the JSON file from the console)",
				"gcs: the stored key is not a service account key: %v", err)
		}
	} else if creds, err = gcsDefaultCredentials(tctx); err != nil {
		if onGoogle {
			return nil, out.Errf(out.ExitConnect, "STORAGE_AUTH",
				"log in with `gcloud auth application-default login`, or store a service account key with `komando secret set NAME` and pass --password-ref secret:NAME",
				"gcs: no Google Cloud login: %v", err)
		}
		creds = nil // an emulator without a login
	}
	b.c = plain
	if creds != nil {
		b.c = &http.Client{Transport: &oauth2.Transport{Source: creds.TokenSource, Base: plain.Transport}, CheckRedirect: plain.CheckRedirect}
		b.signer = newGCSSigner(creds.JSON)
	}
	return b, nil
}

// hostOf is the address for a URL: without the default port.
func hostOf(t driver.Target) string {
	h := t.Address
	if t.Secure {
		return strings.TrimSuffix(h, ":443")
	}
	return strings.TrimSuffix(h, ":80")
}

func (b *gcsBucket) Close() error { return nil }

func (b *gcsBucket) object(rel string) (string, error) { return keyIn(b.prefix, rel) }

func (b *gcsBucket) objectURL(full string) string {
	return b.base + "/storage/v1/b/" + url.PathEscape(b.bucket) + "/o/" + url.PathEscape(full)
}

type gcsObject struct {
	Name    string    `json:"name"`
	Size    string    `json:"size"`
	Updated time.Time `json:"updated"`
}

func (b *gcsBucket) get(ctx context.Context, u string, ok int) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	return do(b.c, "gcs", req, ok)
}

func (b *gcsBucket) List(ctx context.Context, prefix string, recursive bool, limit int) ([]Object, bool, error) {
	full := b.prefix + strings.TrimPrefix(prefix, "/")
	objs := []Object{}
	token := ""
	for {
		q := url.Values{"prefix": {full}, "fields": {"items(name,size,updated),prefixes,nextPageToken"}}
		if !recursive {
			q.Set("delimiter", "/")
		}
		if token != "" {
			q.Set("pageToken", token)
		}
		resp, err := b.get(ctx, b.base+"/storage/v1/b/"+url.PathEscape(b.bucket)+"/o?"+q.Encode(), http.StatusOK)
		if err != nil {
			return nil, false, bucketMissing(err)
		}
		var page struct {
			Items         []gcsObject `json:"items"`
			Prefixes      []string    `json:"prefixes"`
			NextPageToken string      `json:"nextPageToken"`
		}
		err = json.NewDecoder(resp.Body).Decode(&page)
		resp.Body.Close()
		if err != nil {
			return nil, false, webErr("gcs", nil, err)
		}
		var got []Object
		for _, p := range page.Prefixes {
			got = append(got, Object{Key: strings.TrimPrefix(p, b.prefix), Dir: true})
		}
		for _, it := range page.Items {
			if isMarker(it.Name, full, recursive) {
				continue
			}
			n, _ := strconv.ParseInt(it.Size, 10, 64)
			got = append(got, Object{Key: strings.TrimPrefix(it.Name, b.prefix), Size: n, Modified: it.Updated.UTC()})
		}
		sort.Slice(got, func(i, j int) bool { return got[i].Key < got[j].Key })
		for _, o := range got {
			if o.Key == "" {
				continue
			}
			if limit > 0 && len(objs) >= limit {
				return objs, true, nil
			}
			objs = append(objs, o)
		}
		if token = page.NextPageToken; token == "" {
			return objs, false, nil
		}
	}
}

// bucketMissing names a missing bucket (a 404 on a listing) as such.
func bucketMissing(err error) error {
	if oe, ok := err.(*out.Error); ok && oe.Code == "OBJECT_NOT_FOUND" {
		return out.Errf(out.ExitNotFound, "BUCKET_NOT_FOUND", "check the bucket name in the conn URL (`komando conn show NAME`)", "bucket does not exist")
	}
	return err
}

func (b *gcsBucket) Stat(ctx context.Context, rel string) (Object, error) {
	full, err := b.object(rel)
	if err != nil {
		return Object{}, err
	}
	resp, err := b.get(ctx, b.objectURL(full), http.StatusOK)
	if err != nil {
		if oe, ok := err.(*out.Error); ok && oe.Code == "OBJECT_NOT_FOUND" {
			return Object{}, out.Errf(out.ExitNotFound, "OBJECT_NOT_FOUND", "list objects with `komando storage ls CONN [PREFIX]`", "%s not found", rel)
		}
		return Object{}, err
	}
	defer resp.Body.Close()
	var o gcsObject
	if err := json.NewDecoder(resp.Body).Decode(&o); err != nil {
		return Object{}, webErr("gcs", nil, err)
	}
	n, _ := strconv.ParseInt(o.Size, 10, 64)
	return Object{Key: strings.TrimPrefix(rel, "/"), Size: n, Modified: o.Updated.UTC()}, nil
}

func (b *gcsBucket) Exists(ctx context.Context, key string) (bool, error) {
	_, err := b.Stat(ctx, key)
	if oe, ok := err.(*out.Error); ok && oe.Code == "OBJECT_NOT_FOUND" {
		return false, nil
	}
	return err == nil, err
}

func (b *gcsBucket) Get(ctx context.Context, key string, w io.Writer) (int64, error) {
	full, err := b.object(key)
	if err != nil {
		return 0, err
	}
	resp, err := b.get(ctx, b.objectURL(full)+"?alt=media", http.StatusOK)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(w, resp.Body)
	return n, webErr("gcs", nil, err)
}

func (b *gcsBucket) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	full, err := b.object(key)
	if err != nil {
		return err
	}
	q := url.Values{"uploadType": {"media"}, "name": {full}}
	u := b.base + "/upload/storage/v1/b/" + url.PathEscape(b.bucket) + "/o?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, r)
	if err != nil {
		return err
	}
	if size >= 0 {
		req.ContentLength = size
	}
	req.Header.Set("Content-Type", cmp.Or(contentType, "application/octet-stream"))
	resp, err := do(b.c, "gcs", req, http.StatusOK)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// Remove deletes one object; a missing one is not an error, as in S3.
func (b *gcsBucket) Remove(ctx context.Context, key string) error {
	full, err := b.object(key)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, b.objectURL(full), nil)
	if err != nil {
		return err
	}
	resp, err := do(b.c, "gcs", req, http.StatusNoContent, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// gcsSigner signs V4 links with a service account's private key.
type gcsSigner struct {
	email string
	key   *rsa.PrivateKey
}

func newGCSSigner(credJSON []byte) *gcsSigner {
	var sa struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if json.Unmarshal(credJSON, &sa) != nil || sa.Type != "service_account" {
		return nil
	}
	blk, _ := pem.Decode([]byte(sa.PrivateKey))
	if blk == nil {
		return nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil
	}
	return &gcsSigner{email: sa.ClientEmail, key: rk}
}

// Link makes a V4 signed URL: anyone with it can download the object
// until it expires (at most 7 days).
func (b *gcsBucket) Link(ctx context.Context, key string, expires time.Duration) (*url.URL, error) {
	if b.signer == nil {
		return nil, out.Errf(out.ExitUsage, "NOT_SUPPORTED",
			"store a service account key with `komando secret set NAME` and pass --password-ref secret:NAME (gcloud's own login cannot sign links)",
			"gcs links are signed with a service account key, and this conn has none")
	}
	if _, err := b.Stat(ctx, key); err != nil {
		return nil, err
	}
	full, _ := b.object(key)
	return b.signer.sign(b.bucket, full, expires, time.Now().UTC())
}

func (s *gcsSigner) sign(bucket, object string, expires time.Duration, now time.Time) (*url.URL, error) {
	if expires > 7*24*time.Hour {
		return nil, out.Usage("a gcs link lasts at most 7 days")
	}
	day, stamp := now.Format("20060102"), now.Format("20060102T150405Z")
	scope := day + "/auto/storage/goog4_request"
	q := url.Values{
		"X-Goog-Algorithm":             {"GOOG4-RSA-SHA256"},
		"X-Goog-Credential":            {s.email + "/" + scope},
		"X-Goog-Date":                  {stamp},
		"X-Goog-Expires":               {strconv.Itoa(int(expires.Seconds()))},
		"X-Goog-SignedHeaders":         {"host"},
		"response-content-disposition": {contentDisposition(path.Base(object))},
	}
	canonPath := "/" + bucket + "/" + pathEscape(object)
	canonQuery := strings.ReplaceAll(q.Encode(), "+", "%20")
	creq := strings.Join([]string{"GET", canonPath, canonQuery, "host:storage.googleapis.com", "", "host", "UNSIGNED-PAYLOAD"}, "\n")
	h := sha256.Sum256([]byte(creq))
	toSign := strings.Join([]string{"GOOG4-RSA-SHA256", stamp, scope, hex.EncodeToString(h[:])}, "\n")
	digest := sha256.Sum256([]byte(toSign))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return nil, fmt.Errorf("gcs: signing the link: %w", err)
	}
	return url.Parse("https://storage.googleapis.com" + canonPath + "?" + canonQuery + "&X-Goog-Signature=" + hex.EncodeToString(sig))
}
