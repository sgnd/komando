package storex

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/driver"
)

// fakeS3 is the part of the S3 API komando uses, path style, for bucket
// "media": HEAD, GET, PUT (and PUT with x-amz-copy-source), DELETE and
// ListObjectsV2. It checks that requests are signed, not the signature.
type fakeS3 struct {
	mu      sync.Mutex
	objs    map[string][]byte
	copies  int
	badCopy bool // a copy loses its last byte
	sse     string // the encryption every object reports; its ETag is then no MD5
	denyDel bool // DELETE answers AccessDenied
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	key, ok := strings.CutPrefix(r.URL.Path, "/media/")
	switch {
	case r.URL.Path == "/media" || r.URL.Path == "/media/" && r.Method == http.MethodGet:
		f.list(w, r.URL.Query())
		return
	case !ok:
		s3Error(w, http.StatusNotFound, "NoSuchBucket")
		return
	}
	body, found := f.objs[key]
	switch r.Method {
	case http.MethodPut:
		if src := r.Header.Get("X-Amz-Copy-Source"); src != "" {
			src, _ = url.PathUnescape(src)
			srcKey := strings.TrimPrefix(strings.TrimPrefix(src, "/"), "media/")
			from, ok := f.objs[srcKey]
			if !ok {
				s3Error(w, http.StatusNotFound, "NoSuchKey")
				return
			}
			if m := r.Header.Get("X-Amz-Copy-Source-If-Match"); m != "" && strings.Trim(m, `"`) != f.etagOf(srcKey, from) {
				s3Error(w, http.StatusPreconditionFailed, "PreconditionFailed")
				return
			}
			c := append([]byte(nil), from...)
			if f.badCopy && len(c) > 0 {
				c = c[:len(c)-1]
			}
			f.objs[key] = c
			f.copies++
			fmt.Fprintf(w, `<CopyObjectResult><ETag>"%s"</ETag><LastModified>2026-11-08T10:00:00.000Z</LastModified></CopyObjectResult>`, etag(c))
			return
		}
		b, err := s3Body(r)
		if err != nil {
			s3Error(w, http.StatusBadRequest, "IncompleteBody")
			return
		}
		f.objs[key] = b
		w.Header().Set("ETag", `"`+etag(b)+`"`)
	case http.MethodDelete:
		if f.denyDel {
			s3Error(w, http.StatusForbidden, "AccessDenied")
			return
		}
		delete(f.objs, key)
		w.WriteHeader(http.StatusNoContent)
	default: // GET, HEAD
		if !found {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			s3Error(w, http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("ETag", `"`+f.etagOf(key, body)+`"`)
		if f.sse != "" {
			w.Header().Set("X-Amz-Server-Side-Encryption", f.sse)
		}
		w.Header().Set("Last-Modified", "Sun, 08 Nov 2026 10:00:00 GMT")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		if r.Method == http.MethodGet {
			w.Write(body)
		}
	}
}

// etagOf is the ETag an object reports: with encryption, 32 hex digits
// that say nothing of the body.
func (f *fakeS3) etagOf(key string, body []byte) string {
	if f.sse != "" {
		return etag([]byte(key))
	}
	return etag(body)
}

func etag(b []byte) string {
	h := md5.Sum(b)
	return hex.EncodeToString(h[:])
}

func s3Error(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
}

// s3Body reads a PUT body, sent plain or in signed chunks (aws-chunked,
// which the client uses over http).
func s3Body(r *http.Request) ([]byte, error) {
	if !strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
		return io.ReadAll(r.Body)
	}
	br := bufio.NewReader(r.Body)
	var out []byte
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		size, _, _ := strings.Cut(strings.TrimSpace(line), ";")
		n, err := strconv.ParseInt(size, 16, 64)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return out, nil
		}
		chunk := make([]byte, n+2) // and its CRLF
		if _, err := io.ReadFull(br, chunk); err != nil {
			return nil, err
		}
		out = append(out, chunk[:n]...)
	}
}

func (f *fakeS3) list(w http.ResponseWriter, q url.Values) {
	prefix, delim := q.Get("prefix"), q.Get("delimiter")
	max, _ := strconv.Atoi(q.Get("max-keys"))
	if max <= 0 {
		max = 1000
	}
	var keys []string
	for k := range f.objs {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	type content struct {
		Key          string
		Size         int
		ETag         string
		LastModified string
	}
	res := struct {
		XMLName               xml.Name `xml:"ListBucketResult"`
		Name                  string
		Prefix                string
		KeyCount              int
		MaxKeys               int
		IsTruncated           bool
		NextContinuationToken string
		Contents              []content
		CommonPrefixes        []struct{ Prefix string }
	}{Name: "media", Prefix: prefix, MaxKeys: max}
	seen := map[string]bool{}
	last := ""
	for _, k := range keys {
		if k <= q.Get("continuation-token") {
			continue
		}
		if res.KeyCount >= max {
			res.IsTruncated, res.NextContinuationToken = true, last
			break
		}
		last = k
		if i := strings.Index(k[len(prefix):], "/"); delim == "/" && i >= 0 {
			p := k[:len(prefix)+i+1]
			if !seen[p] {
				seen[p] = true
				res.CommonPrefixes = append(res.CommonPrefixes, struct{ Prefix string }{p})
				res.KeyCount++
			}
			continue
		}
		res.Contents = append(res.Contents, content{k, len(f.objs[k]), `"` + etag(f.objs[k]) + `"`, "2026-11-08T10:00:00.000Z"})
		res.KeyCount++
	}
	w.Header().Set("Content-Type", "application/xml")
	xml.NewEncoder(w).Encode(res)
}

// openFakeS3 is an S3 conn on a fakeS3, with its keys under site/.
func openFakeS3(t *testing.T) (Bucket, *fakeS3) {
	t.Helper()
	f := &fakeS3{objs: map[string][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	tg, err := driver.Parse("s3://KEY@media/site?region=us-east-1&endpoint=" + srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := OpenS3(tg, "secret", nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return b, f
}
