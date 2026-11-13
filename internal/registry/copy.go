package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
)

// CopyResult says what a Copy did.
type CopyResult struct {
	Digest       string `json:"digest"`             // of the top manifest (or index)
	Manifests    int    `json:"manifests"`          // manifests written (index + images)
	BlobsCopied  int    `json:"blobs_copied"`       // layers and configs uploaded
	BlobsSkipped int    `json:"blobs_skipped"`      // already in the destination
	BlobsMounted int    `json:"blobs_mounted"`      // linked without copying (same registry)
	Bytes        int64  `json:"bytes"`              // uploaded
	Replaced     bool   `json:"replaced,omitempty"` // the destination tag pointed elsewhere
}

var digestRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func checkDigest(d string) error {
	if !digestRe.MatchString(d) {
		return fmt.Errorf("komando cannot read the digest %q (sha256:<64 hex digits>)", d)
	}
	return nil
}

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type manifestDoc struct {
	MediaType string       `json:"mediaType"`
	Config    *descriptor  `json:"config"`
	Layers    []descriptor `json:"layers"`
	Manifests []descriptor `json:"manifests"`
}

// Copy copies srcRepo:ref from src to dstRepo:dstTag on dst, with every
// platform of a multi-platform image. Blobs the destination already has are
// skipped; on the same registry they are mounted instead of downloaded.
// The manifest bytes are copied unchanged, so the digest stays the same.
func Copy(ctx context.Context, src *Client, srcRepo, ref string, dst *Client, dstRepo, dstTag string) (*CopyResult, error) {
	res := &CopyResult{}
	if old, err := headDigest(ctx, dst, dstRepo, dstTag); err == nil {
		res.Replaced = true
		defer func() {
			if old == res.Digest {
				res.Replaced = false // same image: nothing really changed
			}
		}()
	}
	digest, err := copyManifest(ctx, src, srcRepo, ref, dst, dstRepo, dstTag, res)
	res.Digest = digest
	return res, err
}

// Digest returns the digest a tag points at, with a HEAD request.
func (c *Client) Digest(ctx context.Context, repo, ref string) (string, error) {
	return headDigest(ctx, c, repo, ref)
}

func headDigest(ctx context.Context, c *Client, repo, ref string) (string, error) {
	resp, err := c.Do(ctx, "HEAD", "/v2/"+repo+"/manifests/"+ref, nil, Accept)
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	return resp.Header.Get("Docker-Content-Digest"), nil
}

func copyManifest(ctx context.Context, src *Client, srcRepo, ref string, dst *Client, dstRepo, putRef string, res *CopyResult) (string, error) {
	resp, err := src.Do(ctx, "GET", "/v2/"+srcRepo+"/manifests/"+ref, nil, Accept)
	if err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if d := resp.Header.Get("Docker-Content-Digest"); d != "" && d != digest {
		return "", fmt.Errorf("manifest digest mismatch: registry says %s, content is %s", d, digest)
	}
	// asked for by digest (a pinned image, or an index's child): the
	// content must be exactly that, whatever the registry's headers say
	if digestRe.MatchString(ref) && ref != digest {
		return "", fmt.Errorf("manifest %s has content with digest %s", ref, digest)
	}
	var m manifestDoc
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", fmt.Errorf("unreadable manifest: %w", err)
	}
	mediaType := m.MediaType
	if mediaType == "" {
		mediaType = resp.Header.Get("Content-Type")
	}
	// an index: copy each platform's manifest by digest first
	for _, child := range m.Manifests {
		if err := checkDigest(child.Digest); err != nil {
			return "", err
		}
		if _, err := copyManifest(ctx, src, srcRepo, child.Digest, dst, dstRepo, child.Digest, res); err != nil {
			return "", err
		}
	}
	blobs := m.Layers
	if m.Config != nil && m.Config.Digest != "" {
		blobs = append([]descriptor{*m.Config}, blobs...)
	}
	for _, b := range blobs {
		if err := checkDigest(b.Digest); err != nil {
			return "", err
		}
		if err := copyBlob(ctx, src, srcRepo, dst, dstRepo, b, res); err != nil {
			return "", err
		}
	}
	u := *dst.Base
	u.Path = "/v2/" + dstRepo + "/manifests/" + putRef
	if err := dst.authorize(ctx, dstRepo); err != nil {
		return "", err
	}
	put, err := dst.Send(ctx, "PUT", &u, "", mediaType, bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return "", err
	}
	put.Body.Close()
	res.Manifests++
	return digest, nil
}

func copyBlob(ctx context.Context, src *Client, srcRepo string, dst *Client, dstRepo string, b descriptor, res *CopyResult) error {
	if head, err := dst.Do(ctx, "HEAD", "/v2/"+dstRepo+"/blobs/"+b.Digest, nil, ""); err == nil {
		head.Body.Close()
		res.BlobsSkipped++
		return nil
	}
	// start an upload; on the same registry, ask to mount the blob instead
	start := *dst.Base
	start.Path = "/v2/" + dstRepo + "/blobs/uploads/"
	if src.Base.Host == dst.Base.Host && srcRepo != dstRepo {
		start.RawQuery = url.Values{"mount": {b.Digest}, "from": {srcRepo}}.Encode()
	}
	resp, err := dst.Send(ctx, "POST", &start, "", "", nil, 0)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusCreated {
		res.BlobsMounted++
		return nil
	}
	loc, err := dst.Base.Parse(resp.Header.Get("Location"))
	if err != nil || resp.Header.Get("Location") == "" {
		return fmt.Errorf("registry gave no upload location for %s", b.Digest)
	}
	blob, err := src.Do(ctx, "GET", "/v2/"+srcRepo+"/blobs/"+b.Digest, nil, "")
	if err != nil {
		return err
	}
	defer blob.Body.Close()
	q := loc.Query()
	q.Set("digest", b.Digest)
	loc.RawQuery = q.Encode()
	put, err := dst.Send(ctx, "PUT", loc, "", "application/octet-stream", blob.Body, b.Size)
	if err != nil {
		return err
	}
	put.Body.Close()
	res.BlobsCopied++
	res.Bytes += b.Size
	return nil
}

// authorize fetches a push token before a request with a body, which
// cannot be replayed after a 401.
func (c *Client) authorize(ctx context.Context, repo string) error {
	u := *c.Base
	u.Path = "/v2/" + repo + "/blobs/uploads/"
	resp, err := c.Send(ctx, "POST", &u, "", "", nil, 0)
	if err != nil {
		return err
	}
	resp.Body.Close()
	// the started upload is abandoned; registries expire it on their own
	if loc := resp.Header.Get("Location"); loc != "" {
		if l, err := c.Base.Parse(loc); err == nil {
			if del, err := c.Send(ctx, "DELETE", l, "", "", nil, 0); err == nil {
				del.Body.Close()
			}
		}
	}
	return nil
}
