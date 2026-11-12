package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/registry"
	"github.com/sgnd/komando/internal/store"
)

func registryCopyCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "copy SRC_CONN:IMAGE DST_CONN[:IMAGE]",
		Aliases: []string{"cp"},
		Short:   "Copy an image (all platforms) between registries or repositories",
		Long: `Copies IMAGE (REPO[:TAG] or REPO@DIGEST) from one registry conn to another, or
to another name on the same registry, with every platform of a multi-platform
image. Layers the destination already has are skipped; on the same registry
they are linked instead of copied. The image digest stays the same. Leaving
out the destination image keeps the source name and tag; leaving out only
the tag keeps the source tag. --dry-run reads both registries and says what
the copy would bring and whether it replaces what the tag points to now.

Only the destination changes: a protected destination needs --yes.`,
		Example: `  komando registry copy ghcr:org/app:1.4.2 harbor:prod/app:1.4.2
  komando registry copy ghcr:org/app:1.4.2 harbor:
  komando registry copy reg:app:latest reg:app:stable`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegistryCopy(cmd.Context(), args[0], args[1])
		},
	}
}

type copyData struct {
	From string `json:"from"`
	To   string `json:"to"`
	*registry.CopyResult
	DryRun bool `json:"dry_run,omitempty"`
	// a dry run's findings: the source image, and whether the
	// destination tag points to another image now
	Source       *registry.Manifest `json:"source,omitempty"`
	WouldReplace bool               `json:"would_replace,omitempty"`
}

func (d copyData) Text() string {
	if d.DryRun {
		s := fmt.Sprintf("dry run: would copy %s to %s\n", d.From, d.To)
		if d.Source != nil {
			s += fmt.Sprintf("%s, %s", d.Source.Digest, humanBytes(d.Source.Size))
			if len(d.Source.Platforms) > 0 {
				s += ", " + strings.Join(d.Source.Platforms, " ")
			}
			s += "\n"
		}
		if d.WouldReplace {
			s += "the destination tag points to another image now; the copy would replace it\n"
		}
		return s
	}
	s := fmt.Sprintf("%s -> %s\n%s, %s, %s copied (%s), %d already there, %d linked\n",
		d.From, d.To, d.Digest, countOf(d.Manifests, "manifest"), countOf(d.BlobsCopied, "layer"), humanBytes(d.Bytes), d.BlobsSkipped, d.BlobsMounted)
	if d.Replaced {
		s += "the destination tag pointed to another image before\n"
	}
	return s
}

func runRegistryCopy(ctx context.Context, from, to string) error {
	srcName, srcImage, ok := strings.Cut(from, ":")
	if !ok || srcImage == "" || strings.Contains(srcName, "/") {
		return out.Usage("write the source as CONN:IMAGE, e.g. ghcr:org/app:1.4.2 (%q has no registry conn in front)", from)
	}
	dstName, dstImage, ok := strings.Cut(to, ":")
	if !ok || strings.Contains(dstName, "/") {
		return out.Usage("write the destination as CONN:IMAGE or CONN: (same name), e.g. harbor:prod/app:1.4.2 (%q has no registry conn in front)", to)
	}
	srcRepo, srcRef := splitImage(srcImage)
	dstRepo, dstRef := srcRepo, srcRef
	if dstImage != "" {
		dstRepo, dstRef = splitImage(dstImage)
		if !strings.Contains(dstImage[strings.LastIndex(dstImage, "/")+1:], ":") && !strings.Contains(dstImage, "@") {
			// harbor:prod/app keeps the source's tag, as harbor: keeps its
			// name; a source digest then asks for a tag below, not latest
			dstRef = srcRef
		}
	}
	if err := checkImages(srcRepo, srcRef, dstRepo, dstRef); err != nil {
		return err
	}
	if srcName == dstName && srcRepo == dstRepo && srcRef == dstRef {
		return out.Usage("%s is the source and the destination; name another repository or tag", from)
	}
	if strings.HasPrefix(dstRef, "sha256:") {
		if dstImage != "" && strings.Contains(dstImage, "@") {
			return out.Usage("the destination needs a tag, not a digest (the digest is kept anyway)")
		}
		return out.Usage("copying by digest needs a destination tag: %s:REPO:TAG", dstName)
	}
	st, err := loadState()
	if err != nil {
		return err
	}
	src, err := singleConn(st, srcName, "registry")
	if err != nil {
		return err
	}
	dst, err := singleConn(st, dstName, "registry")
	if err != nil {
		return err
	}
	data := copyData{From: src.Name + ":" + srcRepo + refSep(srcRef) + srcRef, To: dst.Name + ":" + dstRepo + ":" + dstRef}
	rec := map[string]any{"conns": []string{src.Name, dst.Name}, "from": data.From, "to": data.To, "risk": "write"}
	if err := guardConns(st, []*store.Conn{dst}, driver.Verdict{Risk: driver.RiskWrite}); err != nil {
		if g.dryRun {
			out.P.Print("registry.copy", map[string]any{"from": data.From, "to": data.To, "dry_run": true, "would_be_blocked": toErr(err)}, nil)
			return nil
		}
		return err
	}
	if g.timeout > 0 { // a big image may take long: only a --timeout given ends it
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.timeout)
		defer cancel()
	}
	sc, closeSrc, err := openRegistry(ctx, st, src)
	if err != nil {
		return err
	}
	defer closeSrc()
	dc, closeDst, err := openRegistry(ctx, st, dst)
	if err != nil {
		return err
	}
	defer closeDst()
	srcRepo, dstRepo = sc.Repo(srcRepo), dc.Repo(dstRepo) // Docker Hub: nginx is library/nginx
	if g.dryRun {
		if err := copyDryRun(ctx, &data, sc, srcRepo, srcRef, dc, dstRepo, dstRef); err != nil {
			return err
		}
		audit(st, "registry.copy", nil, "", true, rec)
		out.P.Print("registry.copy", data, nil)
		return nil
	}
	res, err := registry.Copy(ctx, sc, srcRepo, srcRef, dc, dstRepo, dstRef)
	if err != nil {
		if _, ierr := sc.Inspect(ctx, srcRepo, srcRef); ierr != nil {
			err = imageErr(ctx, sc, srcRepo, srcRef, ierr) // name the missing source
		}
		err = registryErr(err)
		rec["error"] = toErr(err).Code
		audit(st, "registry.copy", nil, "", false, rec)
		return err
	}
	data.CopyResult = res
	rec["digest"], rec["bytes"] = res.Digest, res.Bytes
	audit(st, "registry.copy", nil, "", true, rec)
	out.P.Print("registry.copy", data, nil)
	return nil
}

// copyDryRun reads both registries: the source image, and whether the
// destination tag points to another image now.
func copyDryRun(ctx context.Context, data *copyData, sc *registry.Client, srcRepo, srcRef string, dc *registry.Client, dstRepo, dstRef string) error {
	m, err := sc.Inspect(ctx, srcRepo, srcRef)
	if err != nil {
		return registryErr(imageErr(ctx, sc, srcRepo, srcRef, err))
	}
	data.DryRun, data.Source = true, m
	old, err := dc.Inspect(ctx, dstRepo, dstRef)
	var answered *registry.Error // not there yet, or not readable before a push: both fine here
	switch {
	case err == nil:
		data.WouldReplace = old.Digest != m.Digest
	case !errors.As(err, &answered):
		return registryErr(err) // the destination must be reachable too
	}
	return nil
}

// checkImages checks repository and tag (or digest) pairs.
func checkImages(repoRef ...string) error {
	for i := 0; i+1 < len(repoRef); i += 2 {
		if err := registry.CheckRepo(repoRef[i]); err != nil {
			return out.Usage("%v", err)
		}
		if err := registry.CheckRef(repoRef[i+1]); err != nil {
			return out.Usage("%v", err)
		}
	}
	return nil
}

func refSep(ref string) string {
	if strings.HasPrefix(ref, "sha256:") {
		return "@"
	}
	return ":"
}
