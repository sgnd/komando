package cli

import (
	"context"
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
		Use:     "copy SRC_CONN:IMAGE DST_CONN:[IMAGE]",
		Aliases: []string{"cp"},
		Short:   "Copy an image (all platforms) between registries or repositories",
		Long: `Copies IMAGE (REPO[:TAG] or REPO@DIGEST) from one registry conn to another, or
to another name on the same registry, with every platform of a multi-platform
image. Layers the destination already has are skipped; on the same registry
they are linked instead of copied. The image digest stays the same. Leaving
out the destination image keeps the source name and tag.

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
}

func (d copyData) Text() string {
	if d.DryRun {
		return fmt.Sprintf("dry run: would copy %s to %s\n", d.From, d.To)
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
	if g.dryRun {
		data.DryRun = true
		audit(st, "registry.copy", nil, "", true, rec)
		out.P.Print("registry.copy", data, nil)
		return nil
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

func refSep(ref string) string {
	if strings.HasPrefix(ref, "sha256:") {
		return "@"
	}
	return ":"
}
