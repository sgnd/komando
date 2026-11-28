package cli

import (
	"context"
	"maps"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/capability"
	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
)

// `komando copy` moves files between this computer and any target that
// stores files: servers (SFTP) or storage conns. Its bodies are the old
// upload and download, which cp runs for its two directions.

// fileTarget says whether a target is servers or one storage conn.
func fileTarget(cl *call, expr string) (storage bool, err error) {
	st, err := loadState()
	if err != nil {
		return false, err
	}
	sel, err := resolveSelection(cl, st, expr)
	if err != nil {
		return false, err
	}
	var buckets []string
	for _, c := range sel.Conns {
		if inventory.ConnFamily(c) == "storage" {
			buckets = append(buckets, c.Name)
		}
	}
	switch {
	case len(sel.Hosts) > 0 && len(buckets) > 0:
		return false, out.Usage("target %q picks servers and storage (%s); give one or the other", expr, strings.Join(buckets, ", "))
	case len(buckets) > 0:
		return true, nil
	}
	return false, nil
}

func uploadCmd() *cobra.Command { return uploadCmdFor(false) }

func downloadCmd() *cobra.Command { return downloadCmdFor(false) }

// storageUploadCmd and storageDownloadCmd are `upload` and `download`
// spelled inside the storage area: the same code, for storage conns only.
func storageUploadCmd() *cobra.Command {
	c := alias(uploadCmdFor(true), "upload TARGET FILE [DEST]", "Upload a file to a storage conn")
	return c
}

func storageDownloadCmd() *cobra.Command {
	c := alias(downloadCmdFor(true), "download TARGET PATH", "Download an object from a storage conn")
	return c
}

// uploadCmdFor builds `upload`, or with storageOnly `storage upload`, which
// has only the flags that mean something for storage.
func uploadCmdFor(storageOnly bool) *cobra.Command {
	var o cpOpts
	c := &cobra.Command{
		Use:  "upload TARGET FILE [DEST]",
		Args: cobra.RangeArgs(2, 3),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			dest := ""
			if len(args) == 3 {
				dest = args[2]
			}
			ctx, finish := startProgress(cl, cmd.Context(), o.progress)
			return finish(runUpload(ctx, cmd, args[0], args[1], dest, storageOnly, o))
		}),
	}
	c.Flags().BoolVar(&o.progress, "progress", false, progressUsage)
	c.Flags().BoolVar(&o.resume, "continue", false, continueUsage)
	o.bindSize(c)
	if storageOnly {
		c.Use, c.Aliases = "upload CONN FILE [OBJECT]", []string{"put"}
		c.Flags().BoolVarP(&o.recursive, "recursive", "r", false, "upload a folder (new and changed files, like komando sync)")
		return c
	}
	o.bindUp(c, "")
	return c
}

// storageFolderDest is where `upload CONN DIR [DEST] -r` puts the folder,
// by the rule servers follow: without DEST, a prefix named like the folder;
// DIR/ sends its contents into DEST; a DEST ending in / gets DEST/DIR.
func storageFolderDest(dir, dest string) string {
	base := filepath.Base(filepath.Clean(dir))
	if base == "." || base == string(filepath.Separator) {
		base = ""
	}
	contents := strings.HasSuffix(dir, "/") || strings.HasSuffix(dir, string(filepath.Separator))
	switch {
	case dest == "":
		return base
	case contents:
		return dest
	case strings.HasSuffix(dest, "/"):
		return dest + base
	}
	return dest
}

func downloadCmdFor(storageOnly bool) *cobra.Command {
	var o cpOpts
	var to string
	c := &cobra.Command{
		Use:  "download TARGET PATH",
		Args: cobra.ExactArgs(2),
		RunE: inCall(func(cl *call, cmd *cobra.Command, args []string) error {
			ctx, finish := startProgress(cl, cmd.Context(), o.progress)
			return finish(runDownload(ctx, cmd, args[0], args[1], to, storageOnly, o))
		}),
	}
	c.Flags().BoolVar(&o.progress, "progress", false, progressUsage)
	c.Flags().StringVar(&to, "to", "", "where to save it, or - to stream it to stdout (default: the current folder)")
	c.Flags().BoolVarP(&o.recursive, "recursive", "r", false, "download a folder (servers) or every object under a prefix (storage)")
	c.Flags().BoolVar(&o.overwrite, "overwrite", false, "replace files that already exist on this computer")
	c.Flags().BoolVar(&o.resume, "continue", false, continueUsage)
	if storageOnly {
		c.Use, c.Aliases = "download CONN OBJECT", []string{"get"}
		return c
	}
	c.Flags().BoolVarP(&o.sudo, "sudo", "s", false, "read the file as root (single files)")
	return c
}

// cmdName is the command's name in JSON and the audit: "upload",
// "storage.upload", "cp".
func cmdName(cmd *cobra.Command) string {
	if p := cmd.Parent(); p != nil && p.Parent() != nil {
		return p.Name() + "." + cmd.Name()
	}
	return cmd.Name()
}

// runUpload is every upload: `upload`, `storage upload` and `cp` to a
// TARGET:PATH. storageOnly skips asking the inventory what target is.
func runUpload(ctx context.Context, cmd *cobra.Command, target, file, dest string, storageOnly bool, o cpOpts) error {
	cl := callOf(cmd)
	name := cmdName(cmd)
	if err := continueFlags(o); err != nil {
		return err
	}
	o.sized = cmd.Flags().Changed("size")
	stdin := file == "-"
	switch {
	case stdin && o.resume:
		return out.Usage("--continue reads the file again from where it stopped; stdin (-) cannot be read again")
	case stdin && o.recursive:
		return out.Usage("stdin (-) is one file; -r uploads a folder")
	case !stdin && o.sized:
		return out.Usage("--size is for an upload from stdin (-); a file's size is known")
	case o.sized && o.size < 0:
		return out.Usage("--size takes a number of bytes, 0 or more")
	case stdin:
		if err := stdinDest(dest); err != nil {
			return err
		}
	}
	storage := storageOnly
	if !storage {
		var err error
		if storage, err = fileTarget(cl, target); err != nil {
			return err
		}
	}
	if storage {
		if o.sudo || o.mkdirs || o.mode != "" {
			return out.Usage("--sudo, -p and --mode are for servers")
		}
		if stdin {
			return storageUploadStdin(cl, ctx, name, target, dest, o)
		}
		if o.recursive {
			// a folder: sent like `komando copy --sync`, new and changed files only
			return syncUp(cl, ctx, name, file, target, storageFolderDest(file, dest), syncOpts{})
		}
		if err := noteUpload(cl, file, nil); err != nil {
			return err
		}
		return storageUpload(cl, ctx, name, target, file, dest, o.resume)
	}
	if dest == "" {
		dest = filepath.Base(file)
	}
	return runCp(cl, ctx, name, target, dest, file, true, o)
}

// runDownload is every download: `download`, `storage download` and `cp`
// from a TARGET:PATH.
func runDownload(ctx context.Context, cmd *cobra.Command, target, p, to string, storageOnly bool, o cpOpts) error {
	cl := callOf(cmd)
	name := cmdName(cmd)
	if err := continueFlags(o); err != nil {
		return err
	}
	if o.resume && to == "-" {
		return out.Usage("--continue adds to a file; a copy to - (stdout) has none")
	}
	if o.progress && to == "-" {
		return out.Usage("--progress counts what is saved; a copy to - (stdout) has one answer on stderr, at the end")
	}
	if cmd.Flags().Lookup("size") != nil && cmd.Flags().Changed("size") {
		return out.Usage("--size is for an upload from stdin (-)")
	}
	storage := storageOnly
	if !storage {
		var err error
		if storage, err = fileTarget(cl, target); err != nil {
			return err
		}
	}
	if storage {
		if o.sudo {
			return out.Usage("--sudo is for servers")
		}
		if !o.recursive {
			return storageDownloadTo(cl, ctx, name, target, p, to, o.overwrite, o.resume)
		}
		if to == "-" {
			return out.Usage("-r saves a folder; a copy to - (stdout) takes one file")
		}
		if to == "" {
			to = path.Base(strings.TrimSuffix(p, "/"))
		}
		// files already here stay unless --overwrite
		return syncDown(cl, ctx, name, target, p, to, syncOpts{onlyNew: !o.overwrite})
	}
	if to == "-" {
		return streamServer(cl, ctx, name, target, p, o)
	}
	if to == "" {
		to = "."
	}
	if o.sudo && o.recursive {
		return out.Usage("--sudo downloads single files; copy the folder to a readable place with `komando host ssh exec --sudo -- cp -r`, then download that")
	}
	return runCp(cl, ctx, name, target, p, to, false, o)
}

// continueFlags refuses flags that do not go with --continue.
func continueFlags(o cpOpts) error {
	switch {
	case !o.resume:
		return nil
	case o.recursive:
		return out.Usage("--continue goes on with one file; for a folder use `komando copy --sync`, which sends only what is still missing")
	case o.sudo:
		return out.Usage("--continue reads and writes as the SSH user; --sudo copies the whole file")
	case o.overwrite:
		return out.Usage("--continue keeps the part already there and --overwrite replaces it; give one of them")
	}
	return nil
}

// copySync says whether c, a copy, was given --sync. Only copy has the flag,
// so a command without it counts as a plain copy, where - is a stream.
func copySync(c *cobra.Command) bool {
	on, _ := c.Flags().GetBool("sync")
	return on
}

// copy is the one command for what cp, upload, download, sync, storage
// upload and storage download did: --sync runs the folder sync body, the
// rest runs cp's, which reads which side is TARGET:PATH.
func init() {
	handlers[capability.Key{Verb: "copy"}] = func(cl *call, ctx context.Context, in leafInput) error {
		if !in.Bool("sync") {
			return runBody(cl, ctx, cpCmd(), in, nil)
		}
		in.vals = maps.Clone(in.vals)
		delete(in.vals, "sync") // the sync body is --sync already
		return runBody(cl, ctx, syncCmd(), in, nil)
	}
	moveTop("copy")
}
