package cli

import (
	"context"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
)

// `komando upload` and `download` move files between this computer and any
// target that stores files: servers (SFTP) or storage conns. `cp` and
// `storage upload/download` are the same thing spelled per area
// (docs/design/ux.md, section 11).

// fileTarget says whether a target is servers or one storage conn.
func fileTarget(expr string) (storage bool, err error) {
	st, err := loadState()
	if err != nil {
		return false, err
	}
	sel, err := resolveSelection(st, expr)
	if err != nil {
		return false, err
	}
	var buckets []string
	for _, c := range sel.Conns {
		if connFamily(c) == "storage" {
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
	c := alias(uploadCmdFor(true), "upload CONN FILE [OBJECT]")
	c.Example = `  komando storage upload backups ./report.pdf reports/2026/`
	return c
}

func storageDownloadCmd() *cobra.Command {
	c := alias(downloadCmdFor(true), "download CONN OBJECT")
	c.Example = `  komando storage download backups reports/q3.pdf --to ~/Downloads/`
	return c
}

// uploadCmdFor builds `upload`, or with storageOnly `storage upload`, which
// has only the flags that mean something for storage.
func uploadCmdFor(storageOnly bool) *cobra.Command {
	var o cpOpts
	c := &cobra.Command{
		Use:   "upload TARGET FILE [DEST]",
		Short: "Upload a file to servers (many at once) or to file storage",
		Long: `DEST is the path on the servers, or the key in the storage conn. It defaults
to the file's name (servers: in the login user's home folder; ~/x works too).
A storage KEY ending in / is a folder, so the file keeps its name inside it.
An existing file at DEST is replaced (the result says replaced).

` + uploadFolderRule,
		Example: `  komando upload @web ./app.tar.gz /tmp/app.tar.gz
  komando upload web1 ./site /var/www/site -r
  komando upload web1 ./nginx.conf /etc/nginx/nginx.conf --sudo
  komando upload backups ./db.sql.gz 2026/db.sql.gz`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			dest := ""
			if len(args) == 3 {
				dest = args[2]
			}
			return runUpload(cmd.Context(), cmd, args[0], args[1], dest, storageOnly, o)
		},
	}
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
		Use:   "download TARGET PATH",
		Short: "Download files from servers or from file storage",
		Long: `PATH is the path on the servers, or the key in the storage conn. --to is
where it lands: a file name, or a folder (existing, or ending in /); a
folder per server when several are picked. A file that is already here is
replaced only with --overwrite: without it, one file stops with FILE_EXISTS,
a folder from servers stops at the first such file, and a folder from
storage keeps them and copies the rest. --sudo reads one file as root (up
to 512 MiB).
From storage, --to - writes the object to stdout.

` + downloadFolderRule,
		Example: `  komando download web1 /var/log/nginx/error.log --to ./logs/
  komando download @web /etc/nginx/nginx.conf --to ./configs/
  komando download backups 2026/db.sql.gz
  komando download backups reports/ -r --to ./reports`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDownload(cmd.Context(), cmd, args[0], args[1], to, storageOnly, o)
		},
	}
	c.Flags().StringVar(&to, "to", "", "where to save it, or - for stdout from storage (default: the current folder)")
	c.Flags().BoolVarP(&o.recursive, "recursive", "r", false, "download a folder (servers) or every object under a prefix (storage)")
	c.Flags().BoolVar(&o.overwrite, "overwrite", false, "replace files that already exist on this computer")
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
	name := cmdName(cmd)
	storage := storageOnly
	if !storage {
		var err error
		if storage, err = fileTarget(target); err != nil {
			return err
		}
	}
	if storage {
		if o.sudo || o.mkdirs || o.mode != "" {
			return out.Usage("--sudo, -p and --mode are for servers")
		}
		if o.recursive {
			// a folder: sent like `komando sync`, new and changed files only
			return syncUp(ctx, name, file, target, storageFolderDest(file, dest), syncOpts{})
		}
		return storageUpload(ctx, name, target, file, dest)
	}
	if dest == "" {
		dest = filepath.Base(file)
	}
	return runCp(ctx, name, target, dest, file, true, o)
}

// runDownload is every download: `download`, `storage download` and `cp`
// from a TARGET:PATH.
func runDownload(ctx context.Context, cmd *cobra.Command, target, p, to string, storageOnly bool, o cpOpts) error {
	name := cmdName(cmd)
	storage := storageOnly
	if !storage {
		var err error
		if storage, err = fileTarget(target); err != nil {
			return err
		}
	}
	if storage {
		if o.sudo {
			return out.Usage("--sudo is for servers")
		}
		if !o.recursive {
			return storageDownloadTo(ctx, name, target, p, to, o.overwrite)
		}
		if to == "-" {
			return out.Usage("-r saves a folder; --to - (stdout) takes one file")
		}
		if to == "" {
			to = path.Base(strings.TrimSuffix(p, "/"))
		}
		// files already here stay unless --overwrite
		return syncDown(ctx, name, target, p, to, syncOpts{onlyNew: !o.overwrite})
	}
	if to == "-" {
		return out.Usage("--to - (stdout) is for storage; to read a file on a server use `komando fs cat %s %s`", target, p)
	}
	if to == "" {
		to = "."
	}
	if o.sudo && o.recursive {
		return out.Usage("--sudo downloads single files; copy the folder to a readable place with `komando exec --sudo -- cp -r`, then download that")
	}
	return runCp(ctx, name, target, p, to, false, o)
}
