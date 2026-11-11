package cli

import (
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

func uploadCmd() *cobra.Command {
	var o cpOpts
	c := &cobra.Command{
		Use:   "upload TARGET FILE [DEST]",
		Short: "Upload a file to servers (many at once) or to file storage",
		Long: `DEST is the path on the servers, or the key in the storage conn. It defaults
to the file's name (servers: in the login user's home folder; ~/x works too).
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
			storage, err := fileTarget(args[0])
			if err != nil {
				return err
			}
			if storage {
				if o.sudo || o.mkdirs || o.mode != "" {
					return out.Usage("--sudo, -p and --mode are for servers")
				}
				if o.recursive {
					// a folder: sent like `komando sync`, new and changed files only
					return syncUp(cmd.Context(), "upload", args[1], args[0], storageFolderDest(args[1], dest), syncOpts{})
				}
				return storageUpload(cmd.Context(), "upload", args[0], args[1], dest)
			}
			if dest == "" {
				dest = filepath.Base(args[1])
			}
			return runCp(cmd.Context(), "upload", args[0], dest, args[1], true, o)
		},
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

func downloadCmd() *cobra.Command {
	var to string
	var recursive, overwrite, sudo bool
	c := &cobra.Command{
		Use:   "download TARGET PATH",
		Short: "Download files from servers or from file storage",
		Long: `PATH is the path on the servers, or the key in the storage conn. --to is
where it lands (a folder per server when several are picked). Files that
already exist here are kept unless --overwrite. --sudo reads one file as
root (up to 512 MiB). From storage, --to - writes the object to stdout.

` + downloadFolderRule,
		Example: `  komando download web1 /var/log/nginx/error.log --to ./logs/
  komando download @web /etc/nginx/nginx.conf --to ./configs/
  komando download backups 2026/db.sql.gz`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			storage, err := fileTarget(args[0])
			if err != nil {
				return err
			}
			if storage {
				if sudo {
					return out.Usage("--sudo is for servers")
				}
				if recursive {
					dest := to
					if dest == "" {
						dest = path.Base(strings.TrimSuffix(args[1], "/"))
					}
					// files already here stay unless --overwrite
					return syncDown(cmd.Context(), "download", args[0], args[1], dest, syncOpts{onlyNew: !overwrite})
				}
				return storageDownloadTo(cmd.Context(), "download", args[0], args[1], to, overwrite)
			}
			dest := to
			if dest == "" {
				dest = "."
			}
			if dest == "-" {
				return out.Usage("--to - (stdout) is for storage; to print a file from a server, use `komando fs cat %s %s`", args[0], args[1])
			}
			if sudo && recursive {
				return out.Usage("--sudo downloads single files; copy the folder to a readable place with `komando exec --sudo -- cp -r`, then download that")
			}
			return runCp(cmd.Context(), "download", args[0], args[1], dest, false, cpOpts{recursive: recursive, overwrite: overwrite, sudo: sudo})
		},
	}
	c.Flags().StringVar(&to, "to", "", "where to save it (default: the current folder)")
	c.Flags().BoolVarP(&recursive, "recursive", "r", false, "download a folder (servers) or every object under a prefix (storage)")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace files that already exist on this computer")
	c.Flags().BoolVarP(&sudo, "sudo", "s", false, "read the file as root (single files)")
	return c
}
