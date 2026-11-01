package cli

import (
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
		Short: "Upload a file to servers (SFTP, many at once) or to storage (S3)",
		Long: `DEST is the path on the servers, or the key in the storage conn. It defaults
to the file's name (servers: in the login user's home folder).`,
		Example: `  komando upload @web ./app.tar.gz /tmp/app.tar.gz
  komando upload web1 ./site /var/www/site -r --sudo
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
				if o.recursive || o.sudo || o.mkdirs || o.mode != "" {
					return out.Usage("-r, --sudo, -p and --mode are for servers; storage takes one file")
				}
				return storageUpload(cmd.Context(), "upload", args[0], args[1], dest)
			}
			if dest == "" {
				dest = filepath.Base(args[1])
			}
			return runCp(cmd.Context(), "upload", args[0], dest, args[1], true, o)
		},
	}
	o.bind(c)
	return c
}

func downloadCmd() *cobra.Command {
	var to string
	var recursive bool
	c := &cobra.Command{
		Use:   "download TARGET PATH",
		Short: "Download a file from servers (SFTP) or from storage (S3) to this computer",
		Long: `PATH is the path on the servers, or the key in the storage conn. --to is
where it lands (a folder per server when several are picked). Storage
downloads never overwrite a file.`,
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
				if recursive {
					return out.Usage("-r is for servers; storage downloads one object")
				}
				return storageDownload(cmd.Context(), "download", args[0], args[1], to)
			}
			dest := to
			if dest == "" {
				dest = "."
			}
			return runCp(cmd.Context(), "download", args[0], args[1], dest, false, cpOpts{recursive: recursive})
		},
	}
	c.Flags().StringVar(&to, "to", "", "where to save it (default: the current folder)")
	c.Flags().BoolVarP(&recursive, "recursive", "r", false, "servers: download a folder")
	return c
}
