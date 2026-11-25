package cli

import (
	"io/fs"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

// infoStat is an os.FileInfo for toInfo: a name, a mode, a size, a time and
// whatever Sys() should return.
type infoStat struct {
	name string
	size int64
	mode fs.FileMode
	mod  time.Time
	sys  any
}

func (f infoStat) Name() string       { return f.name }
func (f infoStat) Size() int64        { return f.size }
func (f infoStat) Mode() fs.FileMode  { return f.mode }
func (f infoStat) ModTime() time.Time { return f.mod }
func (f infoStat) IsDir() bool        { return f.mode.IsDir() }
func (f infoStat) Sys() any           { return f.sys }

// toInfo turns a directory entry into the fileInfo that `fs list` prints.
func TestToInfo(t *testing.T) {
	mod := time.Date(2026, 11, 1, 10, 30, 0, 0, time.FixedZone("WIB", 7*3600))
	tests := []struct {
		name string
		dir  string
		fi   infoStat
		want fileInfo
	}{
		{
			name: "a regular file with an owner",
			dir:  "/etc",
			fi:   infoStat{name: "hosts", size: 221, mode: 0o644, mod: mod, sys: &sftp.FileStat{UID: 0, GID: 4}},
			want: fileInfo{Name: "hosts", Path: "/etc/hosts", Type: "file", Size: 221, Mode: "0644", ModTime: mod.UTC(), UID: 0, GID: 4},
		},
		{
			name: "a directory",
			dir:  "/var",
			fi:   infoStat{name: "log", size: 4096, mode: fs.ModeDir | 0o755, mod: mod, sys: &sftp.FileStat{UID: 0, GID: 0}},
			want: fileInfo{Name: "log", Path: "/var/log", Type: "dir", Size: 4096, Mode: "0755", ModTime: mod.UTC()},
		},
		{
			name: "a symlink",
			dir:  "/usr/bin",
			fi:   infoStat{name: "python", size: 9, mode: fs.ModeSymlink | 0o777, mod: mod},
			want: fileInfo{Name: "python", Path: "/usr/bin/python", Type: "symlink", Size: 9, Mode: "0777", ModTime: mod.UTC()},
		},
		{
			name: "a socket is other",
			dir:  "/run",
			fi:   infoStat{name: "docker.sock", mode: fs.ModeSocket | 0o660, mod: mod, sys: &sftp.FileStat{UID: 0, GID: 998}},
			want: fileInfo{Name: "docker.sock", Path: "/run/docker.sock", Type: "other", Mode: "0660", ModTime: mod.UTC(), GID: 998},
		},
		{
			name: "setuid bits are not in the mode string",
			dir:  "/usr/bin",
			fi:   infoStat{name: "sudo", size: 232416, mode: fs.ModeSetuid | 0o755, mod: mod},
			want: fileInfo{Name: "sudo", Path: "/usr/bin/sudo", Type: "file", Size: 232416, Mode: "0755", ModTime: mod.UTC()},
		},
		{
			name: "Sys that is not an sftp stat leaves owner at zero",
			dir:  "/tmp",
			fi:   infoStat{name: "x", mode: 0o600, mod: mod, sys: struct{}{}},
			want: fileInfo{Name: "x", Path: "/tmp/x", Type: "file", Mode: "0600", ModTime: mod.UTC()},
		},
		{
			name: "the path is cleaned",
			dir:  "/srv//app/",
			fi:   infoStat{name: "a.txt", mode: 0o640, mod: mod},
			want: fileInfo{Name: "a.txt", Path: "/srv/app/a.txt", Type: "file", Mode: "0640", ModTime: mod.UTC()},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toInfo(tt.dir, tt.fi)
			if got != tt.want {
				t.Errorf("toInfo\n got  %+v\n want %+v", got, tt.want)
			}
		})
	}
}
