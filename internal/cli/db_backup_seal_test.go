package cli

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgnd/komando/internal/store"
)

func sealOf(t *testing.T, path string) (*backupSeal, []byte) {
	t.Helper()
	seal := &backupSeal{}
	var got []byte
	if err := withBackup(tcl, path, seal, func(r io.Reader) (err error) {
		got, err = io.ReadAll(r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !seal.sealed {
		t.Fatal("not sealed")
	}
	return seal, got
}

func TestBackupSeal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "b.sql")
	// three chunks and a bit
	orig := bytes.Repeat([]byte("INSERT INTO t VALUES (1);\n"), (3*sealChunk+500)/26)
	write := func(b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(orig)
	seal, got := sealOf(t, path)
	if !bytes.Equal(got, orig) || len(seal.sums) != 4 {
		t.Fatalf("first read: %d bytes, %d chunks", len(got), len(seal.sums))
	}
	read := func() ([]byte, error) {
		var b bytes.Buffer
		err := withBackup(tcl, path, seal, func(r io.Reader) error {
			_, err := io.Copy(&b, r)
			return err
		})
		return b.Bytes(), err
	}
	if b, err := read(); err != nil || !bytes.Equal(b, orig) {
		t.Fatalf("the same file again: %v", err)
	}
	if err := verifyBackup(tcl, path, seal); err != nil {
		t.Fatalf("verify: %v", err)
	}
	last := append([]byte(nil), orig...)
	copy(last[len(last)-30:], "DROP DATABASE shop; --")
	third := append([]byte(nil), orig...)
	copy(third[2*sealChunk+100:], "DROP DATABASE shop; --")
	for name, changed := range map[string][]byte{
		"another file":   []byte("COPY t TO PROGRAM 'id';\n"),
		"one more line":  append(append([]byte(nil), orig...), "DROP DATABASE shop;\n"...),
		"cut short":      orig[:2*sealChunk],
		"cut at a chunk": orig[:3*sealChunk],
		"last chunk":     last,
		"third chunk":    third,
		"empty":          nil,
	} {
		seal.changed = false
		write(changed)
		b, err := read()
		if e := toErr(err); err == nil || e.Code != "BACKUP_CONFLICT" {
			t.Errorf("%s: want BACKUP_CONFLICT, got %v", name, err)
		}
		// what was handed on before the stop is the checked file's own start
		if !bytes.HasPrefix(orig, b) {
			t.Errorf("%s: %d bytes that were never checked were handed on", name, len(b))
		}
		if strings.Contains(string(b), "DROP DATABASE") || strings.Contains(string(b), "PROGRAM") {
			t.Errorf("%s: changed text was handed on", name)
		}
		seal.changed = false
		if e := toErr(verifyBackup(tcl, path, seal)); e.Code != "BACKUP_CONFLICT" {
			t.Errorf("%s: verify: %+v", name, e)
		}
	}
}

// A change made while the restore is reading is caught at its chunk.
func TestBackupSealChangeWhileReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.sql")
	orig := bytes.Repeat([]byte("INSERT INTO t VALUES (1);\n"), (3*sealChunk)/26)
	os.WriteFile(path, orig, 0o600)
	seal, _ := sealOf(t, path)
	var got bytes.Buffer
	err := withBackup(tcl, path, seal, func(r io.Reader) error {
		if _, err := io.CopyN(&got, r, 1000); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		f.WriteAt([]byte("DROP DATABASE shop; --"), 2*sealChunk+10)
		f.Close()
		_, err = io.Copy(&got, r)
		return err
	})
	if e := toErr(err); err == nil || e.Code != "BACKUP_CONFLICT" {
		t.Fatalf("want BACKUP_CONFLICT, got %v", err)
	}
	if !bytes.HasPrefix(orig, got.Bytes()) || got.Len() != 2*sealChunk {
		t.Errorf("handed on %d bytes; the two checked chunks are %d", got.Len(), 2*sealChunk)
	}
}

func TestBackupSealGzip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.sql.gz")
	mk := func(sql string) {
		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		gz.Write([]byte(sql))
		gz.Close()
		os.WriteFile(path, b.Bytes(), 0o600)
	}
	mk("INSERT INTO t VALUES (1);\n")
	seal, got := sealOf(t, path)
	if string(got) != "INSERT INTO t VALUES (1);\n" || seal.archive() {
		t.Fatalf("gzip read: %q", got)
	}
	mk("DROP DATABASE shop;\n")
	err := withBackup(tcl, path, seal, func(r io.Reader) error {
		b, err := io.ReadAll(r)
		if len(b) > 0 {
			t.Errorf("changed bytes handed on: %q", b)
		}
		return err
	})
	if e := toErr(err); err == nil || e.Code != "BACKUP_CONFLICT" {
		t.Errorf("want BACKUP_CONFLICT, got %v", err)
	}
}

// The dump tools never run as a program of this computer: it would be
// looked up on PATH and get the conn's password in its environment.
func TestRunToolNeedsAServer(t *testing.T) {
	invHome(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	os.WriteFile(filepath.Join(dir, "pg_dump"), []byte("#!/bin/sh\necho ran > "+marker+"\n"), 0o755)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	c := &store.Conn{Name: "pg", Kind: "postgres", URL: "postgres://app@127.0.0.1:1/app?sslmode=disable"}
	st, err := loadState()
	if err != nil {
		t.Fatal(err)
	}
	err = runTool(tcl, t.Context(), st, c, nil, dumpTool{passwordEnv: "PGPASSWORD", pkg: "postgresql-client"}, []string{"pg_dump", "--version"}, nil, io.Discard, false)
	if err == nil {
		t.Error("want a refusal")
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Error("a pg_dump found on PATH was run")
	}
}
