package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/inventory"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// noteUpload tells an AI agent's approval window what an upload sends
// (C111): one file as fs write --from content is (shown, or named by its
// size and SHA-256), a folder as the list of its files, each with its size
// and SHA-256. The list is shown whole or there is no window, as for a
// script: a list cut short could leave out the file that matters. exclude
// is sync's --exclude.
func noteUpload(cl *call, local string, exclude []string) error {
	if !cl.caller().IsAgent() {
		return nil
	}
	local = inventory.ExpandHome(local)
	fi, err := os.Stat(local)
	if err != nil {
		return localFileErr("PATH_NOT_FOUND", err, "")
	}
	if !fi.IsDir() {
		return noteApprovalFile(cl, "the file "+local, local)
	}
	var lines []string
	err = filepath.WalkDir(local, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(local, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && excluded(rel, exclude) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || excluded(rel, exclude) {
			return nil
		}
		size, sum, err := fileDigest(p)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s  %d bytes  %s", rel, size, sum))
		return nil
	})
	if err != nil {
		return localFileErr("PATH_NOT_FOUND", err, "")
	}
	body := strings.Join(lines, "\n")
	if body != "" {
		body += "\n"
	}
	noteApprovalBody(cl, fmt.Sprintf("the %s of the folder %s, by name, size and SHA-256", countOf(len(lines), "file"), local), []byte(body))
	return nil
}

// fileDigest is a file's size and SHA-256 in hex.
func fileDigest(p string) (int64, string, error) {
	f, err := os.Open(p)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// noteKubectlFiles tells an AI agent's approval window what a kubectl
// command line sends from this computer (C111): the manifests of -f FILE
// (a folder's .yaml, .yml and .json files, as the run reads them) and the
// files of --from-file. The window shows them as cluster apply --file does.
func noteKubectlFiles(cl *call, args []string) error {
	if !cl.caller().IsAgent() || cl.dryRun() {
		return nil // a dry run opens no window; the run names any stop
	}
	a, err := parseKargs(args)
	if err != nil {
		return nil // the run reports the bad command line
	}
	var all []byte
	var names []string
	for _, f := range a.vals["filename"] {
		if f == "-" {
			continue // stdin is not passed
		}
		b, err := readManifest(cl, f, a.bools["recursive"])
		if err != nil {
			return fileErr(err)
		}
		all, names = append(all, b...), append(names, f)
	}
	for _, f := range a.vals["from-file"] {
		_, p, ok := strings.Cut(f, "=")
		if !ok {
			p = f
		}
		b, err := readFromFile(cl, p)
		if err != nil {
			return fileErr(err)
		}
		all, names = append(all, b...), append(names, p)
	}
	switch len(names) {
	case 0:
	case 1:
		noteApprovalData(cl, "the file "+names[0], all)
	default:
		noteApprovalData(cl, "the files "+strings.Join(names, ", "), all)
	}
	return nil
}

// fileErr is komando's own stop as it is (a file it does not read for an
// agent, also when kctl wrapped it), else PATH_NOT_FOUND.
func fileErr(err error) error {
	var ke *kctlError
	if errors.As(err, &ke) && ke.stop != nil {
		return ke.stop
	}
	var e *out.Error
	if errors.As(err, &e) {
		return e
	}
	return localFileErr("PATH_NOT_FOUND", err, "")
}

// guardUpload is guard for an upload to servers, with what it sends in
// the window (noteUpload).
func guardUpload(cl *call, st *store.State, hosts []*store.Host, local string) error {
	if err := noteUpload(cl, local, nil); err != nil {
		return err
	}
	return Guard(cl, st, hosts, "", true)
}

// guardKubectlRun is cluster run's guard for a kubectl command line, with
// the files it sends in the window (noteKubectlFiles).
func guardKubectlRun(cl *call, st *store.State, c *store.Conn, risk driver.Risk, verb, reason string, args []string) error {
	if err := noteKubectlFiles(cl, args); err != nil {
		return err
	}
	if err := GuardConns(cl, st, []*store.Conn{c}, driver.Verdict{Risk: risk, RuleIDs: []string{"cluster-run"}, Reasons: []string{reason}}); err != nil {
		return execInstead(err, verb)
	}
	return nil
}

// guardRestore is db restore's guard, with the file it sends in the
// window (noteRestoreFile).
func guardRestore(cl *call, st *store.State, c *store.Conn, v driver.Verdict, from string, custom bool, seal *backupSeal) error {
	if err := noteRestoreFile(cl, from, custom, seal); err != nil {
		return err
	}
	return GuardConns(cl, st, []*store.Conn{c}, v)
}
