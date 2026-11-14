// Package boundary checks the paid boundary (docs/design/principles.md,
// section 15, rule 4) in go test: the komando binary never links the sync
// library or a Komando Cloud client, and its code names no komando-owned
// web address except the release site. Plan and account checks live in
// Komando Cloud and the apps, never in komando.
package boundary

import (
	"bytes"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
)

const root = "../.."

// syncModule is the sync library: a public Go module of its own in the
// sync/ folder of this repository. The binary links no package of it.
const syncModule = "github.com/sgnd/komando/sync"

// forbidden says why the binary may not link the package at path, or ""
// when it may. Each part of the path is compared after lower-casing it and
// dropping "-", "_" and ".", so komando-cloud, komando_cloud and
// KomandoCloud are the same word. The words are narrow on purpose:
//   - "cloud" alone is not one of them. internal/cloud is komando's own
//     client for AWS, Google Cloud and Azure, the person's own clouds.
//   - "sync" alone is not one either: it is Go's standard sync package.
func forbidden(path string) string {
	if path == syncModule || strings.HasPrefix(path, syncModule+"/") {
		return "the sync library"
	}
	for _, part := range strings.Split(path, "/") {
		w := strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(part))
		switch {
		case strings.Contains(w, "komandocloud"):
			return "a Komando Cloud client"
		case w == "cloudsync" || w == "syncclient":
			return "a sync client"
		case w == "syncproto":
			// the sync prototype, until it moves into the sync library
			return "the sync prototype"
		}
	}
	return ""
}

// The binary is built for these systems; each links its own set of packages.
var systems = []string{"linux", "darwin", "windows"}

// TestBinaryLinksNoPaidCode lists every package cmd/komando links, on each
// system, and fails on the sync library or a Komando Cloud client.
func TestBinaryLinksNoPaidCode(t *testing.T) {
	gobin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the go tool is not on PATH, so the packages of cmd/komando cannot be listed")
	}
	for _, goos := range systems {
		cmd := exec.Command(gobin, "list", "-deps", "-f", `{{.ImportPath}} {{join .Imports " "}}`, "./cmd/komando")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		outb, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list -deps ./cmd/komando (GOOS=%s): %v\n%s", goos, err, stderr.String())
		}
		importers := map[string][]string{}
		var pkgs []string
		for _, line := range strings.Split(strings.TrimSpace(string(outb)), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			pkgs = append(pkgs, f[0])
			for _, imp := range f[1:] {
				importers[imp] = append(importers[imp], f[0])
			}
		}
		if !contains(pkgs, "github.com/sgnd/komando/internal/cli") {
			t.Fatalf("GOOS=%s: go list did not list internal/cli; the listing is broken", goos)
		}
		for _, p := range pkgs {
			if why := forbidden(p); why != "" {
				by := importers[p]
				sort.Strings(by)
				t.Errorf("GOOS=%s: cmd/komando links %s (%s), imported by %s. "+
					"The komando binary never links the sync library or a Komando Cloud client "+
					"(docs/design/principles.md, the paid boundary). Remove the import. "+
					"If komando must help a paid service, give it a neutral capability instead: "+
					"an open format, a signature check or a local socket.",
					goos, p, why, strings.Join(by, ", "))
			}
		}
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// TestForbiddenPaths keeps the words of forbidden narrow: komando's own
// cloud clients and Go's sync package pass, the paid code does not.
func TestForbiddenPaths(t *testing.T) {
	for path, want := range map[string]bool{
		"sync":                                   false,
		"sync/atomic":                            false,
		"github.com/sgnd/komando/internal/cloud": false,
		"github.com/sgnd/komando/internal/sealfile":     false,
		"github.com/sgnd/komando/syncer":                false,
		"github.com/sgnd/komando/sync":                  true,
		"github.com/sgnd/komando/sync/merge":            true,
		"github.com/sgnd/komando/internal/syncproto":    true,
		"github.com/sgnd/komando/internal/komandocloud": true,
		"example.com/komando-cloud/api":                 true,
		"example.com/Komando_Cloud":                     true,
		"example.com/cloud-sync/client":                 true,
	} {
		if got := forbidden(path) != ""; got != want {
			t.Errorf("forbidden(%q) = %v, want %v", path, got, want)
		}
	}
}
