package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/store"
)

// `komando update`: replace this komando with a release from GitHub. The
// download (update_fetch.go) is checked like install.sh checks it, and put
// in place by update_install.go.

// releasePlatforms are the archives a release has (Makefile, PLATFORMS;
// a test keeps the two the same).
var releasePlatforms = map[string]bool{
	"linux/amd64": true, "linux/arm64": true, "darwin/amd64": true, "darwin/arm64": true,
	"windows/amd64": true, "windows/arm64": true,
}

// asRoot reports whether komando runs as root (sudo komando update).
// Tests pretend.
var asRoot = func() bool { return os.Geteuid() == 0 }

type updateResult struct {
	Path    string `json:"path"`           // the komando program that was (or would be) replaced
	From    string `json:"from"`           // the version that ran
	To      string `json:"to"`             // the newest release, or the version asked for
	Action  string `json:"action"`         // updated | downgraded | unchanged
	Release string `json:"release"`        // the release page: what changed
	Next    string `json:"next,omitempty"` // what to run after an update
	newest  bool   // To is the newest release (no version was asked for)
}

func (r updateResult) Text() string {
	var b strings.Builder
	switch {
	case r.Action == "unchanged" && r.newest && r.From != r.To:
		fmt.Fprintf(&b, "komando %s is newer than the newest release (%s)\n", r.From, r.To)
	case r.Action == "unchanged" && r.newest:
		fmt.Fprintf(&b, "komando %s is the newest version\n", r.From)
	case r.Action == "unchanged":
		fmt.Fprintf(&b, "komando %s is already installed\n", r.From)
	case r.Action == "downgraded" && g.dryRun:
		fmt.Fprintf(&b, "would go back to komando %s (from %s)\n", r.To, r.From)
	case r.Action == "downgraded":
		fmt.Fprintf(&b, "went back to komando %s (was %s)\n", r.To, r.From)
	case g.dryRun:
		fmt.Fprintf(&b, "would update komando %s → %s\n", r.From, r.To)
	default:
		fmt.Fprintf(&b, "updated komando %s → %s\n", r.From, r.To)
	}
	if r.Action == "unchanged" {
		return b.String()
	}
	fmt.Fprintf(&b, "  %s\n", r.Path)
	fmt.Fprintf(&b, "what changed: %s\n", r.Release)
	if r.Next != "" {
		fmt.Fprintf(&b, "next: %s\n", r.Next)
	}
	return b.String()
}

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update [VERSION]",
		Short: "Update komando to the newest release",
		Long: `Replaces this komando program with the newest release from GitHub, or with
the VERSION you name. Like the install line, it checks the download against
checksums.txt from the same release, and it tries the new program before it
replaces the old one. If anything fails, the old komando stays as it was.

See whether there is a newer version, changing nothing: komando update --dry-run.

komando lives in a folder only root may change (/usr/local/bin, for example)?
Then run it with sudo: sudo komando update. As root it writes nothing in
~/.komando; otherwise the update goes into the audit log like other changes.

Going back to an older version needs a person's yes (--yes for an agent): an
older komando may lack safety checks this one has. Without a VERSION it
never goes back.

A komando built from source that is not a release (make build, or go build
of a commit between releases) is not replaced: build it again instead. One
that reports a release version (go install ...@v0.12.0, or go build at a
release tag) counts as that release and is replaced. --timeout limits the
whole update (default 10m).`,
		Example: `  komando update --dry-run    # is there a newer version?
  komando update              # install the newest release
  sudo komando update         # komando is in /usr/local/bin
  komando update v0.6.0       # install this version`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			want := ""
			if len(args) == 1 {
				want = args[0]
			}
			r, err := runUpdate(cmd.Context(), want)
			if err != nil {
				return updateErr(err)
			}
			out.P.Print("update", r, nil)
			return nil
		},
	}
}

// updateErr is komando's error for a failed update: a timeout or Ctrl-C
// says that nothing changed (the rename is the last step).
func updateErr(err error) error {
	e := toErr(err)
	switch e.Code {
	case "TIMEOUT":
		e.Message = "the update took longer than " + strings.TrimSuffix(updateTimeout().String(), "0s")
		e.Hint = "nothing was changed; give it more time: komando update --timeout 30m"
	case "CANCELLED":
		e.Hint = "nothing was changed"
	}
	return e
}

// runUpdate decides what to install, checks that it may, and installs it.
func runUpdate(ctx context.Context, want string) (updateResult, error) {
	exe, err := updatable()
	if err != nil {
		return updateResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout())
	defer cancel()
	r := updateResult{Path: exe, From: Version, newest: want == "" || want == "latest"}
	if r.To, err = pickVersion(ctx, want); err != nil {
		return r, err
	}
	r.Release = releaseSite + "/releases/tag/" + r.To
	c := compareVersions(r.To, r.From)
	if c == 0 || c < 0 && r.newest { // only a VERSION named goes back
		r.Action = "unchanged"
		return r, nil
	}
	r.Action = "updated"
	if c < 0 {
		r.Action = "downgraded"
	}
	// before asking anything: the release exists and has this computer's archive
	sums, err := releaseSums(ctx, r.To)
	if err != nil {
		return r, err
	}
	if err := checkWritable(exe, want); err != nil {
		if !g.dryRun {
			return r, err
		}
		out.P.WouldBlock(err)
	}
	if c < 0 {
		if err := guardSafety("going back to the older komando " + r.To + " (it may lack this version's safety checks)"); err != nil {
			return r, err
		}
	}
	if g.dryRun {
		return r, nil
	}
	err = installRelease(ctx, r.To, exe, sums)
	auditUpdate(r, err)
	if err != nil {
		return r, err
	}
	r.Next = nextAfterUpdate()
	return r, nil
}

// updatable is the komando file to replace, once it is clear that update
// can replace it at all.
func updatable() (string, error) {
	if !releasePlatforms[platform()] {
		return "", out.Errf(out.ExitConflict, "UNSUPPORTED_PLATFORM", "build komando from source: https://github.com/sgnd/komando#install",
			"there is no komando release for %s", platform())
	}
	if !isReleaseTag(Version) {
		return "", out.Errf(out.ExitConflict, "SOURCE_BUILD", "build it again (git pull, then make build), or install a release with the install line: https://github.com/sgnd/komando#install",
			"this komando was built from source (version %s), so update does not replace it", Version)
	}
	exe, err := selfPath()
	if err != nil {
		return "", out.Errf(out.ExitError, "SELF_NOT_FOUND", "run komando by its full path, e.g. /usr/local/bin/komando update",
			"cannot find the komando program that is running: %v", err)
	}
	return exe, nil
}

func platform() string { return runtime.GOOS + "/" + runtime.GOARCH }

// pickVersion is the version asked for (v added when missing), or the
// newest release for none or "latest".
func pickVersion(ctx context.Context, want string) (string, error) {
	if want == "" || want == "latest" {
		return newestRelease(ctx)
	}
	v := want
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !isReleaseTag(v) {
		return "", out.Usage("%q is not a komando version; name one like v0.6.0, or leave it out for the newest", want)
	}
	return v, nil
}

func updateTimeout() time.Duration {
	if g.timeout > 0 {
		return g.timeout
	}
	return 10 * time.Minute // the archives can be slow to download
}

// selfPath is the file of the running komando, symlinks resolved: that file
// is the one to replace. Tests point it at a copy.
var selfPath = func() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}

// releaseTag is a version komando's releases use: v1.2.3, or v1.2.3-rc.1.
// `make build` versions (v0.6.0-3-g975c9e7, -dirty) and dev are not.
var releaseTag = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.?(\d+))?$`)

func isReleaseTag(v string) bool { return releaseTag.MatchString(v) }

// compareVersions orders two release tags: -1, 0 or 1. A pre-release comes
// before its release (v1.0.0-rc.1 < v1.0.0).
func compareVersions(a, b string) int {
	pa, pb := releaseTag.FindStringSubmatch(a), releaseTag.FindStringSubmatch(b)
	if pa == nil || pb == nil {
		return strings.Compare(a, b)
	}
	for i := 1; i <= 3; i++ {
		if c := compareNum(pa[i], pb[i]); c != 0 {
			return c
		}
	}
	switch {
	case pa[4] == pb[4]:
		return compareNum(pa[5], pb[5])
	case pa[4] == "": // a release, b a pre-release
		return 1
	case pb[4] == "":
		return -1
	}
	return strings.Compare(pa[4], pb[4]) // alpha < beta < rc
}

func compareNum(a, b string) int {
	x, _ := strconv.Atoi(a)
	y, _ := strconv.Atoi(b)
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

// checkWritable checks that komando may replace exe: that needs a new file
// in its folder.
func checkWritable(exe, want string) *out.Error {
	dir := filepath.Dir(exe)
	f, err := os.CreateTemp(dir, ".komando-update-*")
	if err == nil {
		name := f.Name()
		_ = f.Close()
		_ = os.Remove(name)
		return nil
	}
	why := err
	var pe *fs.PathError
	if errors.As(err, &pe) {
		why = pe.Err // "read-only file system", not the temporary name
	}
	if !errors.Is(err, fs.ErrPermission) || os.Geteuid() == 0 {
		return out.Errf(out.ExitConflict, "NOT_WRITABLE", "nothing was changed; make "+dir+" writable, or install komando in another folder with the install line (KOMANDO_INSTALL_DIR=DIR)",
			"cannot replace %s: %s: %v", exe, dir, why)
	}
	line := "sudo " + shellQuote(exe) + " update" // sudo's PATH may find another komando, or none
	if want != "" {
		line += " " + shellQuote(want)
	}
	hint := "run `" + line + "`"
	if isAgent() {
		hint = "ask the user to run `" + line + "` in their own terminal: it needs their password"
	}
	who := "you may not write to " + dir
	if o := folderOwner(dir); o != "" {
		if u, err := user.Current(); err != nil || u.Username != o {
			who = "only " + o + " may write to " + dir
		}
	}
	return out.Errf(out.ExitConflict, "NOT_WRITABLE", hint, "cannot replace %s: %s", exe, who)
}

// folderOwner is the name of the user who owns dir, or "".
func folderOwner(dir string) string {
	fi, err := os.Stat(dir)
	if err != nil {
		return ""
	}
	uid, _, ok := fileOwner(fi)
	if !ok {
		return ""
	}
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		return u.Username
	}
	return ""
}

// nextAfterUpdate reminds a person that the skill AI agents read comes with
// komando, so it changes with the version.
func nextAfterUpdate() string {
	if asRoot() {
		return "komando guide install, without sudo (gives your AI agents this version's skill)"
	}
	return "komando guide install (gives your AI agents this version's skill)"
}

// auditUpdate records an update that ran, as other changes are recorded.
// As root it records nothing: root must not write in a person's ~/.komando
// (root.go, leavesHome).
func auditUpdate(r updateResult, err error) {
	if asRoot() {
		return
	}
	st, lerr := store.Load()
	if lerr != nil {
		st = nil // recorded anyway
	}
	extra := map[string]any{"from": r.From, "to": r.To, "action": r.Action, "path": r.Path}
	if err != nil {
		extra["error"] = toErr(err).Code
	}
	audit(st, "update", nil, "", err == nil, extra)
}
