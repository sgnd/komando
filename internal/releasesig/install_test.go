//go:build !windows

package releasesig

// install.sh checks the same signature as `komando update`: these tests run
// the script itself, with a stand-in curl that serves a release from a
// folder, and with only the checking program under test on PATH.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const installScript = "../../install.sh"

var keysLine = regexp.MustCompile(`(?m)^KEYS="([^"]*)"$`)

func readScript(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(installScript)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// install.sh and `komando update` trust the same keys.
func TestInstallScriptHasTheReleaseKeys(t *testing.T) {
	m := keysLine.FindStringSubmatch(readScript(t))
	if m == nil {
		t.Fatal(`install.sh has no KEYS="..." line`)
	}
	if got := strings.Fields(m[1]); !reflect.DeepEqual(got, Keys) {
		t.Errorf("install.sh KEYS = %q, releasesig.Keys = %q: they must be the same list", got, Keys)
	}
}

var unversionedLine = regexp.MustCompile(`(?m)^UNVERSIONED="([^"]*)"$`)

// install.sh and `komando update` take the same releases as signed before
// the version line.
func TestInstallScriptHasTheUnversionedReleases(t *testing.T) {
	m := unversionedLine.FindStringSubmatch(readScript(t))
	if m == nil {
		t.Fatal(`install.sh has no UNVERSIONED="..." line`)
	}
	if got := strings.Fields(m[1]); !reflect.DeepEqual(got, Unversioned) {
		t.Errorf("install.sh UNVERSIONED = %q, releasesig.Unversioned = %q: they must be the same list", got, Unversioned)
	}
}

// the programs install.sh may use, besides the one that checks a signature
var installTools = []string{"sh", "tar", "gzip", "uname", "tr", "grep", "cut", "awk", "sed", "head", "wc", "cat",
	"mktemp", "rm", "cp", "mv", "chmod", "mkdir", "sha256sum", "shasum", "env", "basename", "dirname"}

// checkers are the programs install.sh can check a signature with; a
// computer needs one of them.
var checkers = []string{"openssl", "perl"}

// canCheck: this computer's copy of the program can check an Ed25519
// signature (macOS's own openssl, LibreSSL, cannot).
func canCheck(checker string) bool {
	p, err := exec.LookPath(checker)
	if err != nil {
		return false
	}
	if checker == "openssl" {
		out, _ := exec.Command(p, "pkeyutl", "-help").CombinedOutput()
		return bytes.Contains(out, []byte("-rawin"))
	}
	return exec.Command(p, "-MMath::BigInt", "-MDigest::SHA", "-MMIME::Base64", "-e", "1").Run() == nil
}

// noChecker skips a test on a computer that cannot check a signature; in
// CI, where one always can, a green run must mean the check ran.
func noChecker(t *testing.T) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatal("neither OpenSSL 3 nor perl with Math::BigInt is here: the signature check was not tested")
	}
	t.Skip("neither OpenSSL 3 nor perl with Math::BigInt is on this computer")
}

type release struct {
	archive []byte
	sums    string
	sig     string // "" = the release has no checksums.txt.sig
}

func archiveFile() string { return "komando_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz" }

// newRelease is a release for this computer whose komando is a script that
// prints mark.
func newRelease(t *testing.T, mark string) release {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("#!/bin/sh\necho " + mark + "\n")
	if err := tw.WriteHeader(&tar.Header{Name: "komando", Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return release{archive: buf.Bytes(), sums: VersionLine("v9.9.9", "2026-11-17") + hex.EncodeToString(sum[:]) + "  " + archiveFile() + "\n"}
}

// runInstall runs script against rel with only checker (and the plain
// tools) on PATH. It returns what the script printed, whether it ended
// well, what it installed ("" = nothing), and its curl command lines.
func runInstall(t *testing.T, script string, rel release, checker string, env ...string) (output string, ok bool, installed, curls string) {
	t.Helper()
	dir := t.TempDir()
	served, bin, dest := filepath.Join(dir, "release"), filepath.Join(dir, "bin"), filepath.Join(dir, "dest")
	for _, d := range []string{served, bin, dest} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(served, archiveFile()), string(rel.archive), 0o644)
	write(filepath.Join(served, "checksums.txt"), rel.sums, 0o644)
	if rel.sig != "" {
		write(filepath.Join(served, "checksums.txt.sig"), rel.sig, 0o644)
	}
	// curl: the last word is the URL, -o names the file; a file the
	// release does not have fails as curl -f does on a 404
	write(filepath.Join(bin, "curl"), `#!/bin/sh
echo "$*" >>"$CURL_LOG"
out=
while [ $# -gt 1 ]; do
  [ "$1" = -o ] && out=$2
  shift
done
[ "${1##*/}" = "${CURL_FAIL:-}" ] && exit 56
[ -n "$out" ] && [ -f "$SERVED/${1##*/}" ] || exit 22
cp "$SERVED/${1##*/}" "$out"
`, 0o755)
	for _, tool := range append(append([]string{}, installTools...), checker) {
		if p, err := exec.LookPath(tool); err == nil {
			if err := os.Symlink(p, filepath.Join(bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
	}
	path := filepath.Join(dir, "install.sh")
	write(path, script, 0o644)
	log := filepath.Join(dir, "curl.log")
	cmd := exec.Command("/bin/sh", path)
	cmd.Env = append([]string{"PATH=" + bin, "HOME=" + dir, "SHELL=/bin/sh", "KOMANDO_INSTALL_DIR=" + dest,
		"SERVED=" + served, "CURL_LOG=" + log, "TMPDIR=" + dir}, env...)
	b, err := cmd.CombinedOutput()
	got, _ := os.ReadFile(filepath.Join(dest, "komando"))
	lines, _ := os.ReadFile(log)
	return string(b), err == nil, string(got), string(lines)
}

// withKey is install.sh trusting pub instead of the project's keys.
func withKey(t *testing.T, pub string) string {
	t.Helper()
	s := readScript(t)
	if !keysLine.MatchString(s) {
		t.Fatal(`install.sh has no KEYS="..." line`)
	}
	return keysLine.ReplaceAllLiteralString(s, `KEYS="`+pub+`"`)
}

func TestInstallScriptChecksTheSignature(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	_, other, _ := NewKey()
	script := withKey(t, pub)
	ran := 0
	for _, checker := range checkers {
		if !canCheck(checker) {
			continue
		}
		ran++
		good := newRelease(t, "good")
		good.sig = sign(t, priv, good.sums)

		// someone who can write the release's files replaces the archive
		// and checksums.txt together; they cannot sign the new one
		replaced := newRelease(t, "replaced")
		replaced.sig = good.sig

		foreign := newRelease(t, "foreign")
		foreign.sig = sign(t, other, foreign.sums)

		unsigned := newRelease(t, "unsigned")

		junk := newRelease(t, "junk")
		junk.sig = "hello\n"

		two := newRelease(t, "two")
		two.sig = sign(t, other, two.sums) + sign(t, priv, two.sums)

		crlf := newRelease(t, "crlf")
		crlf.sig = strings.TrimSuffix(sign(t, priv, crlf.sums), "\n") + "\r\n"

		for _, c := range []struct {
			name    string
			rel     release
			install bool
			say     string // what a refusal must say
		}{
			{"a signed release installs", good, true, ""},
			{"one signature of two is ours", two, true, ""},
			{"Windows line ends", crlf, true, ""},
			{"archive and checksums.txt replaced together", replaced, false, "not signed with the komando project's key"},
			{"signed by another key", foreign, false, "not signed with the komando project's key"},
			{"no signature file", unsigned, false, "has no signature"},
			{"a signature file without a signature", junk, false, "has no signature"},
		} {
			t.Run(checker+"/"+c.name, func(t *testing.T) {
				out, ok, installed, _ := runInstall(t, script, c.rel, checker)
				if c.install {
					if !ok || installed == "" {
						t.Fatalf("not installed (ok=%v):\n%s", ok, out)
					}
					return
				}
				if ok || installed != "" {
					t.Fatalf("installed %q (ok=%v), want a refusal:\n%s", installed, ok, out)
				}
				if !strings.Contains(out, c.say) || !strings.Contains(out, "nothing was installed") {
					t.Errorf("the refusal does not say %q and \"nothing was installed\":\n%s", c.say, out)
				}
			})
		}
	}
	if ran == 0 {
		noChecker(t)
	}
}

// The project's real key and a real release's files: every checker accepts
// the signature of v0.14.1's checksums.txt (the stand-in archive then fails
// the checksum, one step later), and refuses it after one changed byte.
func TestInstallScriptAcceptsARealRelease(t *testing.T) {
	sums, err := os.ReadFile("testdata/v0.14.1/checksums.txt")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile("testdata/v0.14.1/checksums.txt.sig")
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(sums, sig); err != nil {
		t.Fatalf("testdata: %v", err)
	}
	script := readScript(t)
	ran := 0
	for _, checker := range checkers {
		if !canCheck(checker) {
			continue
		}
		ran++
		t.Run(checker, func(t *testing.T) {
			rel := newRelease(t, "stand-in")
			rel.sums, rel.sig = string(sums), string(sig)
			// signed before the version line: it installs by version only
			out, ok, installed, _ := runInstall(t, script, rel, checker, "KOMANDO_VERSION=v0.14.1")
			if ok || installed != "" {
				t.Fatalf("installed a stand-in archive:\n%s", out)
			}
			if !strings.Contains(out, "does not match checksums.txt") || strings.Contains(out, "signature") && strings.Contains(out, "not signed") {
				t.Errorf("want the signature accepted and the checksum refused:\n%s", out)
			}

			rel.sums = strings.Replace(string(sums), "a", "b", 1)
			out, ok, installed, _ = runInstall(t, script, rel, checker, "KOMANDO_VERSION=v0.14.1")
			if ok || installed != "" || !strings.Contains(out, "not signed with the komando project's key") {
				t.Errorf("a changed checksums.txt was not refused for its signature (ok=%v):\n%s", ok, out)
			}
		})
	}
	if ran == 0 {
		noChecker(t)
	}
}

// A computer with no program to check a signature installs nothing.
func TestInstallScriptWithoutAChecker(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	rel := newRelease(t, "good")
	rel.sig = sign(t, priv, rel.sums)
	out, ok, installed, _ := runInstall(t, withKey(t, pub), rel, "no-such-program")
	if ok || installed != "" {
		t.Fatalf("installed without checking the signature:\n%s", out)
	}
	if !strings.Contains(out, "OpenSSL") || !strings.Contains(out, "perl") || !strings.Contains(out, "nothing was installed") {
		t.Errorf("the refusal does not name OpenSSL and perl:\n%s", out)
	}
}

// Releases up to 0.13.0 were never signed. install.sh knows the checksums.txt
// each of them was released with, and installs one, asked for by version,
// only with exactly that file: nobody can put other files in its place.
func TestInstallScriptOldReleases(t *testing.T) {
	sums, err := os.ReadFile("testdata/v0.13.0/checksums.txt")
	if err != nil {
		t.Fatal(err)
	}
	script := readScript(t)
	for _, version := range []string{"v0.13.0", "0.13.0"} {
		t.Run("the release's own checksums.txt, "+version, func(t *testing.T) {
			rel := newRelease(t, "stand-in")
			rel.sums = string(sums)
			out, ok, installed, _ := runInstall(t, script, rel, "no-such-program", "KOMANDO_VERSION="+version)
			if ok || installed != "" {
				t.Fatalf("installed a stand-in archive:\n%s", out)
			}
			// accepted as 0.13.0's file; the stand-in archive then fails the checksum
			if !strings.Contains(out, "does not match checksums.txt") || !strings.Contains(out, "has no signature (releases up to 0.13.0 have none)") {
				t.Errorf("want the old release's checksums.txt accepted, with a note, and the archive refused:\n%s", out)
			}
		})
	}
	t.Run("another checksums.txt", func(t *testing.T) {
		out, ok, installed, _ := runInstall(t, script, newRelease(t, "replaced"), "no-such-program", "KOMANDO_VERSION=v0.13.0")
		if ok || installed != "" {
			t.Fatalf("installed replaced files as 0.13.0:\n%s", out)
		}
		if !strings.Contains(out, "not the checksums.txt komando 0.13.0 was released with") || !strings.Contains(out, "nothing was installed") {
			t.Errorf("the refusal:\n%s", out)
		}
	})
	// no release of these versions was made unsigned: they need a signature
	for _, version := range []string{"v0.13.1", "v0.14.0", "v1.0.0", "v0.9.9", "v0.12.99", "v0.13.0-rc1", "v0.13", "v0.13.0.1", "v00.13.0", ""} {
		t.Run("needs a signature: "+version, func(t *testing.T) {
			var env []string
			if version != "" {
				env = append(env, "KOMANDO_VERSION="+version)
			}
			out, ok, installed, _ := runInstall(t, script, newRelease(t, "unsigned"), "no-such-program", env...)
			if ok || installed != "" || !strings.Contains(out, "has no signature") || !strings.Contains(out, "nothing was installed") {
				t.Fatalf("ok=%v installed=%q, want a refusal for the missing signature:\n%s", ok, installed, out)
			}
		})
	}
}

// Nothing in the environment but KOMANDO_VERSION picks the version: a
// variable named v, left there by something else, once made the newest
// release pass as an old, unsigned one.
func TestInstallScriptIgnoresStrayVariables(t *testing.T) {
	out, ok, installed, curls := runInstall(t, readScript(t), newRelease(t, "unsigned"), "no-such-program", "v=v0.13.0")
	if ok || installed != "" || !strings.Contains(out, "has no signature") {
		t.Fatalf("ok=%v installed=%q, want a refusal for the missing signature:\n%s", ok, installed, out)
	}
	if !strings.Contains(curls, "/releases/latest/download/") || strings.Contains(curls, "v0.13.0") {
		t.Errorf("not the newest release: curl %s", curls)
	}
}

// A version that is not a version is refused before anything is downloaded
// (a path in it could name another project's release).
func TestInstallScriptRefusesAVersionWithAPath(t *testing.T) {
	for _, version := range []string{"v0.13.0/../../../../other/repo/releases/download/v1", "v0.14.1?x", "v0.14.1 x", ".."} {
		out, ok, installed, curls := runInstall(t, readScript(t), newRelease(t, "x"), "no-such-program", "KOMANDO_VERSION="+version)
		if ok || installed != "" || curls != "" || !strings.Contains(out, "is not a komando version") {
			t.Errorf("KOMANDO_VERSION=%q: ok=%v, downloads %q:\n%s", version, ok, curls, out)
		}
	}
}

// A signature that could not be downloaded (the connection, not a missing
// file) is a download problem, not a sign that files were replaced.
func TestInstallScriptSignatureDownloadFails(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	rel := newRelease(t, "good")
	rel.sig = sign(t, priv, rel.sums)
	out, ok, installed, _ := runInstall(t, withKey(t, pub), rel, "no-such-program", "CURL_FAIL=checksums.txt.sig")
	if ok || installed != "" || !strings.Contains(out, "Could not download") || strings.Contains(out, "replaced") {
		t.Errorf("ok=%v installed=%q:\n%s", ok, installed, out)
	}
}

// What the script makes while it works is inside TMPDIR and gone afterwards.
func TestInstallScriptCleansUp(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	rel := newRelease(t, "good")
	rel.sig = sign(t, priv, rel.sums)
	tmp := t.TempDir()
	out, ok, _, _ := runInstall(t, withKey(t, pub), rel, "perl", "TMPDIR="+tmp)
	if !canCheck("perl") {
		t.Skip("no perl with Math::BigInt here")
	}
	if !ok {
		t.Fatalf("not installed:\n%s", out)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("left in TMPDIR: %v", left)
	}
}

// Every download is HTTPS only, redirects included.
func TestInstallScriptDownloadsOverHTTPSOnly(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	rel := newRelease(t, "good")
	rel.sig = sign(t, priv, rel.sums)
	_, _, _, curls := runInstall(t, withKey(t, pub), rel, "perl")
	lines := strings.Split(strings.TrimSpace(curls), "\n")
	if len(lines) < 3 {
		t.Fatalf("want three downloads (archive, checksums.txt, checksums.txt.sig), got:\n%s", curls)
	}
	for _, l := range lines {
		if !strings.Contains(l, "--proto =https") || !strings.Contains(l, "--proto-redir =https") || !strings.Contains(l, " https://github.com/sgnd/komando/releases/") {
			t.Errorf("a download that is not HTTPS only: curl %s", l)
		}
	}
}

// The signature covers checksums.txt's version line: a signed release
// installs only as the version it names (C114).
func TestInstallScriptChecksTheVersionLine(t *testing.T) {
	pub, priv, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	script := withKey(t, pub)
	ran := 0
	for _, checker := range checkers {
		if !canCheck(checker) {
			continue
		}
		ran++
		named := func(line string) release {
			r := newRelease(t, "rel")
			_, rest, _ := strings.Cut(r.sums, "\n")
			r.sums = line + rest
			r.sig = sign(t, priv, r.sums)
			return r
		}
		for _, c := range []struct {
			name    string
			rel     release
			version string
			install bool
			say     string
		}{
			{"the newest, named", named(VersionLine("v0.15.0", "2026-11-20")), "", true, "Installing komando 0.15.0 (released 2026-11-20)"},
			{"the version asked for", named(VersionLine("v0.15.0", "2026-11-20")), "v0.15.0", true, ""},
			{"an older release under a newer tag", named(VersionLine("v0.14.9", "2026-11-14")), "v0.16.0", false, "The release under v0.16.0 holds komando v0.14.9"},
			{"the newest without the line", named(""), "", false, "does not name its version, though every release after v0.14.1 does"},
			{"a newer tag without the line", named(""), "v0.16.0", false, "does not name its version"},
			{"signed before the line, by version", named(""), "v0.14.1", true, ""},
		} {
			t.Run(checker+"/"+c.name, func(t *testing.T) {
				var env []string
				if c.version != "" {
					env = append(env, "KOMANDO_VERSION="+c.version)
				}
				out, ok, installed, _ := runInstall(t, script, c.rel, checker, env...)
				if c.install != (ok && installed != "") {
					t.Fatalf("ok=%v installed=%q, want install %v:\n%s", ok, installed, c.install, out)
				}
				if !strings.Contains(out, c.say) || !c.install && !strings.Contains(out, "nothing was installed") {
					t.Errorf("the output does not say %q:\n%s", c.say, out)
				}
			})
		}
	}
	if ran == 0 {
		noChecker(t)
	}
}
