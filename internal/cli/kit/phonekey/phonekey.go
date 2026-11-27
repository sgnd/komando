// Package phonekey holds what `credential key install --public-key-file`
// (C372) checks and writes: a device's public key line for a user on a
// server, always behind komando's gate in server mode (option C of the
// U107 design). The cli runs the scripts; every value is checked here
// first, and none is ever spliced into a shell script's text.
package phonekey

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/engine"
)

// Key is a device's public key.
type Key struct {
	Type        string // ecdsa-sha2-nistp256
	Data        string // the key, base64
	Name        string // the key file's comment: the gate's --name
	Fingerprint string // SHA256:...
}

// maxFile is the most a public key file holds.
const maxFile = 16 << 10

// minRSABits is the smallest RSA key komando accepts (key.go's rule).
const minRSABits = 3072

// keyTypes are the key types a device key may have: no DSA, no
// certificate.
var keyTypes = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256, ssh.KeyAlgoRSA}

// Parse reads a public key file: exactly one key line, no options, no
// private key, its comment a key name (engine.GateLabel).
func Parse(b []byte) (Key, error) {
	if len(b) > maxFile {
		return Key{}, fmt.Errorf("the file is %d bytes; a public key file holds one line", len(b))
	}
	text := string(b)
	if strings.Contains(text, "PRIVATE KEY") {
		return Key{}, errors.New("this is a private key; give the .pub file, the public key")
	}
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) != 1 {
		return Key{}, fmt.Errorf("the file has %d lines; give a file with exactly one public key line", len(lines))
	}
	pub, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(lines[0]))
	switch {
	case err != nil:
		return Key{}, errors.New("not an SSH public key line (TYPE KEY NAME)")
	case len(options) > 0:
		return Key{}, fmt.Errorf("the line has options (%s); give the key alone, komando writes the options", strings.Join(options, ","))
	case len(rest) > 0:
		return Key{}, errors.New("the file has more than one key")
	case !slices.Contains(keyTypes, pub.Type()):
		return Key{}, fmt.Errorf("a %s key is not taken for a device; use ecdsa-sha2-nistp256 or ssh-ed25519", pub.Type())
	}
	if ck, ok := pub.(ssh.CryptoPublicKey); ok {
		if r, ok := ck.CryptoPublicKey().(*rsa.PublicKey); ok && r.N.BitLen() < minRSABits {
			return Key{}, fmt.Errorf("an RSA key of %d bits is too weak; komando takes %d bits or more", r.N.BitLen(), minRSABits)
		}
	}
	f := strings.Fields(lines[0])
	if len(f) != 3 || !engine.GateLabel.MatchString(comment) {
		return Key{}, errors.New("the key's comment names it on the server: one word of 1 to 64 letters, digits, dots, dashes or underscores (komando-phone-DEVICE)")
	}
	// the line carries the parsed key, never the file's text
	typ, data, _ := strings.Cut(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), " ")
	return Key{Type: typ, Data: data, Name: comment, Fingerprint: ssh.FingerprintSHA256(pub)}, nil
}

// UserName is a user name komando writes a key for: letters, digits, dot,
// dash and underscore, starting with a letter or underscore.
var UserName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]{0,31}$`)

// hostPattern is one from= host pattern: a name with * and ? wildcards.
var hostPattern = regexp.MustCompile(`^[A-Za-z0-9.*?:-]+$`)

// CheckAddress checks a from= value: addresses, networks (CIDR) and host
// patterns, comma-separated. Nothing in it can end the quoted option. It
// says whether a host pattern is in it: sshd matches one only with UseDNS
// yes, which is not its default.
func CheckAddress(s string) (hostnames bool, err error) {
	if s == "" || len(s) > 512 {
		return false, errors.New("--from-address takes 1 to 512 characters")
	}
	for _, item := range strings.Split(s, ",") {
		switch {
		case net.ParseIP(item) != nil:
		case strings.Contains(item, "/"):
			if _, _, err := net.ParseCIDR(item); err != nil {
				return false, fmt.Errorf("%q is no network (ADDRESS/BITS)", item)
			}
		case hostPattern.MatchString(item):
			hostnames = true
		default:
			return false, fmt.Errorf("%q is no address, network or host pattern (letters, digits, . - : * ?)", item)
		}
	}
	return hostnames, nil
}

// Line is the authorized_keys line for k: always restrict, always the
// server's own gate in server mode with the key's name, and from= when
// from is given. komando and from are checked before (Facts.Refusal,
// CheckAddress), so nothing in them needs escaping.
func Line(komando string, k Key, from string) string {
	opts := `restrict,command="` + komando + ` ssh-gate --here --name ` + k.Name + `"`
	if from != "" {
		opts += `,from="` + from + `"`
	}
	return opts + " " + k.Type + " " + k.Data + " " + k.Name
}

// Facts are what the probe script found on the server.
type Facts struct {
	NoUser   bool
	UID      string // the user's, by id -u
	Home     string // the user's home
	Login    string // who komando logs in as
	Komando  string // komando's path, symlinks resolved ("" when none)
	Stats    []Stat // the binary and each folder above it, up to /
	PathDirs []Stat // each folder of PathDirs that exists (stat -L)
	Gate     bool   // that komando has the server mode
	Syslog   bool   // the server has a system log the gate writes to
}

// Stat is one path's owner and mode.
type Stat struct{ UID, Mode, Path string }

// ParseFacts reads the probe script's output.
func ParseFacts(s string) Facts {
	var f Facts
	for _, line := range strings.Split(s, "\n") {
		k, v, _ := strings.Cut(strings.TrimRight(line, "\r"), " ")
		switch k {
		case "user":
			f.NoUser = v == "none"
		case "uid":
			f.UID = v
		case "home":
			f.Home = v
		case "login":
			f.Login = v
		case "komando":
			if v != "none" {
				f.Komando = v
			}
		case "stat":
			if p := strings.SplitN(v, " ", 3); len(p) == 3 {
				f.Stats = append(f.Stats, Stat{p[0], p[1], p[2]})
			}
		case "pathdir":
			if p := strings.SplitN(v, " ", 3); len(p) == 3 {
				f.PathDirs = append(f.PathDirs, Stat{p[0], p[1], p[2]})
			}
		case "gate":
			f.Gate = v == "yes"
		case "syslog":
			f.Syslog = v == "yes"
		}
	}
	return f
}

// safePath is a path the line names without quoting.
var safePath = regexp.MustCompile(`^/[A-Za-z0-9/._+-]+$`)

// Refusal says why komando writes no line for user from these facts: an
// error code and the reason, or "". Rule b: the gate's binary is one the
// user cannot replace.
func (f Facts) Refusal(user string) (code, why string) {
	switch {
	case f.NoUser:
		return "KEY_USER_INVALID", "there is no user " + user + " on the server"
	case f.UID == "0":
		return "KEY_USER_INVALID", user + " has uid 0 (root): a device's key never logs in as root, whatever the name"
	case f.UID == "" || strings.Trim(f.UID, "0123456789") != "":
		return "KEY_USER_INVALID", "the server did not tell " + user + "'s uid"
	case f.Komando == "":
		return "KOMANDO_MISSING", "komando is not installed on the server; install it there (owned by root, outside the home), then run this again"
	case !safePath.MatchString(f.Komando) || strings.Contains(f.Komando, "/../"):
		return "GATE_BINARY_INVALID", "komando's path on the server (" + f.Komando + ") has characters the line cannot hold; install it under a plain path such as /usr/local/bin"
	case f.Home == "" || f.Komando == f.Home || strings.HasPrefix(f.Komando, strings.TrimSuffix(f.Home, "/")+"/"):
		return "GATE_BINARY_INVALID", "komando on the server is " + f.Komando + ", inside " + user + "'s home, which " + user + " can replace; install it outside the home, owned by root"
	}
	if why := f.ownedByRoot(); why != "" {
		return "GATE_BINARY_INVALID", why + "; the gate must be a program " + user + " cannot replace (owned by root, not group or world writable, every folder above it the same)"
	}
	if len(f.PathDirs) == 0 {
		return "GATE_BINARY_INVALID", "komando could not check the folders of the gate's PATH (" + strings.Join(PathDirs, " ") + ")"
	}
	for _, d := range f.PathDirs {
		if why := rootOnly(d); why != "" {
			return "GATE_BINARY_INVALID", why + ": a program " + user + " put there would run as " + user + " at the gate's next command"
		}
	}
	if !f.Gate {
		return "GATE_UNSUPPORTED", "komando on the server has no server mode (ssh-gate --here); update it there, then run this again"
	}
	return "", ""
}

// ownedByRoot says why the binary or a folder above it could be replaced
// by someone other than root, or "". Every one up to / must be listed.
func (f Facts) ownedByRoot() string {
	want := f.Komando
	for _, s := range f.Stats {
		if s.Path != want {
			break
		}
		if why := rootOnly(s); why != "" {
			return why
		}
		if want == "/" {
			return ""
		}
		want = filepath.Dir(want)
	}
	return "komando could not check " + want + " and the folders above it"
}

// rootOnly says why someone other than root could change s, or "".
func rootOnly(s Stat) string {
	mode, err := strconv.ParseUint(s.Mode, 8, 32)
	switch {
	case err != nil || s.UID == "?":
		return "komando could not check " + s.Path
	case s.UID != "0":
		return s.Path + " is owned by uid " + s.UID + ", not root"
	case mode&0o022 != 0:
		return s.Path + " is group or world writable (mode " + s.Mode + ")"
	}
	return ""
}
