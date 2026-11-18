// Package releasesig signs a komando release and checks that signature.
//
// The release workflow signs checksums.txt with komando's private key (a
// GitHub secret) and publishes the signature as checksums.txt.sig.
// `komando update` checks it with the public keys built into komando, so a
// release whose files someone replaced (archives and checksums.txt
// together) is refused: checksums.txt alone shows only that the files
// belong together, not who made them.
//
// A key is 32 bytes, written in base64 (standard, with padding). The
// private key is the Ed25519 seed. checksums.txt.sig has one base64
// signature per line; a release signed by two keys (while the key is
// being changed) has two lines.
package releasesig

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// File is the name of the signature next to checksums.txt in a release.
const File = "checksums.txt.sig"

// MaxSize is the most komando reads of a signature file: a few lines.
const MaxSize = 4 << 10

// Keys are the public keys whose signature komando accepts. To change the
// key, add the new one here, release that komando signed with the old
// key, then sign later releases with the new key (and both, for a while,
// so a komando that knows only the old key still updates).
var Keys = []string{
	"GO75zZSPgMzciJXLqfbDrefUFaNQo3sfAZJx1NWxv2k=", // 2026-11-14, the first release key
}

var (
	// ErrNoKeys means this komando was built without a public key.
	ErrNoKeys = errors.New("this komando has no public key to check a release with")
	// ErrNotSigned means no line of the signature file is a signature.
	ErrNotSigned = errors.New("the signature file holds no signature")
	// ErrBadSignature means no signature matches a key komando knows.
	ErrBadSignature = errors.New("no signature matches komando's public key")
)

// Verify checks that one line of sig is a signature of sums by one of
// Keys.
func Verify(sums, sig []byte) error {
	keys, err := publicKeys(Keys)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return ErrNoKeys
	}
	found := false
	for _, line := range strings.Split(string(sig), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		s, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(s) != ed25519.SignatureSize {
			continue // not a signature: maybe a newer format's line
		}
		found = true
		for _, k := range keys {
			if ed25519.Verify(k, sums, s) {
				return nil
			}
		}
	}
	if !found {
		return ErrNotSigned
	}
	return ErrBadSignature
}

func publicKeys(list []string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, k := range list {
		b, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("built-in public key %q is not a base64 Ed25519 key", k)
		}
		keys = append(keys, ed25519.PublicKey(b))
	}
	return keys, nil
}

// NewKey makes a key pair: the public key (for Keys) and the private key
// (for the release workflow's secret), both base64.
func NewKey() (public, private string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv.Seed()), nil
}

// PublicOf is the public key of a private key.
func PublicOf(private string) (string, error) {
	k, err := privateKey(private)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey)), nil
}

// Sign is one line of checksums.txt.sig: the signature of sums by the
// private key, base64, with a line end.
func Sign(private string, sums []byte) (string, error) {
	k, err := privateKey(private)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k, sums)) + "\n", nil
}

func privateKey(private string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(private))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the private key is not a base64 Ed25519 key (44 characters)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// The version line: the first line of checksums.txt names the release,
// "komando-release v0.15.0 2026-11-20" (its tag and the day it was made),
// so the signature covers the version too. Older komando versions and
// install.sh read only lines of two fields and skip it.
const versionWord = "komando-release"

// Unversioned are the releases signed before releases named their
// version (C114). One of them installs or updates only under its own tag;
// any other release without the version line is refused. install.sh keeps
// the same list (UNVERSIONED).
var Unversioned = []string{"v0.14.0", "v0.14.1"}

var (
	// ErrNoVersion means a release outside Unversioned has no version line.
	ErrNoVersion = errors.New("the release does not name its version")
	// ErrOtherVersion means the version line names another release.
	ErrOtherVersion = errors.New("the release holds another version")
)

// VersionLine is the first line of checksums.txt for release tag, made on
// day (YYYY-MM-DD), with its line end.
func VersionLine(tag, day string) string { return versionWord + " " + tag + " " + day + "\n" }

// Version reads the version line of sums: the tag and the day, or ok false
// when there is none.
func Version(sums []byte) (tag, day string, ok bool) {
	first, _, _ := strings.Cut(string(sums), "\n")
	f := strings.Fields(first)
	if len(f) != 3 || f[0] != versionWord {
		return "", "", false
	}
	return f[1], f[2], true
}

// CheckVersion checks that signed sums belong to release tag: its version
// line names tag, or it has none and tag is one of Unversioned.
func CheckVersion(sums []byte, tag string) error {
	got, _, ok := Version(sums)
	switch {
	case ok && got == tag:
		return nil
	case ok:
		return fmt.Errorf("%w: %s", ErrOtherVersion, got)
	}
	for _, u := range Unversioned {
		if u == tag {
			return nil
		}
	}
	return ErrNoVersion
}
