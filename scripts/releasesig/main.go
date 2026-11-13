// releasesig makes komando's release signing key and signs a release's
// checksums.txt with it (see internal/releasesig).
//
//	go run ./scripts/releasesig new FILE          # a new key: the private key goes into FILE, the public key is printed
//	go run ./scripts/releasesig public FILE       # the public key of the private key in FILE
//	go run ./scripts/releasesig sign CHECKSUMS    # write CHECKSUMS.sig (the release workflow runs this)
//
// sign reads the private key from RELEASE_SIGNING_KEY (one key per line;
// each key adds a signature), then checks the result with the public keys
// built into komando, so a release is never published with a signature
// that komando would refuse.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sgnd/komando/internal/releasesig"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "releasesig:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: releasesig new FILE | public FILE | sign CHECKSUMS")
	}
	switch args[0] {
	case "new":
		return newKey(args[1])
	case "public":
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		pub, err := releasesig.PublicOf(string(b))
		if err != nil {
			return err
		}
		fmt.Println(pub)
		return nil
	case "sign":
		return sign(args[1])
	}
	return fmt.Errorf("unknown command %q (new, public or sign)", args[0])
}

func newKey(file string) error {
	pub, priv, err := releasesig.NewKey()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // never over an existing key
	if err != nil {
		return err
	}
	if _, err := f.WriteString(priv + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("private key: %s (keep it secret; it goes into the GitHub secret RELEASE_SIGNING_KEY)\n", file)
	fmt.Printf("public key:  %s\n", pub)
	return nil
}

func sign(checksums string) error {
	keys := strings.Fields(os.Getenv("RELEASE_SIGNING_KEY"))
	if len(keys) == 0 {
		return errors.New("RELEASE_SIGNING_KEY is empty: add the private key as the secret RELEASE_SIGNING_KEY of the GitHub environment \"release\"")
	}
	sums, err := os.ReadFile(checksums)
	if err != nil {
		return err
	}
	var sig strings.Builder
	for _, k := range keys {
		line, err := releasesig.Sign(k, sums)
		if err != nil {
			return err
		}
		sig.WriteString(line)
	}
	if err := releasesig.Verify(sums, []byte(sig.String())); err != nil {
		return fmt.Errorf("komando would refuse this release: %w (is the public key of RELEASE_SIGNING_KEY in releasesig.Keys?)", err)
	}
	return os.WriteFile(checksums+".sig", []byte(sig.String()), 0o644)
}
