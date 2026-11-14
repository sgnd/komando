package sshx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/sgnd/komando/internal/store"
)

// hostKeyNote is where the line about a newly pinned key goes.
var hostKeyNote io.Writer = os.Stderr

// pinnedOnFirstUse tells the person, on stderr, which key was just pinned
// and how to check it, and passes it on to HostKeyPinned.
func pinnedOnFirstUse(ctx context.Context, name, hostname string, key ssh.PublicKey) {
	k := keyNote(name, hostname, key)
	k.key = nil // the note says what it is; the key itself stays in sshx
	fmt.Fprintf(hostKeyNote, "komando: first connection to %s (%s): trusted its %s host key %s\n"+
		"komando: compare it with the server's own (on the server: ssh-keygen -lf /etc/ssh/ssh_host_%s_key.pub); if this key ever changes, komando refuses the server\n",
		name, hostname, k.Type, k.Fingerprint, keyFileType(k.Type))
	if HostKeyPinned != nil {
		HostKeyPinned(ctx, k)
	}
}

// keyNote is the NewHostKey of key at hostname for server name.
func keyNote(name, hostname string, key ssh.PublicKey) NewHostKey {
	return NewHostKey{Host: name, Address: hostname, Type: key.Type(), Fingerprint: ssh.FingerprintSHA256(key), key: key}
}

// keyFileType is the name part of the server's key file for a key type:
// ssh-ed25519 is in ssh_host_ed25519_key.pub.
func keyFileType(t string) string {
	switch {
	case strings.Contains(t, "ed25519"):
		return "ed25519"
	case strings.HasPrefix(t, "ecdsa"):
		return "ecdsa"
	case strings.Contains(t, "rsa"):
		return "rsa"
	}
	return "*"
}

// hostKeyCallback checks the key of server h. q (nil: not a login-ask
// server's connection) hears of a key trusted on first use: a login-ask
// server's new key is pinned only when askLoginNewKey allows it, as a
// person's password goes to whatever answers there.
func hostKeyCallback(ctx context.Context, h *store.Host, policy string, q *LoginAsk) (ssh.HostKeyCallback, error) {
	name := h.Name
	ask := h.AskLogin() && q != nil
	if policy == "off" {
		if !ask {
			return ssh.InsecureIgnoreHostKey(), nil
		}
		return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
			k := keyNote(name, hostname, key)
			k.Unchecked = true
			if err := askLoginNewKey(ctx, h, k); err != nil {
				return &pinRefused{err}
			}
			q.NewKey = &k
			return nil
		}, nil
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// a known server is checked in a read step; only a new one takes
		// the write step that pins it (and checks again inside it)
		var known error
		if verr := HostKeys().view(ctx, func(t hostKeyTx) error { known = t.Check(hostname, remote, key); return nil }); verr != nil {
			return verr
		}
		var ke0 *knownhosts.KeyError
		if known == nil && ask {
			return loginKnownKey(ctx, h, hostname, key, q)
		}
		if !errors.As(known, &ke0) || len(ke0.Want) > 0 {
			if errors.As(known, &ke0) {
				return &hostKeyChanged{offered: key, err: ke0}
			}
			return known
		}
		if ask && policy != "strict" {
			// nobody has seen this key: a person decides before it is pinned
			if err := askLoginNewKey(ctx, h, keyNote(name, hostname, key)); err != nil {
				return &pinRefused{err}
			}
		}
		if policy != "strict" && MayPin != nil {
			if err := MayPin(ctx); err != nil {
				return &pinRefused{err}
			}
		}
		var err error
		pinned := false
		lockErr := HostKeys().update(ctx, func(t hostKeyTx) error {
			err = t.Check(hostname, remote, key)
			var ke *knownhosts.KeyError
			if errors.As(err, &ke) && len(ke.Want) == 0 {
				if policy == "strict" {
					err = errors.New("HOSTKEY_UNKNOWN " + ssh.FingerprintSHA256(key))
					return nil
				}
				if aerr := t.Add(hostname, key); aerr != nil {
					return aerr
				}
				err, pinned = nil, true
				return nil
			}
			if errors.As(err, &ke) {
				err = &hostKeyChanged{offered: key, err: ke}
			}
			return nil
		})
		if lockErr != nil {
			return lockErr
		}
		if pinned {
			pinnedOnFirstUse(ctx, name, hostname, key)
			if ask {
				k := keyNote(name, hostname, key)
				q.NewKey = &k
			}
		}
		return err
	}, nil
}
