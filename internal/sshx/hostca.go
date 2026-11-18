package sshx

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sgnd/komando/internal/sealdb"
)

// A host CA is a certificate authority a person trusts to vouch for the
// host keys of the servers its patterns match (OpenSSH's @cert-authority
// line). One record of type "hostca" per CA in the sealed store. A server
// that shows a host certificate signed by a CA whose patterns match the
// name komando dials, with that name among its principals, inside its
// validity and not revoked, is trusted without a pin.

const hostCAType = "hostca"

// HostCA is one trusted host certificate authority.
type HostCA struct {
	Name    string    `json:"name"`
	Key     string    `json:"key"`   // authorized_keys line of the CA's public key
	Hosts   []string  `json:"hosts"` // host name patterns (* and ?), lower case
	AddedAt time.Time `json:"added_at"`
	AddedBy string    `json:"added_by,omitempty"`
}

// PublicKey is the CA's key, or nil when the line does not parse.
func (c HostCA) PublicKey() ssh.PublicKey {
	k, ok := parsePinLine(c.Key)
	if !ok {
		return nil
	}
	return k
}

// Matches reports host (a name or an address, no port) among c's patterns.
func (c HostCA) Matches(host string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	for _, p := range c.Hosts {
		if ok, _ := path.Match(p, host); ok {
			return true
		}
	}
	return false
}

// CheckCAPattern refuses a pattern that vouches for too much: a CA must
// name at least two fixed labels (*.corp.example, web*.corp.example,
// 10.1.2.*) or be one exact name. `*`, `*.*` and `*.com` are refused.
func CheckCAPattern(p string) (string, error) {
	p = strings.ToLower(strings.TrimSpace(p))
	if p == "" {
		return "", errors.New("an empty host pattern")
	}
	for _, r := range p {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune(".-_*?:", r)) {
			return "", fmt.Errorf("host pattern %q: only letters, digits, . - _ : and the wildcards * and ?", p)
		}
	}
	if !strings.ContainsAny(p, "*?") {
		return p, nil
	}
	fixed := 0
	for _, l := range strings.Split(p, ".") {
		if l != "" && !strings.ContainsAny(l, "*?") {
			fixed++
		}
	}
	if fixed < 2 {
		return "", fmt.Errorf("host pattern %q vouches for too many servers: name at least the domain, as in *.corp.example or 10.1.2.*", p)
	}
	return p, nil
}

func (t *sealedTx) hostCAs() ([]hostCARow, error) {
	if t.tx == nil {
		return nil, nil
	}
	rows, err := t.tx.List(hostCAType)
	if err != nil {
		return nil, err
	}
	var out []hostCARow
	for _, r := range rows {
		var c HostCA
		if err := json.Unmarshal(r.Data, &c); err != nil {
			return nil, err
		}
		if c.Name == "" || slices.ContainsFunc(out, func(o hostCARow) bool { return o.ca.Name == c.Name }) {
			return nil, sealdb.ErrTampered
		}
		out = append(out, hostCARow{r.ID, c})
	}
	return out, nil
}

type hostCARow struct {
	id string
	ca HostCA
}

// certTrusted checks a host certificate against the trusted CAs for the
// dialled hostname (host:port). It returns the CA that vouches for it, or
// "" with the reason none does.
func (t *sealedTx) certTrusted(hostname string, cert *ssh.Certificate) (string, error) {
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		return "", err
	}
	for _, k := range []ssh.PublicKey{cert.Key, cert.SignatureKey} {
		if rev, err := t.isRevoked(k); err != nil || rev {
			if err != nil {
				return "", err
			}
			return "", errRevoked(k)
		}
	}
	cas, err := t.hostCAs()
	if err != nil {
		return "", err
	}
	name := ""
	checker := &ssh.CertChecker{IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
		for _, c := range cas {
			if k := c.ca.PublicKey(); k != nil && SameKey(k, auth) && c.ca.Matches(host) {
				name = c.ca.Name
				return true
			}
		}
		return false
	}}
	if err := checker.CheckHostKey(net.JoinHostPort(host, "22"), nil, cert); err != nil {
		return "", err
	}
	return name, nil
}

// HostCAs lists the trusted host CAs, by name.
func HostCAs(ctx context.Context) ([]HostCA, error) {
	var out []HostCA
	err := HostKeys().view(ctx, func(ht hostKeyTx) error {
		rows, err := ht.(*sealedTx).hostCAs()
		for _, r := range rows {
			out = append(out, r.ca)
		}
		return err
	})
	slices.SortFunc(out, func(a, b HostCA) int { return strings.Compare(a.Name, b.Name) })
	return out, err
}

// ErrHostCAExists and ErrNoHostCA answer AddHostCA and RemoveHostCA.
var (
	ErrHostCAExists = errors.New("a host CA with that name exists")
	ErrNoHostCA     = errors.New("no host CA with that name")
)

// AddHostCA trusts c. A revoked CA key cannot be added.
func AddHostCA(ctx context.Context, c HostCA) error {
	k := c.PublicKey()
	if k == nil {
		return errors.New("the CA key does not parse")
	}
	return HostKeys().update(ctx, func(ht hostKeyTx) error {
		t := ht.(*sealedTx)
		if rev, err := t.isRevoked(k); err != nil || rev {
			if err != nil {
				return err
			}
			return errRevoked(k)
		}
		rows, err := t.hostCAs()
		if err != nil {
			return err
		}
		if slices.ContainsFunc(rows, func(r hostCARow) bool { return r.ca.Name == c.Name }) {
			return ErrHostCAExists
		}
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		_, err = t.tx.Put(hostCAType, "", b)
		return err
	})
}

// RemoveHostCA stops trusting the CA named name.
func RemoveHostCA(ctx context.Context, name string) error {
	return HostKeys().update(ctx, func(ht hostKeyTx) error {
		t := ht.(*sealedTx)
		rows, err := t.hostCAs()
		if err != nil {
			return err
		}
		i := slices.IndexFunc(rows, func(r hostCARow) bool { return r.ca.Name == name })
		if i < 0 {
			return ErrNoHostCA
		}
		return t.tx.Delete(rows[i].id)
	})
}

// HostCAFor is the first trusted CA whose patterns match host, or nil:
// komando then asks the server for its certificate first.
func HostCAFor(ctx context.Context, host string) (*HostCA, error) {
	cas, err := HostCAs(ctx)
	if err != nil {
		return nil, err
	}
	for _, c := range cas {
		if c.Matches(host) {
			return &c, nil
		}
	}
	return nil, nil
}

// certFirst is the host key algorithms with the certificate ones first,
// for a server a trusted CA may vouch for.
func certFirst() []string {
	plain := ssh.SupportedAlgorithms().HostKeys
	var certs []string
	for _, a := range plain {
		if c, ok := certAlgo[a]; ok {
			certs = append(certs, c)
		}
	}
	return append(certs, plain...)
}

var certAlgo = map[string]string{
	ssh.KeyAlgoED25519:   ssh.CertAlgoED25519v01,
	ssh.KeyAlgoECDSA256:  ssh.CertAlgoECDSA256v01,
	ssh.KeyAlgoECDSA384:  ssh.CertAlgoECDSA384v01,
	ssh.KeyAlgoECDSA521:  ssh.CertAlgoECDSA521v01,
	ssh.KeyAlgoRSASHA512: ssh.CertAlgoRSASHA512v01,
	ssh.KeyAlgoRSASHA256: ssh.CertAlgoRSASHA256v01,
}
