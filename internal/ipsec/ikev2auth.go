package ipsec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"time"

	"github.com/sgnd/komando/internal/ppp"
)

// IKEv2 authentication: the server's certificate and signature (RFC 7296
// 3.8, RFC 7427), and the EAP login (EAP-MSCHAPv2, EAP-MD5).

const (
	authRSA      = 1
	authPSK      = 2
	authECDSA256 = 9
	authECDSA384 = 10
	authECDSA512 = 11
	authDigital  = 14
)

// verifyServerCert checks the server's certificate chain and that it is
// for the server komando meant to reach.
func verifyServerCert(certs [][]byte, caPEM []byte, name string) (*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, errors.New("the server sent no certificate")
	}
	leaf, err := x509.ParseCertificate(certs[0])
	if err != nil {
		return nil, fmt.Errorf("the server's certificate: %v", err)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		if x, err := x509.ParseCertificate(c); err == nil {
			inter.AddCert(x)
		}
	}
	opts := x509.VerifyOptions{Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, CurrentTime: time.Now()}
	if len(caPEM) > 0 {
		opts.Roots = x509.NewCertPool()
		if !opts.Roots.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("the --ca file holds no certificate")
		}
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, fmt.Errorf("the server's certificate is not trusted: %v (give its CA with --ca)", err)
	}
	if err := leaf.VerifyHostname(name); err != nil {
		if a, perr := netip.ParseAddr(name); perr != nil || !certHasIP(leaf, a) {
			return nil, fmt.Errorf("the server's certificate is not for %s: %v (use --remote-id if the server has another name)", name, err)
		}
	}
	return leaf, nil
}

func certHasIP(c *x509.Certificate, a netip.Addr) bool {
	for _, ip := range c.IPAddresses {
		if x, ok := netip.AddrFromSlice(ip); ok && x.Unmap() == a {
			return true
		}
	}
	return false
}

var (
	oidSHA256RSA  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384RSA  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512RSA  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidPSS        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidECDSA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSA384   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSA512   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519    = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	errBadSigAlgo = errors.New("the server signed with an algorithm komando does not know")
)

type pssParams struct {
	Hash       pkix.AlgorithmIdentifier `asn1:"explicit,tag:0,optional"`
	MGF        pkix.AlgorithmIdentifier `asn1:"explicit,tag:1,optional"`
	SaltLength int                      `asn1:"explicit,tag:2,optional,default:20"`
}

func hashFor(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	}
	return 0, false
}

func digest(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA1:
		s := sha1.Sum(data)
		return s[:]
	case crypto.SHA256:
		s := sha256.Sum256(data)
		return s[:]
	case crypto.SHA384:
		s := sha512.Sum384(data)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:]
	}
	return nil
}

// verifySignature checks the server's AUTH payload (method and data)
// over the signed octets with the certificate's key.
func verifySignature(cert *x509.Certificate, method byte, sig, signed []byte) error {
	pub := cert.PublicKey
	switch method {
	case authRSA:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("RSA signature, but the certificate has no RSA key")
		}
		return rsa.VerifyPKCS1v15(k, crypto.SHA1, digest(crypto.SHA1, signed), sig)
	case authECDSA256, authECDSA384, authECDSA512:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig)%2 != 0 {
			return errors.New("bad ECDSA signature")
		}
		h := map[byte]crypto.Hash{authECDSA256: crypto.SHA256, authECDSA384: crypto.SHA384, authECDSA512: crypto.SHA512}[method]
		r, s := new(big.Int).SetBytes(sig[:len(sig)/2]), new(big.Int).SetBytes(sig[len(sig)/2:])
		if !ecdsa.Verify(k, digest(h, signed), r, s) {
			return errors.New("the ECDSA signature does not match")
		}
		return nil
	case authDigital:
		if len(sig) < 1 || int(sig[0])+1 > len(sig) {
			return errors.New("bad signature payload")
		}
		var alg pkix.AlgorithmIdentifier
		if _, err := asn1.Unmarshal(sig[1:1+sig[0]], &alg); err != nil {
			return errors.New("bad signature algorithm")
		}
		s := sig[1+sig[0]:]
		switch {
		case alg.Algorithm.Equal(oidSHA256RSA), alg.Algorithm.Equal(oidSHA384RSA), alg.Algorithm.Equal(oidSHA512RSA):
			k, ok := pub.(*rsa.PublicKey)
			if !ok {
				return errors.New("RSA signature, but the certificate has no RSA key")
			}
			h := crypto.SHA256
			if alg.Algorithm.Equal(oidSHA384RSA) {
				h = crypto.SHA384
			} else if alg.Algorithm.Equal(oidSHA512RSA) {
				h = crypto.SHA512
			}
			return rsa.VerifyPKCS1v15(k, h, digest(h, signed), s)
		case alg.Algorithm.Equal(oidPSS):
			k, ok := pub.(*rsa.PublicKey)
			if !ok {
				return errors.New("RSA-PSS signature, but the certificate has no RSA key")
			}
			var p pssParams
			if _, err := asn1.Unmarshal(alg.Parameters.FullBytes, &p); err != nil {
				return errors.New("bad RSA-PSS parameters")
			}
			h, ok := hashFor(p.Hash.Algorithm)
			if !ok {
				return errBadSigAlgo
			}
			return rsa.VerifyPSS(k, h, digest(h, signed), s, &rsa.PSSOptions{SaltLength: p.SaltLength, Hash: h})
		case alg.Algorithm.Equal(oidECDSA256), alg.Algorithm.Equal(oidECDSA384), alg.Algorithm.Equal(oidECDSA512):
			k, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				return errors.New("ECDSA signature, but the certificate has no ECDSA key")
			}
			h := crypto.SHA256
			if alg.Algorithm.Equal(oidECDSA384) {
				h = crypto.SHA384
			} else if alg.Algorithm.Equal(oidECDSA512) {
				h = crypto.SHA512
			}
			if !ecdsa.VerifyASN1(k, digest(h, signed), s) {
				return errors.New("the ECDSA signature does not match")
			}
			return nil
		case alg.Algorithm.Equal(oidEd25519):
			k, ok := pub.(ed25519.PublicKey)
			if !ok || !ed25519.Verify(k, signed, s) {
				return errors.New("the Ed25519 signature does not match")
			}
			return nil
		}
		return errBadSigAlgo
	}
	return fmt.Errorf("the server authenticates with method %d, which komando does not support", method)
}

// EAP.

const (
	eapRequest  = 1
	eapResponse = 2
	eapSuccess  = 3
	eapFailure  = 4

	eapIdentity = 1
	eapNak      = 3
	eapMD5      = 4
	eapMSCHAPv2 = 26
)

func eapPacket(code, id byte, typ byte, data []byte) []byte {
	b := []byte{code, id, 0, 0, typ}
	b = append(b, data...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

// eapClient answers EAP requests; msk is set once a method gives one.
type eapClient struct {
	user, password string
	ms             *ppp.MSCHAPv2
	msk            []byte
}

// answer returns the response to one EAP request, or an error.
func (e *eapClient) answer(req []byte) ([]byte, error) {
	if len(req) < 5 || req[0] != eapRequest {
		return nil, errors.New("not an EAP request")
	}
	id, typ := req[1], req[4]
	n := int(binary.BigEndian.Uint16(req[2:]))
	if n > len(req) || n < 5 {
		return nil, errors.New("bad EAP length")
	}
	data := req[5:n]
	switch typ {
	case eapIdentity:
		return eapPacket(eapResponse, id, eapIdentity, []byte(e.user)), nil
	case eapMD5:
		if len(data) < 1 || int(data[0])+1 > len(data) {
			return nil, errors.New("bad EAP-MD5 challenge")
		}
		h := md5.New()
		h.Write([]byte{id})
		h.Write([]byte(e.password))
		h.Write(data[1 : 1+data[0]])
		return eapPacket(eapResponse, id, eapMD5, append([]byte{16}, h.Sum(nil)...)), nil
	case eapMSCHAPv2:
		if len(data) < 4 {
			return nil, errors.New("bad EAP-MSCHAPv2 request")
		}
		op, msid := data[0], data[1]
		switch op {
		case 1: // challenge
			if len(data) < 5+16 || data[4] != 16 {
				return nil, errors.New("bad EAP-MSCHAPv2 challenge")
			}
			var pc [16]byte
			copy(pc[:], random(16))
			m, err := ppp.NewMSCHAPv2(data[5:21], e.user, e.password, pc)
			if err != nil {
				return nil, err
			}
			e.ms = m
			v := []byte{2, msid, 0, 0, 49}
			v = append(v, pc[:]...)
			v = append(v, make([]byte, 8)...)
			v = append(v, m.NTResponse[:]...)
			v = append(v, 0)
			v = append(v, e.user...)
			binary.BigEndian.PutUint16(v[2:], uint16(len(v)))
			return eapPacket(eapResponse, id, eapMSCHAPv2, v), nil
		case 3: // success, with the server's proof
			if e.ms == nil {
				return nil, errors.New("EAP-MSCHAPv2 success before a challenge")
			}
			if err := e.ms.VerifySuccess(data[4:]); err != nil {
				return nil, err
			}
			e.msk = e.ms.MSK()
			return eapPacket(eapResponse, id, eapMSCHAPv2, []byte{3}), nil
		case 4: // failure
			return nil, &AuthError{Msg: "the VPN refused the login (EAP-MSCHAPv2" + mschapWords(string(data[4:])) + ")"}
		}
		return nil, fmt.Errorf("unknown EAP-MSCHAPv2 operation %d", op)
	}
	// any other method: ask for MS-CHAPv2
	return eapPacket(eapResponse, id, eapNak, []byte{eapMSCHAPv2}), nil
}

func mschapWords(s string) string {
	if len(s) >= 5 && s[:5] == "E=691" {
		return ": wrong user name or password"
	}
	if len(s) >= 5 && s[:5] == "E=648" {
		return ": the password expired"
	}
	return ""
}
