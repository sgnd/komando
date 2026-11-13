package dbx

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"sync"
	"time"

	kdriver "github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
)

// Snowflake's SQL API takes no passwords. The conn's secret
// (--password-ref) is either a private key (PEM, unencrypted: the vault
// encrypts it) for key-pair login, from which komando signs a short-lived
// token itself (a JWT, RS256), or a programmatic access token, which
// Snowflake lets stand where a password goes.

type sfAuth struct {
	token string          // a programmatic access token
	key   *rsa.PrivateKey // key-pair login
	fp    string          // SHA256:... of the public key, as DESC USER shows RSA_PUBLIC_KEY_FP
	now   func() time.Time

	mu  sync.Mutex
	jwt string
	exp time.Time
}

const sfNoSecret = "store a programmatic access token (Snowflake: ALTER USER ... ADD PROGRAMMATIC ACCESS TOKEN) or the user's private key (PEM) with `komando secret set NAME`, then `komando conn edit CONN --password-ref secret:NAME`"

func newSFAuth(secret string) (*sfAuth, error) {
	secret = strings.TrimSpace(secret)
	a := &sfAuth{now: time.Now}
	switch {
	case secret == "":
		return nil, out.Errf(out.ExitConnect, "DB_AUTH", sfNoSecret,
			"a Snowflake conn needs --password-ref: a programmatic access token, or a private key for key-pair login")
	case strings.HasPrefix(secret, "-----BEGIN"):
		key, err := parseSFKey(secret)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(der)
		a.key, a.fp = key, "SHA256:"+base64.StdEncoding.EncodeToString(sum[:])
	default:
		a.token = secret
	}
	return a, nil
}

// parseSFKey reads an RSA private key: PKCS#8 (what Snowflake's guide
// makes) or PKCS#1. An encrypted one is refused: the vault already keeps
// it encrypted, and Go has no reader for encrypted PKCS#8.
func parseSFKey(text string) (*rsa.PrivateKey, error) {
	const plain = "store the key without its passphrase, the vault encrypts it: openssl pkcs8 -topk8 -nocrypt -in KEY_FILE | komando secret set NAME"
	blk, _ := pem.Decode([]byte(text))
	if blk == nil {
		return nil, out.Errf(out.ExitUsage, "USAGE", sfNoSecret, "the conn's secret starts like PEM but holds no PEM block")
	}
	var key any
	var err error
	switch {
	case blk.Type == "ENCRYPTED PRIVATE KEY", strings.Contains(blk.Headers["Proc-Type"], "ENCRYPTED"):
		return nil, out.Errf(out.ExitUsage, "USAGE", plain, "the private key in the conn's secret is encrypted")
	case blk.Type == "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	case blk.Type == "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	default:
		return nil, out.Errf(out.ExitUsage, "USAGE", sfNoSecret, "the conn's secret holds a %s, not a private key", strings.ToLower(blk.Type))
	}
	if err != nil {
		return nil, out.Errf(out.ExitUsage, "USAGE", plain, "the private key in the conn's secret does not parse: %v", err)
	}
	rk, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, out.Errf(out.ExitUsage, "USAGE", "Snowflake key-pair login takes an RSA key (openssl genrsa 2048 | openssl pkcs8 -topk8 -nocrypt)",
			"the private key in the conn's secret is not an RSA key")
	}
	return rk, nil
}

// header is the Authorization token and its kind for the next request. A
// key-pair token is made again when less than five minutes are left.
func (a *sfAuth) header(s kdriver.SnowflakeConn) (token, kind string, err error) {
	if a.key == nil {
		return a.token, "PROGRAMMATIC_ACCESS_TOKEN", nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.jwt == "" || a.now().After(a.exp.Add(-5*time.Minute)) {
		if a.jwt, a.exp, err = a.sign(s); err != nil {
			return "", "", err
		}
	}
	return a.jwt, "KEYPAIR_JWT", nil
}

// sign makes the token Snowflake's key-pair login checks: issued by
// ACCOUNT.USER.SHA256:fingerprint for ACCOUNT.USER, valid 59 minutes
// (Snowflake takes at most an hour).
func (a *sfAuth) sign(s kdriver.SnowflakeConn) (string, time.Time, error) {
	now := a.now()
	exp := now.Add(59 * time.Minute)
	sub := s.JWTAccount + "." + strings.ToUpper(s.User)
	claims, err := json.Marshal(map[string]any{"iss": sub + "." + a.fp, "sub": sub, "iat": now.Unix(), "exp": exp.Unix()})
	if err != nil {
		return "", time.Time{}, err
	}
	enc := base64.RawURLEncoding
	in := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", time.Time{}, err
	}
	return in + "." + enc.EncodeToString(sig), exp, nil
}

// failed is the error for a login Snowflake refused.
func (a *sfAuth) failed(s kdriver.SnowflakeConn, res *sfResult) error {
	hint := "the conn's secret is a programmatic access token (Snowflake's SQL API takes no passwords) or the user's private key (PEM) for key-pair login; check the account and user in the URL too (`komando conn show NAME`)"
	if a.key != nil {
		hint = "Snowflake needs this key's public half for the user: DESC USER " + s.User + " shows RSA_PUBLIC_KEY_FP, which should be " + a.fp +
			" (set it with ALTER USER ... SET RSA_PUBLIC_KEY); check the account and user in the URL too (`komando conn show NAME`)"
	}
	msg := strings.TrimSpace(res.Message)
	if msg == "" {
		msg = "login refused"
	}
	return out.Errf(out.ExitConnect, "DB_AUTH", hint, "Snowflake refused the login of %s at %s: %s", s.User, s.Account, msg)
}

// sfAuthCode: Snowflake's 390xxx codes are about the login (a bad token,
// a locked user, a network policy).
func sfAuthCode(code string) bool { return strings.HasPrefix(code, "390") }
