package cli

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sgnd/komando/internal/store"
)

// evilCert is a self-signed certificate for 127.0.0.1 and its PEM file.
func evilCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "evil"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "evil.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, p
}

// fakePG asks for a cleartext password and records it; with cert it
// speaks TLS when asked.
func fakePG(t *testing.T, cert *tls.Certificate) (port string, got *atomic.Value) {
	t.Helper()
	got = &atomic.Value{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c0, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					var n int32
					if err := binary.Read(r, binary.BigEndian, &n); err != nil || n < 8 {
						return
					}
					b := make([]byte, n-4)
					if _, err := io.ReadFull(r, b); err != nil {
						return
					}
					switch code := binary.BigEndian.Uint32(b[:4]); {
					case code == 80877103 && cert != nil:
						_, _ = c.Write([]byte("S"))
						tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*cert}})
						if tc.Handshake() != nil {
							return
						}
						c, r = tc, bufio.NewReader(tc)
						continue
					case code == 80877103 || code == 80877104:
						_, _ = c.Write([]byte("N"))
						continue
					}
					break
				}
				_, _ = c.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3}) // cleartext password, please
				if typ, _ := r.ReadByte(); typ != 'p' {
					return
				}
				var n int32
				if binary.Read(r, binary.BigEndian, &n) != nil || n < 4 {
					return
				}
				b := make([]byte, n-4)
				_, _ = io.ReadFull(r, b)
				got.Store(strings.TrimRight(string(b), "\x00"))
			}(c0)
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, got
}

// These tests are the attacks of an AI agent that wants a conn's stored
// password (or one the person keeps for Postgres): each moves where the
// login goes without changing the address komando shows.

// A conn URL's own settings move the login as its address does: Postgres
// host=, port=, hostaddr=, service=, sslrootcert=, Redis sentinels=,
// MongoDB seed hosts, RabbitMQ management=. An agent that writes them into
// the URL of a conn with a stored password gets SECRET_DESTINATION, and
// the approval names them. Settings that move nothing go on, as does a
// change of user.
func TestConnURLSettingsAreThePlace(t *testing.T) {
	invHome(t)
	t.Setenv("PW", "stored-pw")
	mustRun(t, "credential", "password", "add", "evilca", "--from-env", "PW")
	mustRun(t, "conn", "add", "pg1", "postgres://app@db.internal:5432/app", "--password-ref", savedRef(t, "pg1-pw", "stored-pw"))
	mustRun(t, "conn", "add", "c1", "rediss://default@10.0.0.5:6379/0", "--password-ref", savedRef(t, "c1-pw", "stored-pw"))
	mustRun(t, "conn", "add", "m1", "mongodb://app@10.0.0.5:27017/app", "--password-ref", savedRef(t, "m1-pw", "stored-pw"))
	mustRun(t, "conn", "add", "q1", "amqp://guest@127.0.0.1:5672/", "--password-ref", savedRef(t, "q1-pw", "stored-pw"))
	setCallerEnv(t, "CLAUDECODE", "1")
	base := mustRun(t, "conn", "show", "pg1")["url"].(string)
	for _, c := range []struct{ conn, url, shows string }{
		{"pg1", base + "&host=127.0.0.1&port=5999", "host=127.0.0.1"},
		{"pg1", base + "&hostaddr=203.0.113.66", "hostaddr=203.0.113.66"},
		{"pg1", base + "&service=evil", "service=evil"},
		{"pg1", base + "&sslrootcert=/tmp/evil.pem", "sslrootcert=/tmp/evil.pem"},
		{"pg1", base + "&ca=credential:evilca", "ca=credential:evilca"},
		{"c1", "rediss://default@10.0.0.5:6379/0?sentinel=m&sentinels=203.0.113.66:26379&sentinel_auth=same", "203.0.113.66:26379"},
		{"m1", "mongodb://app@10.0.0.5:27017,203.0.113.66:27017/app?authMechanism=PLAIN", "203.0.113.66:27017"},
		{"q1", "amqp://guest@127.0.0.1:5672/?management=4444", "127.0.0.1:4444"},
	} {
		if e := wantCode(t, "SECRET_DESTINATION", "conn", "edit", c.conn, "--url", c.url); !strings.Contains(e.Message, c.shows) {
			t.Errorf("%s: the stop does not show %q: %+v", c.url, c.shows, e)
		}
	}
	mustRun(t, "conn", "edit", "pg1", "--url", base+"&connect_timeout=5&application_name=report")
	mustRun(t, "conn", "edit", "pg1", "--url", strings.Replace(base, "app@", "other@", 1)+"&connect_timeout=5&application_name=report")
	st, _ := store.Load()
	if u := st.Conns["pg1"].URL; strings.Contains(u, "host=") || strings.Contains(u, "sslrootcert") {
		t.Errorf("an edit went through: %s", u)
	}
}

// komando reads a Postgres conn from its URL only: PGSSLROOTCERT in this
// process's environment (an agent sets its own) cannot make komando trust
// another server's certificate and send it the stored password.
func TestPostgresEnvIgnored(t *testing.T) {
	invHome(t)
	cert, caFile := evilCert(t)
	port, got := fakePG(t, &cert)
	mustRun(t, "conn", "add", "pg1", "postgres://app@127.0.0.1:"+port+"/app?sslmode=verify-full", "--password-ref", savedRef(t, "pg1-pw", "stored-pw"))
	t.Setenv("PGSSLROOTCERT", caFile)
	_, _ = runCache(t, "-o", "json", "database", "postgres", "query", "pg1", "--", "select 1")
	if v, _ := got.Load().(string); v == "stored-pw" {
		t.Fatalf("the fake server got the stored password")
	}
}

// A conn with no password of komando's own never logs in with the
// person's ~/.pgpass: an agent could add such a conn at a server it
// controls and collect the password.
func TestPostgresPassfileIgnored(t *testing.T) {
	invHome(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".pgpass"), []byte("*:*:*:*:person-pgpass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	port, got := fakePG(t, nil)
	// (an agent reaches such a conn with a server that has a public
	// certificate; here the test server speaks no TLS)
	noAgent(t)
	mustRun(t, "conn", "add", "pg1", "postgres://app@127.0.0.1:"+port+"/app?sslmode=disable")
	setCallerEnv(t, "CLAUDECODE", "1")
	_, _ = runCache(t, "-o", "json", "database", "postgres", "query", "pg1", "--", "select 1")
	if v, _ := got.Load().(string); v == "person-pgpass" {
		t.Fatalf("the fake server got the password from ~/.pgpass")
	}
}

// komando's own folder is never a SQLite conn: its store holds the
// inventory and the sealed secrets.
func TestSQLiteKomandoStoreRefused(t *testing.T) {
	invHome(t)
	mustRun(t, "host", "ssh", "add", "web1", "u@10.0.0.1")
	db := filepath.Join(os.Getenv("KOMANDO_HOME"), "store.db")
	link := filepath.Join(t.TempDir(), "notes.db")
	if err := os.Symlink(db, link); err != nil {
		t.Fatal(err)
	}
	setCallerEnv(t, "CLAUDECODE", "1")
	for _, p := range []string{db, link} {
		if e := wantCode(t, "SENSITIVE_FILE", "conn", "add", "own", "sqlite://"+p); e.Hint == "" {
			t.Errorf("%s: %+v", p, e)
		}
	}
}

// A SQLite conn is a file on this computer, so an AI agent's conn reads
// what the agent guard keeps from it: a credential database in a cloud
// login folder (gcloud's credentials.db), ~/.ssh, ~/.aws. Refused at add,
// and again at open for a conn a person added there; db dump and restore
// do not write or read such paths either.
func TestSQLiteSensitivePathsRefusedForAgents(t *testing.T) {
	invHome(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows
	var paths []string
	for _, rel := range []string{".config/gcloud/credentials.db", ".ssh/keys.db", ".aws/sso.db", ".azure/msal.db", ".kube/cache.db", ".docker/creds.db"} {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	noAgent(t)
	mustRun(t, "conn", "add", "gc", "sqlite://"+paths[0]) // a person may
	mine := filepath.Join(t.TempDir(), "app.db")
	mustRun(t, "conn", "add", "app", "sqlite://"+mine)
	setCallerEnv(t, "CLAUDECODE", "1")
	for i, p := range paths {
		wantCode(t, "SENSITIVE_FILE", "conn", "add", "x"+strconv.Itoa(i), "sqlite://"+p)
	}
	wantCode(t, "SENSITIVE_FILE", "database", "sqlite", "query", "gc", "--", "select 1")
	wantCode(t, "SENSITIVE_FILE", "database", "sqlite", "backup", "gc", "--to", filepath.Join(t.TempDir(), "copy.db"))
	wantCode(t, "SENSITIVE_FILE", "database", "sqlite", "backup", "app", "--to", filepath.Join(home, ".ssh", "copy.db"))
	wantCode(t, "SENSITIVE_FILE", "database", "sqlite", "backup", "app", "--to", filepath.Join(home, ".aws", "copy.db"))
	if err := os.WriteFile(filepath.Join(home, ".aws", "dump.sql"), []byte("select 1;"), 0o600); err != nil {
		t.Fatal(err)
	}
	mustRun(t, "conn", "add", "pg9", "postgres://app@10.0.0.5/app")
	wantCode(t, "SENSITIVE_FILE", "database", "postgres", "restore", "pg9", "--from", filepath.Join(home, ".aws", "dump.sql"))
}

// SQL on a SQLite conn can write any file: ATTACH DATABASE and VACUUM
// INTO create one wherever they are told. An AI agent's query on a SQLite
// conn may not use them at all, and load_extension (native code) stays
// off for everyone.
func TestSQLiteAttachAndVacuumIntoRefusedForAgents(t *testing.T) {
	invHome(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	db := filepath.Join(t.TempDir(), "app.db")
	noAgent(t)
	mustRun(t, "conn", "add", "lite", "sqlite://"+db)
	mustRun(t, "database", "sqlite", "query", "lite", "--write", "create table t(x)")
	setCallerEnv(t, "CLAUDECODE", "1")
	vac := filepath.Join(home, ".ssh", "vac")
	att := filepath.Join(os.Getenv("KOMANDO_HOME"), "att.db")
	for _, q := range []string{
		"VACUUM INTO '" + vac + "'",
		"vacuum main into '" + vac + "'",
		"ATTACH DATABASE '" + att + "' AS a; CREATE TABLE a.t(x)",
		"attach '" + att + "' as a",
	} {
		wantCode(t, "SENSITIVE_FILE", "database", "sqlite", "query", "lite", "--write", q)
	}
	for _, p := range []string{vac, att} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was created", p)
		}
	}
	// a string that only mentions them is fine
	mustRun(t, "database", "sqlite", "query", "lite", "--write", "insert into t values ('attach x; vacuum into y')")
	// native code never loads, for a person either
	noAgent(t)
	if _, err := runCache(t, "-o", "json", "database", "sqlite", "query", "lite", "select load_extension('/tmp/evil')"); err == nil {
		t.Error("load_extension ran")
	}
}
