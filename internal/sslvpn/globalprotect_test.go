package sslvpn

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

const gpJNLP = `<?xml version="1.0"?><jnlp><application-desc><argument>(null)</argument><argument>GPCOOKIE</argument>` +
	`<argument>x</argument><argument>gw1</argument><argument>budi@corp.id</argument><argument>tunnel</argument><argument>-1</argument>` +
	`<argument>corp</argument></application-desc></jnlp>`

const gpSignInPage = `<html><body><form id="myform" method="POST" action="https://idp.example/auth"></form></body></html>`

func gpPreloginXML(samlMethod, samlRequest string) string {
	s := `<?xml version="1.0" encoding="UTF-8" ?><prelogin-response><status>Success</status><msg></msg><region>ID</region>`
	if samlMethod != "" {
		s += `<saml-auth-method>` + samlMethod + `</saml-auth-method><saml-request>` + base64.StdEncoding.EncodeToString([]byte(samlRequest)) + `</saml-request>`
	}
	return s + `</prelogin-response>`
}

// A portal with the Cloud Authentication Service: the browser sign-in
// gives a token, the portal a cookie and its gateways, and the best
// gateway that answers takes the cookie and carries the tunnel.
func TestGlobalProtectPortalBrowser(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/global-protect/prelogin.esp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("cas-support") != "yes" {
			io.WriteString(w, `<prelogin-response><status>Error</status><msg>CAS is not supported by the client. Minimum client version is 6.0</msg></prelogin-response>`)
			return
		}
		io.WriteString(w, gpPreloginXML("POST", gpSignInPage))
	})
	mux.HandleFunc("/global-protect/getconfig.esp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("user") != "budi@corp.id" || r.Form.Get("token") != "TOK+1/2" || r.Form.Get("passwd") != "" {
			w.WriteHeader(512)
			io.WriteString(w, "Authentication failure: Invalid username or password")
			return
		}
		io.WriteString(w, `<?xml version="1.0" encoding="UTF-8" ?><policy><version>6.3.3-1121</version><portal-userauthcookie>PUC</portal-userauthcookie>`+
			`<gateways><external><list>`+
			`<entry name="127.0.0.1"><priority-rule><entry name="Any"><priority>5</priority></entry></priority-rule><description>last</description></entry>`+
			`<entry name="example.com"><priority-rule><entry name="US"><priority>1</priority></entry><entry name="Any"><priority>3</priority></entry></priority-rule></entry>`+
			`<entry name="gw-down.example"><priority-rule><entry name="ID"><priority>1</priority></entry></priority-rule></entry>`+
			`</list></external></gateways></policy>`)
	})
	var gatewayHosts []string
	mux.HandleFunc("/ssl-vpn/login.esp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		gatewayHosts = append(gatewayHosts, r.Host)
		if r.Form.Get("portal-userauthcookie") != "PUC" || r.Form.Get("user") != "budi@corp.id" || r.Form.Get("token") != "" {
			w.WriteHeader(512)
			return
		}
		io.WriteString(w, gpJNLP)
	})
	mux.HandleFunc("/ssl-vpn/getconfig.esp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("authcookie") != "GPCOOKIE" || r.Host != "example.com" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Form.Get("app-version") != "6.3.3-1121" { // the version the portal named
			io.WriteString(w, `<response status="error"><error> Please ensure the compatible GlobalProtect version is: 6.1.4 or above.</error></response>`)
			return
		}
		io.WriteString(w, `<response><ip-address>10.30.0.7</ip-address><mtu>0</mtu></response>`)
	})
	o, _ := fakeGateway(t, mux, func(c net.Conn, br *bufio.Reader, line string) {
		if !strings.Contains(line, "authcookie=GPCOOKIE") {
			c.Close()
			return
		}
		io.WriteString(c, "START_TUNNEL")
		io.Copy(io.Discard, br)
	})
	if _, err := GlobalProtectLogin(context.Background(), o); !errors.Is(err, ErrNeedsPerson) {
		t.Fatalf("a browser sign-in without a person: %v", err)
	}
	shown := 0
	o.Browser = func(_ context.Context, p BrowserPage) (string, error) {
		shown++
		if p.HTML != gpSignInPage || p.URL != "" {
			t.Errorf("page %+v", p)
		}
		return GPCallback + "cas-as=1&un=budi%40corp.id&token=TOK+1%2F2", nil
	}
	s, err := GlobalProtectLogin(context.Background(), o)
	if err != nil || s.AuthCookie != "GPCOOKIE" || s.Gateway != "example.com" || s.User != "budi@corp.id" || s.AppVersion != "6.3.3-1121" {
		t.Fatalf("login: %+v %v", s, err)
	}
	// gw-down.example is first for region ID but its certificate is for
	// another name, so no login is sent there; example.com is next
	if s.Others != "gw-down.example,127.0.0.1" {
		t.Errorf("other gateways %q", s.Others)
	}
	if shown != 1 || len(gatewayHosts) != 1 || gatewayHosts[0] != "example.com" {
		t.Errorf("browser shown %d times, gateways tried %v", shown, gatewayHosts)
	}
	back, err := ParseGPSession(s.String())
	if err != nil || back != s {
		t.Fatalf("session round trip: %+v %v", back, err)
	}
	tun, err := GlobalProtectTunnel(context.Background(), o, s)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if tun.Addresses()[0].String() != "10.30.0.7" {
		t.Errorf("address %v", tun.Addresses())
	}
}

// A gateway that does not take the portal's login has its own sign-in:
// the person signs in once more, and the SAML answer (a page in base64)
// gives the prelogin cookie.
func TestGlobalProtectGatewaySignIn(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/global-protect/prelogin.esp", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, gpPreloginXML("REDIRECT", "https://idp.example/portal"))
	})
	mux.HandleFunc("/global-protect/getconfig.esp", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<policy><portal-userauthcookie>empty</portal-userauthcookie><gateways><external><list><entry name="example.com"/></list></external></gateways></policy>`)
	})
	mux.HandleFunc("/ssl-vpn/prelogin.esp", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, gpPreloginXML("REDIRECT", "https://idp.example/gateway"))
	})
	logins := 0
	mux.HandleFunc("/ssl-vpn/login.esp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		logins++
		if r.Form.Get("prelogin-cookie") != "GWPRE" {
			w.WriteHeader(512)
			return
		}
		io.WriteString(w, gpJNLP)
	})
	o, _ := fakeGateway(t, mux, func(c net.Conn, _ *bufio.Reader, _ string) { c.Close() })
	var notices []string
	o.Notice = func(s string) { notices = append(notices, s) }
	var pages []string
	o.Browser = func(_ context.Context, p BrowserPage) (string, error) {
		pages = append(pages, p.URL)
		cookie := "PORTALPRE"
		if strings.HasSuffix(p.URL, "/gateway") {
			cookie = "GWPRE"
		}
		page := `<html><!-- <saml-auth-status>1</saml-auth-status><prelogin-cookie>` + cookie + `</prelogin-cookie><saml-username>budi</saml-username> --></html>`
		return GPCallback + base64.StdEncoding.EncodeToString([]byte(page)), nil
	}
	s, err := GlobalProtectLogin(context.Background(), o)
	if err != nil || s.AuthCookie != "GPCOOKIE" || s.Gateway != "example.com" {
		t.Fatalf("login: %+v %v", s, err)
	}
	if strings.Join(pages, " ") != "https://idp.example/portal https://idp.example/gateway" || logins != 2 {
		t.Errorf("pages %v, logins %d", pages, logins)
	}
	if len(notices) != 1 || notices[0] != "gateway example.com did not take the sign-in's cookie (example.com refused the login (512)): it has a sign-in of its own, so sign in once more" {
		t.Errorf("notices %q", notices)
	}
}

// A gateway that refuses the portal's cookie is offered the sign-in's
// token next, before anyone is asked to sign in again.
func TestGlobalProtectGatewayToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/global-protect/prelogin.esp", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, gpPreloginXML("POST", gpSignInPage))
	})
	mux.HandleFunc("/global-protect/getconfig.esp", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<policy><portal-userauthcookie>PUC</portal-userauthcookie><gateways><external><list><entry name="example.com"/></list></external></gateways></policy>`)
	})
	var sent []string
	mux.HandleFunc("/ssl-vpn/login.esp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		sent = append(sent, r.Form.Get("portal-userauthcookie")+"/"+r.Form.Get("token"))
		if r.Form.Get("token") != "TOK" {
			w.WriteHeader(512)
			return
		}
		io.WriteString(w, gpJNLP)
	})
	o, _ := fakeGateway(t, mux, func(c net.Conn, _ *bufio.Reader, _ string) { c.Close() })
	shown := 0
	o.Browser = func(context.Context, BrowserPage) (string, error) {
		shown++
		return GPCallback + "cas-as=1&un=budi&token=TOK", nil
	}
	s, err := GlobalProtectLogin(context.Background(), o)
	if err != nil || s.AuthCookie != "GPCOOKIE" || shown != 1 || strings.Join(sent, " ") != "PUC/ /TOK" {
		t.Fatalf("login: %+v %v, browser shown %d times, sent %v", s, err, shown, sent)
	}
}

// A portal with a user name and password: typed when not stored, and a
// refused password is sent once, not again to a gateway.
func TestGlobalProtectPortalPassword(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/global-protect/prelogin.esp", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, gpPreloginXML("", ""))
	})
	sent := 0
	mux.HandleFunc("/global-protect/getconfig.esp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		sent++
		if r.Form.Get("user") != "budi" || r.Form.Get("passwd") != "s3cret" {
			w.WriteHeader(512)
			io.WriteString(w, "Authentication failure:\x1b[31m Invalid username or password")
			return
		}
		io.WriteString(w, `<policy><portal-userauthcookie>empty</portal-userauthcookie></policy>`) // no gateway list: the portal is the gateway
	})
	mux.HandleFunc("/ssl-vpn/login.esp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		sent++
		if r.Form.Get("passwd") != "s3cret" {
			w.WriteHeader(512)
			return
		}
		io.WriteString(w, gpJNLP)
	})
	o, _ := fakeGateway(t, mux, func(c net.Conn, _ *bufio.Reader, _ string) { c.Close() })
	o.User = "budi"
	if _, err := GlobalProtectLogin(context.Background(), o); !errors.Is(err, ErrNeedsPerson) {
		t.Fatalf("no password and nobody to ask: %v", err)
	}
	o.Prompt = func(label string, secret bool) (string, error) {
		if label != "Password for budi" || !secret {
			t.Errorf("prompt %q %v", label, secret)
		}
		return "s3cret", nil
	}
	s, err := GlobalProtectLogin(context.Background(), o)
	if err != nil || s.AuthCookie != "GPCOOKIE" || s.Gateway != "127.0.0.1" {
		t.Fatalf("login: %+v %v", s, err)
	}
	o.Prompt, o.Password, sent = nil, "wrong", 0
	var le *LoginError
	_, err = GlobalProtectLogin(context.Background(), o)
	if !errors.As(err, &le) || le.Msg != "127.0.0.1 refused the login (512: Authentication failure: [31m Invalid username or password)" || sent != 1 {
		t.Fatalf("wrong password: %v, sent %d times", err, sent)
	}
}

func TestParseGPCallback(t *testing.T) {
	page := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, tc := range []struct {
		in   string
		want gpCred
	}{
		{"globalprotectcallback:cas-as=1&un=budi@corp.id&token=a+b", gpCred{User: "budi@corp.id", Token: "a+b"}},
		{"globalprotectcallback://cas-as=1&un=budi%40corp.id&token=a%2Bb%3D", gpCred{User: "budi@corp.id", Token: "a+b="}},
		{"cas-as%3D1%26un%3Dbudi%26token%3Dt", gpCred{User: "budi", Token: "t"}},
		{"cas-as=1&username=budi&preloginCookie=PRE&portalUserauthcookie=PUC", gpCred{User: "budi", PreloginCookie: "PRE", PortalCookie: "PUC"}},
		{" globalprotectcallback:" + page("<!-- <saml-auth-status>1</saml-auth-status><prelogin-cookie> PRE </prelogin-cookie><saml-username>budi</saml-username><saml-slo>no</saml-slo> -->") + "\n",
			gpCred{User: "budi", PreloginCookie: "PRE"}},
		{page("<saml-auth-status>1</saml-auth-status><portal-userauthcookie>PUC</portal-userauthcookie><saml-username>budi</saml-username>"), gpCred{User: "budi", PortalCookie: "PUC"}},
	} {
		got, err := parseGPCallback(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("%q: %+v %v", tc.in, got, err)
		}
	}
	for _, in := range []string{"", "globalprotectcallback:", "cas-as=1&un=budi", "cas-as=1&token=t", "cas-as=1&un=bu%0Adi&token=t", "not base64!",
		page("<saml-auth-status>-1</saml-auth-status><prelogin-cookie>PRE</prelogin-cookie><saml-username>budi</saml-username>"),
		page("<saml-auth-status>1</saml-auth-status><saml-username>budi</saml-username>"),
		page("<saml-auth-status>1</saml-auth-status><prelogin-cookie>PRE</prelogin-cookie>")} {
		var le *LoginError
		if got, err := parseGPCallback(in); !errors.As(err, &le) {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
}

// What a refused answer looked like is said without its values.
func TestGPCallbackShape(t *testing.T) {
	for in, want := range map[string]string{
		"globalprotectcallback:":                         "the sign-in did not end with a GlobalProtect login (0 characters)",
		"globalprotectcallback:cas-as=1&un=budi&tok=abc": "the sign-in did not end with a GlobalProtect login (24 characters; fields: cas-as, un, tok)",
		"cas-as=1&<b>=x&un=budi":                         "the sign-in did not end with a GlobalProtect login (22 characters)",
		base64.StdEncoding.EncodeToString([]byte("<saml-auth-status>1</saml-auth-status><saml-username>budi</saml-username>")): "the sign-in did not end with a GlobalProtect login (100 characters; fields: saml-auth-status, saml-username, status 1)",
	} {
		_, err := parseGPCallback(in)
		if err == nil || err.Error() != want {
			t.Errorf("%q: %v", in, err)
		}
		if GPCallbackOK(in) {
			t.Errorf("%q taken as a login", in)
		}
	}
	if !GPCallbackOK("globalprotectcallback:cas-as=1&un=budi&token=t") {
		t.Error("a real answer refused")
	}
}

// A Prisma Access gateway behind a load balancer cannot carry a tunnel
// yet: the error says so and names the portal's other gateways.
func TestGlobalProtectLoadBalancedGateway(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ssl-vpn/getconfig.esp", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<response status="success"><gw-address>0.0.0.0</gw-address><ip-address>127.127.127.127</ip-address>`+
			`<hs-key><bits>256</bits><val>00ff</val></hs-key><enc-hs-key>AAAA</enc-hs-key><tunnel-opaque><val>AAAA</val></tunnel-opaque></response>`)
	})
	o, _ := fakeGateway(t, mux, func(c net.Conn, _ *bufio.Reader, _ string) { c.Close() })
	_, err := GlobalProtectTunnel(context.Background(), o, GPSession{User: "budi", AuthCookie: "C", Others: "gw-au.example,gw-nl.example"})
	want := "gateway 127.0.0.1 connects in a way komando does not speak yet (a Prisma Access gateway behind a load balancer); " +
		"add one of the portal's other gateways as this VPN's --portal instead: gw-au.example, gw-nl.example"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v", err)
	}
}

func TestGPConfigWhy(t *testing.T) {
	for in, want := range map[string]string{
		`<response status="error"><error>Assign private IP address failed</error></response>`:                                       ": Assign private IP address failed",
		`<response status="success"><need-tunnel>yes</need-tunnel><portal>p</portal><dns><member>1.1.1.1</member></dns></response>`: ": it sent: response status=success, need-tunnel, portal, dns",
		"\x00\x01 not xml": ": its answer was 10 bytes, not a config",
		"":                 ": its answer was 0 bytes, not a config",
	} {
		if got := gpConfigWhy([]byte(in)); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestGPGatewayOrder(t *testing.T) {
	var p gpPortal
	err := xml.Unmarshal([]byte(`<policy><gateways><internal><list><entry name="inside"/></list></internal><external><list>`+
		`<entry name="no-rule"/>`+
		`<entry name="any-2"><priority-rule><entry name="Any"><priority>2</priority></entry></priority-rule></entry>`+
		`<entry name="sg-1"><priority-rule><entry name="SG"><priority>1</priority></entry><entry name="Any"><priority>9</priority></entry></priority-rule></entry>`+
		`<entry name="us-only"><priority-rule><entry name="US"><priority>1</priority></entry></priority-rule></entry>`+
		`<entry name=" "/><entry name="bad"><priority-rule><entry name="Any"><priority>x</priority></entry></priority-rule></entry>`+
		`</list></external></gateways></policy>`), &p)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.gateways("sg"), " "); got != "sg-1 any-2 no-rule us-only bad" {
		t.Errorf("region SG: %s", got)
	}
	if got := strings.Join(p.gateways(""), " "); got != "any-2 sg-1 no-rule us-only bad" {
		t.Errorf("no region: %s", got)
	}
}

func FuzzGlobalProtectParsers(f *testing.F) {
	f.Add([]byte("globalprotectcallback:cas-as=1&un=budi&token=t"))
	f.Add([]byte("PHNhbWwtYXV0aC1zdGF0dXM+MTwvc2FtbC1hdXRoLXN0YXR1cz4="))
	f.Add([]byte(`<policy><portal-userauthcookie>c</portal-userauthcookie><gateways><external><list><entry name="g"><priority-rule><entry name="Any"><priority>1</priority></entry></priority-rule></entry></list></external></gateways></policy>`))
	f.Add([]byte(`var respStatus = "Challenge"; var respMsg = "Enter the code"; inputStr = "abc";`))
	f.Add([]byte(gpJNLP))
	f.Fuzz(func(t *testing.T, b []byte) {
		parseGPCallback(string(b))
		gpTag(b, "saml-username")
		gpWhy(b)
		gpConfigWhy(b)
		gpChallengeText(b)
		gpInputStr(b)
		parseGPLogin(b)
		var p gpPortal
		if xml.Unmarshal(b, &p) == nil {
			p.gateways("ID")
		}
	})
}

// The gateway ends a tunnel long before the login runs out (its
// <timeout>, a reset on the way): the tunnel is set up again with the
// same login and the session goes on. A gateway that then refuses the
// login ends it.
func TestGlobalProtectTunnelRedial(t *testing.T) {
	var mu sync.Mutex
	configs, tunnels, refuse := 0, 0, false
	var preferred []string
	mux := http.NewServeMux()
	mux.HandleFunc("/ssl-vpn/getconfig.esp", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		configs++
		preferred = append(preferred, r.Form.Get("preferred-ip"))
		if refuse {
			w.WriteHeader(512)
			return
		}
		io.WriteString(w, `<response><ip-address>10.30.0.7</ip-address><timeout>1080</timeout></response>`)
	})
	keepalive := make(chan []byte, 8)
	o, _ := fakeGateway(t, mux, func(c net.Conn, br *bufio.Reader, _ string) {
		mu.Lock()
		tunnels++
		n := tunnels
		mu.Unlock()
		io.WriteString(c, "START_TUNNEL")
		if n == 1 { // the first tunnel drops at once
			c.Close()
			return
		}
		for {
			hdr := make([]byte, 16)
			if _, err := io.ReadFull(br, hdr); err != nil {
				return
			}
			l := binary.BigEndian.Uint16(hdr[6:])
			p := make([]byte, l)
			io.ReadFull(br, p)
			if l == 0 {
				select {
				case keepalive <- hdr:
				default:
				}
				continue
			}
			p = append(p, 0xee) // echo, marked
			binary.BigEndian.PutUint16(hdr[6:], uint16(len(p)))
			c.Write(append(hdr, p...))
		}
	})
	gpKeepalive, gpRedialFor = 50*time.Millisecond, 3*time.Second
	defer func() { gpKeepalive, gpRedialFor = 10*time.Second, 5*time.Minute }()
	tun, err := GlobalProtectTunnel(context.Background(), o, GPSession{User: "budi", AuthCookie: "C"})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	select {
	case hdr := <-keepalive:
		if !bytes.Equal(hdr, gpKeepaliveFrame) {
			t.Errorf("keepalive % x", hdr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no keepalive on the second tunnel")
	}
	echoIP(t, tun)
	mu.Lock()
	if tunnels != 2 || configs != 2 || preferred[1] != "10.30.0.7" {
		t.Errorf("tunnels %d, configs %d, preferred %q", tunnels, configs, preferred)
	}
	refuse = true
	mu.Unlock()
	tun.(*gpTun).wmu.Lock()
	tun.(*gpTun).c.Close() // the gateway drops it again, and refuses the login now
	tun.(*gpTun).wmu.Unlock()
	select {
	case <-tun.Done():
		if !strings.Contains(tun.Err().Error(), "the gateway refused the session") {
			t.Errorf("err %v", tun.Err())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a refused login did not end the session")
	}
	if d := gpRekey("1080"); d != 17*time.Minute {
		t.Errorf("rekey %v", d)
	}
	if gpRekey("") != 0 || gpRekey("60") != 0 {
		t.Error("rekey without a usable timeout")
	}
}
