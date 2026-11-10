package sslvpn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// Palo Alto GlobalProtect. A portal (/global-protect/prelogin.esp says how
// it logs in, /global-protect/getconfig.esp lists the gateways) and then a
// gateway: /ssl-vpn/login.esp (a challenge asks a person for a code),
// /ssl-vpn/getconfig.esp for the address, then the GPST tunnel inside TLS.
// A host that is only a gateway is logged in to directly. A portal or
// gateway with a browser sign-in (SAML, or Palo Alto's Cloud
// Authentication Service) hands over a page; the sign-in ends on a
// globalprotectcallback: address that carries the login for getconfig.esp
// or login.esp. Each tunnel frame: magic 1a2b3c4d, ethertype (0800),
// length, 8 bytes 01 00..., the IP packet. A frame with length 0 keeps the
// link alive. ESP over UDP is not used, and no HIP report is sent.

const gpUserAgent = "PAN GlobalProtect"

// GPCallback starts the address a GlobalProtect browser sign-in ends on.
const GPCallback = "globalprotectcallback:"

// GPSession is what the tunnel needs from a login. Gateway is the host the
// portal chose; empty means the portal address is the gateway.
type GPSession struct {
	User, AuthCookie, Portal, Domain, Computer, Gateway string
	// AppVersion is the app version the portal hands out ("" when unknown).
	AppVersion string
	// Others are the portal's other gateways, comma-separated: named when
	// this one cannot carry a tunnel.
	Others string
}

// String packs the session for `komando vpn serve` (one line, no secrets
// beyond the cookie it already is).
func (s GPSession) String() string {
	return url.Values{"user": {s.User}, "authcookie": {s.AuthCookie}, "portal": {s.Portal}, "domain": {s.Domain},
		"computer": {s.Computer}, "gateway": {s.Gateway}, "appversion": {s.AppVersion}, "others": {s.Others}}.Encode()
}

// ParseGPSession is the reverse of GPSession.String.
func ParseGPSession(s string) (GPSession, error) {
	v, err := url.ParseQuery(s)
	if err != nil || v.Get("authcookie") == "" {
		return GPSession{}, errors.New("not a GlobalProtect session")
	}
	return GPSession{User: v.Get("user"), AuthCookie: v.Get("authcookie"), Portal: v.Get("portal"), Domain: v.Get("domain"),
		Computer: v.Get("computer"), Gateway: v.Get("gateway"), AppVersion: v.Get("appversion"), Others: v.Get("others")}, nil
}

// gpOS is this computer's system in GlobalProtect's words.
func gpOS() string {
	switch runtime.GOOS {
	case "darwin":
		return "Mac"
	case "windows":
		return "Windows"
	}
	return "Linux"
}

// gpCred is a login for a portal or gateway: a password, or what a browser
// sign-in or the portal handed out.
type gpCred struct {
	User, Password, PreloginCookie, PortalCookie, Token string
}

func (c gpCred) usable() bool {
	return c.Password != "" || c.PreloginCookie != "" || c.PortalCookie != "" || c.Token != ""
}

func gpForm(host string, c gpCred) url.Values {
	f := url.Values{"prot": {"https:"}, "server": {host}, "inputStr": {""}, "jnlpReady": {"jnlpReady"},
		"user": {c.User}, "passwd": {c.Password}, "computer": {"komando"}, "ok": {"Login"}, "direct": {"yes"},
		"clientVer": {"4100"}, "os-version": {gpOS()}, "clientos": {gpOS()}, "prelogin-cookie": {c.PreloginCookie},
		"portal-userauthcookie": {c.PortalCookie}, "portal-prelogonuserauthcookie": {""}}
	if c.Token != "" {
		f.Set("token", c.Token)
	}
	return f
}

func gpPost(ctx context.Context, hc *http.Client, u *url.URL, path string, form url.Values) (int, []byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", u.Scheme+"://"+u.Host+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", gpUserAgent)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, nil
}

// gpAuthPost sends a login form and answers the server's challenges (a
// one-time code) through o.Prompt. It returns the answer to a login the
// server took.
func gpAuthPost(ctx context.Context, o Options, hc *http.Client, u *url.URL, path string, form url.Values) ([]byte, error) {
	for round := 0; round < 4; round++ {
		status, b, err := gpPost(ctx, hc, u, path, form)
		if err != nil {
			return nil, err
		}
		if bytes.Contains(b, []byte("Challenge")) {
			if o.Prompt == nil {
				return nil, ErrNeedsPerson
			}
			code, err := o.Prompt(gpChallengeText(b), false)
			if err != nil {
				return nil, err
			}
			form.Set("passwd", code)
			form.Set("inputStr", gpInputStr(b))
			continue
		}
		if status != http.StatusOK {
			return nil, &LoginError{Msg: fmt.Sprintf("%s refused the login (%d%s)", u.Hostname(), status, gpWhy(b))}
		}
		return b, nil
	}
	return nil, &LoginError{Msg: "the GlobalProtect login did not finish"}
}

// gpWhy is the start of a refusal's text, cleaned: the server wrote it.
func gpWhy(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, string(b[:min(len(b), 400)]))
	if strings.Contains(s, "<") { // a page, not a message
		return ""
	}
	if s = strings.Join(strings.Fields(s), " "); s == "" {
		return ""
	}
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return ": " + s
}

// gpAppVersion is the GlobalProtect app version komando tells a gateway
// when the portal named none. A gateway may refuse an app older than its
// administrator set ("Please ensure the compatible GlobalProtect version
// is: 6.1.4 or above"); the portal's config names the version it hands
// out, and that one is used when known.
const gpAppVersion = "6.3.3-1121"

// gpVersionOK reports whether v looks like an app version (6.3.3-1121):
// it goes to the gateway as the portal wrote it.
func gpVersionOK(v string) bool {
	if v == "" || len(v) > 24 || v[0] < '0' || v[0] > '9' {
		return false
	}
	for _, r := range v {
		if (r < '0' || r > '9') && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

// gpConfigWhy says why a gateway's config has no address: its error text,
// else the names of what it did send (names, never values).
func gpConfigWhy(b []byte) string {
	for _, tag := range []string{"error", "msg"} {
		if v := gpTag(b, tag); v != "" {
			return gpWhy([]byte(v))
		}
	}
	var names []string
	d := xml.NewDecoder(bytes.NewReader(b))
	for depth := 0; len(names) < 16; {
		tok, err := d.Token()
		if err != nil {
			break
		}
		switch e := tok.(type) {
		case xml.StartElement:
			if depth++; depth <= 2 {
				name := e.Name.Local
				for _, a := range e.Attr {
					if a.Name.Local == "status" {
						name += " status=" + a.Value
					}
				}
				names = append(names, name)
			}
		case xml.EndElement:
			depth--
		}
	}
	if len(names) == 0 {
		return gpWhy([]byte(fmt.Sprintf("its answer was %d bytes, not a config", len(b))))
	}
	return gpWhy([]byte("it sent: " + strings.Join(names, ", ")))
}

// gpPrelogin is how a portal or gateway logs in: with a browser sign-in
// when Request is set, else with a user name and password.
type gpPrelogin struct {
	Status  string `xml:"status"`
	Msg     string `xml:"msg"`
	Region  string `xml:"region"`
	Method  string `xml:"saml-auth-method"`
	Request string `xml:"saml-request"`
}

// gpPreloginAt asks the host's portal ("global-protect") or gateway
// ("ssl-vpn") side how it logs in. there is false when the host has no
// such side. cas-support is what lets a portal with the Cloud
// Authentication Service answer at all; default-browser asks for the
// sign-in that ends on a globalprotectcallback: address.
func gpPreloginAt(ctx context.Context, hc *http.Client, u *url.URL, side string) (pre gpPrelogin, there bool, err error) {
	form := url.Values{"tmp": {"tmp"}, "clientVer": {"4100"}, "clientos": {gpOS()}, "os-version": {gpOS()},
		"default-browser": {"1"}, "cas-support": {"yes"}}
	status, b, err := gpPost(ctx, hc, u, "/"+side+"/prelogin.esp", form)
	if err != nil {
		return pre, false, err
	}
	if status != http.StatusOK || xml.Unmarshal(b, &pre) != nil {
		return gpPrelogin{}, false, nil
	}
	if !strings.EqualFold(strings.TrimSpace(pre.Status), "success") {
		if strings.Contains(pre.Msg, "does not exist") {
			return gpPrelogin{}, false, nil
		}
		return pre, true, &LoginError{Msg: fmt.Sprintf("%s refused to start a login%s", u.Hostname(), gpWhy([]byte(pre.Msg)))}
	}
	pre.Request, pre.Region = strings.TrimSpace(pre.Request), strings.TrimSpace(pre.Region)
	return pre, true, nil
}

// gpAsk gets the login a portal or gateway wants: a browser sign-in, or
// the stored user name and password (typed, when not stored).
func gpAsk(ctx context.Context, o Options, pre gpPrelogin) (gpCred, error) {
	if pre.Request != "" {
		return gpBrowserLogin(ctx, o, pre)
	}
	c := gpCred{User: o.User, Password: o.Password}
	var err error
	if c.User == "" {
		if o.Prompt == nil {
			return c, ErrNeedsPerson
		}
		if c.User, err = o.Prompt("User name", false); err != nil {
			return c, err
		}
	}
	if c.Password == "" {
		if o.Prompt == nil {
			return c, ErrNeedsPerson
		}
		if c.Password, err = o.Prompt("Password for "+c.User, true); err != nil {
			return c, err
		}
	}
	return c, nil
}

// gpBrowserLogin shows the sign-in page to a person and reads the login
// from the address it ends on.
func gpBrowserLogin(ctx context.Context, o Options, pre gpPrelogin) (gpCred, error) {
	if o.Browser == nil {
		return gpCred{}, ErrNeedsPerson
	}
	raw, err := base64.StdEncoding.DecodeString(pre.Request)
	if err != nil {
		return gpCred{}, &LoginError{Msg: "the VPN's sign-in page could not be read"}
	}
	var page BrowserPage
	switch strings.ToUpper(strings.TrimSpace(pre.Method)) {
	case "REDIRECT":
		su, err := url.Parse(strings.TrimSpace(string(raw)))
		if err != nil || su.Scheme != "https" || su.Host == "" {
			return gpCred{}, &LoginError{Msg: "the VPN's sign-in address is not an https address"}
		}
		page.URL = su.String()
	case "POST":
		page.HTML = string(raw)
	default:
		return gpCred{}, &LoginError{Msg: "the VPN asks for a kind of browser sign-in komando does not know"}
	}
	back, err := o.Browser(ctx, page)
	if err != nil {
		return gpCred{}, err
	}
	return parseGPCallback(back)
}

// GPCallbackOK reports whether s is the address a browser sign-in ends on,
// with a login in it. A sign-in page may name the bare prefix in a script
// before the sign-in ends; that is not it.
func GPCallbackOK(s string) bool {
	_, err := parseGPCallback(s)
	return err == nil
}

// gpCallbackShape describes an answer komando could not use, without its
// values: the field names, which are not secret.
func gpCallbackShape(s string) string {
	var names []string
	if strings.HasPrefix(s, "cas-as") || strings.Contains(s, "=") && strings.Contains(s, "&") {
		for _, kv := range strings.Split(s, "&") {
			k, _, _ := strings.Cut(kv, "=")
			if len(k) > 30 {
				k = k[:30]
			}
			names = append(names, k)
		}
	} else if page, err := base64.StdEncoding.DecodeString(s); err == nil {
		for _, tag := range []string{"saml-auth-status", "saml-username", "prelogin-cookie", "portal-userauthcookie", "saml-slo"} {
			if bytes.Contains(page, []byte("<"+tag+">")) {
				names = append(names, tag)
			}
		}
		if st := gpTag(page, "saml-auth-status"); st != "" && len(st) < 6 {
			names = append(names, "status "+st)
		}
	}
	if len(names) > 12 {
		names = names[:12]
	}
	why := fmt.Sprintf("%d characters", len(s))
	if len(names) > 0 {
		why += "; fields: " + strings.Join(names, ", ")
	}
	if why = strings.TrimPrefix(gpWhy([]byte(why)), ": "); why == "" { // a name with markup in it
		why = fmt.Sprintf("%d characters", len(s))
	}
	return why
}

// parseGPCallback reads the login from the address a browser sign-in ends
// on. Two forms: "cas-as=1&un=USER&token=TOKEN" from the Cloud
// Authentication Service, and base64 of a page whose comments carry
// saml-auth-status, saml-username and a prelogin-cookie or
// portal-userauthcookie.
func parseGPCallback(s string) (gpCred, error) {
	s = strings.TrimLeft(strings.TrimPrefix(strings.TrimSpace(s), GPCallback), "/")
	var c gpCred
	if strings.HasPrefix(s, "cas-as") {
		if !strings.Contains(s, "&") { // the whole answer percent-encoded
			if d, err := url.PathUnescape(s); err == nil {
				s = d
			}
		}
		for _, kv := range strings.Split(s, "&") {
			k, v, _ := strings.Cut(kv, "=")
			if d, err := url.PathUnescape(v); err == nil { // not QueryUnescape: a + stays a +
				v = d
			}
			switch k {
			case "un", "username":
				c.User = v
			case "token":
				c.Token = v
			case "preloginCookie", "prelogin-cookie":
				c.PreloginCookie = v
			case "portalUserauthcookie", "portal-userauthcookie":
				c.PortalCookie = v
			}
		}
	} else {
		var page []byte
		var err error
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if page, err = enc.DecodeString(s); err == nil {
				break
			}
		}
		if err != nil || len(page) == 0 {
			return gpCred{}, &LoginError{Msg: "the sign-in did not end with a GlobalProtect login (" + gpCallbackShape(s) + ")"}
		}
		if st := gpTag(page, "saml-auth-status"); st != "1" {
			return gpCred{}, &LoginError{Msg: "the sign-in service refused the login"}
		}
		c = gpCred{User: gpTag(page, "saml-username"), PreloginCookie: gpTag(page, "prelogin-cookie"), PortalCookie: gpTag(page, "portal-userauthcookie")}
	}
	if c.User == "" || !c.usable() || strings.ContainsFunc(c.User, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return gpCred{}, &LoginError{Msg: "the sign-in did not end with a GlobalProtect login (" + gpCallbackShape(s) + ")"}
	}
	return c, nil
}

// gpTag is the text between <name> and </name>.
func gpTag(b []byte, name string) string {
	_, rest, ok := bytes.Cut(b, []byte("<"+name+">"))
	if !ok {
		return ""
	}
	v, _, ok := bytes.Cut(rest, []byte("</"+name+">"))
	if !ok {
		return ""
	}
	return strings.TrimSpace(string(v))
}

// gpPortal is the part of a portal's config komando uses.
type gpPortal struct {
	Cookie   string `xml:"portal-userauthcookie"`
	Version  string `xml:"version"`
	Gateways []struct {
		Name  string `xml:"name,attr"`
		Rules []struct {
			Region   string `xml:"name,attr"`
			Priority string `xml:"priority"`
		} `xml:"priority-rule>entry"`
	} `xml:"gateways>external>list>entry"`
}

// gateways are the portal's gateways, best first: the lowest priority
// number among a gateway's rules for this region or for Any; gateways
// without such a rule keep the portal's order, after the others.
func (p gpPortal) gateways(region string) []string {
	type gw struct {
		name string
		prio int
	}
	var all []gw
	for _, g := range p.Gateways {
		name := strings.TrimSpace(g.Name)
		if name == "" {
			continue
		}
		prio := math.MaxInt
		for _, r := range g.Rules {
			n, err := strconv.Atoi(strings.TrimSpace(r.Priority))
			if err != nil || n <= 0 || n >= prio {
				continue
			}
			if strings.EqualFold(r.Region, "Any") || (region != "" && strings.EqualFold(r.Region, region)) {
				prio = n
			}
		}
		all = append(all, gw{name, prio})
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].prio < all[j].prio })
	names := make([]string, len(all))
	for i, g := range all {
		names[i] = g.name
	}
	return names
}

// GlobalProtectLogin logs in to the portal, takes the best gateway that
// answers from its list and logs in there. A host that is no portal is
// logged in to as a gateway.
func GlobalProtectLogin(ctx context.Context, o Options) (GPSession, error) {
	u, err := portalURL(o.Portal)
	if err != nil {
		return GPSession{}, err
	}
	hc, err := httpClient(o, u.Hostname())
	if err != nil {
		return GPSession{}, err
	}
	pre, portal, err := gpPreloginAt(ctx, hc, u, "global-protect")
	if err != nil {
		return GPSession{}, err
	}
	if !portal {
		return gpGatewayLogin(ctx, o, u, gpCred{}, gpCred{})
	}
	cred, err := gpAsk(ctx, o, pre)
	if err != nil {
		return GPSession{}, err
	}
	b, err := gpAuthPost(ctx, o, hc, u, "/global-protect/getconfig.esp", gpForm(u.Hostname(), cred))
	if err != nil {
		return GPSession{}, err
	}
	var cfg gpPortal
	if err := xml.Unmarshal(b, &cfg); err != nil {
		return GPSession{}, &LoginError{Msg: "the portal's list of gateways could not be read"}
	}
	// the portal's cookie logs in to its gateways. What a browser sign-in
	// gave is offered to a gateway too, after the cookie or without one:
	// neither is a password, so a second try costs nothing
	var alt gpCred
	if ck := strings.TrimSpace(cfg.Cookie); ck != "" && ck != "empty" && ck != "(null)" {
		if cred.Token != "" || cred.PreloginCookie != "" {
			alt = gpCred{User: cred.User, Token: cred.Token, PreloginCookie: cred.PreloginCookie}
		}
		cred = gpCred{User: cred.User, Password: cred.Password, PortalCookie: ck}
	}
	names := cfg.gateways(pre.Region)
	if len(names) == 0 {
		names = []string{u.Host}
	}
	var last error
	for _, name := range names {
		gu, err := portalURL(name)
		if err != nil {
			last = fmt.Errorf("the portal names a gateway komando cannot use: %w", err)
			continue
		}
		s, err := gpGatewayLogin(ctx, o, gu, cred, alt)
		if err == nil {
			s.Gateway = gu.Host
			if v := strings.TrimSpace(cfg.Version); gpVersionOK(v) {
				s.AppVersion = v
			}
			var others []string
			for _, n := range names {
				if ou, err := portalURL(n); err == nil && ou.Host != gu.Host && len(others) < 6 {
					others = append(others, ou.Host)
				}
			}
			s.Others = strings.Join(others, ",")
			return s, nil
		}
		// only a gateway that cannot be reached is skipped: a refused login
		// is not tried again on the next one
		var ue *url.Error
		if ctx.Err() != nil || !errors.As(err, &ue) {
			return GPSession{}, err
		}
		last = err
	}
	return GPSession{}, last
}

// what names a login for a notice, without its value.
func (c gpCred) what() string {
	switch {
	case c.PortalCookie != "":
		return "the portal's cookie"
	case c.Token != "":
		return "the sign-in's token"
	case c.PreloginCookie != "":
		return "the sign-in's cookie"
	}
	return "the password"
}

// gpGatewayLogin logs in to a gateway with cred, then with alt when the
// gateway refuses cred (alt is never a password). Without a usable cred,
// or when the gateway refuses both and has a browser sign-in of its own,
// the person logs in to the gateway itself.
func gpGatewayLogin(ctx context.Context, o Options, gw *url.URL, cred, alt gpCred) (GPSession, error) {
	hc, err := httpClient(o, gw.Hostname())
	if err != nil {
		return GPSession{}, err
	}
	asked := false
	if !cred.usable() {
		pre, _, err := gpPreloginAt(ctx, hc, gw, "ssl-vpn")
		if err != nil {
			return GPSession{}, err
		}
		if cred, err = gpAsk(ctx, o, pre); err != nil {
			return GPSession{}, err
		}
		asked = true
	}
	tried := []string{}
	for {
		var s GPSession
		tried = append(tried, cred.what())
		b, err := gpAuthPost(ctx, o, hc, gw, "/ssl-vpn/login.esp", gpForm(gw.Hostname(), cred))
		if err == nil {
			s, err = parseGPLogin(b)
		}
		if err == nil {
			s.User = firstNonEmptyS(s.User, cred.User)
			return s, nil
		}
		var le *LoginError
		if asked || !errors.As(err, &le) {
			return GPSession{}, err
		}
		if alt.usable() {
			cred, alt = alt, gpCred{}
			continue
		}
		pre, _, perr := gpPreloginAt(ctx, hc, gw, "ssl-vpn")
		if perr != nil || pre.Request == "" {
			return GPSession{}, err // a password is not sent twice
		}
		if o.Notice != nil {
			o.Notice("gateway " + gw.Hostname() + " did not take " + strings.Join(tried, " or ") + " (" + le.Msg + "): it has a sign-in of its own, so sign in once more")
		}
		if cred, err = gpBrowserLogin(ctx, o, pre); err != nil {
			return GPSession{}, err
		}
		asked = true
	}
}

// parseGPLogin reads the jnlp answer: an argument list whose positions
// carry the cookie, portal, user, domain and computer.
func parseGPLogin(b []byte) (GPSession, error) {
	var j struct {
		Args []string `xml:"application-desc>argument"`
	}
	if err := xml.Unmarshal(b, &j); err != nil || len(j.Args) < 5 {
		return GPSession{}, &LoginError{Msg: "the VPN refused the login"}
	}
	at := func(i int) string {
		if i < len(j.Args) {
			return strings.TrimSpace(j.Args[i])
		}
		return ""
	}
	s := GPSession{AuthCookie: at(1), Portal: at(3), User: at(4), Domain: at(7), Computer: "komando"}
	if s.AuthCookie == "" || s.AuthCookie == "(null)" {
		return GPSession{}, &LoginError{Msg: "the VPN gave no session cookie"}
	}
	return s, nil
}

func gpChallengeText(b []byte) string {
	if i := bytes.Index(b, []byte("respMsg = \"")); i >= 0 {
		rest := b[i+len("respMsg = \""):]
		if j := bytes.IndexByte(rest, '"'); j >= 0 {
			return string(rest[:j])
		}
	}
	return "Code"
}

func gpInputStr(b []byte) string {
	if i := bytes.Index(b, []byte("inputStr = \"")); i >= 0 {
		rest := b[i+len("inputStr = \""):]
		if j := bytes.IndexByte(rest, '"'); j >= 0 {
			return string(rest[:j])
		}
	}
	return ""
}
