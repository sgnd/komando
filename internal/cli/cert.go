package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// certRoots is the trust store used to verify served chains; nil means the
// system's. Tests set their own.
var certRoots *x509.CertPool

// certNow is the clock the expiry is measured against (tests fix it).
var certNow = time.Now

func certCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "cert",
		Aliases: []string{"certs", "tls"},
		Short:   "TLS certificates: when do they expire, and do they verify",
	}
	c.AddCommand(certCheckCmd())
	return c
}

func certCheckCmd() *cobra.Command {
	var warn, via string
	var paths []string
	c := &cobra.Command{
		Use:   "check TARGET...",
		Short: "Certificate expiry on servers (certbot, nginx, haproxy, apache) and of websites",
		Long: `Reads certificates and says when they expire. It only reads.

A server (or @group, tag:, ...): komando looks for the certificates the
server uses: certbot's /etc/letsencrypt/live/*/cert.pem and the files that
nginx (ssl_certificate), haproxy (crt) and apache (SSLCertificateFile) name,
plus any --path. Files that need root are read with sudo only when sudo
works without a password; komando never asks for one. Only the CERTIFICATE
blocks of a file leave the server: a private key in the same file never
does. When certbot is there, the state of its renewal timer is shown too.

A website (https://example.com, example.com:443) or a conn that uses TLS:
komando connects from this computer (or through --via, or the conn's own
--via), reads the certificate the server sends and checks that it is
trusted and matches the name.

A certificate that expires within --warn (default 30d), has expired, is not
trusted, or a certbot renewal that failed is a problem: the command then
exits 1 (code CERT_PROBLEMS), like ` + "`komando doctor`" + `.`,
		Example: `  komando cert check web1
  komando cert check @prod --warn 14d
  komando cert check https://shop.example.com api.example.com:8443
  komando cert check https://intranet.local --via bastion
  komando cert check web1 --path /etc/ssl/private/site.pem`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			w, err := parseAge(warn, "--warn")
			if err != nil {
				e := toErr(err)
				e.Hint = "for example: komando cert check @prod --warn 14d"
				return e
			}
			for _, p := range paths {
				if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\n\r\x00") {
					return out.Usage("--path takes an absolute path on the server (got %q)", p)
				}
			}
			return runCertCheck(cmd.Context(), args, certOpts{warn: w, warnText: warn, via: via, paths: paths})
		},
	}
	spanText(c.Flags(), &warn, "warn", "30d", true, "flag certificates that expire within this time (e.g. 30d, 72h)")
	c.Flags().StringVar(&via, "via", "", "reach websites through this server or VPN (a --via path)")
	c.Flags().StringSliceVar(&paths, "path", nil, "also check this certificate file (or folder) on the servers")
	return c
}

type certOpts struct {
	warn     time.Duration
	warnText string
	via      string
	paths    []string
}

// certInfo is one certificate: where it was found and what it says.
type certInfo struct {
	Sources     []string  `json:"sources,omitempty"` // nginx, certbot, haproxy, apache, path
	Path        string    `json:"path,omitempty"`    // file on the server
	Address     string    `json:"address,omitempty"` // host:port it was served from
	Subject     string    `json:"subject,omitempty"`
	Names       []string  `json:"names,omitempty"` // DNS names and IPs it is valid for
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	DaysLeft    int       `json:"days_left"`
	Chain       int       `json:"chain,omitempty"`    // certificates in the file or the served chain
	Verified    *bool     `json:"verified,omitempty"` // served chains only
	VerifyError string    `json:"verify_error,omitempty"`
	Status      string    `json:"status"` // ok | expiring | expired | not_yet_valid | not_trusted | unreadable | no_certificate
	Problem     string    `json:"problem,omitempty"`
}

type unitState struct {
	Unit   string `json:"unit"`
	Active string `json:"active"`
	Result string `json:"result,omitempty"`
}

type certbotState struct {
	Renewal []unitState `json:"renewal"`
	Cron    bool        `json:"cron,omitempty"`
	Problem string      `json:"problem,omitempty"`
}

type certTarget struct {
	Target  string        `json:"target"`
	Kind    string        `json:"kind"` // host | url | conn
	OK      bool          `json:"ok"`
	Certs   []certInfo    `json:"certs"`
	Certbot *certbotState `json:"certbot,omitempty"`
	Notes   []string      `json:"notes,omitempty"`
	Error   *out.Error    `json:"error,omitempty"`
}

type certSummary struct {
	Targets    int `json:"targets"`
	Certs      int `json:"certs"`
	OK         int `json:"ok"`
	Expiring   int `json:"expiring"`
	Expired    int `json:"expired"`
	NotTrusted int `json:"not_trusted"`
	Unchecked  int `json:"unchecked"`
	Failed     int `json:"failed"` // targets komando could not reach or read
}

type certData struct {
	Warn     string       `json:"warn"`
	WarnDays int          `json:"warn_days"`
	Results  []certTarget `json:"results"`
	Summary  certSummary  `json:"summary"`
}

func (d certData) Text() string {
	var rows [][]string
	var tail []string
	for _, r := range d.Results {
		if r.Error != nil {
			rows = append(rows, []string{r.Target, "-", "-", "-", "-", "error: " + r.Error.Message})
			continue
		}
		for _, c := range r.Certs {
			where := c.Path
			if where == "" {
				where = c.Address
			}
			if len(c.Sources) > 0 && c.Sources[0] != "url" {
				where += " (" + strings.Join(c.Sources, ", ") + ")"
			}
			names := strings.Join(c.Names, ", ")
			if names == "" {
				names = c.Subject
			}
			exp, days := "-", "-"
			if !c.NotAfter.IsZero() {
				exp, days = c.NotAfter.UTC().Format("2006-01-02"), strconv.Itoa(c.DaysLeft)
			}
			status := c.Status
			if c.Problem != "" && c.Status != "ok" {
				status += ": " + c.Problem
			}
			rows = append(rows, []string{r.Target, where, names, exp, days, status})
		}
		if len(r.Certs) == 0 {
			rows = append(rows, []string{r.Target, "-", "-", "-", "-", "no certificates found"})
		}
		if cb := r.Certbot; cb != nil {
			var parts []string
			for _, u := range cb.Renewal {
				s := u.Unit + " " + u.Active
				if u.Result != "" && u.Result != "success" {
					s += " (" + u.Result + ")"
				}
				parts = append(parts, s)
			}
			if cb.Cron {
				parts = append(parts, "cron job")
			}
			line := r.Target + ": certbot renewal: " + strings.Join(parts, ", ")
			if len(parts) == 0 {
				line = r.Target + ": certbot renewal: no timer or cron job found"
			}
			if cb.Problem != "" {
				line += "  PROBLEM: " + cb.Problem
			}
			tail = append(tail, line)
		}
		for _, n := range r.Notes {
			tail = append(tail, r.Target+": "+n)
		}
	}
	s := textTable([]string{"target", "where", "names", "expires", "days", "status"}, rows)
	if len(tail) > 0 {
		s += "\n" + strings.Join(tail, "\n") + "\n"
	}
	return s
}

// certURL is a website or TLS conn to connect to.
type certURL struct {
	target     string // as given (or the conn's name)
	kind       string // url | conn
	address    string // host:port
	serverName string
	via        string
}

func runCertCheck(ctx context.Context, args []string, o certOpts) error {
	st, err := loadState()
	if err != nil {
		return err
	}
	if o.via != "" {
		if _, _, err := resolveVia(st, o.via); err != nil {
			return err
		}
	}
	var hosts []*store.Host
	var urls []certURL
	seen := map[string]bool{}
	for _, a := range args {
		if addr, sn, ok, err := parseCertURL(st, a); err != nil {
			return err
		} else if ok {
			urls = append(urls, certURL{target: a, kind: "url", address: addr, serverName: sn, via: o.via})
			continue
		}
		sel, err := resolveSelection(st, a)
		if err != nil {
			e := toErr(err)
			if !strings.Contains(a, ".") || e.Exit != out.ExitNotFound {
				return e
			}
			e.Hint = "for a website write https://" + a + " or " + a + ":443"
			return e.Say(fmt.Sprintf("Nothing named %q in your list to check.", a), e.Hint)
		}
		for _, h := range sel.Hosts {
			if !seen["h:"+h.Name] {
				seen["h:"+h.Name] = true
				hosts = append(hosts, h)
			}
		}
		for _, c := range sel.Conns {
			if seen["c:"+c.Name] {
				continue
			}
			seen["c:"+c.Name] = true
			t, err := driver.Parse(c.URL)
			if err != nil || !t.Secure || t.Address == "" {
				out.P.Skip(out.Skipped{Name: c.Name, Kind: c.Kind, Reason: "does not use TLS (or its URL has no address)"})
				continue
			}
			host, _, _ := net.SplitHostPort(t.Address)
			v := c.Via
			if o.via != "" {
				v = o.via
			}
			urls = append(urls, certURL{target: c.Name, kind: "conn", address: t.DialAddress(), serverName: host, via: v})
		}
		skipVpns(sel.Vpns)
	}
	if err := certTargetsFit(ctx, hosts, urls, o); err != nil {
		return err
	}
	if g.dryRun {
		plan := map[string]any{"hosts": hostNames(hosts), "warn": o.warnText}
		if len(hosts) > 0 {
			plan["would_read"] = append([]string{"certbot, nginx, haproxy and apache certificate files (CERTIFICATE blocks only)"}, o.paths...)
		}
		var conns []map[string]any
		for _, u := range urls {
			conns = append(conns, map[string]any{"target": u.target, "address": u.address, "via": u.via})
		}
		if conns != nil {
			plan["would_connect"] = conns
		}
		out.P.Print("cert.check", plan, nil)
		return nil
	}

	data := certData{Warn: o.warnText, WarnDays: int(o.warn.Hours() / 24), Results: []certTarget{}}
	maxOut := max(maxOutput(st), 4<<20)
	for _, oc := range fanout(ctx, st, hosts, func(ctx context.Context, c *sshx.Client) (any, error) {
		return checkHostCerts(ctx, c, o, cmdTimeout(st), maxOut)
	}) {
		r := certTarget{Target: oc.Host.Name, Kind: "host", Certs: []certInfo{}}
		if oc.Err != nil {
			r.Error = toErr(oc.Err)
		} else {
			r = oc.Value.(certTarget)
			r.Target = oc.Host.Name
			if r.Certbot != nil {
				r.Certbot.Problem = strings.ReplaceAll(r.Certbot.Problem, "logs TARGET", "logs "+oc.Host.Name)
			}
		}
		data.Results = append(data.Results, r)
	}
	urlRes := make([]certTarget, len(urls))
	var wg sync.WaitGroup
	sem := make(chan struct{}, max(1, parallelism(st)))
	for i, u := range urls {
		wg.Add(1)
		go func(i int, u certURL) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := certTarget{Target: u.target, Kind: u.kind, Certs: []certInfo{}}
			ci, err := checkServedCert(ctx, st, u)
			if err != nil {
				r.Error = toErr(err)
			} else {
				r.Certs = append(r.Certs, ci)
			}
			urlRes[i] = r
		}(i, u)
	}
	wg.Wait()
	data.Results = append(data.Results, urlRes...)

	worst := 0
	problems := false
	var names, bad []string
	for i := range data.Results {
		r := &data.Results[i]
		names = append(names, r.Target)
		data.Summary.Targets++
		if r.Error != nil {
			data.Summary.Failed++
			worst = worse(worst, r.Error.Exit)
			bad = append(bad, r.Target+" ("+failReason(0, r.Error)+")")
			continue
		}
		r.OK = true
		for j := range r.Certs {
			c := &r.Certs[j]
			rateCert(c, o.warn)
			data.Summary.Certs++
			switch c.Status {
			case "ok":
				data.Summary.OK++
			case "expiring":
				data.Summary.Expiring++
			case "expired", "not_yet_valid":
				data.Summary.Expired++
			case "not_trusted":
				data.Summary.NotTrusted++
			default:
				data.Summary.Unchecked++
			}
			if certProblem(c.Status) {
				r.OK = false
			}
		}
		if r.Certbot != nil && r.Certbot.Problem != "" {
			r.OK = false
		}
		if !r.OK {
			problems = true
			bad = append(bad, r.Target)
		}
	}
	audit(st, "cert.check", names, "", len(bad) == 0, nil)
	if len(bad) == 0 {
		out.P.Print("cert.check", data, nil)
		return nil
	}
	if problems {
		worst = worse(worst, out.ExitError)
	}
	code := "CERT_PROBLEMS"
	hint := "renew or replace the certificates marked expiring, expired or not_trusted; see each result"
	soft := &out.Error{Code: code, Exit: worst, Hint: hint,
		Message: fmt.Sprintf("%d of %d targets need attention: %s", len(bad), data.Summary.Targets, strings.Join(bad, ", "))}
	if !problems {
		soft.Code, soft.Hint = "PARTIAL_FAILURE", "see each result's error and hint"
		if data.Summary.Targets == 1 { // one target: its own error, code and hint
			e := data.Results[0].Error
			soft.Code, soft.Message, soft.Hint = e.Code, withHost(data.Results[0].Target, e.Message), e.Hint
		}
	}
	out.P.Print("cert.check", data, soft)
	return exitCode(worst)
}

// certTargetsFit refuses, before anything runs, targets that cannot be
// checked and flags that would do nothing for them.
func certTargetsFit(ctx context.Context, hosts []*store.Host, urls []certURL, o certOpts) error {
	if len(hosts)+len(urls) == 0 {
		return out.Errf(out.ExitNotFound, "NO_MATCHING_TARGETS", "give a server, a TLS conn or a website (https://NAME)", "nothing to check")
	}
	if _, err := windowsGate(ctx, "cert.check", hosts, false); err != nil {
		return err
	}
	if len(o.paths) > 0 && len(hosts) == 0 {
		return out.Usage("--path reads files on servers, and no target here is a server")
	}
	if o.via != "" && len(urls) == 0 {
		return out.Usage("--via is for websites and conns; komando reaches the servers directly")
	}
	return nil
}

func certProblem(status string) bool {
	return oneOf(status, "expiring", "expired", "not_yet_valid", "not_trusted")
}

// rateCert sets days_left and the status from the dates and verification.
// A file komando could not read keeps its status.
func rateCert(c *certInfo, warn time.Duration) {
	if c.NotAfter.IsZero() {
		return
	}
	now := certNow()
	left := c.NotAfter.Sub(now)
	c.DaysLeft = int(math.Floor(left.Hours() / 24))
	switch {
	case left <= 0:
		c.Status, c.Problem = "expired", "expired "+c.NotAfter.UTC().Format("2006-01-02")
	case now.Before(c.NotBefore):
		c.Status, c.Problem = "not_yet_valid", "valid only from "+c.NotBefore.UTC().Format("2006-01-02")
	case c.Verified != nil && !*c.Verified:
		c.Status, c.Problem = "not_trusted", c.VerifyError
	case left < warn:
		c.Status, c.Problem = "expiring", fmt.Sprintf("expires in %d days", c.DaysLeft)
	default:
		c.Status, c.Problem = "ok", ""
	}
}

// certFields reads what a person needs from a certificate.
func certFields(c *x509.Certificate) certInfo {
	names := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	subject := c.Subject.CommonName
	if subject == "" {
		subject = c.Subject.String()
	}
	issuer := c.Issuer.CommonName
	if o := c.Issuer.Organization; len(o) > 0 && issuer != "" {
		issuer = o[0] + " (" + issuer + ")"
	} else if issuer == "" {
		issuer = c.Issuer.String()
	}
	return certInfo{Subject: subject, Names: names, Issuer: issuer, NotBefore: c.NotBefore, NotAfter: c.NotAfter}
}

// Certificates on a server.

// certDiscoverScript finds the certificates a server uses. It prints only
// file names and the certificate lines of the configs, never the configs
// or any file's content. sudo is used only when it works without a
// password (sudo -n); nothing ever waits for one.
const certDiscoverScript = `S=""
if [ "$(id -u)" != 0 ] && sudo -n true 2>/dev/null; then S="sudo -n"; fi
echo "== root"
if [ "$(id -u)" = 0 ] || [ -n "$S" ]; then echo yes; else echo no; fi
echo "== certbot"
if command -v certbot >/dev/null 2>&1 || [ -d /etc/letsencrypt ]; then echo present; fi
echo "== certbot-live"
$S find /etc/letsencrypt/live -mindepth 2 -maxdepth 2 -name cert.pem 2>/dev/null
echo "== units"
systemctl show -p Id,LoadState,ActiveState,Result certbot.timer certbot.service snap.certbot.renew.timer snap.certbot.renew.service 2>/dev/null
echo "== cron"
ls /etc/cron.d/certbot 2>/dev/null; grep -ls certbot /etc/crontab /var/spool/cron/crontabs/root /var/spool/cron/root 2>/dev/null
echo "== nginx"
if command -v nginx >/dev/null 2>&1 || [ -d /etc/nginx ]; then { $S nginx -T 2>/dev/null || $S cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null; } | grep -E '^[[:space:]]*ssl_certificate[[:space:]]'; fi
echo "== haproxy"
$S cat /etc/haproxy/haproxy.cfg 2>/dev/null | grep -E '[[:space:]]crt[[:space:]]' | grep -v '^[[:space:]]*#'
echo "== apache"
$S cat /etc/apache2/apache2.conf /etc/apache2/sites-enabled/* /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf 2>/dev/null | grep -iE '^[[:space:]]*SSLCertificateFile[[:space:]]'
true
`

// certBlocksAwk prints only the CERTIFICATE blocks of a PEM file: lines of
// any other block (a private key) are never printed.
const certBlocksAwk = `awk '{sub(/\r$/,"")} /^-----BEGIN /{p=($0=="-----BEGIN CERTIFICATE-----")} p{print} /^-----END /{p=0}'`

// certReadScript reads the certificate blocks of the files (a folder: the
// files in it, as haproxy's crt allows).
func certReadScript(paths []string) string {
	var b strings.Builder
	b.WriteString("S=\"\"\nif [ \"$(id -u)\" != 0 ] && sudo -n true 2>/dev/null; then S=\"sudo -n\"; fi\n")
	for _, p := range paths {
		fmt.Fprintf(&b, "echo %s\n", sshx.Q("== path "+p))
		fmt.Fprintf(&b, "$S find -L %s -maxdepth 1 -type f 2>/dev/null | head -n 50 | while IFS= read -r f; do echo \"== file $f\"; $S %s \"$f\" 2>/dev/null | head -n 3000; done\n",
			sshx.Q(p), certBlocksAwk)
	}
	b.WriteString("true\n")
	return b.String()
}

// sections splits "== name" headed output into its sections, in order.
type section struct{ name, body string }

func splitSections(s string) []section {
	var res []section
	for _, line := range strings.Split(s, "\n") {
		if name, ok := strings.CutPrefix(line, "== "); ok {
			res = append(res, section{name: name})
			continue
		}
		if len(res) > 0 {
			res[len(res)-1].body += line + "\n"
		}
	}
	return res
}

func sectionMap(s string) map[string]string {
	m := map[string]string{}
	for _, sec := range splitSections(s) {
		m[sec.name] += sec.body
	}
	return m
}

// discovered is what certDiscoverScript found.
type discovered struct {
	root    bool
	certbot *certbotState
	paths   []string            // in order
	sources map[string][]string // path -> who uses it
	notes   []string
}

func parseCertDiscovery(s string) discovered {
	m := sectionMap(s)
	d := discovered{root: strings.TrimSpace(m["root"]) == "yes", sources: map[string][]string{}}
	add := func(p, src string) {
		p = strings.Trim(p, `"'`)
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "$ \t") {
			return // a variable ($ssl_server_name) or a relative path: cannot follow
		}
		if _, ok := d.sources[p]; !ok {
			d.paths = append(d.paths, p)
		}
		for _, have := range d.sources[p] {
			if have == src {
				return
			}
		}
		d.sources[p] = append(d.sources[p], src)
	}
	for _, l := range lines(m["certbot-live"]) {
		name := strings.TrimSuffix(strings.TrimPrefix(l, "/etc/letsencrypt/live/"), "/cert.pem")
		add(l, "certbot "+name)
	}
	for _, l := range lines(m["nginx"]) {
		f := strings.Fields(strings.TrimSuffix(strings.TrimSpace(l), ";"))
		if len(f) >= 2 && f[0] == "ssl_certificate" {
			add(strings.TrimSuffix(f[1], ";"), "nginx")
		}
	}
	for _, l := range lines(m["haproxy"]) {
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "crt" {
				add(f[i+1], "haproxy")
			}
		}
	}
	for _, l := range lines(m["apache"]) {
		if f := strings.Fields(l); len(f) >= 2 {
			add(f[1], "apache")
		}
	}
	if strings.TrimSpace(m["certbot"]) == "present" {
		cb := &certbotState{Renewal: []unitState{}, Cron: strings.TrimSpace(m["cron"]) != ""}
		for _, u := range parseUnits(m["units"]) {
			cb.Renewal = append(cb.Renewal, u)
			if u.Active == "failed" || (strings.HasSuffix(u.Unit, ".service") && u.Result != "" && u.Result != "success") {
				cb.Problem = "the last renewal failed (" + u.Unit + " " + u.Active + ", " + u.Result + "); read its log with `komando logs TARGET --unit " + u.Unit + "`"
			}
		}
		if cb.Problem == "" && !cb.Cron && !hasActiveTimer(cb.Renewal) {
			d.notes = append(d.notes, "certbot is installed but no renewal timer or cron job was found")
		}
		if len(lines(m["certbot-live"])) == 0 && !d.root {
			d.notes = append(d.notes, "certbot's certificates need root to read: allow passwordless sudo for the login user, or check the website with `komando cert check https://NAME`")
		}
		d.certbot = cb
	}
	return d
}

func hasActiveTimer(us []unitState) bool {
	for _, u := range us {
		if strings.HasSuffix(u.Unit, ".timer") && u.Active == "active" {
			return true
		}
	}
	return false
}

// parseUnits reads `systemctl show -p Id,LoadState,ActiveState,Result`
// (blocks split by an empty line); units that are not there are left out.
func parseUnits(s string) []unitState {
	var res []unitState
	for _, block := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n\n") {
		kv := map[string]string{}
		for _, l := range lines(block) {
			if k, v, ok := strings.Cut(l, "="); ok {
				kv[k] = v
			}
		}
		if kv["Id"] == "" || kv["LoadState"] != "loaded" {
			continue
		}
		u := unitState{Unit: kv["Id"], Active: kv["ActiveState"]}
		if strings.HasSuffix(u.Unit, ".service") {
			u.Result = kv["Result"]
		}
		res = append(res, u)
	}
	return res
}

func lines(s string) []string {
	var res []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			res = append(res, l)
		}
	}
	return res
}

// parseCertFiles reads certReadScript's output: per path, the files and
// their certificate blocks. A path with no readable file is "unreadable";
// a file named directly without a certificate is "no_certificate" (files
// in a folder without one, such as keys, are left out).
func parseCertFiles(s string, sources map[string][]string) []certInfo {
	var res []certInfo
	var curPath string
	var files []section
	flush := func() {
		if curPath == "" {
			return
		}
		src := sources[curPath]
		if len(files) == 0 {
			res = append(res, certInfo{Sources: src, Path: curPath, Status: "unreadable",
				Problem: "missing, or needs root (komando uses sudo only when it needs no password)"})
		}
		for _, f := range files {
			ci, ok := certFromPEM(f.body)
			ci.Sources, ci.Path = src, f.name
			if !ok {
				if f.name != curPath {
					continue // a key or other file in a folder
				}
				ci.Status, ci.Problem = "no_certificate", "no CERTIFICATE block in the file"
			}
			res = append(res, ci)
		}
		curPath, files = "", nil
	}
	for _, sec := range splitSections(s) {
		switch {
		case strings.HasPrefix(sec.name, "path "):
			flush()
			curPath = strings.TrimPrefix(sec.name, "path ")
		case strings.HasPrefix(sec.name, "file "):
			files = append(files, section{name: strings.TrimPrefix(sec.name, "file "), body: sec.body})
		}
	}
	flush()
	return res
}

// certFromPEM reads the first certificate (the server's own) of a PEM
// text; anything that is not a CERTIFICATE block is ignored.
func certFromPEM(s string) (certInfo, bool) {
	rest := []byte(s)
	var first *x509.Certificate
	n := 0
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			continue
		}
		n++
		if first == nil {
			first = c
		}
	}
	if first == nil {
		return certInfo{}, false
	}
	ci := certFields(first)
	ci.Chain = n
	return ci, true
}

func checkHostCerts(ctx context.Context, c *sshx.Client, o certOpts, timeout time.Duration, maxOut int) (any, error) {
	rr, err := sshx.Run(ctx, c, sshx.RunRequest{Command: certDiscoverScript, Timeout: timeout, MaxOutput: maxOut})
	if err != nil {
		return nil, err
	}
	if rr.TimedOut {
		return nil, out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout", "looking for certificates timed out")
	}
	d := parseCertDiscovery(rr.Stdout)
	for _, p := range o.paths {
		if _, ok := d.sources[p]; !ok {
			d.paths = append(d.paths, p)
		}
		d.sources[p] = append(d.sources[p], "path")
	}
	r := certTarget{Kind: "host", Certs: []certInfo{}, Certbot: d.certbot, Notes: d.notes}
	if len(d.paths) > 100 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d certificate paths found; only the first 100 were read", len(d.paths)))
		d.paths = d.paths[:100]
	}
	if len(d.paths) == 0 {
		r.Notes = append(r.Notes, "no certificates found (looked at certbot, nginx, haproxy and apache); name a file with --path")
		return r, nil
	}
	rr, err = sshx.Run(ctx, c, sshx.RunRequest{Command: certReadScript(d.paths), Timeout: timeout, MaxOutput: maxOut})
	if err != nil {
		return nil, err
	}
	if rr.TimedOut {
		return nil, out.Errf(out.ExitTimeout, "TIMEOUT", "raise --timeout", "reading certificates timed out")
	}
	r.Certs = parseCertFiles(rr.Stdout, d.sources)
	sort.SliceStable(r.Certs, func(i, j int) bool { return r.Certs[i].Path < r.Certs[j].Path })
	return r, nil
}
