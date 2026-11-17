package cli

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/sgnd/komando/internal/driver"
	"github.com/sgnd/komando/internal/netx"
)

// The kinds `vpn add` and `conn add` take, with the flags that go with
// each. One table each feeds vpn add's help ("Which flags go with which
// VPN kind"), the flags vpn add refuses for a kind, and the add_kinds list
// of `komando schema vpn add` and `komando schema conn add`, from which an
// app builds its add forms.

// vpnKindSpec is one VPN kind of `vpn add`.
type vpnKindSpec struct {
	kind    string
	title   string // the name people know it by
	family  string // portal, config_file, server_psk, auth_key, system or proxy
	aliases []string
	need    []string          // flags it always needs
	oneOf   [][]string        // it needs at least one flag of each group
	takes   []string          // flags it may take, beyond vpnEveryKind
	notes   map[string]string // what a flag holds for this kind
	browser string            // when `vpn up` opens a browser to sign in; "" never
}

// vpnEveryKind are the vpn add flags every kind takes.
var vpnEveryKind = []string{"check", "mfa", "protected", "label", "group", "tag", "notes", "overwrite"}

// vpnKindSpecs are the kinds in the order help and forms show them.
var vpnKindSpecs = []vpnKindSpec{
	{kind: "wireguard", title: "WireGuard", family: "config_file", need: []string{"config"},
		notes: map[string]string{"config": "the .conf file"}},
	{kind: "openvpn", title: "OpenVPN", family: "config_file", aliases: []string{"pritunl"}, need: []string{"config", "check"},
		takes: []string{"user", "password-ref", "ask-password"}, notes: map[string]string{"config": "the .ovpn file"}},
	vpnPortalSpec("globalprotect", "GlobalProtect", "when the portal signs in through a browser (SAML)"),
	vpnPortalSpec("fortinet", "Fortinet", ""),
	vpnPortalSpec("anyconnect", "Cisco AnyConnect", ""),
	vpnPortalSpec("pulse", "Pulse Secure or Ivanti", ""),
	vpnPortalSpec("f5", "F5 BIG-IP", ""),
	{kind: "l2tp", title: "L2TP/IPsec", family: "server_psk", need: []string{"server", "user"}, oneOf: [][]string{{"psk-ref", "ask-psk"}},
		takes: []string{"password-ref", "ask-password", "legacy-crypto", "allow-pap"}},
	{kind: "ipsec", title: "Cisco IPsec", family: "server_psk", aliases: []string{"cisco", "xauth"}, need: []string{"server"},
		oneOf: [][]string{{"psk-ref", "ask-psk"}}, takes: []string{"id", "user", "password-ref", "ask-password", "legacy-crypto"},
		notes: map[string]string{"id": "the group name", "psk-ref": "the group password"}},
	{kind: "ikev2", title: "IKEv2", family: "server_psk", need: []string{"server"}, oneOf: [][]string{{"psk-ref", "ask-psk", "user"}},
		takes: []string{"password-ref", "ask-password", "id", "remote-id", "ca"},
		notes: map[string]string{"id": "your identity", "remote-id": "the server's identity", "ca": "the server's CA, PEM"}},
	{kind: "tailscale", title: "Tailscale", family: "auth_key", takes: []string{"password-ref", "server"},
		notes:   map[string]string{"password-ref": "the auth key", "server": "a Headscale login server"},
		browser: "without an auth key (--password-ref)"},
	{kind: "system", title: "System VPN", family: "system", need: []string{"check"}, takes: []string{"service"},
		notes: map[string]string{"service": "its name in your computer's settings"}},
	vpnProxySpec("socks", "SOCKS proxy"),
	vpnProxySpec("proxy", "HTTP proxy"),
}

// vpnPortalSpec is a corporate SSL VPN: one portal address and a login.
func vpnPortalSpec(kind, title, browser string) vpnKindSpec {
	return vpnKindSpec{kind: kind, title: title, family: "portal", need: []string{"portal"}, takes: []string{"user", "password-ref", "ask-password"},
		notes: map[string]string{"portal": "the VPN server or portal"}, browser: browser}
}

// vpnProxySpec is a SOCKS or HTTP proxy that is already running.
func vpnProxySpec(kind, title string) vpnKindSpec {
	return vpnKindSpec{kind: kind, title: title, family: "proxy", need: []string{"proxy-address"}, takes: []string{"user", "password-ref", "ask-password"}}
}

// vpnSpec is the spec of kind, which is an ID (never an alias).
func vpnSpec(kind string) (vpnKindSpec, bool) {
	i := slices.IndexFunc(vpnKindSpecs, func(s vpnKindSpec) bool { return s.kind == kind })
	if i < 0 {
		return vpnKindSpec{}, false
	}
	return vpnKindSpecs[i], true
}

// vpnKindWord is the kind a person typed: lower case, an alias resolved.
func vpnKindWord(word string) string {
	word = strings.ToLower(word)
	for _, s := range vpnKindSpecs {
		if slices.Contains(s.aliases, word) {
			return s.kind
		}
	}
	return word
}

// accepts: vpn add takes flag for this kind.
func (s vpnKindSpec) accepts(flag string) bool {
	return slices.Contains(vpnEveryKind, flag) || slices.Contains(s.need, flag) || slices.Contains(s.takes, flag) ||
		slices.ContainsFunc(s.oneOf, func(g []string) bool { return slices.Contains(g, flag) })
}

// optional are the flags it takes that it does not need.
func (s vpnKindSpec) optional() []string {
	var res []string
	for _, f := range append(slices.Clone(s.takes), vpnEveryKind...) {
		if !slices.Contains(s.need, f) && !slices.Contains(res, f) {
			res = append(res, f)
		}
	}
	return res
}

// vpnTakes: vpn add takes flag for kind (an unknown kind takes none).
func vpnTakes(kind, flag string) bool {
	s, ok := vpnSpec(kind)
	return ok && s.accepts(flag)
}

// vpnKindsTaking are the kinds that take flag, for a message.
func vpnKindsTaking(flag string) []string {
	var res []string
	for _, s := range vpnKindSpecs {
		if s.accepts(flag) {
			res = append(res, s.kind)
		}
	}
	return res
}

// vpnAliasLine is the help's "also: pritunl = openvpn; ..." note.
func vpnAliasLine() string {
	var parts []string
	for _, s := range vpnKindSpecs {
		if len(s.aliases) > 0 {
			parts = append(parts, strings.Join(s.aliases, ", ")+" = "+s.kind)
		}
	}
	return "also: " + strings.Join(parts, "; ")
}

// vpnFlagTable is vpn add's "Which flags go with which VPN kind" table:
// kinds with the same flags share a row.
func vpnFlagTable(c *cobra.Command) string {
	const left = 17 // the kinds column: two spaces, the kinds, one space at least
	flag := func(name string) string {
		if f := c.Flags().Lookup(name); f != nil && f.Shorthand != "" {
			return "-" + f.Shorthand
		}
		return "--" + name
	}
	noted := func(s vpnKindSpec, name string) string {
		if n := s.notes[name]; n != "" {
			return flag(name) + " (" + n + ")"
		}
		return flag(name)
	}
	var every []string
	for _, f := range vpnEveryKind {
		every = append(every, flag(f))
	}
	type row struct{ kinds, flags string }
	rows := []row{{"every kind", "takes " + strings.Join(every, ", ")}}
	for _, s := range vpnKindSpecs {
		var need, takes []string
		for _, f := range s.need {
			need = append(need, noted(s, f))
		}
		for _, g := range s.oneOf {
			var alt []string
			for _, f := range g {
				alt = append(alt, noted(s, f))
			}
			need = append(need, strings.Join(alt[:len(alt)-1], ", ")+" or "+alt[len(alt)-1])
		}
		for _, f := range s.takes {
			takes = append(takes, noted(s, f))
		}
		var parts []string
		if len(need) > 0 {
			parts = append(parts, "needs "+joinAnd(need))
		}
		if len(takes) > 0 {
			parts = append(parts, "takes "+strings.Join(takes, ", "))
		}
		text := strings.Join(parts, "; ")
		if last := &rows[len(rows)-1]; last.flags == text {
			last.kinds += ", " + s.kind
			continue
		}
		rows = append(rows, row{s.kind, text})
	}
	lines := []string{"Which flags go with which VPN kind:"}
	for _, r := range rows {
		l := fillWords(r.kinds, left-3, "")
		f := fillWords(r.flags, helpWidth-left, "")
		for i := 0; i < max(len(l), len(f)); i++ {
			k, v := "", ""
			if i < len(l) {
				k = l[i]
			}
			if i < len(f) {
				v = f[i]
			}
			lines = append(lines, strings.TrimRight("  "+k+strings.Repeat(" ", max(1, left-2-len(k)))+v, " "))
		}
	}
	return strings.Join(lines, "\n")
}

// vpnKindSchema is one VPN kind in `komando schema vpn add`.
type vpnKindSchema struct {
	ID           string            `json:"id"`
	DisplayName  string            `json:"display_name"`
	Family       string            `json:"family"`
	Description  string            `json:"description"`
	Aliases      []string          `json:"aliases"`
	Required     []string          `json:"required"`
	OneOf        [][]string        `json:"one_of"`
	Optional     []string          `json:"optional"`
	FlagNotes    map[string]string `json:"flag_notes"`
	OpensBrowser bool              `json:"opens_browser"`
	BrowserNote  string            `json:"browser_note,omitempty"`
}

func vpnKindSchemas() []vpnKindSchema {
	res := make([]vpnKindSchema, 0, len(vpnKindSpecs))
	for _, s := range vpnKindSpecs {
		k := vpnKindSchema{ID: s.kind, DisplayName: s.title, Family: s.family, Description: netx.Kinds[s.kind].Desc,
			Aliases: nonNil(s.aliases), Required: nonNil(s.need), OneOf: nonNil(s.oneOf), Optional: s.optional(), FlagNotes: s.notes,
			OpensBrowser: s.browser != "", BrowserNote: s.browser}
		if k.FlagNotes == nil {
			k.FlagNotes = map[string]string{}
		}
		res = append(res, k)
	}
	return res
}

// connKindTitles are the names people know the conn kinds by.
var connKindTitles = map[string]string{
	"postgres": "PostgreSQL", "mysql": "MySQL or MariaDB", "sqlserver": "SQL Server", "oracle": "Oracle Database",
	"clickhouse": "ClickHouse", "snowflake": "Snowflake", "bigquery": "Google BigQuery", "sqlite": "SQLite", "mongodb": "MongoDB",
	"redis": "Redis or Valkey", "memcached": "Memcached",
	"kafka": "Apache Kafka", "rabbitmq": "RabbitMQ", "nats": "NATS JetStream", "sqs": "Amazon SQS", "pubsub": "Google Cloud Pub/Sub",
	"k8s": "Kubernetes", "registry": "Container registry",
	"s3": "S3 or S3-compatible storage", "ftps": "FTPS", "ftp": "FTP", "sftp": "SFTP", "gcs": "Google Cloud Storage",
	"azblob": "Azure Blob Storage", "webdav": "WebDAV", "smb": "SMB share",
}

// connKindNeeds are the flags `komando FAMILY add` needs for kind k
// (family "" is conn add): a Kubernetes cluster logs in with a whole
// kubeconfig, which only --password-ref gives.
func connKindNeeds(family string, k driver.Kind) []string {
	if family == "cluster" && k.Name == "k8s" {
		return []string{"password-ref"}
	}
	return []string{}
}

// connKindSchema is one conn kind in `komando schema conn add` (and db
// add, cache add, ...).
type connKindSchema struct {
	ID          string     `json:"id"`
	DisplayName string     `json:"display_name"`
	Family      string     `json:"family"`
	URLSchemes  []string   `json:"url_schemes"`
	URLExample  string     `json:"url_example"`
	URLNote     string     `json:"url_note,omitempty"`
	DefaultPort int        `json:"default_port,omitempty"`
	File        bool       `json:"file"`
	Required    []string   `json:"required"`
	OneOf       [][]string `json:"one_of"`
	Optional    []string   `json:"optional"`
}

// connKindSchemas are the kinds c (conn add, or `komando FAMILY add`
// for family) takes, with c's own flags.
func connKindSchemas(c *cobra.Command, family string) []connKindSchema {
	var res []connKindSchema
	for _, k := range driver.Kinds() {
		if family != "" && k.Family != family {
			continue
		}
		need := connKindNeeds(family, k)
		var opt []string
		ownFlags(c).VisitAll(func(f *pflag.Flag) {
			switch {
			case f.Hidden, f.Name == "help", slices.Contains(need, f.Name):
			case f.Name == "via" && k.File: // a file on this computer
			case f.Name == "ask-password" && slices.Contains(need, "password-ref"): // a kubeconfig is not typed
			default:
				opt = append(opt, f.Name)
			}
		})
		example, note, _ := strings.Cut(k.Example, " (")
		res = append(res, connKindSchema{ID: k.Name, DisplayName: connKindTitles[k.Name], Family: k.Family, URLSchemes: k.Schemes,
			URLExample: example, URLNote: strings.TrimSuffix(note, ")"), DefaultPort: k.DefaultPort, File: k.File,
			Required: need, OneOf: [][]string{}, Optional: opt})
	}
	return res
}

// addKindsOf is the add_kinds list of c in `komando schema`, or nil for
// a command that adds no kind.
func addKindsOf(c *cobra.Command) any {
	switch id := cmdID(c); {
	case id == "vpn.add":
		return vpnKindSchemas()
	case id == "conn.add":
		return connKindSchemas(c, "")
	case strings.HasSuffix(id, ".add") && connAddKinds[strings.TrimSuffix(id, ".add")].what != "":
		return connKindSchemas(c, strings.TrimSuffix(id, ".add"))
	}
	return nil
}
