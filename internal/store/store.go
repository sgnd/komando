// Package store keeps komando state (inventory, conns, keys, snippets,
// jobs, tunnels, settings) in the sealed store under $KOMANDO_HOME
// (default ~/.komando).
package store

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/flock"
	"github.com/sgnd/komando/internal/tmpclean"
)

type Host struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Port        int    `json:"port,omitempty"`
	User        string `json:"user,omitempty"`
	Key         string `json:"key,omitempty"`          // name of a key in the keychain
	KeyID       string `json:"key_id,omitempty"`       // that key's record ID (refs.go)
	Identity    string `json:"identity,omitempty"`     // path to a private key file
	PasswordRef string `json:"password_ref,omitempty"` // secret:<name> or env:<VAR>
	SudoRef     string `json:"sudo_ref,omitempty"`     // sudo password ref (secret:/env:)
	Via         string `json:"via,omitempty"`          // the way there: host name(s), comma-separated chain
	// ViaIDs are the record IDs of Via's steps, in order ("" for a step
	// that names no server or VPN); see refs.go
	ViaIDs []string `json:"via_ids,omitempty"`
	// ProxyCommand is a program on this computer whose stdin and stdout
	// carry the SSH connection (OpenSSH ProxyCommand): aws ssm start-session,
	// gcloud compute start-iap-tunnel, cloudflared access ssh. %h %p %r %n.
	ProxyCommand string            `json:"proxy_command,omitempty"`
	Groups       []string          `json:"groups,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Env          map[string]string `json:"env,omitempty"` // exported before every command
	Protected    bool              `json:"protected,omitempty"`
	// ForwardAgent lends the server this computer's ssh-agent while
	// komando is connected (host edit --forward-agent; root there can use
	// the keys in it meanwhile)
	ForwardAgent bool   `json:"forward_agent,omitempty"`
	Notes        string `json:"notes,omitempty"`
	// OS is "windows" for a Windows server: commands are PowerShell, not
	// sh. Empty: Linux or another Unix (docs/features/windows.md).
	OS string `json:"os,omitempty"`
	// Transport is "winrm" for a Windows server reached over WinRM, with
	// its settings in WinRMOpts. Empty: SSH.
	Transport string     `json:"transport,omitempty"`
	WinRMOpts *WinRMOpts `json:"winrm,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	Rec       Rec        `json:"-"`
}

// TransportWinRM is Host.Transport for a server reached over WinRM.
const TransportWinRM = "winrm"

// WinRMOpts is how komando speaks WinRM to a server.
type WinRMOpts struct {
	Auth string `json:"auth,omitempty"` // ntlm (default) | basic
	// TLS: "" checks the certificate (HTTPS, port 5986), skip-verify does
	// not, off is plain HTTP (port 5985)
	TLS string `json:"tls,omitempty"`
	CA  string `json:"ca,omitempty"` // secret:NAME holding the PEM of the CA that signed the server's certificate
}

// WinRM reports a server reached over WinRM.
func (h *Host) WinRM() bool { return h != nil && h.Transport == TransportWinRM }

// OSWindows is Host.OS for a Windows server.
const OSWindows = "windows"

// Windows reports a Windows server: its commands are PowerShell.
func (h *Host) Windows() bool {
	return h != nil && (h.OS == OSWindows || h.Transport == TransportWinRM)
}

func (h *Host) EffectivePort() int {
	switch {
	case h.Port != 0:
		return h.Port
	case h.WinRM() && h.WinRMOpts != nil && h.WinRMOpts.TLS == "off":
		return 5985
	case h.WinRM():
		return 5986
	}
	if h.Port == 0 {
		return 22
	}
	return h.Port
}

// Conn is a non-SSH resource (database, cache, ...) reached directly or
// through an SSH host. The URL never holds a password; see PasswordRef.
type Conn struct {
	Name        string            `json:"name"`
	Kind        string            `json:"kind"` // a name from driver.Kinds: postgres, redis, s3, kafka ...
	URL         string            `json:"url"`
	PasswordRef string            `json:"password_ref,omitempty"` // secret:<name>, env:<VAR> or file:<path>
	Via         string            `json:"via,omitempty"`          // host used to reach the resource
	ViaIDs      []string          `json:"via_ids,omitempty"`      // the record IDs of Via's steps (refs.go)
	Groups      []string          `json:"groups,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Options     map[string]string `json:"options,omitempty"` // kind-specific settings
	Protected   bool              `json:"protected,omitempty"`
	Notes       string            `json:"notes,omitempty"`
	// TrustedPlugin is the hash of the kubeconfig login program a person
	// trusted for this conn (import kubeconfig). Not an Option: only a
	// person's import sets it, never --option.
	TrustedPlugin string    `json:"trusted_plugin,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	Rec           Rec       `json:"-"`
}

type Key struct {
	Name          string `json:"name"`
	Path          string `json:"path"`
	Type          string `json:"type,omitempty"`
	PublicKey     string `json:"public_key,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	PassphraseRef string `json:"passphrase_ref,omitempty"`
	// CertPath is an OpenSSH user certificate for the key (key add --cert);
	// without it a key file's KEY-cert.pub next to it is used, as ssh does
	CertPath  string    `json:"cert_path,omitempty"`
	Managed   bool      `json:"managed"` // generated/stored by komando
	CreatedAt time.Time `json:"created_at"`
	Rec       Rec       `json:"-"`
}

type Snippet struct {
	Name        string `json:"name"`
	Command     string `json:"command"`
	Description string `json:"description,omitempty"`
	Sudo        bool   `json:"sudo,omitempty"`
	// ReadOnly snippets skip the protected-host check. A snippet without it
	// counts as a change.
	ReadOnly  bool      `json:"read_only,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Rec       Rec       `json:"-"`
}

type Job struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Command   string    `json:"command"`
	PID       int       `json:"pid"`
	RemoteDir string    `json:"remote_dir"`
	StartedAt time.Time `json:"started_at"`
	// Ended is how the job ended (exited, killed, lost) the last time
	// komando asked its server; empty while it ran or nobody asked yet
	Ended string `json:"ended,omitempty"`
}

type Tunnel struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Via       string    `json:"via,omitempty"`  // the --via chain when forwarding to a conn
	Conn      string    `json:"conn,omitempty"` // the conn this tunnel leads to
	Kind      string    `json:"kind"`           // local | remote | dynamic
	Spec      string    `json:"spec"`
	PID       int       `json:"pid"`
	LogFile   string    `json:"log_file"`
	StartedAt time.Time `json:"started_at"`
}

type Settings struct {
	HostKeyPolicy    string   `json:"host_key_policy"` // accept-new | strict | off
	DefaultUser      string   `json:"default_user,omitempty"`
	DefaultTimeout   string   `json:"default_timeout"`
	ConnectTimeout   string   `json:"connect_timeout"`
	Parallel         int      `json:"parallel"`
	MaxOutputBytes   int      `json:"max_output_bytes"`
	ExtraDenyPattern []string `json:"extra_deny_patterns,omitempty"`
	Audit            bool     `json:"audit"`
	AuditSQL         string   `json:"audit_sql"`               // full | hash | off: how SQL text is kept in the audit log
	VpnIdle          string   `json:"vpn_idle"`                // a VPN session unused this long is disconnected
	LoginFor         string   `json:"login_for"`               // how long `komando login SERVER` keeps a server's login
	ApprovalCode     bool     `json:"approval_code,omitempty"` // the approval window asks for a TOTP code
	AuditSyslog      string   `json:"audit_syslog,omitempty"`  // also send audit records to this log server (udp://, tcp://, tls://)
	MaskPersonal     string   `json:"mask_personal,omitempty"` // protected | all | off: where AI agents see personal data hidden
}

func DefaultSettings() Settings {
	return Settings{
		HostKeyPolicy:  "accept-new",
		DefaultTimeout: "5m",
		ConnectTimeout: "15s",
		Parallel:       10,
		MaxOutputBytes: 256 * 1024,
		Audit:          true,
		AuditSQL:       "full",
		VpnIdle:        "30m",
		LoginFor:       "8h",
		MaskPersonal:   "protected",
	}
}

// Vpn is a network komando opens inside its own process to reach targets
// (docs/features/vpn.md). Keys live in the vault, referenced by KeyRef.
type Vpn struct {
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`                 // see netx.Kinds
	Config    string            `json:"config,omitempty"`     // wireguard: the wg-quick file without its keys
	ConfigRef string            `json:"config_ref,omitempty"` // openvpn: the whole .ovpn, kept in the vault (it may hold keys)
	Address   string            `json:"address,omitempty"`    // socks: host:port of the proxy
	Portal    string            `json:"portal,omitempty"`     // openconnect kinds: the VPN server or portal
	Service   string            `json:"service,omitempty"`    // system: the OS VPN's name, to connect it with `vpn up`
	Server    string            `json:"server,omitempty"`     // tailscale: a Headscale login server; l2tp, ipsec, ikev2: the VPN server
	User      string            `json:"user,omitempty"`       // user name, if the VPN wants one
	KeyRef    string            `json:"key_ref,omitempty"`    // password, private key or auth key, as secret:/env:/file:
	PSKRef    string            `json:"psk_ref,omitempty"`    // wireguard, l2tp, ipsec, ikev2: preshared key, if any
	LocalID   string            `json:"id,omitempty"`         // ipsec: the group name; ikev2: our identity
	RemoteID  string            `json:"remote_id,omitempty"`  // ikev2: the server's identity (default: --server)
	CA        string            `json:"ca,omitempty"`         // ikev2: PEM of the CA that signed the server certificate
	MFA       bool              `json:"mfa,omitempty"`        // a human must log in (`vpn up`); never automated
	Protected bool              `json:"protected,omitempty"`  // changing or removing it needs a person's yes
	OSMode    bool              `json:"os_mode,omitempty"`    // removed OpenVPN OS mode; kept only so `vpn up` refuses such a VPN
	Check     string            `json:"check,omitempty"`      // host:port that answers only through the VPN
	Groups    []string          `json:"groups,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Notes     string            `json:"notes,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`

	// Weaker logins a person allowed for this VPN (`vpn edit`, with a yes).
	LegacyCrypto bool `json:"legacy_crypto,omitempty"` // l2tp, ipsec: also offer 3DES and DH groups 2 and 5
	AllowPAP     bool `json:"allow_pap,omitempty"`     // l2tp: the server may pick PAP, which sends the password itself

	Rec Rec `json:"-"`
}

// VpnSession is a VPN kept up in the background between commands.
type VpnSession struct {
	Vpn       string    `json:"vpn"`
	PID       int       `json:"pid"`
	Socks     string    `json:"socks,omitempty"`      // local SOCKS5 address; empty when the OS routes the traffic
	SocksUser string    `json:"socks_user,omitempty"` // login for the container's SOCKS port, random per session
	SocksPass string    `json:"socks_pass,omitempty"`
	Exe       string    `json:"exe,omitempty"` // the program the pid must still be, so a reused pid is never signalled
	LogFile   string    `json:"log_file,omitempty"`
	StartedAt time.Time `json:"started_at"`
	LastUsed  time.Time `json:"last_used"`
}

// SSHLogin is a server login a person made with `komando login SERVER`, held
// by a background komando process (sshx/held.go) on a Unix socket only this
// user can open, and only for a client with Token.
type SSHLogin struct {
	Host      string    `json:"host"`
	Target    string    `json:"target"` // user@address:port when it logged in: the login is used only while the host still points there
	PID       int       `json:"pid"`
	Exe       string    `json:"exe,omitempty"`
	Socket    string    `json:"socket"`
	Token     string    `json:"token"`    // the socket's password, random per login
	HostKey   string    `json:"host_key"` // the socket's own key (authorized_keys form), random per login
	LogFile   string    `json:"log_file,omitempty"`
	StartedAt time.Time `json:"started_at"`
	Until     time.Time `json:"until"`
}

type State struct {
	Hosts    map[string]*Host    `json:"hosts"`
	Conns    map[string]*Conn    `json:"conns,omitempty"`
	Vpns     map[string]*Vpn     `json:"vpns,omitempty"`
	Keys     map[string]*Key     `json:"keys"`
	Snippets map[string]*Snippet `json:"snippets"`
	// Runtime data (VPN sessions, logins, jobs, tunnels) lives in its own
	// file (runtime.go); Load puts it here.
	Runtime
	Settings Settings `json:"settings"`

	settingsRec Rec // the settings record in the sealed store
}

func Home() string {
	if h := os.Getenv("KOMANDO_HOME"); h != "" {
		return h
	}
	d, err := os.UserHomeDir()
	if err != nil {
		return ".komando"
	}
	return filepath.Join(d, ".komando")
}

func Path(parts ...string) string { return filepath.Join(append([]string{Home()}, parts...)...) }

// EnsureHome creates the state directory tree.
func EnsureHome() error { return ensureHome() }

// ensureHome makes komando's folder when it is missing, private to this
// user: mode 0700, and on Windows an access list of its own (privateHome).
// So does every folder above it that it has to make (KOMANDO_HOME=
// C:\a\b\komando with no C:\a): one made with the access list of the
// drive's root would let any user rename it and put a folder of their own
// in its place. A new folder that cannot be made private is removed again,
// so komando keeps nothing in it; doctor checks a folder that was already
// there.
func ensureHome() error {
	h := Home()
	made := missingFolders(h)
	if err := os.MkdirAll(h, 0o700); err != nil {
		return err
	}
	for _, d := range made {
		if err := makePrivate(d); err != nil {
			for i := len(made) - 1; i >= 0; i-- {
				_ = os.Remove(made[i]) // only while it is still empty
			}
			return fmt.Errorf("could not make %s private to you (%w); set KOMANDO_HOME to a folder on an NTFS drive", d, err)
		}
	}
	if len(made) == 0 {
		tightenHome(h)
	}
	return nil
}

// makePrivate is privateHome; tests replace it.
var makePrivate = privateHome

// missingFolders lists h and the folders above it that do not exist yet,
// the topmost first.
func missingFolders(h string) []string {
	var made []string
	for d := h; ; {
		if _, err := os.Stat(d); !errors.Is(err, fs.ErrNotExist) {
			break
		}
		made = append([]string{d}, made...)
		up := filepath.Dir(d)
		if up == d {
			break
		}
		d = up
	}
	return made
}

func (s *State) init() {
	if s.Hosts == nil {
		s.Hosts = map[string]*Host{}
	}
	if s.Conns == nil {
		s.Conns = map[string]*Conn{}
	}
	if s.Vpns == nil {
		s.Vpns = map[string]*Vpn{}
	}
	if s.Keys == nil {
		s.Keys = map[string]*Key{}
	}
	if s.Snippets == nil {
		s.Snippets = map[string]*Snippet{}
	}
	s.Runtime.init()
	d := DefaultSettings()
	if s.Settings.HostKeyPolicy == "" {
		s.Settings.HostKeyPolicy = d.HostKeyPolicy
	}
	if s.Settings.DefaultTimeout == "" {
		s.Settings.DefaultTimeout = d.DefaultTimeout
	}
	if s.Settings.ConnectTimeout == "" {
		s.Settings.ConnectTimeout = d.ConnectTimeout
	}
	if s.Settings.Parallel == 0 {
		s.Settings.Parallel = d.Parallel
	}
	if s.Settings.VpnIdle == "" {
		s.Settings.VpnIdle = d.VpnIdle
	}
	if s.Settings.LoginFor == "" {
		s.Settings.LoginFor = d.LoginFor
	}
	if s.Settings.AuditSQL == "" {
		s.Settings.AuditSQL = d.AuditSQL
	}
	if s.Settings.MaskPersonal == "" {
		s.Settings.MaskPersonal = d.MaskPersonal
	}
	if s.Settings.MaxOutputBytes == 0 {
		s.Settings.MaxOutputBytes = d.MaxOutputBytes
	}
}

// Write says what a change does: Save makes it; Preview (a command's
// --dry-run) applies it to a copy that is never saved, so the command
// shows the result of its change (and its validation errors) without
// making it. Each command passes its own, so a dry run never turns
// another command's change into a preview. A struct, not a bool, so a
// bare true or false does not compile: every change names Save or
// Preview.
type Write struct{ preview bool }

var (
	Save    = Write{}
	Preview = Write{preview: true}
)

// ErrDryRun is returned by writes that cannot be previewed (the vault).
var ErrDryRun = errors.New("this command cannot preview its change; nothing was changed")

// Update reads the inventory, applies fn and writes what changed, in one
// write step of the store; with Preview it only applies fn to a copy.
// Safe for concurrent komando processes (parallel agents).
func Update(w Write, fn func(s *State) error) error {
	if w == Preview {
		s, err := Load()
		if err != nil {
			return err
		}
		return fn(s)
	}
	return updateStore(fn)
}

// Lock takes an exclusive lock on the file name in the state directory
// and returns the function that releases it. komando processes running at
// the same time (parallel agents) wait for each other.
func Lock(name string) (unlock func(), err error) {
	if err := ensureHome(); err != nil {
		return nil, err
	}
	lf, err := os.OpenFile(Path(name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := flock.Lock(lf); err != nil {
		lf.Close()
		return nil, err
	}
	return func() { _ = flock.Unlock(lf); lf.Close() }, nil
}

// WriteFileAtomic replaces path with b: a temporary file next to it is
// written, flushed to disk and renamed into place, and the folder is
// flushed too, so after a crash or power loss path holds either the old
// content or the new, never an empty or half-written file. The temporary
// file is removed on any failure.
func WriteFileAtomic(path string, b []byte, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer tmpclean.Add(tmp.Name())()
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil { // F_FULLFSYNC on macOS
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// the rename itself lives in the folder
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil // the new file is in place; only the flush is missing
	}
	defer d.Close()
	_ = d.Sync() // some file systems cannot flush a folder; the file is in place
	return nil
}

func (s *State) SortedHosts() []*Host {
	hs := make([]*Host, 0, len(s.Hosts))
	for _, h := range s.Hosts {
		hs = append(hs, h)
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].Name < hs[j].Name })
	return hs
}

func (s *State) SortedConns() []*Conn {
	cs := make([]*Conn, 0, len(s.Conns))
	for _, c := range s.Conns {
		cs = append(cs, c)
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
	return cs
}

func (s *State) SortedVpns() []*Vpn {
	vs := make([]*Vpn, 0, len(s.Vpns))
	for _, v := range s.Vpns {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i].Name < vs[j].Name })
	return vs
}

// FindName finds the host or conn whose name equals name, ignoring case, so
// "Web1" and "web1" cannot both exist. existing is the name as stored. Hosts
// and conns share one namespace so selectors stay unambiguous.
func (s *State) FindName(name string) (kind, existing string, found bool) {
	for n := range s.Hosts {
		if strings.EqualFold(n, name) {
			return "host", n, true
		}
	}
	for n := range s.Conns {
		if strings.EqualFold(n, name) {
			return "conn", n, true
		}
	}
	for n := range s.Vpns {
		if strings.EqualFold(n, name) {
			return "vpn", n, true
		}
	}
	return "", "", false
}
