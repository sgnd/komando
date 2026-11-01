// Package store persists komando state (inventory, conns, keys, snippets,
// jobs, tunnels, settings) as JSON files under $KOMANDO_HOME (default ~/.komando).
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type Host struct {
	Name        string            `json:"name"`
	Address     string            `json:"address"`
	Port        int               `json:"port,omitempty"`
	User        string            `json:"user,omitempty"`
	Key         string            `json:"key,omitempty"`          // name of a key in the keychain
	Identity    string            `json:"identity,omitempty"`     // path to a private key file
	PasswordRef string            `json:"password_ref,omitempty"` // secret:<name> or env:<VAR>
	SudoRef     string            `json:"sudo_ref,omitempty"`     // sudo password ref (secret:/env:)
	Jump        string            `json:"jump,omitempty"`         // host name or comma-separated chain
	Groups      []string          `json:"groups,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Env         map[string]string `json:"env,omitempty"` // exported before every command
	Protected   bool              `json:"protected,omitempty"`
	Notes       string            `json:"notes,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

func (h *Host) EffectivePort() int {
	if h.Port == 0 {
		return 22
	}
	return h.Port
}

func (h *Host) InGroup(g string) bool { return contains(h.Groups, g) }
func (h *Host) HasTag(t string) bool  { return contains(h.Tags, t) }

// Conn is a non-SSH resource (database, cache, ...) reached directly or
// through an SSH host. The URL never holds a password; see PasswordRef.
type Conn struct {
	Name        string            `json:"name"`
	Kind        string            `json:"kind"` // postgres | mysql | sqlite
	URL         string            `json:"url"`
	PasswordRef string            `json:"password_ref,omitempty"` // secret:<name>, env:<VAR> or file:<path>
	Via         string            `json:"via,omitempty"`          // host used to reach the resource
	Groups      []string          `json:"groups,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Options     map[string]string `json:"options,omitempty"` // kind-specific settings
	Protected   bool              `json:"protected,omitempty"`
	Notes       string            `json:"notes,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

type Key struct {
	Name          string    `json:"name"`
	Path          string    `json:"path"`
	Type          string    `json:"type,omitempty"`
	PublicKey     string    `json:"public_key,omitempty"`
	Fingerprint   string    `json:"fingerprint,omitempty"`
	PassphraseRef string    `json:"passphrase_ref,omitempty"`
	Managed       bool      `json:"managed"` // generated/stored by komando
	CreatedAt     time.Time `json:"created_at"`
}

type Snippet struct {
	Name        string    `json:"name"`
	Command     string    `json:"command"`
	Description string    `json:"description,omitempty"`
	Sudo        bool      `json:"sudo,omitempty"`
	Mutating    bool      `json:"mutating,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type Job struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Command   string    `json:"command"`
	PID       int       `json:"pid"`
	RemoteDir string    `json:"remote_dir"`
	StartedAt time.Time `json:"started_at"`
}

type Tunnel struct {
	ID        string    `json:"id"`
	Host      string    `json:"host"`
	Kind      string    `json:"kind"` // local | remote | dynamic
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
	AuditSQL         string   `json:"audit_sql"` // full | hash | off: how SQL text is kept in the audit log
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
	}
}

type State struct {
	Hosts    map[string]*Host    `json:"hosts"`
	Conns    map[string]*Conn    `json:"conns,omitempty"`
	Keys     map[string]*Key     `json:"keys"`
	Snippets map[string]*Snippet `json:"snippets"`
	Jobs     map[string]*Job     `json:"jobs"`
	Tunnels  map[string]*Tunnel  `json:"tunnels"`
	Settings Settings            `json:"settings"`
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

func ensureHome() error {
	if err := os.MkdirAll(Home(), 0o700); err != nil {
		return err
	}
	return os.MkdirAll(Path("keys"), 0o700)
}

func statePath() string { return Path("state.json") }

// Load reads state. Callers that mutate must use Update for locking.
func Load() (*State, error) {
	if err := ensureHome(); err != nil {
		return nil, err
	}
	s := &State{Settings: DefaultSettings()}
	b, err := os.ReadFile(statePath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, fmt.Errorf("corrupt state file %s: %w", statePath(), err)
		}
	}
	s.init()
	return s, nil
}

func (s *State) init() {
	if s.Hosts == nil {
		s.Hosts = map[string]*Host{}
	}
	if s.Conns == nil {
		s.Conns = map[string]*Conn{}
	}
	if s.Keys == nil {
		s.Keys = map[string]*Key{}
	}
	if s.Snippets == nil {
		s.Snippets = map[string]*Snippet{}
	}
	if s.Jobs == nil {
		s.Jobs = map[string]*Job{}
	}
	if s.Tunnels == nil {
		s.Tunnels = map[string]*Tunnel{}
	}
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
	if s.Settings.AuditSQL == "" {
		s.Settings.AuditSQL = d.AuditSQL
	}
	if s.Settings.MaxOutputBytes == 0 {
		s.Settings.MaxOutputBytes = d.MaxOutputBytes
	}
}

// Update loads state under an exclusive file lock, applies fn and saves
// atomically. Safe for concurrent komando processes (parallel agents).
func Update(fn func(s *State) error) error {
	if err := ensureHome(); err != nil {
		return err
	}
	lf, err := os.OpenFile(Path(".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	s, err := Load()
	if err != nil {
		return err
	}
	if err := fn(s); err != nil {
		return err
	}
	return s.save()
}

func (s *State) save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(statePath(), b, 0o600)
}

func WriteFileAtomic(path string, b []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
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

// NameTaken reports whether a host or conn already uses name. Hosts and conns
// share one namespace so selectors stay unambiguous.
func (s *State) NameTaken(name string) (kind string, taken bool) {
	if _, ok := s.Hosts[name]; ok {
		return "host", true
	}
	if _, ok := s.Conns[name]; ok {
		return "conn", true
	}
	return "", false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
