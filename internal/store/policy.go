package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealkey"
	"github.com/sgnd/komando/internal/sealrow"
)

// A store's keys and its safety rows (C234). From the master key
// (sealkey): the row key seals store.db's records, the runtime key seals
// runtime.json, and the policy key binds the safety rows with the policy
// MAC (sealdb/policy.go). The vault makes the value and ticket keys.
//
// The safety rows are what komando asks a person before it changes
// (docs/features/settings.md, "Safety rows"): a process that holds only
// the row key cannot change them unseen. Names, notes, addresses and
// display settings stay outside.

// storeKeys are the keys a store of one format opens with.
type storeKeys struct {
	row    *sealrow.Key
	policy *sealdb.Policy // nil for format 1, which has no policy MAC
}

// keysFor makes the keys of a store of format from master. A format-1
// store sealed its rows with the derivation that is the runtime key now.
func keysFor(master []byte, format string) (storeKeys, error) {
	label := sealkey.Rows
	if format == "1" {
		label = sealkey.Runtime
	}
	rk, err := sealkey.Derive(master, label)
	if err != nil {
		return storeKeys{}, err
	}
	defer clear(rk)
	row, err := sealrow.NewKey(rk)
	if err != nil || format == "1" {
		return storeKeys{row: row}, err
	}
	pk, err := sealkey.Derive(master, sealkey.Policy)
	if err != nil {
		return storeKeys{}, err
	}
	defer clear(pk)
	p, err := sealdb.NewPolicy(pk, policyParts)
	return storeKeys{row: row, policy: p}, err
}

// newestFormat is the format of a store this komando makes or upgrades to.
var newestFormat = strconv.Itoa(sealdb.Format)

// upgrade gives a store an older komando made (format 1) its policy MAC,
// once: every row sealed again under the row key, the safety rows bound as
// they are now, the format raised. From then on a missing MAC is
// tampering. The caller holds the store lock.
func upgrade(d *sealdb.DB, master []byte) error {
	ks, err := keysFor(master, newestFormat)
	if err != nil {
		return err
	}
	if err := d.Upgrade(context.Background(), ks.row, ks.policy); err != nil {
		return fmt.Errorf("giving %s its policy MAC: %w", Path(StoreFile), err)
	}
	return nil
}

// Opens reports sealdb.ErrWrongKey when master does not open this home's
// store.
func Opens(master []byte) error {
	meta, err := sealdb.Peek(context.Background(), DBPath())
	if err != nil {
		return err
	}
	ks, err := keysFor(master, meta["format"])
	if err != nil {
		return err
	}
	d, err := sealdb.Open(context.Background(), DBPath(), ks.row)
	if err != nil {
		return err
	}
	return d.Close()
}

// The safety part of each record type that has one. The part of a record
// without any safety mark is nil, so adding a plain server needs no
// policy key.
type (
	hostSafety struct {
		Protected    bool   `json:"protected"`
		ForwardAgent bool   `json:"forward_agent"` // host edit --forward-agent (guardSafety)
		ProxyCommand string `json:"proxy_command"` // --proxy-command (guardProxyCommand)
	}
	connSafety struct {
		Protected        bool   `json:"protected"`
		TrustedPlugin    string `json:"trusted_plugin"` // only a person's import sets these three
		PluginProgram    string `json:"plugin_program"`
		PluginSearchPath string `json:"plugin_search_path"`
	}
	vpnSafety struct {
		Protected    bool `json:"protected"`
		MFA          bool `json:"mfa"` // vpn edit (guardVpnEdit)
		LegacyCrypto bool `json:"legacy_crypto"`
		AllowPAP     bool `json:"allow_pap"`
	}
	// settingsSafety are the settings komando asks a person to loosen
	// (config, policy remove, config approval-code); the rest are display.
	settingsSafety struct {
		HostKeyPolicy    string   `json:"host_key_policy"`
		ExtraDenyPattern []string `json:"extra_deny_patterns"`
		Audit            bool     `json:"audit"`
		AuditSQL         string   `json:"audit_sql"`
		AuditSyslog      string   `json:"audit_syslog"`
		MaskPersonal     string   `json:"mask_personal"`
		LoginFor         string   `json:"login_for"`
		VpnIdle          string   `json:"vpn_idle"`
		ApprovalCode     bool     `json:"approval_code"`
		ApprovalCodeStep int64    `json:"approval_code_step"`
	}
)

var policyParts = map[string]sealdb.Part{
	KindHost: jsonPart(func(h *Host) (string, any) {
		return "server " + h.Name, unlessZero(hostSafety{h.Protected, h.ForwardAgent, h.ProxyCommand})
	}),
	KindConn: jsonPart(func(c *Conn) (string, any) {
		return "conn " + c.Name, unlessZero(connSafety{c.Protected, c.TrustedPlugin, c.PluginProgram, c.PluginSearchPath})
	}),
	KindVpn: jsonPart(func(v *Vpn) (string, any) {
		return "VPN " + v.Name, unlessZero(vpnSafety{v.Protected, v.MFA, v.LegacyCrypto, v.AllowPAP})
	}),
	kindSettings: jsonPart(func(s *Settings) (string, any) {
		return "settings", settingsSafety{s.HostKeyPolicy, s.ExtraDenyPattern, s.Audit, s.AuditSQL, s.AuditSyslog,
			s.MaskPersonal, s.LoginFor, s.VpnIdle, s.ApprovalCode, s.ApprovalCodeStep}
	}),
	// sshx's records (hostkeys_sealed.go, hostca.go), whole
	KindPin:        wholeNamed("host key pin", "addr"),
	KindPinRevoked: wholeNamed("revoked host keys", ""),
	KindHostCA:     wholeNamed("host CA", "name"),
}

// jsonPart is the part of a record holding a T as JSON: safety gives the
// row's name and its safety part (nil: none).
func jsonPart[T any](safety func(*T) (label string, part any)) sealdb.Part {
	return func(b []byte) ([]byte, string, error) {
		v := new(T)
		if err := json.Unmarshal(b, v); err != nil {
			return nil, "", err
		}
		label, part := safety(v)
		if part == nil {
			return nil, label, nil
		}
		c, err := json.Marshal(part)
		return c, label, err
	}
}

// unlessZero is v, or nil for its zero value.
func unlessZero[T comparable](v T) any {
	var zero T
	if v == zero {
		return nil
	}
	return v
}

// wholeNamed covers a record whole and names it by what and its JSON
// field (none when field is "").
func wholeNamed(what, field string) sealdb.Part {
	return func(b []byte) ([]byte, string, error) {
		c, _, _ := sealdb.Whole(b)
		var m map[string]json.RawMessage
		var name string
		label := what // per call: the part is shared by every record it reads
		if field != "" && json.Unmarshal(b, &m) == nil && json.Unmarshal(m[field], &name) == nil && name != "" {
			label += " " + name
		}
		return c, label, nil
	}
}

// PolicyErr is the error of a safety row that does not match the policy
// MAC, or of a store that lost its MAC; nil for any other error.
func PolicyErr(err error) *out.Error {
	var pe *sealdb.PolicyError
	var what string
	switch {
	case errors.Is(err, sealdb.ErrPolicyMissing):
		what = "its safety rows have no policy MAC, though it had one"
	case !errors.As(err, &pe):
		return nil
	case pe.Change == "":
		what = "its policy MAC was made with another key"
	default:
		row := pe.Type
		if pe.Label != "" {
			row = pe.Label
		}
		what = fmt.Sprintf("the safety row %s (record %s) %s outside komando", row, pe.ID, map[string]string{
			"changed": "was changed",
			"added":   "got a safety mark",
			"removed": "lost its safety mark, or was removed,",
		}[pe.Change])
		if pe.More > 0 {
			what += fmt.Sprintf(", and %d more", pe.More)
		}
	}
	return out.Errf(out.ExitError, "POLICY_MAC_FAILED",
		"something other than komando changed a protection, rule, setting or pinned host key; a person finds out what, then restores the komando folder from a backup made before it (`komando doctor` then says whether that copy is older than the keychain remembers)",
		"%s: %s, so komando does not run (the safety rows no longer match their policy MAC)", Path(StoreFile), what)
}
