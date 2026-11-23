package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealdb"
	"github.com/sgnd/komando/internal/sealkey"
	"github.com/sgnd/komando/internal/sealrow"
)

// Format 3 is the v2.7 shape of the store (vault note
// 2026-11-24-komando-v2-7-stored-data-migration-design). Entries keep
// their record types and IDs (host, conn, vpn), so a Via or a group
// member that names an ID still finds it; they name credentials instead of
// holding users and secret: references. Nothing outside the migration and
// its tests reads this shape until the v2.7 cut.

// Format3 is the store format the migration writes.
const Format3 = 3

// rowsV3 seals the records and audit entries of a format-3 store: a new
// key, so a step of a v0.17 process that still holds the store open stops
// with sealdb.ErrKeyChanged. It moves into sealkey's list at the cut.
const rowsV3 sealkey.Label = "komando local store v3"

// Record types that format 3 adds.
const (
	KindCredential   = "credential"
	KindCredStore    = "credstore" // an outside secret store (credential store <provider>)
	KindGroup        = "group"
	KindApprovalSeed = "approvalseed" // the approval code's seed: never a credential
)

// ApprovalSeedName is the name the approval code's seed is sealed under,
// the vault name it had (cli approvalSecret).
const ApprovalSeedName = "komando-approval-totp"

// Credential kinds. A trusted host CA (kind certificate) stays a hostca
// record, whose fields already are that kind's.
const (
	CredPassword = "password"
	CredToken    = "token"
	CredKey      = "key"
)

// HostV3 is a server in format 3: provider ssh or winrm. The login user
// lives in its credential (owner, O-42).
type HostV3 struct {
	Name           string            `json:"name"`
	Provider       string            `json:"provider"`
	Address        string            `json:"address"`
	Port           int               `json:"port,omitempty"`
	Credential     string            `json:"credential,omitempty"`
	CredentialID   string            `json:"credential_id,omitempty"`
	SudoCredential string            `json:"sudo_credential,omitempty"`
	Login          string            `json:"login,omitempty"`
	Via            string            `json:"via,omitempty"`
	ViaIDs         []string          `json:"via_ids,omitempty"`
	ProxyCommand   string            `json:"proxy_command,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Env            map[string]string `json:"env,omitempty"` // credential:NAME for a credential's value
	Protected      bool              `json:"protected,omitempty"`
	ForwardAgent   bool              `json:"forward_agent,omitempty"`
	Notes          string            `json:"notes,omitempty"`
	OS             string            `json:"os,omitempty"`
	WinRMOpts      *WinRMOpts        `json:"winrm,omitempty"` // CA: credential:NAME
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

// ServiceV3 is a conn in format 3, typed by (type, provider): a database,
// cache, queue, storage, cluster or registry. A swarm cluster names its
// manager server instead of a URL.
type ServiceV3 struct {
	Name             string            `json:"name"`
	Type             string            `json:"type"`
	Provider         string            `json:"provider"`
	URL              string            `json:"url,omitempty"` // no user; ?ca=credential:NAME
	Manager          string            `json:"manager,omitempty"`
	ManagerID        string            `json:"manager_id,omitempty"`
	Credential       string            `json:"credential,omitempty"`
	Login            string            `json:"login,omitempty"`
	Via              string            `json:"via,omitempty"`
	ViaIDs           []string          `json:"via_ids,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	Options          map[string]string `json:"options,omitempty"`
	Protected        bool              `json:"protected,omitempty"`
	Notes            string            `json:"notes,omitempty"`
	TrustedPlugin    string            `json:"trusted_plugin,omitempty"`
	PluginProgram    string            `json:"plugin_program,omitempty"`
	PluginSearchPath string            `json:"plugin_search_path,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// VpnV3 is a VPN in format 3; its secrets are credentials.
type VpnV3 struct {
	Name             string            `json:"name"`
	Provider         string            `json:"provider"`
	Config           string            `json:"config,omitempty"`
	ConfigCredential string            `json:"config_credential,omitempty"`
	Address          string            `json:"address,omitempty"`
	Portal           string            `json:"portal,omitempty"`
	Service          string            `json:"service,omitempty"`
	Server           string            `json:"server,omitempty"`
	User             string            `json:"user,omitempty"`
	Credential       string            `json:"credential,omitempty"`
	PSKCredential    string            `json:"psk_credential,omitempty"`
	LocalID          string            `json:"id,omitempty"`
	RemoteID         string            `json:"remote_id,omitempty"`
	CA               string            `json:"ca,omitempty"`
	MFA              bool              `json:"mfa,omitempty"`
	Protected        bool              `json:"protected,omitempty"`
	Check            string            `json:"check,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
	Labels           map[string]string `json:"labels,omitempty"`
	Notes            string            `json:"notes,omitempty"`
	LegacyCrypto     bool              `json:"legacy_crypto,omitempty"`
	AllowPAP         bool              `json:"allow_pap,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
	UpdatedAt        time.Time         `json:"updated_at"`
}

// SealedValue is a value sealed with the vault's value key and bound to
// the name of the record that holds it.
type SealedValue struct {
	Nonce []byte `json:"nonce"`
	Data  []byte `json:"data"`
}

// Credential is what an entry logs in with. A value komando keeps is in
// Value; one kept outside is Item in Store; a key is in Key. Ask: a person
// types the password at every connect and nothing is kept.
type Credential struct {
	Name      string         `json:"name"`
	Kind      string         `json:"kind"`
	User      string         `json:"user,omitempty"`
	Value     *SealedValue   `json:"value,omitempty"`
	Store     string         `json:"store,omitempty"`
	Item      string         `json:"item,omitempty"`
	Ask       bool           `json:"ask,omitempty"`
	Key       *CredentialKey `json:"key,omitempty"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// CredentialKey is an SSH key pair: a file of the person, the sealed pair
// komando made (Path sealed:<keydata ID>), or ssh-agent (Agent).
type CredentialKey struct {
	Path        string `json:"path,omitempty"`
	Type        string `json:"type,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Passphrase  string `json:"passphrase,omitempty"` // a credential name
	CertPath    string `json:"cert_path,omitempty"`
	Managed     bool   `json:"managed,omitempty"`
	Agent       bool   `json:"agent,omitempty"`
}

// CredentialStore is an outside secret store; its options come from the
// environment until `credential store <provider> edit` sets them.
type CredentialStore struct {
	Name     string            `json:"name"`
	Provider string            `json:"provider"`
	Options  map[string]string `json:"options,omitempty"`
}

// Group holds entries and snippets by record ID.
type Group struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// approvalSeed is the approval code's seed, sealed under ApprovalSeedName.
type approvalSeed struct {
	Value SealedValue `json:"value"`
}

// policyParts3 are the safety parts of a format-3 store: the same parts as
// format 2, read from the format-3 shapes, so a migrated store has the
// same safety rows (Audit M4).
var policyParts3 = map[string]sealdb.Part{
	KindHost: jsonPart(func(h *HostV3) (string, any) {
		return "server " + h.Name, unlessZero(hostSafety{h.Protected, h.ForwardAgent, h.ProxyCommand})
	}),
	KindConn: jsonPart(func(c *ServiceV3) (string, any) {
		return "conn " + c.Name, unlessZero(connSafety{c.Protected, c.TrustedPlugin, c.PluginProgram, c.PluginSearchPath})
	}),
	KindVpn: jsonPart(func(v *VpnV3) (string, any) {
		return "VPN " + v.Name, unlessZero(vpnSafety{v.Protected, v.MFA, v.LegacyCrypto, v.AllowPAP})
	}),
	kindSettings:   policyParts[kindSettings],
	KindPin:        policyParts[KindPin],
	KindPinRevoked: policyParts[KindPinRevoked],
	KindHostCA:     policyParts[KindHostCA],
}

// keysFor3 makes the row key and the policy of a format-3 store.
func keysFor3(master []byte) (storeKeys, error) {
	rk, err := sealkey.Derive(master, rowsV3)
	if err != nil {
		return storeKeys{}, err
	}
	defer clear(rk)
	row, err := sealrow.NewKey(rk)
	if err != nil {
		return storeKeys{}, err
	}
	pk, err := sealkey.Derive(master, sealkey.Policy)
	if err != nil {
		return storeKeys{}, err
	}
	defer clear(pk)
	p, err := sealdb.NewPolicy(pk, policyParts3)
	return storeKeys{row: row, policy: p}, err
}

// ReservedCredential refuses the name of the approval code's seed: a
// person manages it with `config approval-code`, and no credential verb,
// import or export reaches it (Audit M1).
func ReservedCredential(name string) error {
	if strings.EqualFold(name, ApprovalSeedName) {
		return out.Errf(out.ExitUsage, "RESERVED_SECRET", "a person manages it with `komando config approval-code`",
			"%s belongs to komando's approval code and is no credential", name)
	}
	return nil
}

// ExportRecord3 reports whether an export takes records of type kind: the
// approval code's seed never leaves this computer (Audit L1).
func ExportRecord3(kind string) bool { return kind != KindApprovalSeed }

// export3 is a format-3 export as import reads it.
type export3 struct {
	Format  int `json:"format"`
	Records []struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	} `json:"records"`
}

// checkImport3 refuses an import that holds the approval code's seed,
// under any name, or a credential that takes the seed's name (Audit L1).
func checkImport3(b []byte) error {
	var f export3
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("import: %w", err)
	}
	for i, r := range f.Records {
		if strings.EqualFold(r.Type, KindApprovalSeed) {
			return out.Errf(out.ExitUsage, "RESERVED_SECRET", "a person sets the approval code up on this computer with `komando config approval-code`",
				"the import file holds komando's approval code seed (record %d); it is never imported", i+1)
		}
		if strings.EqualFold(r.Type, KindCredential) {
			var c struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(r.Data, &c); err != nil {
				return fmt.Errorf("import record %d: %w", i+1, err)
			}
			if err := ReservedCredential(c.Name); err != nil {
				return err
			}
		}
	}
	return nil
}
