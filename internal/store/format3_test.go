package store

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sealkey"
)

// The approval-code seed is no credential: every credential verb (the
// leaves come with the cut; TestCredentialLeavesReserved there calls this
// guard from each) and import stop on its name (Audit M1).
func TestReservedCredential(t *testing.T) {
	for _, name := range []string{ApprovalSeedName, "KOMANDO-APPROVAL-TOTP"} {
		err := ReservedCredential(name)
		var e *out.Error
		if !errors.As(err, &e) || e.Code != "RESERVED_SECRET" {
			t.Errorf("%s: want RESERVED_SECRET, got %v", name, err)
		}
	}
	if err := ReservedCredential("db-pass"); err != nil {
		t.Errorf("an ordinary name: %v", err)
	}
}

// Export never writes the seed, and import refuses a seed record whatever
// its name, and a credential that takes the seed's name (Audit L1).
func TestImportExport3Seed(t *testing.T) {
	if ExportRecord3(KindApprovalSeed) {
		t.Error("export writes the approval seed")
	}
	for _, k := range []string{KindHost, KindConn, KindVpn, KindCredential, KindGroup, KindRecipe} {
		if !ExportRecord3(k) {
			t.Errorf("export leaves out %s", k)
		}
	}
	crafted := []struct {
		name string
		file string
	}{
		{"a seed under its own name", `{"format":3,"records":[{"type":"approvalseed","data":{"name":"komando-approval-totp"}}]}`},
		{"a seed under another name", `{"format":3,"records":[{"type":"approvalseed","data":{"name":"innocent"}}]}`},
		{"a credential named like the seed", `{"format":3,"records":[{"type":"credential","data":{"name":"komando-approval-totp","kind":"token"}}]}`},
	}
	for _, tt := range crafted {
		t.Run(tt.name, func(t *testing.T) {
			err := checkImport3([]byte(tt.file))
			var e *out.Error
			if !errors.As(err, &e) || e.Code != "RESERVED_SECRET" {
				t.Errorf("want RESERVED_SECRET, got %v", err)
			}
		})
	}
	okFile, _ := json.Marshal(map[string]any{"format": 3, "records": []map[string]any{
		{"type": "credential", "data": map[string]any{"name": "db-pass", "kind": "password"}},
	}})
	if err := checkImport3(okFile); err != nil {
		t.Errorf("an ordinary file: %v", err)
	}
}

// The format-3 row label is new: it shares no derivation with any key of
// format 2 or with the vault's value key.
func TestRowsV3Label(t *testing.T) {
	for _, l := range []sealkey.Label{sealkey.Rows, sealkey.Runtime, sealkey.Values, sealkey.Tickets, sealkey.Policy} {
		if l == rowsV3 {
			t.Errorf("rowsV3 is %q, the label of another key", l)
		}
	}
}
