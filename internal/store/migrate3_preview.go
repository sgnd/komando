package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/sgnd/komando/internal/sealdb"
)

// MigrationPreview is what the move of this home's store to format 3
// would do: counts only, never the name of a record, a secret or a server,
// and never a value.
type MigrationPreview struct {
	Format    string `json:"format"` // the store's format now: 1, 2, 3, or none
	WouldMove bool   `json:"would_move"`
	// Counts is, per record type, the number now and after the move.
	Counts             map[string][2]int `json:"counts,omitempty"`
	NamesChanged       int               `json:"names_changed"`
	FieldsRewritten    int               `json:"fields_rewritten"`
	KeyAndPassword     int               `json:"servers_with_key_and_password"`
	SnippetsWithOldRef int               `json:"snippets_with_old_reference"`
	MergedGroups       int               `json:"groups_merged"`
	Backup             string            `json:"backup_would_be,omitempty"`
	// WouldRefuse is each reason the move would stop, by kind and field.
	WouldRefuse []string `json:"would_refuse,omitempty"`
	// Fix is the steps for the fields in WouldRefuse, the same the move
	// gives when it stops on them (C558).
	Fix []string `json:"fix,omitempty"`
	// NotChecked is what only the real move checks.
	NotChecked []string `json:"not_checked,omitempty"`
}

// PreviewMigration reads this home's store and says what moving it to
// format 3 would do (the dry run a person runs before the real move). It
// writes nothing: the store is opened read-only, no lock, backup, key or
// marker file is made, and the keychain is only read. refGuard is the
// vault's reference guard, as for the real move.
func PreviewMigration(ctx context.Context, refGuard func(kind, name string) error) (MigrationPreview, error) {
	var pv MigrationPreview
	path := DBPath()
	meta, err := sealdb.Peek(ctx, path)
	if errors.Is(err, os.ErrNotExist) {
		pv.Format = "none"
		return pv, nil
	}
	if err != nil {
		return pv, err
	}
	pv.Format = meta["format"]
	if pv.Format != "1" && pv.Format != "2" {
		return pv, nil
	}
	if meta["key_mode"] == "keyfile" {
		if _, err := os.Stat(Path("store.key")); err != nil {
			pv.WouldRefuse = append(pv.WouldRefuse, "the store's key file is missing")
			return pv, nil
		}
	}
	if KeySource == nil {
		return pv, errors.New("store: no key source (the vault package is not linked)")
	}
	master, _, err := KeySource(meta, false)
	if err != nil {
		return pv, err
	}
	defer clear(master)
	ks, err := keysFor(master, pv.Format)
	if err != nil {
		return pv, err
	}
	d, err := sealdb.OpenReadOnly(ctx, path, ks.row)
	if err != nil {
		return pv, err
	}
	defer d.Close()
	if ks.policy != nil {
		if err := d.SetPolicy(ctx, ks.policy); err != nil {
			pv.WouldRefuse = append(pv.WouldRefuse, "the safety settings do not pass their check")
		}
	}
	if err := d.View(ctx, checkChain); err != nil {
		pv.WouldRefuse = append(pv.WouldRefuse, "the audit log is broken")
	}
	var snap *snapshot2
	if err := d.View(ctx, func(tx *sealdb.Tx) error {
		var err error
		snap, err = readFormat2(tx)
		return err
	}); err != nil {
		return pv, err
	}
	p := buildPlan3(snap, refGuard)
	pv.WouldRefuse = append(pv.WouldRefuse, p.plain...)
	pv.Fix = p.fix()
	r := p.report
	pv.Counts, pv.NamesChanged, pv.FieldsRewritten = r.Counts, len(r.Names), len(r.Rewritten)
	pv.KeyAndPassword, pv.SnippetsWithOldRef, pv.MergedGroups = len(r.KeyAndPassword), len(r.SnippetsWithOldRef), len(r.MergedGroups)
	pv.WouldMove = len(pv.WouldRefuse) == 0
	if pv.WouldMove {
		b, err := backupName(time.Now())
		if err != nil {
			return pv, err
		}
		pv.Backup = filepath.Base(b)
	}
	pv.NotChecked = []string{
		"VPN connections, logins and tunnels that are running (the move waits until they end)",
		"that this is the newest copy of the store (the keychain's change count)",
		"each value opening under its name once written (the move reads every one back)",
	}
	if pv.Format == "1" {
		pv.NotChecked = append(pv.NotChecked, "the upgrade of format 1 to format 2, which the move does first")
	}
	return pv, nil
}
