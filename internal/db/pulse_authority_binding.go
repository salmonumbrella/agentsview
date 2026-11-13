package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const pulseAuthorityMetadataKey = "federation_pulse_authority"

// pulseAuthorityReference is stored with the source archive, not its frontier.
type pulseAuthorityReference struct {
	AuthorityID  string `json:"authority_id"`
	Incarnation  string `json:"incarnation"`
	ProofVersion int    `json:"proof_version"`
}

// BindFederationPulseAuthority binds the hub archive to its per-user registry.
// Publication also requires the separate proof and admission owners.
func (db *DB) BindFederationPulseAuthority(ctx context.Context) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("locating pulse authority home: %w", err)
	}
	_, err = db.bindPulseAuthority(ctx, home, true)
	return err
}

// bindPulseAuthority binds metadata while holding the registry lock through the
// source transaction. It does not activate publication or establish a frontier.
// Callers must establish managed-copy provenance before allowing creation.
func (db *DB) bindPulseAuthority(ctx context.Context, home string, allowOriginal bool) (pulseAuthorityBinding, error) {
	var empty pulseAuthorityBinding
	archiveID, err := db.GetArchiveID(ctx)
	if err != nil {
		return empty, err
	}
	path, err := pulseAuthorityPath(home, archiveID)
	if err != nil {
		return empty, err
	}
	var exists, archiveOnly, requiresRejoin bool
	err = db.getReader().QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM archive_metadata WHERE key=?),
		EXISTS(SELECT 1 FROM archive_metadata WHERE key='archive_only' AND value='1'),
		EXISTS(SELECT 1 FROM archive_metadata WHERE key='federation_pulse_requires_rejoin' AND value='1')`, pulseAuthorityMetadataKey).Scan(&exists, &archiveOnly, &requiresRejoin)
	if err != nil {
		return empty, err
	}
	if requiresRejoin || (!exists && (!allowOriginal || archiveOnly)) {
		return empty, errors.New("pulse authority requires rejoin")
	}
	original, err := filepath.Abs(db.Path())
	if err != nil {
		return empty, err
	}
	original, err = filepath.EvalSymlinks(original)
	if err != nil {
		return empty, err
	}
	return withPulseAuthorityLock(ctx, path, !exists && allowOriginal, func() (pulseAuthorityBinding, error) {
		var binding pulseAuthorityBinding
		err := db.Update(ctx, func(tx *sql.Tx) error {
			var pending bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM archive_metadata WHERE key='federation_pulse_requires_rejoin' AND value='1')`).Scan(&pending); err != nil {
				return err
			}
			if pending {
				return errors.New("pulse authority requires rejoin")
			}
			var currentID string
			if err := tx.QueryRowContext(ctx, `SELECT value FROM archive_metadata WHERE key=?`, archiveMetadataArchiveIDKey).Scan(&currentID); err != nil {
				return err
			}
			if currentID != archiveID {
				return errors.New("pulse archive identity changed")
			}
			var raw string
			err := tx.QueryRowContext(ctx, `SELECT value FROM archive_metadata WHERE key=?`, pulseAuthorityMetadataKey).Scan(&raw)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if errors.Is(err, sql.ErrNoRows) {
				var copied bool
				if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM archive_metadata WHERE key='archive_only' AND value='1')`).Scan(&copied); err != nil {
					return err
				}
				if !allowOriginal || copied {
					return errors.New("pulse authority requires rejoin")
				}
				binding, err = readPulseAuthorityLocked(path, archiveID)
				if errors.Is(err, os.ErrNotExist) {
					binding, err = createPulseAuthorityLocked(path, archiveID, original)
				}
				if err != nil {
					return err
				}
				if binding.CanonicalOriginal != original {
					return errors.New("pulse authority original does not match")
				}
				ref := pulseAuthorityReference{AuthorityID: binding.AuthorityID, Incarnation: binding.Incarnation, ProofVersion: 1}
				encoded, err := json.Marshal(ref)
				if err != nil {
					return err
				}
				_, err = tx.ExecContext(ctx, `INSERT INTO archive_metadata(key,value) VALUES(?,?)`, pulseAuthorityMetadataKey, string(encoded))
				return err
			}
			var ref pulseAuthorityReference
			if json.Unmarshal([]byte(raw), &ref) != nil || !validPulseIdentity(ref.AuthorityID) || !validPulseIdentity(ref.Incarnation) || ref.ProofVersion != 1 {
				return errors.New("invalid pulse archive authority reference")
			}
			binding, err = readPulseAuthorityLocked(path, archiveID)
			if err != nil {
				return err
			}
			if binding.AuthorityID != ref.AuthorityID || binding.Incarnation != ref.Incarnation {
				return errors.New("pulse authority reference mismatch")
			}
			return nil
		})
		if err != nil {
			return empty, fmt.Errorf("bind pulse authority: %w", err)
		}
		return binding, nil
	})
}
