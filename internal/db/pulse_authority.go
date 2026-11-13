package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
	"go.kenn.io/kit/safefileio"
)

// pulseAuthorityBinding is registry state, not proof of publication admission.
// The archive must persist and validate the matching reference before it can use it.
type pulseAuthorityBinding struct {
	Version           int    `json:"version"`
	ArchiveID         string `json:"archive_id"`
	AuthorityID       string `json:"authority_id"`
	CanonicalOriginal string `json:"canonical_original"`
	Incarnation       string `json:"incarnation"`
}

func pulseAuthorityPath(home, archiveID string) (string, error) {
	if !filepath.IsAbs(home) || archiveID == "" || len(archiveID) > 100 {
		return "", errors.New("invalid pulse authority location or archive identity")
	}
	return filepath.Join(home, ".agentsview-pulse-authority", hex.EncodeToString([]byte(archiveID))+".json"), nil
}

// createPulseAuthority is reserved for explicit first-original activation. It
// never replaces a registry entry, including a partial or corrupt entry.
func createPulseAuthority(ctx context.Context, home, archiveID, original string) (pulseAuthorityBinding, error) {
	var empty pulseAuthorityBinding
	path, err := pulseAuthorityPath(home, archiveID)
	if err != nil {
		return empty, err
	}
	original, err = filepath.Abs(original)
	if err != nil {
		return empty, err
	}
	original, err = filepath.EvalSymlinks(original)
	if err != nil {
		return empty, err
	}
	return withPulseAuthorityLock(ctx, path, true, func() (pulseAuthorityBinding, error) {
		return createPulseAuthorityLocked(path, archiveID, original)
	})
}

func createPulseAuthorityLocked(path, archiveID, original string) (pulseAuthorityBinding, error) {
	var empty pulseAuthorityBinding
	authority, err := randomPulseIdentity()
	if err != nil {
		return empty, err
	}
	incarnation, err := randomPulseIdentity()
	if err != nil {
		return empty, err
	}
	binding := pulseAuthorityBinding{Version: 1, ArchiveID: archiveID, AuthorityID: authority, CanonicalOriginal: original, Incarnation: incarnation}
	data, err := json.Marshal(binding)
	if err != nil {
		return empty, err
	}
	file, err := safefileio.CreatePrivateFile(path)
	if err != nil {
		return empty, fmt.Errorf("create pulse authority: %w", err)
	}
	if n, writeErr := file.Write(data); writeErr != nil {
		err = writeErr
	} else if n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = syncPulseAuthorityDir(filepath.Dir(path))
	}
	if err != nil {
		return empty, fmt.Errorf("persist pulse authority: %w", err)
	}
	return binding, nil
}

// rejoinPulseAuthority never creates the directory, lock or registry entry.
func rejoinPulseAuthority(ctx context.Context, home, archiveID, authorityID string) (pulseAuthorityBinding, error) {
	var empty pulseAuthorityBinding
	path, err := pulseAuthorityPath(home, archiveID)
	if err != nil {
		return empty, err
	}
	if authorityID == "" {
		return empty, errors.New("missing pulse authority identity")
	}
	return withPulseAuthorityLock(ctx, path, false, func() (pulseAuthorityBinding, error) {
		binding, err := readPulseAuthorityLocked(path, archiveID)
		if err == nil && binding.AuthorityID != authorityID {
			return empty, errors.New("invalid pulse authority identity")
		}
		return binding, err
	})
}

func readPulseAuthorityLocked(path, archiveID string) (pulseAuthorityBinding, error) {
	var empty pulseAuthorityBinding
	file, err := safefileio.OpenCurrentUserFile(path)
	if err != nil {
		return empty, fmt.Errorf("read pulse authority: %w", err)
	}
	defer file.Close()
	if err := safefileio.ValidatePrivateCurrentUserFile(file); err != nil {
		return empty, err
	}
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return empty, errors.New("invalid pulse authority state")
	}
	var binding pulseAuthorityBinding
	if json.Unmarshal(data, &binding) != nil || binding.Version != 1 || binding.ArchiveID != archiveID || !validPulseIdentity(binding.AuthorityID) || !validPulseIdentity(binding.Incarnation) || !filepath.IsAbs(binding.CanonicalOriginal) {
		return empty, errors.New("invalid pulse authority binding")
	}
	return binding, nil
}

func randomPulseIdentity() (string, error) {
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func validPulseIdentity(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == 32
}

func withPulseAuthorityLock(ctx context.Context, path string, create bool, fn func() (pulseAuthorityBinding, error)) (pulseAuthorityBinding, error) {
	var empty pulseAuthorityBinding
	dir := filepath.Dir(path)
	var err error
	if create {
		err = safefileio.EnsurePrivateDir(dir)
		if err == nil {
			err = syncPulseAuthorityDir(filepath.Dir(dir))
		}
	} else {
		err = safefileio.ValidatePrivateDir(dir)
	}
	if err != nil {
		return empty, err
	}
	lockPath := filepath.Join(dir, "registry.lock")
	if create {
		file, createErr := safefileio.CreatePrivateFile(lockPath)
		if createErr == nil {
			if err = file.Sync(); err == nil {
				err = file.Close()
			} else {
				_ = file.Close()
			}
			if err == nil {
				err = syncPulseAuthorityDir(dir)
			}
			if err != nil {
				return empty, err
			}
		} else if !errors.Is(createErr, os.ErrExist) {
			return empty, createErr
		}
	}
	file, err := safefileio.OpenCurrentUserFile(lockPath)
	if err != nil {
		return empty, err
	}
	err = safefileio.ValidatePrivateCurrentUserFile(file)
	_ = file.Close()
	if err != nil {
		return empty, err
	}
	lock := flock.New(lockPath)
	locked, err := lock.TryLockContext(ctx, 50*time.Millisecond)
	if err != nil {
		return empty, err
	}
	if !locked {
		return empty, errors.New("pulse authority lock unavailable")
	}
	defer func() { _ = lock.Unlock() }()
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return fn()
}
