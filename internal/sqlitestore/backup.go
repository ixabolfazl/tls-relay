package sqlitestore

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Backup creates a point-in-time snapshot copy of the SQLite database at destPath
// using SQLite's VACUUM INTO command.
func (s *Store) Backup(ctx context.Context, destPath string) error {
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return fmt.Errorf("creating backup directory %q: %w", destDir, err)
	}

	// Remove existing destination file if present, as VACUUM INTO requires target file not to exist.
	_ = os.Remove(destPath)

	query := fmt.Sprintf("VACUUM INTO %s", quoteSQLiteLiteral(destPath))
	if _, err := s.reader.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("executing sqlite backup (VACUUM INTO): %w", err)
	}
	_ = os.Chmod(destPath, 0o600)
	return nil
}

// BackupToWriter creates a temp database snapshot via Backup and streams it to w.
func (s *Store) BackupToWriter(ctx context.Context, w io.Writer) error {
	tmpFile, err := os.CreateTemp("", "sqlite-backup-*.db")
	if err != nil {
		return fmt.Errorf("creating temp backup file: %w", err)
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	if err := s.Backup(ctx, tmpPath); err != nil {
		return err
	}

	f, err := os.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("opening backup temp file: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(w, f); err != nil {
		return fmt.Errorf("streaming backup file: %w", err)
	}
	return nil
}
