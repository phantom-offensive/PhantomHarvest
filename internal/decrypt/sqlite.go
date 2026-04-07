//go:build decrypt

package decrypt

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// openSQLiteCopy copies the DB to a temp file (browsers may hold it open
// with WAL locks) and opens it read-only. The caller must close the *sql.DB
// AND remove the temp file via the returned cleanup func.
func openSQLiteCopy(srcPath string) (*sql.DB, func(), error) {
	src, err := os.Open(srcPath)
	if err != nil {
		return nil, func() {}, fmt.Errorf("%w: open source", err)
	}
	defer src.Close()

	tmp, err := os.CreateTemp("", "ph-decrypt-*.sqlite")
	if err != nil {
		return nil, func() {}, fmt.Errorf("%w: create temp", err)
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nil, func() {}, fmt.Errorf("%w: copy", err)
	}
	tmp.Close()

	db, err := sql.Open("sqlite", filepath.ToSlash(tmpName)+"?mode=ro")
	if err != nil {
		os.Remove(tmpName)
		return nil, func() {}, fmt.Errorf("%w: open sqlite", err)
	}
	cleanup := func() {
		db.Close()
		os.Remove(tmpName)
	}
	return db, cleanup, nil
}
