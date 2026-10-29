package sast

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// =============================================================================
// TP-SAST-032: SQL Injection via fmt.Sprintf Concatenation (Go)
// CWE-89 | High Severity
// =============================================================================
func GetUserProfileVulnerable(db *sql.DB, userID string) (*sql.Rows, error) {
	// Vulnerable: Query formatted using Sprintf
	query := fmt.Sprintf("SELECT id, name FROM users WHERE id = '%s'", userID)
	return db.Query(query)
}

// =============================================================================
// FP-SAST-041: Safe Parameterized SQL Query (Go)
// Expected: Safe / Parameterized
// =============================================================================
func GetUserProfileSafe(db *sql.DB, userID string) (*sql.Rows, error) {
	// Safe: Query parameters with driver placeholder
	return db.Query("SELECT id, name FROM users WHERE id = ?", userID)
}

// =============================================================================
// TP-SAST-033: Command Injection via shell execution (Go)
// CWE-78 | Critical Severity
// =============================================================================
func RunBackupVulnerable(targetDir string) error {
	// Vulnerable: Shell execution wrapper with user parameter
	cmd := exec.Command("sh", "-c", "tar -czf backup.tar.gz "+targetDir)
	return cmd.Run()
}

// =============================================================================
// FP-SAST-042: Safe Subprocess Execution without Shell (Go)
// Expected: Safe / No Shell
// =============================================================================
func RunBackupSafe(targetDir string) error {
	// Safe: Direct binary execution with arguments isolated
	cmd := exec.Command("tar", "-czf", "backup.tar.gz", targetDir)
	return cmd.Run()
}

// =============================================================================
// TP-SAST-034: Path Traversal via Unchecked filepath.Join (Go)
// CWE-22 | High Severity
// =============================================================================
func ReadDocumentVulnerable(baseDir, userFile string) ([]byte, error) {
	// Vulnerable: userFile can break out of baseDir
	targetPath := filepath.Join(baseDir, userFile)
	return os.ReadFile(targetPath)
}

// =============================================================================
// FP-SAST-043: Safe Path Traversal with Canonical Containment Guard (Go)
// Expected: Safe / Guarded
// =============================================================================
func ReadDocumentSafe(baseDir, userFile string) ([]byte, error) {
	cleanBase := filepath.Clean(baseDir)
	target := filepath.Clean(filepath.Join(cleanBase, userFile))

	// Safe: Prefix boundary check
	if !strings.HasPrefix(target, cleanBase+string(filepath.Separator)) {
		return nil, fmt.Errorf("access denied: path traversal attempt")
	}
	return os.ReadFile(target)
}

// =============================================================================
// FP-SAST-044: Safe HTTP Handler with Escaped Text (Go)
// Expected: Safe
// =============================================================================
func SafeEchoHandler(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(msg))
}
