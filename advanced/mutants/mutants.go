package main

import (
	"database/sql"
	"os/exec"
)

func executeExtractedSQL(db *sql.DB, rawQuery string) error {
	// GT: id=MUTANT-GO-001 type=TP cwe=CWE-89 rule=sql-injection parent_id=SAST-GO-001 mutation=extract_helper
	_, err := db.Query(rawQuery)
	return err
}

func runRenamedVarsCommand(targetHost string) ([]byte, error) {
	// GT: id=MUTANT-GO-002 type=TP cwe=CWE-78 rule=command-injection parent_id=SAST-GO-002 mutation=rename_vars
	return exec.Command("sh", "-c", "ping -c 1 "+targetHost).Output()
}

func runSafeParameterizedGo(db *sql.DB, safeID string) error {
	// GT: id=MUTANT-GO-003 type=FP reason=parameterized-query parent_id=SAST-GO-015 mutation=extract_helper
	_, err := db.Query("SELECT name FROM items WHERE id = ?", safeID)
	return err
}

func main() {}
