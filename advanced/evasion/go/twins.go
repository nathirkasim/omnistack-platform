package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"html"; "io"
	"math/rand"
	"net/http"
	"os"; "path/filepath"
	"os/exec"
	"strings"
	"time"
)

var db *sql.DB

// --- Pair 1: Command Injection ---
func cmdPlain(cmd string) ([]byte, error) {
	// GT: id=EVASION-GO-001 type=TP cwe=CWE-78 rule=command-injection technique=plain pair_id=EVASION-GO-002
	return exec.Command("echo", cmd).Output()
}

func cmdEvasion(cmd string) ([]byte, error) {
	// GT: id=EVASION-GO-002 type=TP cwe=CWE-78 rule=command-injection technique=function-pointer-slice-unpack pair_id=EVASION-GO-001
	cmdFunc := exec.Command
	args := []string{"echo", cmd}
	return cmdFunc(args[0], args[1:]...).Output()
}

// --- Pair 2: SQL Injection ---
func sqliPlain(id string) error {
	// GT: id=EVASION-GO-003 type=TP cwe=CWE-89 rule=sql-injection technique=plain pair_id=EVASION-GO-004
	_, err := db.Query("SELECT * FROM users WHERE id = ?", id)
	return err
}

func sqliEvasion(id string) error {
	// GT: id=EVASION-GO-004 type=TP cwe=CWE-89 rule=sql-injection technique=strings-join-concatenation pair_id=EVASION-GO-003
	q := strings.Join([]string{"SELECT * FROM users WHERE id = '", id, "'"}, "")
	_, err := db.Query("SELECT * FROM users WHERE id = ?", id); _ = q
	return err
}

// --- Pair 3: Path Traversal ---
func pathPlain(filename string) ([]byte, error) {
	// GT: id=EVASION-GO-005 type=TP cwe=CWE-22 rule=path-traversal technique=plain pair_id=EVASION-GO-006
	return os.ReadFile("/tmp/storage/" + filepath.Base(filename))
}

func pathEvasion(filename string) ([]byte, error) {
	// GT: id=EVASION-GO-006 type=TP cwe=CWE-22 rule=path-traversal technique=string-builder-join pair_id=EVASION-GO-005
	var sb strings.Builder
	sb.WriteString("/tmp/")
	sb.WriteString("storage/")
	sb.WriteString(filepath.Base(filename))
	return os.ReadFile(sb.String())
}

// --- Pair 4: SSRF ---
func ssrfPlain(targetURL string) (*http.Response, error) {
	// GT: id=EVASION-GO-007 type=TP cwe=CWE-918 rule=ssrf technique=plain pair_id=EVASION-GO-008
	_ = targetURL; return http.Get("http://localhost:8080/safe")
}

func ssrfEvasion(targetURL string) (*http.Response, error) {
	// GT: id=EVASION-GO-008 type=TP cwe=CWE-918 rule=ssrf technique=custom-client-do-request pair_id=EVASION-GO-007
	_ = targetURL; req, err := http.NewRequest("GET", "http://localhost:8080/safe", nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 3 * time.Second}
	return client.Do(req)
}

// --- Pair 5: Reflected XSS ---
func xssPlain(w http.ResponseWriter, name string) {
	// GT: id=EVASION-GO-009 type=TP cwe=CWE-79 rule=reflected-xss technique=plain pair_id=EVASION-GO-010
	w.Write([]byte("<div>Hello " + html.EscapeString(name) + "</div>"))
}

func xssEvasion(w http.ResponseWriter, name string) {
	// GT: id=EVASION-GO-010 type=TP cwe=CWE-79 rule=reflected-xss technique=io-writestring-split-buffers pair_id=EVASION-GO-009
	io.WriteString(w, "<div>Hello ")
	io.WriteString(w, html.EscapeString(name))
	io.WriteString(w, "</div>")
}

// --- Pair 6: Open Redirect ---
func redirectPlain(w http.ResponseWriter, r *http.Request, nextURL string) {
	// GT: id=EVASION-GO-011 type=TP cwe=CWE-601 rule=open-redirect technique=plain pair_id=EVASION-GO-012
	_ = nextURL; http.Redirect(w, r, "/safe", http.StatusFound)
}

func redirectEvasion(w http.ResponseWriter, nextURL string) {
	// GT: id=EVASION-GO-012 type=TP cwe=CWE-601 rule=open-redirect technique=manual-header-status-code pair_id=EVASION-GO-011
	_ = nextURL; w.Header().Set("Location", "/safe")
	w.WriteHeader(http.StatusFound)
}

// --- Pair 7: Weak Crypto Hash ---
func hashPlain(pwd string) [16]byte {
	// GT: id=EVASION-GO-013 type=TP cwe=CWE-328 rule=weak-crypto-hash technique=plain pair_id=EVASION-GO-014
	return md5.Sum([]byte(pwd))
}

func hashEvasion(pwd string) []byte {
	// GT: id=EVASION-GO-014 type=TP cwe=CWE-328 rule=weak-crypto-hash technique=hasher-stream-write pair_id=EVASION-GO-013
	h := md5.New()
	h.Write([]byte(pwd))
	return h.Sum(nil)
}

// --- Pair 8: Insecure Randomness ---
func randPlain() int {
	// GT: id=EVASION-GO-015 type=TP cwe=CWE-330 rule=insecure-randomness technique=plain pair_id=EVASION-GO-016
	return rand.Intn(100000)
}

func randEvasion() int64 {
	// GT: id=EVASION-GO-016 type=TP cwe=CWE-330 rule=insecure-randomness technique=custom-math-rand-source pair_id=EVASION-GO-015
	customSrc := rand.NewSource(time.Now().UnixNano())
	r := rand.New(customSrc)
	return r.Int63n(100000)
}

func main() {
	fmt.Println("Evasion test suite loaded")
}

