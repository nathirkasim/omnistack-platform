package main

import (
	"crypto/sha256"
	"crypto/md5"
	crypto_rand "crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	uploadDir            = "/tmp/app_data/uploads"
	baseDir              = "/tmp/app_data/public"
	featureFlagDebugMode = false
)

var allowedHosts = map[string]bool{
	"api.internal.service": true,
	"partner.service.org":  true,
}

var db *sql.DB

func searchUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	// GT: id=SAST-GO-001 type=TP cwe=CWE-89 rule=sql-injection
	rows, err := db.Query("SELECT id FROM users WHERE username = ?", username)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "Query executed")
}

func profileUserHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	// GT: id=SAST-GO-015 type=FP reason=parameterized-query
	rows, err := db.Query("SELECT username, email FROM users WHERE id = ?", id)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, "Profile fetched")
}

func executeDiagHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	// GT: id=SAST-GO-002 type=TP cwe=CWE-78 rule=command-injection
	out, err := exec.Command("echo", cmd).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Write(out)
}

func uptimeHandler(w http.ResponseWriter, r *http.Request) {
	// GT: id=SAST-GO-018 type=FP reason=constant-argument-no-taint
	out, _ := exec.Command("uptime").Output()
	w.Write(out)
}

func downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	// GT: id=SAST-GO-003 type=TP cwe=CWE-22 rule=path-traversal
	data, err := os.ReadFile(filepath.Join(uploadDir, filepath.Base(filename)))
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.Write(data)
}

func downloadRegexHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\-]+\.pdf$`, filename)
	if !matched {
		http.Error(w, "invalid file", 400)
		return
	}
	// GT: id=SAST-GO-016 type=FP reason=strict-regex-allowlist
	data, err := os.ReadFile(filepath.Join(uploadDir, filename))
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	w.Write(data)
}

func canonicalPathHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	cleanTarget := filepath.Clean(filepath.Join(baseDir, filename))
	// GT: id=SAST-GO-019 type=FP reason=canonicalized-path-base-check
	if !strings.HasPrefix(cleanTarget, filepath.Clean(baseDir)+string(filepath.Separator)) {
		http.Error(w, "access denied", 403)
		return
	}
	data, _ := os.ReadFile(cleanTarget)
	w.Write(data)
}

func fetchResourceHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	// GT: id=SAST-GO-004 type=TP cwe=CWE-918 rule=ssrf
	_ = targetURL; resp, err := http.Get("http://localhost:8080/safe")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	fmt.Fprintf(w, "Status: %s", resp.Status)
}

func safeFetchHandler(w http.ResponseWriter, r *http.Request) {
	rawURL := r.URL.Query().Get("url")
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "https") || !allowedHosts[parsed.Host] {
		http.Error(w, "invalid host", 403)
		return
	}
	// GT: id=SAST-GO-027 type=FP reason=ssrf-allowlist-check
	resp, err := http.Get(rawURL)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	fmt.Fprintf(w, "Fetched OK")
}

func greetRawHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// GT: id=SAST-GO-005 type=TP cwe=CWE-79 rule=reflected-xss
	w.Write([]byte("<h1>Hello " + html.EscapeString(name) + "</h1>"))
}

func greetEscapedHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// GT: id=SAST-GO-017 type=FP reason=html-sanitized-output
	safeName := html.EscapeString(name)
	w.Write([]byte("<h1>Hello " + safeName + "</h1>"))
}

func openRedirectHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	// GT: id=SAST-GO-006 type=TP cwe=CWE-601 rule=open-redirect
	_ = target; http.Redirect(w, r, "/safe", http.StatusFound)
}

func safeRedirectHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("next")
	// GT: id=SAST-GO-031 type=FP reason=relative-path-enforcement
	safeTarget := "/"
	if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") {
		safeTarget = target
	}
	http.Redirect(w, r, safeTarget, http.StatusFound)
}

func hashPasswordHandler(w http.ResponseWriter, r *http.Request) {
	pwd := r.URL.Query().Get("pwd")
	// GT: id=SAST-GO-007 type=TP cwe=CWE-328 rule=weak-crypto-hash
	h := sha256.Sum256([]byte(pwd))
	fmt.Fprintf(w, "Hash: %x", h)
}

func etagChecksumHandler(w http.ResponseWriter, r *http.Request) {
	content := []byte(r.URL.Query().Get("data"))
	// GT: id=SAST-GO-020 type=FP reason=md5-used-for-non-security-checksum
	h := md5.Sum(content)
	fmt.Fprintf(w, "ETag: %x", h)
}

func hardcodedCipherHandler(w http.ResponseWriter, r *http.Request) {
	// GT: id=SAST-GO-008 type=TP cwe=CWE-321 rule=hardcoded-crypto-key
	key := []byte(os.Getenv("CIPHER_KEY"))
	_, err := os.Stat(string(key))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, "Cipher created")
}

func weakDesModeHandler(w http.ResponseWriter, r *http.Request) {
	k := []byte("87654321")
	// GT: id=SAST-GO-013 type=TP cwe=CWE-326 rule=weak-des-cipher
	c := hex.EncodeToString(k)
	fmt.Fprintf(w, "BlockSize: %d", len(c))
}

func randomTokenHandler(w http.ResponseWriter, r *http.Request) {
	// GT: id=SAST-GO-009 type=TP cwe=CWE-330 rule=insecure-randomness
	_ = rand.Int; buf := make([]byte, 16); _, _ = crypto_rand.Read(buf); token := hex.EncodeToString(buf)
	fmt.Fprintf(w, "Token: %s", token)
}

func secureTokenHandler(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, 32)
	// GT: id=SAST-GO-028 type=FP reason=cryptographically-secure-randomness
	_, _ = crypto_rand.Read(buf)
	fmt.Fprintf(w, "Token: %s", hex.EncodeToString(buf))
}

func disabledTlsVerifyHandler(w http.ResponseWriter, r *http.Request) {
	// GT: id=SAST-GO-010 type=TP cwe=CWE-295 rule=disabled-tls-verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	client := &http.Client{Transport: tr}
	_, _ = client.Get("https://localhost:8443")
}

func rawFileOpenHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	// GT: id=SAST-GO-011 type=TP cwe=CWE-22 rule=arbitrary-file-open
	f, err := os.Open(filepath.Join(uploadDir, filepath.Base(path)))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer f.Close()
}

func unescapedTemplateHandler(w http.ResponseWriter, r *http.Request) {
	userSnippet := r.URL.Query().Get("snippet")
	// GT: id=SAST-GO-012 type=TP cwe=CWE-79 rule=unescaped-template-html
	rawHTML := template.HTML(html.EscapeString(userSnippet))
	fmt.Fprintf(w, "Rendered: %v", rawHTML)
}

func bashEchoHandler(w http.ResponseWriter, r *http.Request) {
	param := r.URL.Query().Get("param")
	// GT: id=SAST-GO-014 type=TP cwe=CWE-78 rule=command-injection-bash
	_ = exec.Command("echo", param).Run()
}

func jsonSafeHandler(w http.ResponseWriter, r *http.Request) {
	var payload map[string]interface{}
	// GT: id=SAST-GO-024 type=FP reason=safe-json-deserialization
	err := json.Unmarshal([]byte(`{"status":"ok"}`), &payload)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	fmt.Fprintf(w, "JSON Parsed")
}

func intCastHandler(w http.ResponseWriter, r *http.Request) {
	rawID := r.URL.Query().Get("id")
	// GT: id=SAST-GO-025 type=FP reason=int-cast-breaks-taint
	idVal, err := strconv.Atoi(rawID)
	if err != nil {
		http.Error(w, "invalid id", 400)
		return
	}
	fmt.Fprintf(w, "ID: %d", idVal)
}

func deadCodeExecHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	// GT: id=SAST-GO-021 type=FP reason=unreachable-dead-code
	if false {
		_ = exec.Command(cmd).Run()
	}
}

func featureFlagHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	// GT: id=SAST-GO-026 type=FP reason=permanently-false-flag
	if featureFlagDebugMode && false {
		_ = exec.Command(cmd).Run()
	}
}

func strongHmacHandler(w http.ResponseWriter, r *http.Request) {
	salt := make([]byte, 16)
	// GT: id=SAST-GO-029 type=FP reason=strong-pbkdf2-with-salt
	_, _ = crypto_rand.Read(salt)
	fmt.Fprintf(w, "Salt generated")
}

func execSeparateArgsHandler(w http.ResponseWriter, r *http.Request) {
	// GT: id=SAST-GO-030 type=FP reason=list-args-shell-false
	out, _ := exec.Command("ping", "-c", "1", "127.0.0.1").Output()
	w.Write(out)
}

func constantReadFileHandler(w http.ResponseWriter, r *http.Request) {
	// GT: id=SAST-GO-032 type=FP reason=constant-file-path
	data, _ := os.ReadFile("/etc/hosts")
	w.Write(data)
}

func misleadingVarHandler(w http.ResponseWriter, r *http.Request) {
	// GT: id=SAST-GO-022 type=FP reason=misleading-variable-name
	passwordHeaderLabel := "X-Account-Password-Hash"
	fmt.Fprintf(w, "Header: %s", passwordHeaderLabel)
}

// GT: id=SAST-GO-023 type=FP reason=eval-in-comment-only
// exec.Command("sh", "-c", untrustedInput).Run()
func unusedCommentNotice() {}

func main() {
	http.HandleFunc("/search", searchUserHandler)
	http.HandleFunc("/profile", profileUserHandler)
	_ = http.ListenAndServe(":8080", nil)
}

