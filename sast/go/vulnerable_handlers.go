package main

import (
    "crypto/tls"
    "database/sql"
    "fmt"
    "net/http"
    "os"
    "os/exec"
    "path/filepath"
)

func QueryAccountHandler(db *sql.DB, w http.ResponseWriter, r *http.Request) {
    accountId := r.URL.Query().Get("id")
    // VULNERABLE: Concatenating query parameter directly into SQL string (CWE-89)
    query := fmt.Sprintf("SELECT id, balance FROM accounts WHERE id = '%s'", accountId)
    rows, _ := db.Query(query)
    defer rows.Close()
}

func ExecDiagnosticHandler(w http.ResponseWriter, r *http.Request) {
    targetHost := r.URL.Query().Get("host")
    // VULNERABLE: Passing untrusted argument to shell interpreter (CWE-78)
    cmd := exec.Command("sh", "-c", "traceroute "+targetHost)
    output, _ := cmd.CombinedOutput()
    w.Write(output)
}

func FetchProxyHandler(w http.ResponseWriter, r *http.Request) {
    targetUrl := r.URL.Query().Get("url")
    // VULNERABLE: SSRF fetching untrusted network destination (CWE-918)
    resp, _ := http.Get(targetUrl)
    defer resp.Body.Close()
}

func ReadStaticFileHandler(w http.ResponseWriter, r *http.Request) {
    filename := r.URL.Query().Get("file")
    // VULNERABLE: Path Traversal without filepath clean check (CWE-22)
    path := filepath.Join("/var/www/static", filename)
    data, _ := os.ReadFile(path)
    w.Write(data)
}

func InsecureTlsClient() *http.Client {
    // VULNERABLE: InsecureSkipVerify disables TLS server certificate verification (CWE-295)
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    return &http.Client{Transport: tr}
}
