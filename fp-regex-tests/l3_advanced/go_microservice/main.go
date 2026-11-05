package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"
)

type AppConfig struct {
	Port string
	DBUrl string
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"UP"}`))
}

func queryUserSafe(ctx context.Context, db *sql.DB, uid string) error {
	row := db.QueryRowContext(ctx, "SELECT email FROM users WHERE id = $1", uid)
	var email string
	return row.Scan(&email)
}

func queryUserUnsafe(ctx context.Context, db *sql.DB, uid string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT email FROM users WHERE id = '%s'", uid)
	return db.QueryContext(ctx, query)
}

func executeUptime() error {
	cmd := exec.Command("/usr/bin/uptime")
	return cmd.Run()
}

func executeDynamicShell(input string) error {
	cmd := exec.Command("sh", "-c", input)
	return cmd.Run()
}

func createInsecureTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

func main() {
	apiKey := os.Getenv("API_SECRET_KEY")
	if apiKey == "" {
		log.Println("API key unset")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	server := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
