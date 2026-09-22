package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/penysho/passkeys/internal/auth"
	"github.com/penysho/passkeys/internal/httpapi"
	"github.com/penysho/passkeys/internal/passkey"
	"github.com/penysho/passkeys/internal/store"
)

func main() {
	addr := env("HTTP_ADDR", ":8080")
	dbPath := env("DB_PATH", filepath.Join("data", "passkeys.db"))
	rpID := env("RP_ID", "localhost")
	rpName := env("RP_DISPLAY_NAME", "Passkeys Demo")
	origins := strings.Split(env("RP_ORIGINS", "http://localhost:3000"), ",")

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer st.Close()

	authSvc := auth.New(st)
	passkeySvc, err := passkey.New(st, rpName, rpID, trimAll(origins))
	if err != nil {
		log.Fatalf("webauthn: %v", err)
	}

	handler := httpapi.New(authSvc, passkeySvc, st)
	log.Printf("listening on %s (rpID=%s origins=%v)", addr, rpID, origins)
	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatal(err)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func trimAll(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}
