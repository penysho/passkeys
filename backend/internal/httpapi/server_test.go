package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/penysho/passkeys/internal/auth"
	"github.com/penysho/passkeys/internal/passkey"
	"github.com/penysho/passkeys/internal/store"
)

func TestPasswordAuthFlow(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	authSvc := auth.New(st)
	passkeySvc, err := passkey.New(st, "Test", "localhost", []string{"http://localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(New(authSvc, passkeySvc, st))
	t.Cleanup(server.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}

	res, err := client.Post(server.URL+"/api/auth/register", "application/json", strings.NewReader(`{"username":"alice","password":"password123"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("register status %d: %s", res.StatusCode, body)
	}

	res, err = client.Get(server.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("me status %d: %s", res.StatusCode, body)
	}
	var me map[string]any
	if err := json.Unmarshal(body, &me); err != nil {
		t.Fatal(err)
	}
	if me["username"] != "alice" {
		t.Fatalf("username = %v", me["username"])
	}

	res, err = client.Post(server.URL+"/api/passkeys/register/begin", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("register begin status %d: %s", res.StatusCode, body)
	}
	var opts map[string]any
	if err := json.Unmarshal(body, &opts); err != nil {
		t.Fatal(err)
	}
	if _, ok := opts["challenge"].(string); !ok {
		t.Fatalf("missing challenge: %s", body)
	}
	user, _ := opts["user"].(map[string]any)
	if user["name"] != "alice" {
		t.Fatalf("user = %v", user)
	}
	selection, _ := opts["authenticatorSelection"].(map[string]any)
	if _, ok := selection["authenticatorAttachment"]; ok {
		t.Fatalf("authenticatorAttachment must be omitted: %s", body)
	}
	if selection["residentKey"] != "required" {
		t.Fatalf("residentKey = %v", selection["residentKey"])
	}

	res, err = client.Post(server.URL+"/api/auth/logout", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()

	res, err = client.Get(server.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d", res.StatusCode)
	}

	res, err = client.Post(server.URL+"/api/auth/login", "application/json", strings.NewReader(`{"username":"alice","password":"password123"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login status %d: %s", res.StatusCode, body)
	}
}
