package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/penysho/passkeys/internal/auth"
	"github.com/penysho/passkeys/internal/passkey"
	"github.com/penysho/passkeys/internal/store"
)

type contextKey int

const userContextKey contextKey = 1

type Server struct {
	auth    *auth.Service
	passkey *passkey.Service
	store   *store.Store
}

func New(authSvc *auth.Service, passkeySvc *passkey.Service, st *store.Store) http.Handler {
	s := &Server{auth: authSvc, passkey: passkeySvc, store: st}
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Route("/api", func(r chi.Router) {
		r.Post("/auth/register", s.handleRegister)
		r.Post("/auth/login", s.handleLogin)
		r.Post("/auth/logout", s.handleLogout)
		r.Get("/me", s.handleMe)

		r.Post("/passkeys/login/begin", s.handlePasskeyLoginBegin)
		r.Post("/passkeys/login/finish", s.handlePasskeyLoginFinish)

		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)
			r.Get("/passkeys", s.handleListPasskeys)
			r.Post("/passkeys/register/begin", s.handlePasskeyRegisterBegin)
			r.Post("/passkeys/register/finish", s.handlePasskeyRegisterFinish)
			r.Delete("/passkeys/{id}", s.handleDeletePasskey)
		})
	})

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return r
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := s.auth.UserFromRequest(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "ログインが必要です")
			return
		}
		ctx := context.WithValue(r.Context(), userContextKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func currentUser(r *http.Request) *store.User {
	user, _ := r.Context().Value(userContextKey).(*store.User)
	return user
}

type credentialsBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body credentialsBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "リクエストの形式が正しくありません")
		return
	}
	user, err := s.auth.Register(body.Username, body.Password)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if err := s.auth.CreateSession(w, user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "セッションの作成に失敗しました")
		return
	}
	writeJSON(w, http.StatusCreated, userJSON(user))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body credentialsBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "リクエストの形式が正しくありません")
		return
	}
	user, err := s.auth.Login(body.Username, body.Password)
	if err != nil {
		writeAuthError(w, err)
		return
	}
	if err := s.auth.CreateSession(w, user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "セッションの作成に失敗しました")
		return
	}
	writeJSON(w, http.StatusOK, userJSON(user))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.Logout(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, err := s.auth.UserFromRequest(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "ログインが必要です")
		return
	}
	writeJSON(w, http.StatusOK, userJSON(user))
}

func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	creation, err := s.passkey.BeginRegistration(w, user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "パスキー登録の開始に失敗しました")
		return
	}
	writeJSON(w, http.StatusOK, creation.Response)
}

func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	cred, err := s.passkey.FinishRegistration(r, user, r.URL.Query().Get("name"))
	if err != nil {
		writePasskeyError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, credentialJSON(*cred))
}

type passkeyLoginBeginBody struct {
	Username string `json:"username"`
}

func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	var body passkeyLoginBeginBody
	_ = json.NewDecoder(r.Body).Decode(&body)
	assertion, err := s.passkey.BeginLogin(w, body.Username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "ユーザーが見つかりません")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, assertion.Response)
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	user, err := s.passkey.FinishLogin(r)
	if err != nil {
		writePasskeyError(w, err)
		return
	}
	if err := s.auth.CreateSession(w, user.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "セッションの作成に失敗しました")
		return
	}
	writeJSON(w, http.StatusOK, userJSON(user))
}

func (s *Server) handleListPasskeys(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	creds, err := s.store.ListCredentials(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "パスキー一覧の取得に失敗しました")
		return
	}
	out := make([]map[string]any, 0, len(creds))
	for _, c := range creds {
		out = append(out, credentialJSON(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "パスキーIDが正しくありません")
		return
	}
	if err := s.store.DeleteCredential(user.ID, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "パスキーが見つかりません")
			return
		}
		writeError(w, http.StatusInternalServerError, "パスキーの削除に失敗しました")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func userJSON(user *store.User) map[string]any {
	return map[string]any{
		"id":       user.ID,
		"username": user.Username,
	}
}

func credentialJSON(c store.Credential) map[string]any {
	var lastUsed any
	if c.LastUsedAt != nil {
		lastUsed = c.LastUsedAt.Format(time.RFC3339)
	}
	return map[string]any{
		"id":           c.ID,
		"name":         c.FriendlyName,
		"transports":   c.Transports,
		"createdAt":    c.CreatedAt.Format(time.RFC3339),
		"lastUsedAt":   lastUsed,
		"backupState":  c.Credential.Flags.BackupState,
		"userVerified": c.Credential.Flags.UserVerified,
	}
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidUsername), errors.Is(err, auth.ErrInvalidPassword), errors.Is(err, auth.ErrUsernameTaken):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, auth.ErrBadCredentials):
		writeError(w, http.StatusUnauthorized, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "処理に失敗しました")
	}
}

func writePasskeyError(w http.ResponseWriter, err error) {
	log.Printf("passkey error: %v", err)
	switch {
	case errors.Is(err, passkey.ErrNoChallenge), errors.Is(err, passkey.ErrChallengeUser):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, passkey.ErrCredentialClone):
		writeError(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, store.ErrAlreadyExists):
		writeError(w, http.StatusConflict, "このパスキーは既に登録されています")
	default:
		writeError(w, http.StatusBadRequest, "パスキーの検証に失敗しました")
	}
}
