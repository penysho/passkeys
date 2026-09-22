package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/penysho/passkeys/internal/store"
	"golang.org/x/crypto/bcrypt"
)

const (
	SessionCookieName = "session_id"
	sessionTTL        = 7 * 24 * time.Hour
	bcryptCost        = bcrypt.DefaultCost
)

var (
	ErrInvalidUsername = errors.New("ユーザー名は3〜32文字の英数字とアンダースコアのみです")
	ErrInvalidPassword = errors.New("パスワードは8文字以上にしてください")
	ErrBadCredentials  = errors.New("ユーザー名またはパスワードが正しくありません")
	ErrUsernameTaken   = errors.New("このユーザー名は既に使われています")
)

type Service struct {
	store *store.Store
}

func New(s *store.Store) *Service {
	return &Service{store: s}
}

func (s *Service) Register(username, password string) (*store.User, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	handle := make([]byte, 64)
	if _, err := rand.Read(handle); err != nil {
		return nil, fmt.Errorf("generate handle: %w", err)
	}
	user, err := s.store.CreateUser(username, string(hash), handle)
	if errors.Is(err, store.ErrAlreadyExists) {
		return nil, ErrUsernameTaken
	}
	return user, err
}

func (s *Service) Login(username, password string) (*store.User, error) {
	user, err := s.store.GetUserByUsername(username)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrBadCredentials
	}
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrBadCredentials
	}
	return user, nil
}

func (s *Service) CreateSession(w http.ResponseWriter, userID int64) error {
	id, err := randomID()
	if err != nil {
		return err
	}
	expires := time.Now().Add(sessionTTL)
	if err := s.store.CreateSession(id, userID, expires); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    id,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
	})
	return nil
}

func (s *Service) UserFromRequest(r *http.Request) (*store.User, error) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return nil, store.ErrNotFound
	}
	sess, err := s.store.GetSession(c.Value)
	if err != nil {
		return nil, err
	}
	return s.store.GetUserByID(sess.UserID)
}

func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil && c.Value != "" {
		_ = s.store.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func randomID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func validateUsername(username string) error {
	n := utf8.RuneCountInString(username)
	if n < 3 || n > 32 {
		return ErrInvalidUsername
	}
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return ErrInvalidUsername
	}
	return nil
}

func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < 8 {
		return ErrInvalidPassword
	}
	return nil
}
