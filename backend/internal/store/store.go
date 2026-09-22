package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrAlreadyExists = errors.New("already exists")
)

type Store struct {
	db *sql.DB
}

type User struct {
	ID             int64
	Username       string
	PasswordHash   string
	WebAuthnHandle []byte
	CreatedAt      time.Time
}

type Credential struct {
	ID           int64
	UserID       int64
	CredentialID []byte
	FriendlyName string
	Transports   []string
	Credential   webauthn.Credential
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

type Session struct {
	ID        string
	UserID    int64
	ExpiresAt time.Time
}

type WebAuthnChallenge struct {
	ID        string
	UserID    *int64
	Data      webauthn.SessionData
	ExpiresAt time.Time
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    webauthn_handle BLOB NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    friendly_name TEXT NOT NULL,
    transports TEXT NOT NULL DEFAULT '[]',
    credential_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    data_json TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON webauthn_challenges(expires_at);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

func (s *Store) CreateUser(username, passwordHash string, handle []byte) (*User, error) {
	now := time.Now().UTC()
	res, err := s.db.Exec(
		`INSERT INTO users (username, password_hash, webauthn_handle, created_at) VALUES (?, ?, ?, ?)`,
		username, passwordHash, handle, now.Format(time.RFC3339Nano),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &User{
		ID:             id,
		Username:       username,
		PasswordHash:   passwordHash,
		WebAuthnHandle: handle,
		CreatedAt:      now,
	}, nil
}

func (s *Store) GetUserByID(id int64) (*User, error) {
	return scanUser(s.db.QueryRow(
		`SELECT id, username, password_hash, webauthn_handle, created_at FROM users WHERE id = ?`,
		id,
	))
}

func (s *Store) GetUserByUsername(username string) (*User, error) {
	return scanUser(s.db.QueryRow(
		`SELECT id, username, password_hash, webauthn_handle, created_at FROM users WHERE username = ?`,
		username,
	))
}

func (s *Store) GetUserByHandle(handle []byte) (*User, error) {
	return scanUser(s.db.QueryRow(
		`SELECT id, username, password_hash, webauthn_handle, created_at FROM users WHERE webauthn_handle = ?`,
		handle,
	))
}

func scanUser(row *sql.Row) (*User, error) {
	var (
		u       User
		created string
	)
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.WebAuthnHandle, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		u.CreatedAt, err = time.Parse(time.RFC3339, created)
		if err != nil {
			return nil, err
		}
	}
	return &u, nil
}

func (s *Store) ListCredentials(userID int64) ([]Credential, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, credential_id, friendly_name, transports, credential_json, created_at, last_used_at
         FROM credentials WHERE user_id = ? ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *Store) GetCredentialByCredentialID(credentialID []byte) (*Credential, error) {
	row := s.db.QueryRow(
		`SELECT id, user_id, credential_id, friendly_name, transports, credential_json, created_at, last_used_at
         FROM credentials WHERE credential_id = ?`,
		credentialID,
	)
	c, err := scanCredential(row)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Store) InsertCredential(userID int64, friendlyName string, cred webauthn.Credential) (*Credential, error) {
	now := time.Now().UTC()
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	transportJSON, err := json.Marshal(transports)
	if err != nil {
		return nil, err
	}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	res, err := s.db.Exec(
		`INSERT INTO credentials (user_id, credential_id, friendly_name, transports, credential_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
		userID, cred.ID, friendlyName, string(transportJSON), string(credJSON), now.Format(time.RFC3339Nano),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &Credential{
		ID:           id,
		UserID:       userID,
		CredentialID: cred.ID,
		FriendlyName: friendlyName,
		Transports:   transports,
		Credential:   cred,
		CreatedAt:    now,
	}, nil
}

func (s *Store) UpdateCredential(cred webauthn.Credential) error {
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	transportJSON, err := json.Marshal(transports)
	if err != nil {
		return err
	}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(
		`UPDATE credentials SET credential_json = ?, transports = ?, last_used_at = ? WHERE credential_id = ?`,
		string(credJSON), string(transportJSON), now, cred.ID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteCredential(userID, id int64) error {
	res, err := s.db.Exec(`DELETE FROM credentials WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCredential(row rowScanner) (*Credential, error) {
	var (
		c          Credential
		transports string
		credJSON   string
		created    string
		lastUsed   sql.NullString
	)
	err := row.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.FriendlyName, &transports, &credJSON, &created, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(transports), &c.Transports); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(credJSON), &c.Credential); err != nil {
		return nil, err
	}
	c.CreatedAt, err = parseTime(created)
	if err != nil {
		return nil, err
	}
	if lastUsed.Valid && lastUsed.String != "" {
		t, err := parseTime(lastUsed.String)
		if err != nil {
			return nil, err
		}
		c.LastUsedAt = &t
	}
	return &c, nil
}

func (s *Store) CreateSession(id string, userID int64, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)`,
		id, userID, expiresAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *Store) GetSession(id string) (*Session, error) {
	var (
		sess    Session
		expires string
	)
	err := s.db.QueryRow(
		`SELECT id, user_id, expires_at FROM sessions WHERE id = ?`,
		id,
	).Scan(&sess.ID, &sess.UserID, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt, err = parseTime(expires)
	if err != nil {
		return nil, err
	}
	if time.Now().After(sess.ExpiresAt) {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
		return nil, ErrNotFound
	}
	return &sess, nil
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (s *Store) CreateChallenge(id string, userID *int64, data webauthn.SessionData, expiresAt time.Time) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO webauthn_challenges (id, user_id, data_json, expires_at) VALUES (?, ?, ?, ?)`,
		id, userID, string(raw), expiresAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (s *Store) TakeChallenge(id string) (*WebAuthnChallenge, error) {
	var (
		c       WebAuthnChallenge
		userID  sql.NullInt64
		raw     string
		expires string
	)
	err := s.db.QueryRow(
		`SELECT id, user_id, data_json, expires_at FROM webauthn_challenges WHERE id = ?`,
		id,
	).Scan(&c.ID, &userID, &raw, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(`DELETE FROM webauthn_challenges WHERE id = ?`, id); err != nil {
		return nil, err
	}
	if userID.Valid {
		v := userID.Int64
		c.UserID = &v
	}
	if err := json.Unmarshal([]byte(raw), &c.Data); err != nil {
		return nil, err
	}
	c.ExpiresAt, err = parseTime(expires)
	if err != nil {
		return nil, err
	}
	if time.Now().After(c.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &c, nil
}

func parseTime(v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, v)
	if err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, v)
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "constraint failed")
}
