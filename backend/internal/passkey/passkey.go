package passkey

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/penysho/passkeys/internal/store"
)

const (
	ChallengeCookieName = "webauthn_challenge"
	challengeTTL        = 5 * time.Minute
)

var (
	ErrNoChallenge     = errors.New("認証チャレンジが見つかりません。最初からやり直してください")
	ErrChallengeUser   = errors.New("認証セッションが一致しません")
	ErrCredentialClone = errors.New("認証器のカウンターが不正です。パスキーが複製された可能性があります")
)

type Service struct {
	store *store.Store
	wa    *webauthn.WebAuthn
}

func New(s *store.Store, rpDisplayName, rpID string, origins []string) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     origins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn config: %w", err)
	}
	return &Service{store: s, wa: wa}, nil
}

type waUser struct {
	user        *store.User
	credentials []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.user.WebAuthnHandle }
func (u *waUser) WebAuthnName() string                       { return u.user.Username }
func (u *waUser) WebAuthnDisplayName() string                { return u.user.Username }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (s *Service) loadUser(user *store.User) (*waUser, error) {
	stored, err := s.store.ListCredentials(user.ID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, c := range stored {
		creds = append(creds, c.Credential)
	}
	return &waUser{user: user, credentials: creds}, nil
}

func (s *Service) BeginRegistration(w http.ResponseWriter, user *store.User) (*protocol.CredentialCreation, error) {
	wu, err := s.loadUser(user)
	if err != nil {
		return nil, err
	}
	exclude := make([]protocol.CredentialDescriptor, 0, len(wu.credentials))
	for _, c := range wu.credentials {
		exclude = append(exclude, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.ID,
			Transport:    c.Transport,
		})
	}
	creation, session, err := s.wa.BeginRegistration(wu,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationPreferred,
		}),
		webauthn.WithCredentialParameters([]protocol.CredentialParameter{
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
		}),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		return nil, err
	}
	if err := s.saveChallenge(w, &user.ID, *session); err != nil {
		return nil, err
	}
	return creation, nil
}

func (s *Service) FinishRegistration(r *http.Request, user *store.User) (*store.Credential, error) {
	ch, err := s.takeChallenge(r)
	if err != nil {
		return nil, err
	}
	if ch.UserID == nil || *ch.UserID != user.ID {
		return nil, ErrChallengeUser
	}
	wu, err := s.loadUser(user)
	if err != nil {
		return nil, err
	}
	cred, err := s.wa.FinishRegistration(wu, ch.Data, r)
	if err != nil {
		return nil, err
	}
	stored, err := s.store.InsertCredential(user.ID, DisplayName(cred.Authenticator.AAGUID, r.UserAgent()), *cred)
	if err != nil {
		return nil, err
	}
	return stored, nil
}

func (s *Service) BeginLogin(w http.ResponseWriter, username string) (*protocol.CredentialAssertion, error) {
	if username == "" {
		assertion, session, err := s.wa.BeginDiscoverableLogin(
			webauthn.WithUserVerification(protocol.VerificationPreferred),
		)
		if err != nil {
			return nil, err
		}
		if err := s.saveChallenge(w, nil, *session); err != nil {
			return nil, err
		}
		return assertion, nil
	}

	user, err := s.store.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}
	wu, err := s.loadUser(user)
	if err != nil {
		return nil, err
	}
	if len(wu.credentials) == 0 {
		return nil, errors.New("このユーザーにはパスキーが登録されていません")
	}
	assertion, session, err := s.wa.BeginLogin(wu,
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		return nil, err
	}
	if err := s.saveChallenge(w, &user.ID, *session); err != nil {
		return nil, err
	}
	return assertion, nil
}

func (s *Service) FinishLogin(r *http.Request) (*store.User, error) {
	ch, err := s.takeChallenge(r)
	if err != nil {
		return nil, err
	}

	var (
		user *store.User
		cred *webauthn.Credential
	)

	if ch.UserID != nil {
		user, err = s.store.GetUserByID(*ch.UserID)
		if err != nil {
			return nil, err
		}
		wu, err := s.loadUser(user)
		if err != nil {
			return nil, err
		}
		cred, err = s.wa.FinishLogin(wu, ch.Data, r)
		if err != nil {
			return nil, err
		}
	} else {
		handler := func(rawID, userHandle []byte) (webauthn.User, error) {
			u, err := s.store.GetUserByHandle(userHandle)
			if err != nil {
				return nil, err
			}
			return s.loadUser(u)
		}
		var wu webauthn.User
		wu, cred, err = s.wa.FinishPasskeyLogin(handler, ch.Data, r)
		if err != nil {
			return nil, err
		}
		loaded, ok := wu.(*waUser)
		if !ok {
			return nil, errors.New("ユーザー情報の取得に失敗しました")
		}
		user = loaded.user
	}

	if cred != nil && cred.Authenticator.CloneWarning {
		return nil, ErrCredentialClone
	}
	if cred != nil {
		if err := s.store.UpdateCredential(*cred); err != nil {
			return nil, err
		}
	}
	return user, nil
}

func (s *Service) saveChallenge(w http.ResponseWriter, userID *int64, data webauthn.SessionData) error {
	id, err := randomID()
	if err != nil {
		return err
	}
	expires := time.Now().Add(challengeTTL)
	if err := s.store.CreateChallenge(id, userID, data, expires); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     ChallengeCookieName,
		Value:    id,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(challengeTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
	})
	return nil
}

func (s *Service) takeChallenge(r *http.Request) (*store.WebAuthnChallenge, error) {
	c, err := r.Cookie(ChallengeCookieName)
	if err != nil || c.Value == "" {
		return nil, ErrNoChallenge
	}
	ch, err := s.store.TakeChallenge(c.Value)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoChallenge
	}
	return ch, err
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
