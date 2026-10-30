package app

import (
	"context"
	"errors"
	"strings"

	"github.com/Rass0l/storage-boxes/internal/identity/domain"
	"github.com/Rass0l/storage-boxes/internal/platform/clock"
	platerr "github.com/Rass0l/storage-boxes/internal/platform/errors"
	"github.com/Rass0l/storage-boxes/internal/platform/ids"
)

// Deps bundles the collaborators required by the identity service.
type Deps struct {
	Users       UserStore
	Credentials CredentialStore
	Sessions    SessionService
	Roles       RoleStore
	Hasher      PasswordHasher
	IDs         ids.IDGenerator
	Clock       clock.Clock
}

// Service is the concrete implementation of IdentityService.
type Service struct {
	deps      Deps
	auditSink AuditSink
}

var _ IdentityService = (*Service)(nil)

func NewService(deps Deps) *Service {
	if deps.IDs == nil {
		deps.IDs = ids.RandomGenerator{}
	}
	if deps.Clock == nil {
		deps.Clock = clock.RealClock{}
	}
	return &Service{deps: deps}
}

func (s *Service) CreateUser(ctx context.Context, input CreateUserInput) (domain.User, error) {
	email := strings.ToLower(strings.TrimSpace(input.Email))
	if email == "" || !strings.Contains(email, "@") {
		return domain.User{}, platerr.New(platerr.CategoryValidation, "invalid_email", "email is required")
	}
	if len(input.Password) < 8 {
		return domain.User{}, platerr.New(platerr.CategoryValidation, "weak_password", "password must be at least 8 characters")
	}
	if _, err := s.deps.Users.GetByEmail(ctx, email); err == nil {
		return domain.User{}, platerr.New(platerr.CategoryConflict, "email_in_use", "email is already registered")
	}
	hashed, err := s.deps.Hasher.Hash(input.Password)
	if err != nil {
		return domain.User{}, platerr.New(platerr.CategoryInternal, "hash_failed", err.Error())
	}
	user := domain.User{
		ID:          s.deps.IDs.New("usr"),
		Email:       email,
		DisplayName: strings.TrimSpace(input.DisplayName),
		Status:      "active",
		CreatedAt:   s.deps.Clock.Now(),
	}
	if err := s.deps.Users.Put(ctx, user); err != nil {
		return domain.User{}, platerr.New(platerr.CategoryInternal, "persist_user_failed", err.Error())
	}
	cred := domain.Credential{
		UserID:        user.ID,
		PasswordHash:  hashed,
		HashAlgorithm: "argon2id",
		HashVersion:   1,
	}
	if err := s.deps.Credentials.Put(ctx, cred); err != nil {
		return domain.User{}, platerr.New(platerr.CategoryInternal, "persist_credential_failed", err.Error())
	}
	return user, nil
}

var errInvalidCredentials = platerr.New(platerr.CategoryAuth, domain.ErrCodeInvalidCredentials, "invalid email or password")

func (s *Service) Authenticate(ctx context.Context, email, password string) (domain.Session, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || password == "" {
		return domain.Session{}, errInvalidCredentials
	}
	user, err := s.deps.Users.GetByEmail(ctx, email)
	if err != nil {
		// Still run a hash verify to reduce timing signal on unknown users.
		_, _ = s.deps.Hasher.Verify(password, "$argon2id$v=19$m=8,t=1,p=1$YWFhYWFhYWE$YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")
		s.emitAudit(ctx, "identity.login_failed", "", "", map[string]any{"email": email, "reason": "unknown_user"})
		return domain.Session{}, errInvalidCredentials
	}
	if user.Status == "disabled" || user.Status == "locked" {
		return domain.Session{}, platerr.New(platerr.CategoryAuth, domain.ErrCodeUserLocked, "user locked")
	}
	cred, err := s.deps.Credentials.GetByUserID(ctx, user.ID)
	if err != nil {
		return domain.Session{}, errInvalidCredentials
	}
	ok, err := s.deps.Hasher.Verify(password, cred.PasswordHash)
	if err != nil || !ok {
		s.emitAudit(ctx, "identity.login_failed", user.ID, "", map[string]any{"email": email, "reason": "bad_password"})
		return domain.Session{}, errInvalidCredentials
	}
	session, err := s.deps.Sessions.Issue(ctx, user)
	if err != nil {
		return domain.Session{}, platerr.New(platerr.CategoryInternal, "session_issue_failed", err.Error())
	}
	s.emitAudit(ctx, "identity.login_succeeded", user.ID, user.ID, map[string]any{"session_id": session.ID})
	return session, nil
}

func (s *Service) RevokeSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return errors.New("session id required")
	}
	if err := s.deps.Sessions.Revoke(ctx, sessionID); err != nil {
		return err
	}
	s.emitAudit(ctx, "identity.logout", "", "", map[string]any{"session_id": sessionID})
	return nil
}

// Resolve returns the active user + roles for a session ID (advances idle
// expiry). Used by the auth middleware.
func (s *Service) Resolve(ctx context.Context, sessionID string) (domain.User, []string, domain.Session, error) {
	session, err := s.deps.Sessions.Current(ctx, sessionID)
	if err != nil {
		return domain.User{}, nil, domain.Session{}, platerr.New(platerr.CategoryAuth, "session_invalid", err.Error())
	}
	user, err := s.deps.Users.GetByID(ctx, session.UserID)
	if err != nil {
		return domain.User{}, nil, domain.Session{}, platerr.New(platerr.CategoryAuth, "user_missing", err.Error())
	}
	roles, err := s.deps.Roles.RolesFor(ctx, user.ID)
	if err != nil {
		return domain.User{}, nil, domain.Session{}, platerr.New(platerr.CategoryInternal, "roles_lookup_failed", err.Error())
	}
	return user, roles, session, nil
}

// ListUsers returns all users (admin).
func (s *Service) ListUsers(ctx context.Context) ([]domain.User, error) {
	return s.deps.Users.List(ctx)
}

// UserByEmail looks up a single user by email. Used during startup seeding
// to detect "already exists" cases idempotently.
func (s *Service) UserByEmail(ctx context.Context, email string) (domain.User, error) {
	return s.deps.Users.GetByEmail(ctx, email)
}

// UpsertCredentialPassword rehashes and stores the password for the given
// user. Called during startup to keep the bootstrap admin's credential in
// sync with the env-configured SEED_ADMIN_PASSWORD — even on a DB that was
// populated by migration 010's placeholder hash.
func (s *Service) UpsertCredentialPassword(ctx context.Context, userID, password string) error {
	if len(password) < 8 {
		return platerr.New(platerr.CategoryValidation, "weak_password", "password must be at least 8 characters")
	}
	hashed, err := s.deps.Hasher.Hash(password)
	if err != nil {
		return platerr.New(platerr.CategoryInternal, "hash_failed", err.Error())
	}
	return s.deps.Credentials.Put(ctx, domain.Credential{
		UserID: userID, PasswordHash: hashed, HashAlgorithm: "argon2id", HashVersion: 1,
	})
}
