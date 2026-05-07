// auth.Manager owns OAuth token lifecycle: persistence, proactive refresh,
// and propagation into the live state.Agent for SSE broadcasts.
//
// It is the single source of truth for "is the user logged in?" — callers
// must use GetValidToken() rather than reading state.Agent directly so that
// a near-expired token is refreshed transparently.

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// refreshLeeway mirrors the extension's TOKEN_REFRESH_LEEWAY_MS (3 minutes):
// proxy CONNECTs happen many times per page load and each re-checks token
// validity, so we refresh well before the actual expiry to avoid a thundering
// herd of 401s.
const refreshLeeway = 3 * time.Minute

// RefreshFunc exchanges a refresh token for a fresh access/refresh pair via
// vpn-core's POST /api/v1/auth/refresh. It is injected so this package stays
// free of HTTP / apiClient coupling.
//
// Returns (access, refresh, expiresInSeconds, error). On a definitive 4xx
// the caller should signal shouldClear = true via DefiniteAuthError.
type RefreshFunc func(ctx context.Context, refreshToken string) (access, refresh string, expiresIn int64, err error)

// DefiniteAuthError marks a refresh failure that is permanent — the agent
// should clear stored tokens and force the user to re-authenticate.
type DefiniteAuthError struct{ Err error }

func (e *DefiniteAuthError) Error() string { return "auth definitively failed: " + e.Err.Error() }
func (e *DefiniteAuthError) Unwrap() error { return e.Err }

// Notifier is invoked whenever the authenticated state changes. The desktop
// agent uses it to broadcast SSE events to the Tauri UI.
type Notifier func(t Tokens, loggedIn bool)

// Manager coordinates token storage and refresh. Safe for concurrent use.
type Manager struct {
	store   Store
	refresh RefreshFunc
	notify  Notifier
	logger  *slog.Logger

	mu         sync.Mutex
	tokens     Tokens
	loaded     bool
	refreshing bool
	queue      []chan refreshResult

	// Background refresh goroutine state.
	timer *time.Timer
}

type refreshResult struct {
	token string
	err   error
}

// NewManager wires a Store with a refresh function. It does NOT load tokens
// from disk — call Init() once after construction so the caller can decide
// the initialisation context (e.g. with a startup timeout).
func NewManager(store Store, refresh RefreshFunc, notify Notifier) *Manager {
	if notify == nil {
		notify = func(Tokens, bool) {}
	}
	return &Manager{
		store:   store,
		refresh: refresh,
		notify:  notify,
		logger:  slog.Default().With("module", "auth"),
	}
}

// Init loads any persisted tokens, performs an initial refresh if the access
// token is already expired, and schedules the next proactive refresh. It is
// safe to call Init even when no tokens are stored — it returns nil and the
// agent simply starts in the unauthenticated state.
func (m *Manager) Init(ctx context.Context) error {
	t, err := m.store.Load()
	if errors.Is(err, ErrNotFound) {
		m.logger.Info("no persisted tokens; starting unauthenticated")
		return nil
	}
	if err != nil {
		m.logger.Warn("failed to load persisted tokens; starting unauthenticated", "err", err)
		return nil
	}
	m.mu.Lock()
	m.tokens = t
	m.loaded = true
	m.mu.Unlock()

	m.notify(t, true)
	m.scheduleRefresh()

	// If the access token is already in the leeway window, refresh now so
	// the first downstream API call doesn't block on a slow Authentik.
	if m.expiringSoon(t) && t.RefreshToken != "" {
		if _, rerr := m.RefreshNow(ctx); rerr != nil {
			m.logger.Warn("startup refresh failed; will retry on demand", "err", rerr)
		}
	}
	return nil
}

// Save persists a fresh credential set (e.g. just received from OAuth code
// exchange) and reschedules the next refresh.
func (m *Manager) Save(t Tokens) error {
	if t.IsZero() {
		return fmt.Errorf("auth: refusing to save empty tokens")
	}
	if err := m.store.Save(t); err != nil {
		return err
	}
	m.mu.Lock()
	m.tokens = t
	m.loaded = true
	m.mu.Unlock()
	m.notify(t, true)
	m.scheduleRefresh()
	return nil
}

// Clear wipes persisted tokens and schedules nothing further. The notifier
// is invoked with an empty Tokens / loggedIn=false.
func (m *Manager) Clear() error {
	m.mu.Lock()
	m.tokens = Tokens{}
	m.loaded = false
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	m.mu.Unlock()
	m.notify(Tokens{}, false)
	if err := m.store.Clear(); err != nil {
		m.logger.Warn("failed to clear stored tokens", "err", err)
		return err
	}
	return nil
}

// Snapshot returns a copy of the current tokens (or zero value if logged out).
func (m *Manager) Snapshot() Tokens {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokens
}

// LoggedIn reports whether at least an access or refresh token is held.
func (m *Manager) LoggedIn() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.tokens.IsZero()
}

// GetValidToken returns a non-expired access token, refreshing transparently
// if needed. Returns "" and a nil error when the manager has no tokens.
func (m *Manager) GetValidToken(ctx context.Context) (string, error) {
	m.mu.Lock()
	t := m.tokens
	m.mu.Unlock()

	if t.IsZero() {
		return "", nil
	}
	if !m.expiringSoon(t) && t.AccessToken != "" {
		return t.AccessToken, nil
	}
	if t.RefreshToken == "" {
		// Access token expired and no way to refresh — caller will get 401
		// and surface re-login UI.
		return t.AccessToken, nil
	}
	return m.RefreshNow(ctx)
}

// RefreshNow forces a refresh, coalescing concurrent callers so only one
// HTTP refresh fires. All waiters get the same result.
func (m *Manager) RefreshNow(ctx context.Context) (string, error) {
	m.mu.Lock()
	if m.refreshing {
		ch := make(chan refreshResult, 1)
		m.queue = append(m.queue, ch)
		m.mu.Unlock()
		select {
		case r := <-ch:
			return r.token, r.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if m.tokens.RefreshToken == "" {
		m.mu.Unlock()
		return "", fmt.Errorf("no refresh token available")
	}
	rt := m.tokens.RefreshToken
	username := m.tokens.Username
	m.refreshing = true
	m.mu.Unlock()

	access, refresh, expiresIn, rerr := m.refresh(ctx, rt)
	if rerr != nil {
		m.mu.Lock()
		m.refreshing = false
		waiters := m.queue
		m.queue = nil
		m.mu.Unlock()
		var defErr *DefiniteAuthError
		if errors.As(rerr, &defErr) {
			m.logger.Warn("refresh failed permanently; clearing stored tokens", "err", rerr)
			_ = m.Clear()
		}
		for _, ch := range waiters {
			ch <- refreshResult{err: rerr}
		}
		return "", rerr
	}
	if refresh == "" {
		// Some IdPs only rotate access tokens.
		refresh = rt
	}
	newT := Tokens{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		Username:     username,
	}
	if serr := m.store.Save(newT); serr != nil {
		m.logger.Warn("failed to persist refreshed tokens", "err", serr)
	}
	m.mu.Lock()
	m.tokens = newT
	m.loaded = true
	m.refreshing = false
	waiters := m.queue
	m.queue = nil
	m.mu.Unlock()

	m.notify(newT, true)
	m.scheduleRefresh()

	for _, ch := range waiters {
		ch <- refreshResult{token: access}
	}
	return access, nil
}

// scheduleRefresh arms a single-shot timer for the next proactive refresh.
// It must be called from a locked section OR with no other goroutine
// currently mutating m.timer; we acquire the lock locally to be safe.
func (m *Manager) scheduleRefresh() {
	m.mu.Lock()
	t := m.tokens
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	if t.IsZero() || t.RefreshToken == "" || t.ExpiresAt == 0 {
		m.mu.Unlock()
		return
	}
	exp := time.Unix(t.ExpiresAt, 0)
	delay := time.Until(exp) - refreshLeeway
	if delay < 5*time.Second {
		delay = 5 * time.Second
	}
	m.timer = time.AfterFunc(delay, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := m.RefreshNow(ctx); err != nil {
			m.logger.Warn("scheduled refresh failed", "err", err)
		}
	})
	m.mu.Unlock()
}

func (m *Manager) expiringSoon(t Tokens) bool {
	if t.ExpiresAt == 0 {
		return false
	}
	return time.Until(time.Unix(t.ExpiresAt, 0)) <= refreshLeeway
}

// SoftRefreshNow refreshes the token like RefreshNow, but never calls Clear()
// on failure.  Use this for on-demand API retries (e.g. when CreateConnection
// gets a 401) so a transient IdP outage or a falsely-expired access token
// doesn't log the user out.  The manager's own scheduled refresh (RefreshNow)
// is still responsible for clearing the session on definitively expired tokens.
func (m *Manager) SoftRefreshNow(ctx context.Context) (string, error) {
	m.mu.Lock()
	if m.tokens.RefreshToken == "" {
		m.mu.Unlock()
		return "", fmt.Errorf("no refresh token available")
	}
	rt := m.tokens.RefreshToken
	username := m.tokens.Username
	m.mu.Unlock()

	access, refresh, expiresIn, rerr := m.refresh(ctx, rt)
	if rerr != nil {
		// Unwrap DefiniteAuthError to a regular error — we intentionally do NOT
		// call Clear() here.  If the refresh token is truly expired the next
		// scheduled RefreshNow will detect it and clear the session properly.
		var defErr *DefiniteAuthError
		if errors.As(rerr, &defErr) {
			return "", defErr.Unwrap()
		}
		return "", rerr
	}
	if refresh == "" {
		refresh = rt
	}
	newT := Tokens{
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		Username:     username,
	}
	if serr := m.store.Save(newT); serr != nil {
		m.logger.Warn("soft-refresh: failed to persist tokens", "err", serr)
	}
	m.mu.Lock()
	m.tokens = newT
	m.loaded = true
	m.mu.Unlock()
	m.notify(newT, true)
	m.scheduleRefresh()
	return access, nil
}
