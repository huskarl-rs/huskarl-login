//! Framework-neutral login state machine and HTTP boundary types.
//!
//! [`LoginEngine`] exposes the OAuth 2.0 Authorization Code flow as operations
//! a framework adapter can compose into middleware:
//!
//! 1. route callbacks and logout through
//!    [`LoginEngine::try_handle_login_route`];
//! 2. classify the request with [`LoginEngine::load_session`];
//! 3. serve the application or start login with
//!    [`LoginEngine::redirect_to_login`]; and
//! 4. deliver every [`LoginResponse`] and [`SetCookies`] value returned.
//!
//! See [Build a framework adapter](crate::_docs::how_to::adapter) for the full
//! request lifecycle.

use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};

use crate::{
    ConfigError, DefaultErrorPage, DriverLoad, ErrorPage, InvalidSessionReason, LivenessVerdict,
    LoginConfig, Session, SessionDriver, SessionError, SessionErrorKind,
    client::{
        grant::{
            authorization_code::{AuthorizationCodeGrant, PendingState},
            core::{OAuth2ExchangeGrant as _, TokenResponse},
            refresh::RefreshGrantParameters,
        },
        token::RefreshToken,
    },
    cookie::SessionCipher,
    core::{
        Error, RetryAdvice,
        crypto::seal::AeadSealerUnsealer,
        platform::{Duration, MaybeSendSync, SystemTime, sleep},
        serde_utils::time::unix_secs,
    },
    metrics::{LoginCompleteResult, LoginStartResult, RefreshResult},
    session::advises_retry,
    session_state::bounded_time_add,
};

/// Engine operation whose error was consumed rather than returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::AsRefStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum DiagnosticOperation {
    /// Construct the authorization redirect.
    Start,
    /// Complete the authorization-code exchange.
    Exchange,
    /// Create a session after exchange.
    Create,
    /// Load an existing session during callback fallback.
    CallbackLoad,
    /// Persist refreshed tokens eagerly (a deferred retry follows).
    EagerPersist,
    /// Refresh tokens, after the retry loop has terminated.
    Refresh,
    /// Revoke a session during automatic teardown.
    Revoke,
    /// Load a session during logout.
    LogoutLoad,
    /// Revoke a session during logout.
    LogoutRevoke,
    /// Construct the end-session URL (falls back to the local target).
    LogoutUrl,
    /// Encode the logout redirect header.
    LogoutRedirect,
}

/// Borrowed operational diagnostic; not a durable audit or lifecycle event.
#[derive(Debug)]
pub struct LoginDiagnostic<'a> {
    /// Operation that failed.
    pub operation: DiagnosticOperation,
    /// Original error and source chain; potentially sensitive or untrusted.
    /// Downcast to the concrete error type to inspect its domain classification.
    pub error: &'a (dyn std::error::Error + 'static),
}

type DiagnosticHandler = Arc<dyn Fn(LoginDiagnostic<'_>) + Send + Sync>;

mod callback;
mod logout;
mod redirect;

#[cfg(test)]
mod tests;

type EngineError = SessionError;

// ── Public types ──────────────────────────────────────────────────────────────

/// A framework-neutral HTTP response produced by the login engine.
///
/// Framework adapters convert this into their native response type via
/// [`into_parts`](Self::into_parts) at the response boundary.
#[must_use]
pub enum LoginResponse {
    /// A redirect: `302 Found` from GET contexts (login start, callback),
    /// `303 See Other` after a POST (logout), which pins the follow-up
    /// request to GET. The boundary also emits `Cache-Control: no-store`,
    /// since these redirects carry session-bearing cookies.
    Redirect {
        /// The redirect status (`302` or `303`).
        status: StatusCode,
        /// The `Location` to redirect to.
        location: HeaderValue,
        /// `Set-Cookie` values to emit alongside the redirect: after the
        /// callback they mint the initial session cookie, after logout they
        /// clear it — every one must reach the response. Prefer
        /// [`into_parts`](LoginResponse::into_parts), which cannot lose them.
        set_cookies: Vec<HeaderValue>,
    },
    /// A response rendered with an explicit status, header set, and body.
    Rendered {
        /// HTTP status code.
        status: StatusCode,
        /// Response headers (may repeat a name, e.g. multiple `Set-Cookie`).
        headers: Vec<(HeaderName, HeaderValue)>,
        /// Response body.
        body: Bytes,
    },
}

impl LoginResponse {
    /// The status code this response is served with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::Redirect { status, .. } | Self::Rendered { status, .. } => *status,
        }
    }

    /// Converts this response into concrete HTTP parts: status, full header list,
    /// and body (a [`Redirect`](Self::Redirect)'s headers are materialized here).
    #[must_use]
    pub fn into_parts(self) -> (StatusCode, Vec<(HeaderName, HeaderValue)>, Bytes) {
        match self {
            Self::Redirect {
                status,
                location,
                set_cookies,
            } => {
                let mut headers = Vec::with_capacity(set_cookies.len() + 2);
                headers.push((header::LOCATION, location));
                headers.push((header::CACHE_CONTROL, HeaderValue::from_static("no-store")));
                for c in set_cookies {
                    headers.push((header::SET_COOKIE, c));
                }
                (status, headers, Bytes::new())
            }
            Self::Rendered {
                status,
                headers,
                body,
            } => (status, headers, body),
        }
    }

    /// The full header list this response is served with, materialized
    /// (cloning). For non-clone access at the boundary prefer
    /// [`into_parts`](Self::into_parts).
    #[must_use]
    pub fn headers(&self) -> Vec<(HeaderName, HeaderValue)> {
        match self {
            Self::Redirect {
                location,
                set_cookies,
                ..
            } => {
                let mut headers = Vec::with_capacity(set_cookies.len() + 2);
                headers.push((header::LOCATION, location.clone()));
                headers.push((header::CACHE_CONTROL, HeaderValue::from_static("no-store")));
                for c in set_cookies {
                    headers.push((header::SET_COOKIE, c.clone()));
                }
                headers
            }
            Self::Rendered { headers, .. } => headers.clone(),
        }
    }

    /// Appends a header to a [`Rendered`](Self::Rendered) response; a no-op on
    /// [`Redirect`](Self::Redirect).
    fn push_rendered_header(&mut self, name: HeaderName, value: HeaderValue) {
        if let Self::Rendered { headers, .. } = self {
            headers.push((name, value));
        }
    }
}

/// Session `Set-Cookie` headers owed to the client's response.
///
/// A drop-guard around the cookie headers produced by
/// [`load_session`](LoginEngine::load_session) and the explicit
/// persist/save/terminate methods. Consume it with
/// [`into_headers`](Self::into_headers) (or iterate it) and append every
/// value to the outgoing response.
///
/// Dropping a **non-empty**, unconsumed `SetCookies` increments the optional
/// dropped-work counter; dropping an empty guard (the steady state) is silent. For what a discarded cookie
/// costs, see the [refresh explanation](crate::_docs::explanation::refresh).
#[must_use = "session Set-Cookie headers must be appended to the response"]
#[derive(Default)]
pub struct SetCookies {
    #[cfg(feature = "metrics")]
    metrics_name: Option<Arc<str>>,
    headers: Vec<HeaderValue>,
    /// Test-only observer incremented when the guard fires, so tests can
    /// assert drop detection deterministically (a global counter would race
    /// across parallel tests).
    #[cfg(test)]
    drop_probe: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

impl SetCookies {
    fn with_metrics_name(mut self, name: Option<&Arc<str>>) -> Self {
        #[cfg(feature = "metrics")]
        {
            self.metrics_name = name.cloned();
        }
        #[cfg(not(feature = "metrics"))]
        {
            let _ = (&mut self, name);
        }
        self
    }

    fn metrics_name(&self) -> Option<&str> {
        #[cfg(feature = "metrics")]
        {
            self.metrics_name.as_deref()
        }
        #[cfg(not(feature = "metrics"))]
        {
            let _ = self;
            None
        }
    }

    /// Wraps headers owed to the response. Crate-internal: adapters only
    /// consume this type.
    pub(crate) fn new(headers: Vec<HeaderValue>) -> Self {
        Self {
            headers,
            #[cfg(test)]
            drop_probe: None,
            #[cfg(feature = "metrics")]
            metrics_name: None,
        }
    }

    /// `true` when there is nothing to append.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    /// Number of `Set-Cookie` headers owed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Consumes the guard, returning the `Set-Cookie` values to append to the
    /// response.
    #[must_use = "session Set-Cookie headers must be appended to the response"]
    pub fn into_headers(mut self) -> Vec<HeaderValue> {
        std::mem::take(&mut self.headers)
    }

    /// Consumes the guard without counting a drop, dropping the cookies.
    ///
    /// Only correct when the response is already gone — e.g. a persistence
    /// fallback that runs after the response was written, where non-delivery
    /// is a fact rather than a bug. Everywhere else, append the cookies to
    /// the response; to also report what could not be delivered, use
    /// [`into_headers`](Self::into_headers) and inspect the result instead.
    pub fn discard(mut self) {
        self.headers.clear();
    }

    /// Attaches the test drop-probe — see [`Self::drop_probe`].
    #[cfg(test)]
    pub(crate) fn with_drop_probe(
        mut self,
        probe: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.drop_probe = Some(probe);
        self
    }
}

/// Consuming iteration for `response.extend(set_cookies)`-style appends;
/// defuses the drop guard like [`into_headers`](SetCookies::into_headers).
impl IntoIterator for SetCookies {
    type Item = HeaderValue;
    type IntoIter = std::vec::IntoIter<HeaderValue>;
    fn into_iter(self) -> Self::IntoIter {
        self.into_headers().into_iter()
    }
}

// Manual `Debug`: the values are live session cookies — print only the count.
impl std::fmt::Debug for SetCookies {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SetCookies")
            .field(&self.headers.len())
            .finish()
    }
}

impl Drop for SetCookies {
    fn drop(&mut self) {
        // During unwinding the cookies are collateral of the panic — an error
        // here would misdirect whoever is diagnosing that panic.
        if self.headers.is_empty() || std::thread::panicking() {
            return;
        }
        #[cfg(test)]
        if let Some(probe) = &self.drop_probe {
            probe.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        crate::metrics::emit_counter(
            "huskarl.session.dropped",
            [("operation", "set_cookies")],
            self.metrics_name(),
        );
    }
}

/// Result of explicit session termination.
///
/// Browser clearing and authoritative server-side revocation are independent:
/// even when revocation fails, the clears returned by [`into_parts`](Self::into_parts)
/// must still be appended to the current response. Keeping both values in one
/// outcome prevents an error return from accidentally discarding the browser
/// action.
#[must_use = "session cookie clears and the revocation result must both be handled"]
pub struct TerminateSessionOutcome {
    clears: SetCookies,
    revocation: Result<(), SessionError>,
}

impl TerminateSessionOutcome {
    /// Consumes the outcome into the browser clears and revocation result.
    #[must_use = "append the cookie clears and inspect the revocation result"]
    pub fn into_parts(self) -> (SetCookies, Result<(), SessionError>) {
        (self.clears, self.revocation)
    }
}

impl std::fmt::Debug for TerminateSessionOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminateSessionOutcome")
            .field("clears", &self.clears.len())
            .field("revocation", &self.revocation)
            .finish()
    }
}

/// The authentication state observed by [`LoginEngine::load_session`].
///
/// Loading classifies a request; it never redirects. The adapter decides
/// whether a missing or cleared session requires login or may continue
/// anonymously. This enum is intentionally exhaustive: adding a state causes
/// a compile error at every adapter that must decide how to handle it.
#[must_use]
pub enum LoadedSession<S> {
    /// The request carried no session cookie.
    Missing,
    /// A session was presented but torn down. `clears` must reach the final
    /// response to drop the now-stale session cookies.
    Cleared {
        /// Why the session was torn down.
        reason: TeardownReason,
        /// `Set-Cookie` clears for the stale session cookies.
        clears: SetCookies,
    },
    /// Authenticated, with no deferred store write required. Any `set_cookies`
    /// must still be delivered on the final response.
    Active {
        /// The loaded session.
        session: S,
        /// `Set-Cookie` headers that must reach the final response (re-sealed
        /// session cookies after an eager refresh, else empty); see
        /// [`load_session`](LoginEngine::load_session) on caching.
        set_cookies: SetCookies,
    },
    /// A session was presented, its access token has expired, and the token
    /// refresh failed **transiently** — authentication can be neither
    /// confirmed nor refuted right now. The session and its cookies are
    /// retained so a later request can retry the refresh once the
    /// authorization server recovers.
    ///
    /// Serve a retryable error (e.g. `503` with `Retry-After`, via
    /// [`LoginEngine::render_error`]). Do **not** treat the request as
    /// anonymous: that would bounce the user into a login flow against the
    /// same unavailable server, and an anonymous fallback page could leak
    /// that state into caches keyed on the user.
    RefreshUnavailable,
    /// Authenticated, with a save owed after the inner handler responds.
    /// Arises only when the eager persist of a refreshed session failed.
    ActivePending {
        /// The refreshed session together with the save owed for it. Serve
        /// [`PendingPersist::session`] (or a shared
        /// [`PendingPersist::session_arc`] handle) during the request, then
        /// call [`PendingPersist::commit`] once the inner handler has
        /// responded.
        pending: PendingPersist<S>,
    },
}

impl<S> LoadedSession<S> {
    /// Convenience accessor: the session, when the request is authenticated.
    pub fn session(&self) -> Option<&S> {
        match self {
            Self::Missing | Self::Cleared { .. } | Self::RefreshUnavailable => None,
            Self::Active { session, .. } => Some(session),
            Self::ActivePending { pending } => Some(pending.session()),
        }
    }
}

// Manual `Debug` so the impl holds without `S: Debug` and never prints the
// session payload (which can carry tokens/PII) — only the variant and its
// non-secret metadata.
impl<S> std::fmt::Debug for LoadedSession<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("Missing"),
            Self::RefreshUnavailable => f.write_str("RefreshUnavailable"),
            Self::Cleared { reason, clears } => f
                .debug_struct("Cleared")
                .field("reason", reason)
                .field("clears", &clears.len())
                .finish(),
            Self::Active { set_cookies, .. } => f
                .debug_struct("Active")
                .field("set_cookies", &set_cookies.len())
                .finish_non_exhaustive(),
            Self::ActivePending { .. } => f.debug_struct("ActivePending").finish_non_exhaustive(),
        }
    }
}

/// The save owed by a [`LoadedSession::ActivePending`]: the refreshed session
/// and the refresh response that must be re-committed, bound together so an
/// adapter cannot pair a session with the wrong refresh. Hold it across the
/// inner handler, then [`commit`](Self::commit) it in the response phase.
///
/// Serve the session during the request via [`session`](Self::session), or
/// take a shared [`session_arc`](Self::session_arc) handle (e.g. for a
/// request extension) — `commit` does not need the handle back.
///
/// Dropping an uncommitted `PendingPersist` forfeits the retry of the failed
/// eager persist, so, like [`SetCookies`], the drop is detected at runtime
/// and counted when `metrics` is enabled; for what a forfeited retry costs, see
/// [refresh explanation](crate::_docs::explanation::refresh). The one
/// legitimate abandonment (the session was deleted instead) is spelled
/// [`abandon`](Self::abandon).
#[must_use = "an owed session persist must be committed after the response"]
pub struct PendingPersist<S> {
    #[cfg(feature = "metrics")]
    metrics_name: Option<Arc<str>>,
    /// The loaded session, with the refresh applied in memory. Shared so
    /// adapters can serve it while this value waits out the inner handler.
    session: Arc<S>,
    /// The refresh response to re-commit against fresh store state. Boxed to
    /// keep the rare variant from inflating every [`LoadedSession`] returned,
    /// and `Some` until [`commit`](Self::commit) or [`abandon`](Self::abandon)
    /// consumes it — `Drop` reports a still-armed guard.
    token_response: Option<Box<TokenResponse>>,
    /// Revision observed before exchange, retained even if the eager write
    /// committed but its acknowledgement was lost.
    expected_refresh_revision: u64,
    /// Test-only observer incremented when the guard fires, so tests can
    /// assert drop detection deterministically — same rationale as
    /// [`SetCookies::drop_probe`].
    #[cfg(test)]
    drop_probe: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

#[bon::bon]
impl<S> PendingPersist<S> {
    fn with_metrics_name(mut self, name: Option<&Arc<str>>) -> Self {
        #[cfg(feature = "metrics")]
        {
            self.metrics_name = name.cloned();
        }
        #[cfg(not(feature = "metrics"))]
        {
            let _ = (&mut self, name);
        }
        self
    }

    fn metrics_name(&self) -> Option<&str> {
        #[cfg(feature = "metrics")]
        {
            self.metrics_name.as_deref()
        }
        #[cfg(not(feature = "metrics"))]
        {
            let _ = self;
            None
        }
    }

    /// Pairs a refreshed session with the refresh response whose persist is
    /// owed. [`LoginEngine::load_session`] constructs these; the constructor
    /// is public so adapter tests can fabricate the deferred-persist path
    /// without arranging a failing store.
    /// `expected_refresh_revision` must be the revision from before exchange,
    /// not one inferred from the already-refreshed session.
    #[builder]
    pub fn new(session: S, token_response: TokenResponse, expected_refresh_revision: u64) -> Self {
        Self {
            session: Arc::new(session),
            token_response: Some(Box::new(token_response)),
            expected_refresh_revision,
            #[cfg(test)]
            drop_probe: None,
            #[cfg(feature = "metrics")]
            metrics_name: None,
        }
    }

    /// Attaches the test drop-probe — see [`Self::drop_probe`].
    #[cfg(test)]
    pub(crate) fn with_drop_probe(
        mut self,
        probe: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.drop_probe = Some(probe);
        self
    }

    /// The refreshed session (the owed refresh is already applied in memory).
    #[must_use]
    pub fn session(&self) -> &S {
        &self.session
    }

    /// A shared handle to the session, for serving it while this value waits
    /// out the inner handler. The handle never has to be returned: one still
    /// alive at [`commit`](Self::commit) time keeps its pre-commit view and
    /// the commit proceeds on a clone.
    #[must_use]
    pub fn session_arc(&self) -> Arc<S> {
        Arc::clone(&self.session)
    }

    /// Commits the owed refresh after the inner service responded, returning
    /// [`SetCookies`] to append. The refresh is re-committed through the same
    /// merge-safe path as the eager persist, so a concurrent
    /// [`StoreBackedSessionStore::update`] landing in between is preserved.
    /// `request_headers` are the original request cookies (used by
    /// cookie-backed stores to clear stale slots); see
    /// [`LoginEngine::load_session`] on response caching.
    ///
    /// This is why the session type must be `Clone`: a
    /// [`session_arc`](Self::session_arc) handle still alive at commit time
    /// keeps its pre-commit view, and the commit proceeds on a clone.
    ///
    /// [`StoreBackedSessionStore::update`]: crate::StoreBackedSessionStore::update
    ///
    /// # Cancellation
    ///
    /// Once polled, this future disarms the dropped-persist guard before awaiting
    /// the store. Cancellation during that await emits neither a dropped-persist
    /// count nor a completed-operation result. The backend may already have
    /// committed; cancellation does not establish whether persistence succeeded.
    /// Dropping an unpolled commit future still drops an armed guard.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the session store fails to write.
    pub async fn commit<SD>(
        mut self,
        engine: &LoginEngine<SD>,
        request_headers: &HeaderMap,
    ) -> Result<SetCookies, SessionError>
    where
        SD: SessionDriver<SessionType = S>,
        // Always satisfiable: the trait requires `SessionType: Clone`, but
        // rustc does not carry that bound through the `SessionType = S`
        // equality, so it is restated here for `Arc::make_mut`.
        S: Clone,
    {
        // Taking the response disarms the drop guard; it is present here by
        // construction — only `commit` and `abandon` remove it, and both
        // consume `self`.
        let Some(token_response) = self.token_response.take() else {
            return Ok(SetCookies::default());
        };
        // Post-response the serving handles are normally gone, so this mutates
        // in place; a handle a handler stashed away keeps its pre-commit view
        // and the commit works on a clone instead.
        let session = Arc::make_mut(&mut self.session);
        engine
            .session_store
            .apply_refresh_and_save(
                session,
                &token_response,
                self.expected_refresh_revision,
                engine.config.default_token_lifetime,
                request_headers,
            )
            .await
            .map(|headers| engine.set_cookies(headers))
    }

    /// Defuses the drop guard without committing — only correct when the owed
    /// save became moot because the session was deleted instead.
    pub fn abandon(mut self) {
        self.token_response = None;
    }
}

// Manual `Debug` for the same reason as [`LoadedSession`]: never print the
// session payload or the token response.
impl<S> std::fmt::Debug for PendingPersist<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingPersist").finish_non_exhaustive()
    }
}

impl<S> Drop for PendingPersist<S> {
    fn drop(&mut self) {
        // During unwinding the owed persist is collateral of the panic — an
        // error here would misdirect whoever is diagnosing that panic.
        if self.token_response.is_none() || std::thread::panicking() {
            return;
        }
        #[cfg(test)]
        if let Some(probe) = &self.drop_probe {
            probe.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        crate::metrics::emit_counter(
            "huskarl.session.dropped",
            [("operation", "persist")],
            self.metrics_name(),
        );
    }
}

/// Why [`LoginEngine::load_session`] tore down a presented session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum TeardownReason {
    /// The [`SessionLifetime::Bounded`](crate::SessionLifetime::Bounded) cap
    /// exceeded.
    MaxLifetime,
    /// Idle timeout exceeded (server-side liveness verdict
    /// [`crate::LivenessVerdict::Expired`]).
    IdleTimeout,
    /// Session timestamps too far in the future — corrupt or forged.
    ClockSkew,
    /// The authorization server conclusively rejected the refresh token
    /// (e.g. `invalid_grant`).
    RefreshRejected,
    /// The access token expired and the session holds no refresh token.
    NoRefreshToken,
    /// Session-shaped browser state was malformed, undecryptable, or pointed
    /// to a record that no longer exists.
    InvalidSession,
}

impl TeardownReason {
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Decides how a framework adapter reacts when the deferred save of a
/// refreshed session fails.
///
/// The inner handler has already run (including side effects) by the time this
/// is called; a replacement response will cause well-behaved clients to retry.
pub trait PersistFailurePolicy: MaybeSendSync + 'static {
    /// Decide what to do after a [`LoadedSession::ActivePending`] save failed.
    /// `Some(response)` replaces the handler's response; `None` lets it pass
    /// through.
    fn handle(&self, error: &SessionError) -> Option<LoginResponse>;
}

/// Default policy: fail closed when the refreshed-session save fails, replacing
/// the response to force a clean retry.
///
/// The replacement status is derived from a [`SessionError`]'s
/// [`SessionErrorKind`]: [`Conflict`](SessionErrorKind::Conflict) → `409`,
/// [`Gone`](SessionErrorKind::Gone) → `401`,
/// [`Crypto`](SessionErrorKind::Crypto)/[`Encoding`](SessionErrorKind::Encoding)/
/// [`Store`](SessionErrorKind::Store) → `500`, and
/// [`Unavailable`](SessionErrorKind::Unavailable) → `503`.
pub struct DefaultPersistFailurePolicy;

impl PersistFailurePolicy for DefaultPersistFailurePolicy {
    fn handle(&self, error: &SessionError) -> Option<LoginResponse> {
        let status = match error.kind() {
            SessionErrorKind::Gone => StatusCode::UNAUTHORIZED,
            SessionErrorKind::Conflict => StatusCode::CONFLICT,
            SessionErrorKind::Crypto | SessionErrorKind::Encoding | SessionErrorKind::Store => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            SessionErrorKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        };
        let mut headers = vec![(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))];
        if status == StatusCode::UNAUTHORIZED {
            headers.push((header::WWW_AUTHENTICATE, HeaderValue::from_static("Cookie")));
        }
        Some(LoginResponse::Rendered {
            status,
            // Same rule as every engine-rendered response: session-adjacent
            // responses are never cacheable.
            headers,
            body: Bytes::new(),
        })
    }
}

// ── Internal types ────────────────────────────────────────────────────────────

/// Encrypted payload stored in the per-flow login-state cookie. The AEAD
/// associated data is [`login_state_aad`] over the flow's `state` value.
#[derive(Serialize, Deserialize)]
struct LoginStateCookie {
    original_url: String,
    pending_state: PendingState,
    /// Flow start time; enforces [`LoginConfig::login_state_ttl`] server-side.
    /// Cookies sealed before this field existed decode as the epoch (treated
    /// as expired).
    #[serde(with = "unix_secs", default = "unix_epoch")]
    created_at: SystemTime,
}

/// `#[serde(default)]` helper — see [`LoginStateCookie::created_at`].
fn unix_epoch() -> SystemTime {
    SystemTime::UNIX_EPOCH
}

/// AEAD associated data for the login-state cookie: `"login_state:{state}"`.
/// The `login_state:` prefix domain-separates this seal from the session
/// seals (`"session:{name}"` / `"session_ptr:{name}"`) by construction, so a
/// shared AEAD key can never confuse the two — independent of the state's
/// charset.
pub(super) fn login_state_aad(state: &str) -> Vec<u8> {
    format!("login_state:{state}").into_bytes()
}

// ── LoginEngine ───────────────────────────────────────────────────────────────

/// Drives login, callback, session loading and refresh, and logout.
///
/// `SD` selects the persistence model through a [`SessionDriver`]. The engine
/// is HTTP-framework-neutral: an adapter calls its operations and converts
/// [`LoginResponse`] and [`SetCookies`] values into framework responses. Build
/// an engine with [`LoginEngine::builder`].
///
/// The engine validates sessions but does not decide which application routes
/// require authentication. That policy remains in the adapter or application.
///
/// See [Build a login engine](crate::_docs::tutorial::getting_started) for
/// construction and [Build a framework adapter](crate::_docs::how_to::adapter)
/// for routing, session loading, and response handling.
#[non_exhaustive]
pub struct LoginEngine<SD> {
    /// The login configuration.
    config: LoginConfig,
    grant: AuthorizationCodeGrant,
    /// The session store, kept private so construction-time policy stamping
    /// cannot be invalidated by replacing it afterward.
    session_store: SD,
    /// Client-facing base URL, reconstructed at build from the grant's
    /// `redirect_uri` origin joined with [`LoginConfig::base_path`].
    base_url: http::Uri,
    /// Whether the deployment is HTTPS, from the `redirect_uri` scheme; drives
    /// `Secure`/`__Host-` on the cookies this engine sets.
    secure: bool,
    cipher: SessionCipher,
    error_page: Box<dyn ErrorPage>,
    /// Instance `name` label for emitted counters; `None` uses the empty string.
    metrics_name: Option<Arc<str>>,
    diagnostic_handler: Option<DiagnosticHandler>,
}

// ── Constructor ───────────────────────────────────────────────────────────────

#[bon::bon]
impl<SD> LoginEngine<SD>
where
    SD: SessionDriver,
{
    /// Builds a [`LoginEngine`]; invoked via `LoginEngine::builder()`.
    ///
    /// `grant` drives the OAuth flow per its own configuration.
    ///
    /// `sealer` seals the short-lived login-state cookie. Optional: defaults
    /// to the store's own sealer ([`SessionDriver::session_sealer`]); the seals
    /// are AAD-domain-separated, so sharing one key is safe — see
    /// [cookie security](crate::_docs::explanation::cookie_security). Pass it
    /// only to use a distinct login-state sealer.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if configuration revalidation fails, the grant's
    /// redirect URI is unusable or disagrees with the public URL mapping or
    /// callback path, or the session cookie path does not cover the required
    /// routes. Cookie paths must cover logout for both drivers and the callback
    /// for store-backed sessions. See [Configure public and ingress
    /// URLs](crate::_docs::how_to::url_mapping) for a mapped deployment.
    #[builder]
    pub fn new(
        mut config: LoginConfig,
        grant: AuthorizationCodeGrant,
        session_store: SD,
        #[builder(with = |sealer: impl AeadSealerUnsealer + 'static| Arc::new(sealer) as Arc<dyn AeadSealerUnsealer>)]
        sealer: Option<Arc<dyn AeadSealerUnsealer>>,
        /// Custom error page renderer. Defaults to [`DefaultErrorPage`].
        #[builder(default = Box::new(DefaultErrorPage) as Box<dyn ErrorPage>)]
        error_page: Box<dyn ErrorPage>,
        /// Instance name added as the `name` label on every counter this
        /// engine and its session store emit, telling engines apart when one
        /// process runs several. `None` (the default) uses `name=""`. Keep names
        /// bounded by configuration.
        #[builder(into)]
        metrics_name: Option<String>,
        /// Receives errors consumed by the engine. Runs synchronously and may
        /// run concurrently; must not block or panic. Handler panics propagate.
        /// Error sources can contain secrets or untrusted text: redact before
        /// export. No durable delivery or security-event semantics are implied.
        /// Works without `metrics`. See [Observe login failures](crate::_docs::how_to::observability).
        #[builder(with = |handler: impl Fn(LoginDiagnostic<'_>) + Send + Sync + 'static| Arc::new(handler) as DiagnosticHandler)]
        diagnostics: Option<DiagnosticHandler>,
    ) -> Result<Self, ConfigError> {
        // Re-derive these values at the trust boundary. `LoginConfig` fields
        // are public for adapter inspection and may have been changed after
        // the builder ran; stale derived paths must not bypass cookie-scope
        // validation or leak into login-state cookies.
        config.validate_and_recompute()?;

        // The client-facing origin is the single source of truth: the grant's
        // `redirect_uri`. Reconstruct the base URL from its origin joined with
        // the config's `base_path`, and derive `secure` from its scheme. Because
        // the origin comes from the same value the AS returns the browser to,
        // the session cookie's host is correct by construction — there is no
        // second origin to disagree with. (The grant validates `redirect_uri`,
        // so the error paths are defensive.)
        let redirect =
            grant
                .redirect_uri
                .parse::<Uri>()
                .map_err(|_| ConfigError::InvalidRedirectUri {
                    url: grant.redirect_uri.clone(),
                    reason: "must be a valid absolute URL",
                })?;
        let (Some(scheme), Some(authority)) = (
            redirect.scheme_str(),
            redirect.authority().map(http::uri::Authority::as_str),
        ) else {
            return Err(ConfigError::InvalidRedirectUri {
                url: grant.redirect_uri.clone(),
                reason: "must be an absolute URL with scheme and authority",
            });
        };
        let base_path = config.base_path.as_ref().map_or("", |p| p.as_str());
        let base_url = format!("{scheme}://{authority}{base_path}")
            .parse::<Uri>()
            .map_err(|_| ConfigError::InvalidRedirectUri {
                url: grant.redirect_uri.clone(),
                reason: "origin is not a valid base URL",
            })?;
        if let Some(mapping) = &config.url_mapping
            && (mapping.public_base().scheme() != redirect.scheme()
                || mapping.public_base().authority() != redirect.authority())
        {
            return Err(ConfigError::InvalidRedirectUri {
                url: grant.redirect_uri.clone(),
                reason: "redirect origin disagrees with url_mapping",
            });
        }
        if config.browser_callback_path.as_str() != redirect.path() {
            return Err(ConfigError::InvalidRedirectUri {
                url: grant.redirect_uri.clone(),
                reason: "public callback path does not match the mapped callback_path",
            });
        }
        let secure = scheme == "https";

        // Single source of truth for cookie security and session lifetime:
        // stamp the store with the reconstructed `secure` and the
        // `session_lifetime` bound, so session cookies share one
        // `secure`/`__Host-` policy and no cookie outlives the session cap.
        let mut session_store = session_store;
        let session_policy = crate::session::SessionPolicy::builder()
            .secure(secure)
            .maybe_max_lifetime(config.session_lifetime.bound())
            .maybe_metrics_name(metrics_name.as_deref())
            .browser_callback_path(config.browser_callback_path.clone())
            .maybe_browser_logout_path(config.browser_logout_path.clone())
            .build();
        session_store.apply_session_policy(&session_policy)?;
        // Default here rather than in each adapter, so every adapter gets the
        // shared-key setup (and its safety argument) without reimplementing it.
        let sealer = sealer.unwrap_or_else(|| session_store.session_sealer());
        Ok(Self {
            config,
            grant,
            session_store,
            base_url,
            secure,
            cipher: sealer,
            error_page,
            metrics_name: metrics_name.map(Arc::from),
            diagnostic_handler: diagnostics,
        })
    }
}

// ── Core logic ────────────────────────────────────────────────────────────────

impl<SD> LoginEngine<SD>
where
    SD: SessionDriver,
{
    /// Returns the immutable login configuration validated at construction.
    ///
    /// Route and browser-cookie paths are frozen together so their visibility
    /// invariants cannot drift after the engine has stamped its session
    /// driver policy.
    #[must_use]
    pub fn config(&self) -> &LoginConfig {
        &self.config
    }

    /// Returns the session store stamped with this engine's cookie, lifetime,
    /// route, and metrics policy.
    ///
    /// The reference is immutable so the validated store cannot be replaced or
    /// have its construction-time policy changed after engine construction.
    #[must_use]
    pub fn session_store(&self) -> &SD {
        &self.session_store
    }

    /// Removes this engine's session credentials from request cookies while
    /// preserving unrelated application cookies.
    ///
    /// Reverse-proxy adapters should call this on the request headers they send
    /// upstream. Cookie names and layouts remain an implementation detail of
    /// the session driver, including chunk cookies and key-id sidecars.
    pub fn strip_session_credentials(&self, headers: &mut HeaderMap) {
        self.session_store.strip_session_credentials(headers);
    }

    /// If `uri`'s path is the configured callback or logout path, returns the
    /// corresponding response; otherwise `None` (the adapter falls through).
    ///
    /// Pass the engine-side URI (including any front-proxy `strip_prefix`). The
    /// callback accepts only `GET`, logout only `POST`; other methods on these
    /// paths get `405 Method Not Allowed` with an `Allow` header.
    /// Logout also requires the request's `Origin` to match the public origin;
    /// preserve that header when forwarding the request. A rejected origin
    /// produces `403 Forbidden`.
    pub async fn try_handle_login_route(
        &self,
        method: &Method,
        headers: &HeaderMap,
        uri: &Uri,
    ) -> Option<LoginResponse> {
        let path = uri.path();
        if self.config.callback_path == path {
            if *method != Method::GET {
                return Some(self.method_not_allowed("GET"));
            }
            return Some(self.handle_callback(uri, headers).await);
        }
        if let Some(logout) = &self.config.logout
            && logout.path == path
        {
            if *method != Method::POST {
                return Some(self.method_not_allowed("POST"));
            }
            return Some(self.handle_logout(logout, headers).await);
        }
        None
    }

    /// Converts a trusted, already resolved public URL to the engine's ingress
    /// coordinates. Used by adapters with an explicit public URL override;
    /// rejects another origin or a path outside the configured public prefix.
    ///
    /// # Errors
    /// Rejects another origin or a URL outside the configured public mapping.
    pub fn incoming_uri(
        &self,
        public: &Uri,
    ) -> Result<Uri, crate::core::url_mapping::MappingError> {
        crate::core::url_mapping::PublicUrlMapping::new(
            &self.base_url.to_string(),
            self.config
                .strip_prefix
                .as_ref()
                .map_or("/", crate::config::RoutePath::as_str),
        )?
        .incoming_uri(public)
    }

    /// Builds a `405 Method Not Allowed` response with an `Allow` header.
    fn method_not_allowed(&self, allow: &'static str) -> LoginResponse {
        let mut resp =
            self.build_error_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        resp.push_rendered_header(header::ALLOW, HeaderValue::from_static(allow));
        resp
    }

    /// Loads and validates the session from request cookies, refreshing the
    /// access token if near expiry. Returns a session state without producing
    /// an HTTP response; store failures return [`SessionError`]. A successful
    /// refresh is persisted eagerly, yielding [`LoadedSession::Active`] (or
    /// [`LoadedSession::ActivePending`] if that persist failed).
    ///
    /// # Response caching
    ///
    /// Any response carrying session `Set-Cookie` values — `Active`'s
    /// `set_cookies`, [`LoadedSession::Cleared`]'s clears, or those from
    /// [`PendingPersist::commit`] — MUST be made non-cacheable by the
    /// adapter, or a shared cache could replay a session cookie.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the session store fails to load.
    pub async fn load_session(
        &self,
        headers: &HeaderMap,
    ) -> Result<LoadedSession<SD::SessionType>, SessionError> {
        let session = match self.session_store.load(headers).await? {
            DriverLoad::Absent => return Ok(LoadedSession::Missing),
            DriverLoad::Valid(session) => session,
            DriverLoad::Invalid(invalid_reason) => {
                let reason = TeardownReason::InvalidSession;
                self.record_teardown_with_invalid_reason(reason, Some(invalid_reason));
                return Ok(LoadedSession::Cleared {
                    reason,
                    clears: self.set_cookies(self.session_store.clear_session_cookies(headers)),
                });
            }
        };

        let now = SystemTime::now();

        if let Some(reason) = self.session_teardown_reason(&session, now) {
            let clears = self.terminate_best_effort(&session, headers).await;
            self.record_teardown(reason);
            return Ok(LoadedSession::Cleared { reason, clears });
        }

        // Server-side liveness. `check_liveness` returns the idle verdict
        // (always, so expiry is enforced) and, when this request counts as
        // activity under the configured `ActivityPolicy`, records it as a side
        // effect (throttled in the store). It is `Untracked` for cookie sessions
        // and store-backed sessions without a liveness store, and fails open so
        // an outage never expires a session. The engine acts only on `Expired`.
        let record_activity = self.config.activity_policy.counts_as_activity(headers);
        // Effective absolute deadline (frozen `expire_at` tightened by the
        // live config cap; `None` under a delegated lifetime). The store
        // combines it with the activity horizon into the liveness entry's
        // TTL — see `check_liveness` in store_session.rs.
        let expire_at = self.session_deadline(&session);
        if self
            .session_store
            .check_liveness(&session, now, record_activity, expire_at)
            .await?
            == LivenessVerdict::Expired
        {
            let clears = self.terminate_best_effort(&session, headers).await;
            let reason = TeardownReason::IdleTimeout;
            self.record_teardown(reason);
            return Ok(LoadedSession::Cleared { reason, clears });
        }

        if refresh_due(
            session.token_expiry(),
            now,
            self.config.token_refresh_margin,
            &mut rand::rng(),
        ) {
            return Ok(self.refresh_or_clear(session, headers).await);
        }

        Ok(LoadedSession::Active {
            session,
            set_cookies: SetCookies::default(),
        })
    }

    /// Produces a response that asks the client to authenticate: `302 Found`
    /// to the authorization server for browser navigation (current URL sealed
    /// in a cookie for return), `401 Unauthorized` for API/XHR.
    pub async fn redirect_to_login(&self, headers: &HeaderMap, uri: &Uri) -> LoginResponse {
        if !is_navigation_request(headers) {
            // RFC 9110 §15.5.2: a 401 MUST carry `WWW-Authenticate`. No
            // scheme is registered for cookie-session auth; `Cookie` is a
            // syntactically valid scheme token that names the mechanism
            // without inviting bearer tokens this middleware won't accept.
            let mut resp =
                self.build_error_response(StatusCode::UNAUTHORIZED, "authentication required");
            resp.push_rendered_header(header::WWW_AUTHENTICATE, HeaderValue::from_static("Cookie"));
            return resp;
        }
        match self.redirect_to_as(uri).await {
            Ok(resp) => {
                self.record_login_start(&LoginStartResult::Ok);
                resp
            }
            Err(e) => {
                self.diagnose(DiagnosticOperation::Start, &e);
                self.record_login_start(&LoginStartResult::Error);
                self.build_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to start login",
                )
            }
        }
    }

    /// The session's effective absolute deadline: the earlier of the deadline
    /// frozen into the session at login ([`Session::expire_at`]) and the one
    /// the live config implies (`created_at` + the current
    /// [`SessionLifetime::Bounded`](crate::SessionLifetime) cap). The minimum
    /// is what makes cap changes one-directional for existing sessions — see
    /// [`Bounded`](crate::SessionLifetime::Bounded).
    fn session_deadline(&self, session: &SD::SessionType) -> Option<SystemTime> {
        let configured = self
            .config
            .session_lifetime
            .bound()
            .map(|max| bounded_time_add(session.created_at(), max));
        match (session.expire_at(), configured) {
            (Some(frozen), Some(configured)) => Some(frozen.min(configured)),
            (frozen, configured) => frozen.or(configured),
        }
    }

    /// Returns the teardown reason from the absolute checks (clock skew, max
    /// lifetime), or `None`. Idle timeout is enforced separately via
    /// [`SessionDriver::check_liveness`].
    fn session_teardown_reason(
        &self,
        session: &SD::SessionType,
        now: SystemTime,
    ) -> Option<TeardownReason> {
        if is_too_far_future(session.created_at(), now) {
            return Some(TeardownReason::ClockSkew);
        }
        if let Some(deadline) = self.session_deadline(session)
            && now > deadline
        {
            return Some(TeardownReason::MaxLifetime);
        }
        None
    }

    /// Exchanges the refresh token. A transient failure while the access token
    /// is still valid retains the session and keeps serving; a transient
    /// failure after token expiry retains the session but yields
    /// [`LoadedSession::RefreshUnavailable`] (fail the request, not the
    /// session); only a conclusive rejection — or an expired access token with
    /// no refresh token — tears the session down and emits cookie clears.
    async fn refresh_or_clear(
        &self,
        mut session: SD::SessionType,
        headers: &HeaderMap,
    ) -> LoadedSession<SD::SessionType> {
        let expected_refresh_revision = session.state().refresh_revision;
        let Some(rt) = session.refresh_token().cloned() else {
            // The refresh margin schedules proactive refresh; it does not
            // shorten the lifetime of a token that cannot be refreshed.
            if SystemTime::now() < session.token_expiry() {
                return LoadedSession::Active {
                    session,
                    set_cookies: SetCookies::default(),
                };
            }
            let clears = self.terminate_best_effort(&session, headers).await;
            self.record_refresh(&RefreshResult::NoRefreshToken);
            let reason = TeardownReason::NoRefreshToken;
            self.record_teardown(reason);
            return LoadedSession::Cleared { reason, clears };
        };
        match self.refresh_with_retry(&rt).await {
            Ok(token_response) => {
                self.record_refresh(&RefreshResult::Ok);
                // Persist eagerly rather than waiting for the adapter's
                // post-response phase: with refresh-token rotation, a later
                // phase that is skipped or fails would strand the rotated
                // token and lock the session out. The driver applies the
                // refresh as a replayable mutation (store-backed sessions
                // commit via CAS so a concurrent `update` is merged, not
                // overwritten). On failure, fall back to `ActivePending` so
                // the adapter's persist step (and its `PersistFailurePolicy`)
                // gets a second attempt.
                match self
                    .session_store
                    .apply_refresh_and_save(
                        &mut session,
                        &token_response,
                        expected_refresh_revision,
                        self.config.default_token_lifetime,
                        headers,
                    )
                    .await
                {
                    Ok(set_cookies) => LoadedSession::Active {
                        session,
                        set_cookies: self.set_cookies(set_cookies),
                    },
                    Err(e) if e.kind() == SessionErrorKind::Gone => {
                        let reason = self
                            .session_teardown_reason(&session, SystemTime::now())
                            .unwrap_or(TeardownReason::InvalidSession);
                        let invalid_reason = (reason == TeardownReason::InvalidSession)
                            .then_some(InvalidSessionReason::SessionNotFound);
                        self.record_teardown_with_invalid_reason(reason, invalid_reason);
                        LoadedSession::Cleared {
                            reason,
                            clears: self
                                .set_cookies(self.session_store.clear_session_cookies(headers)),
                        }
                    }
                    Err(e) => {
                        self.diagnose(DiagnosticOperation::EagerPersist, &e);
                        LoadedSession::ActivePending {
                            pending: PendingPersist::builder()
                                .session(session)
                                .token_response(token_response)
                                .expected_refresh_revision(expected_refresh_revision)
                                .build()
                                .with_metrics_name(self.metrics_name.as_ref()),
                        }
                    }
                }
            }
            // Re-read the clock: the retry loop slept, and the token may have
            // expired while we were waiting.
            Err(e) if advises_retry(&e) && SystemTime::now() < session.token_expiry() => {
                self.diagnose(DiagnosticOperation::Refresh, &e);
                self.record_refresh(&RefreshResult::FailedRetained);
                // Rare transient path — retain as-is without an activity touch;
                // the next request re-evaluates liveness.
                LoadedSession::Active {
                    session,
                    set_cookies: SetCookies::default(),
                }
            }
            // Transient failure past token expiry: authentication can be
            // neither confirmed nor refuted, so fail the *request*, not the
            // session. Deleting here would permanently destroy a session (and
            // its refresh token) that resumes by itself once the authorization
            // server recovers — an AS blip at the wrong moment must not force
            // every idle user back through login.
            Err(e) if advises_retry(&e) => {
                self.diagnose(DiagnosticOperation::Refresh, &e);
                self.record_refresh(&RefreshResult::FailedUnavailable);
                LoadedSession::RefreshUnavailable
            }
            // Conclusive rejection (e.g. `invalid_grant`, possibly
            // reuse-detection revocation): the AS disowned the refresh token,
            // so the session is dead — tear it down.
            Err(e) => {
                self.diagnose(DiagnosticOperation::Refresh, &e);
                let reason = TeardownReason::RefreshRejected;
                let clears = self.terminate_best_effort(&session, headers).await;
                self.record_refresh(&RefreshResult::Failed);
                self.record_teardown(reason);
                LoadedSession::Cleared { reason, clears }
            }
        }
    }

    /// Builds browser clears first, then attempts authoritative revocation.
    /// A backend failure is reported to the diagnostic handler but cannot
    /// prevent returning clears for the current browser.
    async fn terminate_best_effort(
        &self,
        session: &SD::SessionType,
        headers: &HeaderMap,
    ) -> SetCookies {
        let clears = self.set_cookies(self.session_store.clear_session_cookies(headers));
        if let Err(e) = self.session_store.revoke(session).await {
            self.diagnose(DiagnosticOperation::Revoke, &e);
        }
        clears
    }

    /// Exchanges the refresh token up to [`REFRESH_MAX_ATTEMPTS`] times,
    /// retrying [`RetryAdvice::Retry`] errors with exponential backoff plus
    /// jitter ([`refresh_retry_delay`]), extended to any delay the server asked
    /// for and capped at [`REFRESH_RETRY_MAX_DELAY`]. Errors advising no retry,
    /// and delays past that cap, return immediately.
    async fn refresh_with_retry(&self, rt: &RefreshToken) -> Result<TokenResponse, Error> {
        let refresh_grant = self.grant.to_refresh_grant();
        let mut attempt = 0;
        loop {
            attempt += 1;
            match refresh_grant
                .exchange(RefreshGrantParameters::refresh_token(rt.clone()))
                .await
            {
                Ok(tr) => return Ok(tr),
                Err(e) => {
                    // Only a transient failure is worth repeating, and only
                    // within the attempt budget.
                    let RetryAdvice::Retry { after } = e.retry_advice() else {
                        return Err(e);
                    };
                    if attempt >= REFRESH_MAX_ATTEMPTS {
                        return Err(e);
                    }
                    // Honour a server-supplied delay (`Retry-After`, `slow_down`)
                    // when it exceeds our own backoff, but never hold the request
                    // longer than `REFRESH_RETRY_MAX_DELAY`: past that the caller
                    // is better served by the retryable-failure path, which keeps
                    // the session and lets the next request try again.
                    let delay = refresh_retry_delay(attempt).max(after.unwrap_or_default());
                    if delay > REFRESH_RETRY_MAX_DELAY {
                        crate::metrics::emit_counter(
                            "huskarl.session.refresh_retry",
                            [("outcome", "delay_exceeded")],
                            self.metrics_name.as_deref(),
                        );
                        return Err(e);
                    }
                    crate::metrics::emit_counter(
                        "huskarl.session.refresh_retry",
                        [("outcome", "scheduled")],
                        self.metrics_name.as_deref(),
                    );
                    sleep(delay).await;
                }
            }
        }
    }

    fn diagnose(&self, operation: DiagnosticOperation, error: &(dyn std::error::Error + 'static)) {
        crate::metrics::emit_counter(
            "huskarl.login.handled_failure",
            [("operation", operation.as_ref())],
            self.metrics_name.as_deref(),
        );
        if let Some(handler) = &self.diagnostic_handler {
            handler(LoginDiagnostic { operation, error });
        }
    }

    fn set_cookies(&self, headers: Vec<HeaderValue>) -> SetCookies {
        SetCookies::new(headers).with_metrics_name(self.metrics_name.as_ref())
    }

    fn record_login_start(&self, result: &LoginStartResult) {
        crate::metrics::emit_counter(
            "huskarl.login.start",
            [("outcome", result.as_str())],
            self.metrics_name.as_deref(),
        );
    }

    fn record_login_complete(&self, result: &LoginCompleteResult, as_error: Option<&'static str>) {
        crate::metrics::emit_counter(
            "huskarl.login.complete",
            [
                ("outcome", result.as_str()),
                ("error", as_error.unwrap_or("none")),
            ],
            self.metrics_name.as_deref(),
        );
    }

    fn record_refresh(&self, result: &RefreshResult) {
        crate::metrics::emit_counter(
            "huskarl.session.refresh",
            [("outcome", result.as_str())],
            self.metrics_name.as_deref(),
        );
    }

    fn record_teardown(&self, reason: TeardownReason) {
        self.record_teardown_with_invalid_reason(reason, None);
    }

    fn record_teardown_with_invalid_reason(
        &self,
        reason: TeardownReason,
        invalid_reason: Option<InvalidSessionReason>,
    ) {
        crate::metrics::emit_counter(
            "huskarl.session.teardown",
            [
                ("reason", reason.as_str()),
                (
                    "invalid_reason",
                    invalid_reason.map_or("none", |reason| reason.as_str()),
                ),
            ],
            self.metrics_name.as_deref(),
        );
    }

    /// Terminates a session, returning both the [`SetCookies`] that clear the
    /// browser and the independent server-side revocation result.
    ///
    /// The clears are constructed before revocation and remain available when
    /// the backend fails. Consume [`TerminateSessionOutcome::into_parts`], append
    /// the clears to the response, then handle or report the revocation result.
    pub async fn terminate_session(
        &self,
        session: &SD::SessionType,
        request_headers: &HeaderMap,
    ) -> TerminateSessionOutcome {
        let clears = self.set_cookies(self.session_store.clear_session_cookies(request_headers));
        let revocation = self.session_store.revoke(session).await;
        TerminateSessionOutcome { clears, revocation }
    }

    /// Explicitly saves a session (e.g. after the
    /// application mutated it), returning [`SetCookies`]; unlike the deferred
    /// [`PendingPersist::commit`]. See [`PendingPersist::commit`] for
    /// `request_headers`.
    ///
    /// Store-backed saves require matching refresh revision, token, and expiry
    /// (at serialized whole-second precision), preserving the stored expiry
    /// and committing via CAS. Mismatches return [`SessionErrorKind::Conflict`].
    /// Within
    /// that generation, application fields remain last-writer-wins. Cookie
    /// saves remain last-writer-wins in the browser. For store-backed sessions
    /// that may be mutated concurrently, prefer
    /// [`StoreBackedSessionStore::update`](crate::StoreBackedSessionStore::update),
    /// which merges via compare-and-swap.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the session store fails to save.
    pub async fn save_session(
        &self,
        session: &SD::SessionType,
        request_headers: &HeaderMap,
    ) -> Result<SetCookies, SessionError> {
        self.session_store
            .save(session, request_headers)
            .await
            .map(|headers| self.set_cookies(headers))
    }

    /// Renders an error response through the configured [`ErrorPage`].
    pub fn render_error(&self, status: StatusCode, message: &str) -> LoginResponse {
        self.build_error_response(status, message)
    }

    fn build_error_response(&self, status: StatusCode, message: &str) -> LoginResponse {
        let rendered = self.error_page.render(status, message);
        LoginResponse::Rendered {
            status,
            headers: vec![
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(rendered.content_type),
                ),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            body: rendered.body,
        }
    }
}

// ── Utility functions ─────────────────────────────────────────────────────────

/// Maximum number of refresh attempts (initial + retries) before giving up.
const REFRESH_MAX_ATTEMPTS: u32 = 3;

/// Base delay for the first refresh retry; doubled on each subsequent attempt.
const REFRESH_RETRY_BASE_DELAY: Duration = Duration::from_millis(100);

/// Maximum random jitter added on top of the exponential base.
const REFRESH_RETRY_JITTER_MAX: Duration = Duration::from_millis(50);

/// Longest a single refresh retry may wait, server-supplied delays included.
///
/// The retry happens inside a request the browser is waiting on, so a
/// `Retry-After` of a minute must not become a minute of latency.
const REFRESH_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);

/// Randomize the proactive refresh threshold independently on each load.
/// Keep at least three quarters of the configured headroom, without sleeping
/// or postponing an expired token. A session-wide offset would merely move
/// the point at which concurrent requests all decide to refresh.
fn refresh_due(
    expiry: SystemTime,
    now: SystemTime,
    margin: Duration,
    rng: &mut impl rand::Rng,
) -> bool {
    let Ok(remaining) = expiry.duration_since(now) else {
        return true;
    };
    let jitter_window = margin / 4;
    if remaining <= margin.saturating_sub(jitter_window) {
        return true;
    }
    if remaining > margin {
        return false;
    }
    remaining <= margin.saturating_sub(rng.random_range(Duration::ZERO..=jitter_window))
}

/// Wait before retry `attempt` (1-indexed): `base * 2^(attempt-1) + jitter`,
/// jitter uniform in `[0, REFRESH_RETRY_JITTER_MAX)`.
fn refresh_retry_delay(attempt: u32) -> Duration {
    let base = REFRESH_RETRY_BASE_DELAY * (1u32 << (attempt - 1).min(16));
    let jitter_max_ms = u64::try_from(REFRESH_RETRY_JITTER_MAX.as_millis()).unwrap_or(u64::MAX);
    let jitter_ms = rand::rng().random_range(0..jitter_max_ms);
    base + Duration::from_millis(jitter_ms)
}

/// Maximum tolerated clock skew when validating sealed timestamps: a session
/// or login-state `created_at` further than this ahead of the wall clock is
/// treated as corrupted and rejected.
///
/// Within the tolerance the record is served as-is: a future `created_at`
/// can only extend the absolute deadline (or the login-state TTL window) by
/// the skew amount, and [`elapsed_since`] already clamps future timestamps
/// to zero. The value is sized for real fleet incidents (one node with a
/// stalled NTP daemon or a paused VM), where records minted on healthy nodes
/// look future to the lagging one — rejecting them there would destroy valid
/// sessions fleet-wide.
const MAX_CLOCK_SKEW: Duration = Duration::from_mins(5);

/// Returns `true` if `timestamp` is more than [`MAX_CLOCK_SKEW`] ahead of `now`.
fn is_too_far_future(timestamp: SystemTime, now: SystemTime) -> bool {
    timestamp
        .duration_since(now)
        .is_ok_and(|ahead| ahead > MAX_CLOCK_SKEW)
}

/// `now - earlier`, clamped to zero if `earlier` is in the future (small skew
/// already filtered by [`is_too_far_future`]).
fn elapsed_since(earlier: SystemTime, now: SystemTime) -> Duration {
    now.duration_since(earlier).unwrap_or(Duration::ZERO)
}

/// Browser fetch-metadata header names, materialized once.
static SEC_FETCH_MODE: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("sec-fetch-mode"));
static SEC_FETCH_DEST: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("sec-fetch-dest"));
static SEC_FETCH_SITE: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("sec-fetch-site"));
static SEC_FETCH_USER: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("sec-fetch-user"));
static X_REQUESTED_WITH: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("x-requested-with"));
static SEC_PURPOSE: LazyLock<HeaderName> = LazyLock::new(|| HeaderName::from_static("sec-purpose"));
static PURPOSE: LazyLock<HeaderName> = LazyLock::new(|| HeaderName::from_static("purpose"));

/// Returns `true` for a CORS preflight (`OPTIONS` + `Access-Control-Request-Method`).
pub fn is_cors_preflight(method: &Method, headers: &HeaderMap) -> bool {
    *method == Method::OPTIONS && headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
}

/// Returns `true` if this looks like a top-level browser navigation, using
/// fetch-metadata headers (`Sec-Fetch-Mode`/`-Dest`/`-User`,
/// `X-Requested-With`) with an `Accept: text/html` fallback for older clients.
/// Frame loads (`Sec-Fetch-Dest: iframe` etc.) and speculative
/// prefetch/prerender loads (`Sec-Purpose`) are not navigations — see
/// [the adapter guide](crate::_docs::how_to::adapter#speculative-loads-and-frames).
pub fn is_navigation_request(headers: &HeaderMap) -> bool {
    // Classic XHR signal — never a top-level navigation.
    if headers
        .get(&*X_REQUESTED_WITH)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"XMLHttpRequest"))
    {
        return false;
    }

    // Speculative prefetch/prerender — the user may never look at the result,
    // so don't start a login flow for it. `Sec-Purpose` is only ever sent on
    // such loads (`prefetch`, `prefetch;prerender`, ...); `Purpose: prefetch`
    // is the legacy spelling still sent by Chrome and Safari.
    if headers.contains_key(&*SEC_PURPOSE)
        || headers
            .get(&*PURPOSE)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"prefetch"))
    {
        return false;
    }

    // Fetch Metadata (all modern browsers send both).
    if let Some(mode) = headers.get(&*SEC_FETCH_MODE) {
        // Iframe/embed loads also send `mode=navigate`; when the browser also
        // says where the response lands, require a top-level document.
        return mode.as_bytes() == b"navigate"
            && headers
                .get(&*SEC_FETCH_DEST)
                .is_none_or(|dest| dest.as_bytes() == b"document");
    }
    if let Some(dest) = headers.get(&*SEC_FETCH_DEST) {
        return dest.as_bytes() == b"document";
    }

    // Affirmative navigation signal: only sent on user-activated top-level
    // navigations, always `?1`. Reached only when `Sec-Fetch-Mode`/`-Dest`
    // were stripped, so its presence rescues such a navigation more precisely
    // than the `Accept` heuristic below.
    if headers
        .get(&*SEC_FETCH_USER)
        .is_some_and(|v| v.as_bytes() == b"?1")
    {
        return true;
    }

    // Fallback for older clients.
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html") || v.contains("application/xhtml+xml"))
}

/// Returns `true` when `Sec-Fetch-Site` identifies the request as cross-site.
/// Requests without the header are not considered cross-site.
#[must_use]
pub fn is_cross_site_request(headers: &HeaderMap) -> bool {
    headers
        .get(&*SEC_FETCH_SITE)
        .is_some_and(|v| v.as_bytes() == b"cross-site")
}

/// Formats an error and its full source chain as a colon-separated string,
/// e.g. `"outer: middle: root cause"`.
pub fn error_chain(e: &dyn std::error::Error) -> String {
    use std::fmt::Write as _;
    let mut s = e.to_string();
    let mut source = e.source();
    while let Some(cause) = source {
        let _ = write!(s, ": {cause}");
        source = cause.source();
    }
    s
}

#[cfg(test)]
mod retry_delay_tests {
    use std::collections::HashSet;

    use super::{REFRESH_RETRY_BASE_DELAY, REFRESH_RETRY_JITTER_MAX, refresh_retry_delay};

    fn base(attempt: u32) -> std::time::Duration {
        REFRESH_RETRY_BASE_DELAY * (1u32 << (attempt - 1))
    }

    #[test]
    fn delay_stays_within_jitter_window() {
        for attempt in 1..=3 {
            let lo = base(attempt);
            let hi = lo + REFRESH_RETRY_JITTER_MAX;
            // Sample repeatedly: a single sample could miss a future
            // off-by-one that only fires near the window edges.
            for _ in 0..50 {
                let d = refresh_retry_delay(attempt);
                assert!(
                    d >= lo && d < hi,
                    "attempt {attempt}: delay {d:?} out of [{lo:?}, {hi:?})",
                );
            }
        }
    }

    #[test]
    fn later_attempts_strictly_outpace_earlier_ones() {
        // Attempt n+1's minimum (2×base) must exceed attempt n's maximum
        // (base + jitter_max). Holds as long as jitter_max < base, which the
        // constants enforce: 50ms < 100ms.
        assert!(
            REFRESH_RETRY_JITTER_MAX < REFRESH_RETRY_BASE_DELAY,
            "jitter must stay below base or successive windows overlap",
        );
    }

    #[test]
    fn jitter_actually_varies_across_calls() {
        // With a real PRNG, 50 samples should produce many distinct values.
        // A single value would mean the random source isn't wired up.
        let samples: HashSet<_> = (0..50).map(|_| refresh_retry_delay(1)).collect();
        assert!(
            samples.len() > 5,
            "expected jitter to vary, got {samples:?}"
        );
    }
}

#[cfg(test)]
mod refresh_threshold_tests {
    use rand::{SeedableRng, rngs::StdRng};
    use rstest::rstest;

    use super::{Duration, SystemTime, refresh_due};

    #[rstest]
    #[case::expired(Duration::from_secs(30), -1, true)]
    #[case::at_expiry(Duration::from_secs(30), 0, true)]
    #[case::guaranteed_refresh(Duration::from_secs(30), 22_500_000_000, true)]
    #[case::outside_margin(Duration::from_secs(30), 30_000_000_001, false)]
    #[case::zero_margin_before_expiry(Duration::ZERO, 1, false)]
    #[case::zero_margin_at_expiry(Duration::ZERO, 0, true)]
    #[case::zero_margin_expired(Duration::ZERO, -1, true)]
    #[case::subnanosecond_window(Duration::from_nanos(3), 3, true)]
    #[case::tiny_margin_outside(Duration::from_nanos(3), 4, false)]
    #[case::maximum_margin(Duration::MAX, 1, true)]
    fn threshold_boundaries(
        #[case] margin: Duration,
        #[case] remaining_nanos: i64,
        #[case] expected: bool,
    ) {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        let remaining = Duration::from_nanos(remaining_nanos.unsigned_abs());
        let expiry = if remaining_nanos < 0 {
            now - remaining
        } else {
            now + remaining
        };
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..100 {
            assert_eq!(refresh_due(expiry, now, margin, &mut rng), expected);
        }
    }

    #[test]
    fn requests_in_jitter_window_make_different_decisions() {
        let now = SystemTime::UNIX_EPOCH;
        let expiry = now + Duration::from_secs(26);
        let mut rng = StdRng::seed_from_u64(42);
        let due = (0..100)
            .filter(|_| refresh_due(expiry, now, Duration::from_secs(30), &mut rng))
            .count();
        assert!(
            due > 0 && due < 100,
            "requests must not share a fixed threshold"
        );
    }
}
