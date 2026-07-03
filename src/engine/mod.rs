//! Framework-agnostic login engine. [`LoginEngine`] exposes the OAuth 2.0
//! Authorization Code Grant as composable primitives that framework adapters
//! compose into middleware.

use std::sync::{Arc, LazyLock};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use huskarl::{
    core::{
        Error,
        crypto::cipher::{AeadCipher, AeadV1Cipher},
        platform::{Duration, MaybeSendSync, SystemTime, sleep},
        serde_utils::time::unix_secs,
    },
    grant::{
        authorization_code::{AuthorizationCodeGrant, PendingState},
        core::{OAuth2ExchangeGrant as _, TokenResponse},
        refresh::RefreshGrantParameters,
    },
    token::RefreshToken,
};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};

use crate::{
    DefaultErrorPage, ErrorPage, LivenessVerdict, LoginConfig, Session, SessionDriver,
    SessionError, SessionErrorKind,
    cookie::SessionCipher,
    metrics::{LoginCompleteResult, LoginEngineMetrics, LoginStartResult, RefreshResult},
};

mod callback;
mod logout;
mod redirect;

#[cfg(test)]
mod tests;

type EngineError = SessionError;

// ── Public types ──────────────────────────────────────────────────────────────

/// A framework-neutral HTTP response produced by the login engine.
///
/// Framework adapters lower this into their native response type via
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
        /// `Set-Cookie` values to emit alongside the redirect.
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

    /// Lowers this response into concrete HTTP parts: status, full header list,
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

/// The result of [`LoginEngine::load_session`] — one variant per session
/// state the adapter can observe.
///
/// Not `#[non_exhaustive]`: every state must be handled, so a new variant is a
/// compile error at each call site.
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
        clears: Vec<HeaderValue>,
    },
    /// Authenticated and fully persisted — nothing is owed after the inner
    /// handler responds.
    Active {
        /// The loaded session.
        session: S,
        /// `Set-Cookie` headers that must reach the final response (re-sealed
        /// session cookies after an eager refresh, else empty); see
        /// [`load_session`](LoginEngine::load_session) on caching.
        set_cookies: Vec<HeaderValue>,
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
    /// Authenticated, with a save owed after the inner handler responds — pass
    /// `session` and `token_response` to [`LoginEngine::persist_session`].
    /// Arises only when the eager persist of a refreshed session failed.
    ActivePending {
        /// The loaded session, with the refresh applied in memory.
        session: S,
        /// The refresh response, so [`LoginEngine::persist_session`] can
        /// re-commit it against fresh store state. Boxed to keep the rare
        /// variant from inflating every [`LoadedSession`] returned.
        token_response: Box<TokenResponse>,
    },
}

impl<S> LoadedSession<S> {
    /// Convenience accessor: the session, when the request is authenticated.
    pub fn session(&self) -> Option<&S> {
        match self {
            Self::Missing | Self::Cleared { .. } | Self::RefreshUnavailable => None,
            Self::Active { session, .. } | Self::ActivePending { session, .. } => Some(session),
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

/// Why [`LoginEngine::load_session`] tore down a presented session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum TeardownReason {
    /// [`LoginConfig::max_lifetime`](crate::LoginConfig::max_lifetime) exceeded.
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
}

impl TeardownReason {
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Decides how a framework adapter reacts when the post-response save of a
/// refreshed session fails.
///
/// The inner handler has already run (including side effects) by the time this
/// is called; a replacement response will cause well-behaved clients to retry.
pub trait PersistFailurePolicy: MaybeSendSync + 'static {
    /// Decide what to do after a [`LoadedSession::ActivePending`] save failed.
    /// `Some(response)` replaces the handler's response; `None` lets it pass
    /// through. `error` may downcast to [`SessionError`].
    fn handle(&self, error: &(dyn std::error::Error + 'static)) -> Option<LoginResponse>;
}

/// Default policy: fail closed when the refreshed-session save fails, replacing
/// the response to force a clean retry.
///
/// The replacement status is derived from a [`SessionError`]'s
/// [`SessionErrorKind`]: [`Conflict`](SessionErrorKind::Conflict) → `409`,
/// [`Crypto`](SessionErrorKind::Crypto)/[`Store`](SessionErrorKind::Store) →
/// `500`, anything else → `503`.
pub struct DefaultPersistFailurePolicy;

impl PersistFailurePolicy for DefaultPersistFailurePolicy {
    fn handle(&self, error: &(dyn std::error::Error + 'static)) -> Option<LoginResponse> {
        let status = match error.downcast_ref::<SessionError>().map(SessionError::kind) {
            Some(SessionErrorKind::Conflict) => StatusCode::CONFLICT,
            Some(SessionErrorKind::Crypto | SessionErrorKind::Store) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        Some(LoginResponse::Rendered {
            status,
            // Same rule as every engine-rendered response: session-adjacent
            // responses are never cacheable.
            headers: vec![(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            body: Bytes::new(),
        })
    }
}

// ── Internal types ────────────────────────────────────────────────────────────

/// Encrypted payload stored in the per-flow login-state cookie. The flow's
/// `state` value is the AEAD associated data.
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

// ── LoginEngine ───────────────────────────────────────────────────────────────

/// Framework-agnostic login engine: drives the OAuth flow (start, callback,
/// logout) and persists sessions through its [`SessionDriver`] `SD`.
///
/// Build one with `LoginEngine::builder()`.
#[non_exhaustive]
pub struct LoginEngine<SD> {
    /// The login configuration.
    pub config: LoginConfig,
    grant: AuthorizationCodeGrant,
    /// The session store.
    pub session_store: SD,
    cipher: SessionCipher,
    error_page: Box<dyn ErrorPage>,
    metrics: Option<Arc<dyn LoginEngineMetrics>>,
}

// ── Constructor ───────────────────────────────────────────────────────────────

#[bon::bon]
impl<SD> LoginEngine<SD>
where
    SD: SessionDriver,
{
    /// Builds a [`LoginEngine`]; invoked via `LoginEngine::builder()`.
    ///
    /// `grant` drives the OAuth flow per its own configuration. `cipher` seals
    /// only the short-lived login-state cookie; sessions are persisted by the
    /// session store.
    #[builder]
    pub fn new(
        config: LoginConfig,
        grant: AuthorizationCodeGrant,
        session_store: SD,
        #[builder(with = |cipher: impl AeadCipher + 'static| Arc::new(cipher) as Arc<dyn AeadCipher>)]
        cipher: Arc<dyn AeadCipher>,
        /// Custom error page renderer. Defaults to [`DefaultErrorPage`].
        #[builder(default = Box::new(DefaultErrorPage) as Box<dyn ErrorPage>)]
        error_page: Box<dyn ErrorPage>,
        /// Optional metrics observer for login-flow events.
        metrics: Option<Arc<dyn LoginEngineMetrics>>,
    ) -> Self {
        // Single source of truth for cookie security: stamp the store with the
        // value derived from `base_url`, so session cookies and login-state
        // cookies share one `secure`/`__Host-` policy.
        let mut session_store = session_store;
        session_store.apply_cookie_secure(config.secure);
        Self {
            config,
            grant,
            session_store,
            cipher: AeadV1Cipher::new(cipher),
            error_page,
            metrics,
        }
    }
}

// ── Core logic ────────────────────────────────────────────────────────────────

impl<SD> LoginEngine<SD>
where
    SD: SessionDriver,
{
    /// If `uri`'s path is the configured callback or logout path, returns the
    /// corresponding response; otherwise `None` (the adapter falls through).
    ///
    /// Pass the engine-side URI (including any front-proxy `strip_prefix`). The
    /// callback accepts only `GET`, logout only `POST`; other methods on these
    /// paths get `405 Method Not Allowed` with an `Allow` header.
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

    /// Builds a `405 Method Not Allowed` response with an `Allow` header.
    fn method_not_allowed(&self, allow: &'static str) -> LoginResponse {
        let mut resp =
            self.build_error_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        resp.push_rendered_header(header::ALLOW, HeaderValue::from_static(allow));
        resp
    }

    /// Loads and validates the session from request cookies, refreshing the
    /// access token if near expiry. Never redirects or errors. A successful
    /// refresh is persisted eagerly, yielding [`LoadedSession::Active`] (or
    /// [`LoadedSession::ActivePending`] if that persist failed).
    ///
    /// # Response caching
    ///
    /// Any response carrying session `Set-Cookie` values — `Active`'s
    /// `set_cookies`, [`LoadedSession::Cleared`]'s clears, or those from
    /// [`persist_session`](Self::persist_session) — MUST be made non-cacheable
    /// by the adapter, or a shared cache could replay a session cookie.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the session store fails to load.
    pub async fn load_session(
        &self,
        headers: &HeaderMap,
    ) -> Result<LoadedSession<SD::SessionType>, SessionError> {
        let Some(session) = self
            .session_store
            .load(headers)
            .await
            .map_err(crate::session::to_session_err)?
        else {
            return Ok(LoadedSession::Missing);
        };

        let now = SystemTime::now();

        if let Some(reason) = self.session_teardown_reason(&session, now) {
            let clears = self.delete_best_effort(&session, headers).await;
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
        // Absolute deadline handed to the liveness store so its entry expires
        // exactly when the session can no longer be valid (never on a sliding
        // idle TTL, which would break fail-open).
        let expire_at = self
            .config
            .max_lifetime
            .map(|max| session.created_at() + max);
        if self
            .session_store
            .check_liveness(&session, now, record_activity, expire_at)
            .await?
            == LivenessVerdict::Expired
        {
            let clears = self.delete_best_effort(&session, headers).await;
            let reason = TeardownReason::IdleTimeout;
            self.record_teardown(reason);
            return Ok(LoadedSession::Cleared { reason, clears });
        }

        if now + self.config.token_refresh_margin >= session.token_expiry() {
            return Ok(self.refresh_or_clear(session, headers).await);
        }

        Ok(LoadedSession::Active {
            session,
            set_cookies: vec![],
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
                log::error!(
                    "failed to redirect to authorization server: {}",
                    error_chain(&e)
                );
                self.record_login_start(&LoginStartResult::Error);
                self.build_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to start login",
                )
            }
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
            log::warn!("session timestamps are too far in the future — treating as expired");
            return Some(TeardownReason::ClockSkew);
        }
        if let Some(max_lifetime) = self.config.max_lifetime
            && elapsed_since(session.created_at(), now) > max_lifetime
        {
            return Some(TeardownReason::MaxLifetime);
        }
        None
    }

    /// Exchanges the refresh token. A transient failure while the access token
    /// is still valid retains the session and keeps serving; a transient
    /// failure after token expiry retains the session but yields
    /// [`LoadedSession::RefreshUnavailable`] (fail the request, not the
    /// session); only a conclusive rejection — or a session with no refresh
    /// token — tears the session down and emits cookie clears.
    async fn refresh_or_clear(
        &self,
        mut session: SD::SessionType,
        headers: &HeaderMap,
    ) -> LoadedSession<SD::SessionType> {
        let Some(rt) = session.refresh_token().cloned() else {
            let clears = self.delete_best_effort(&session, headers).await;
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
                        self.config.default_token_lifetime,
                        headers,
                    )
                    .await
                {
                    Ok(set_cookies) => LoadedSession::Active {
                        session,
                        set_cookies,
                    },
                    Err(e) => {
                        log::warn!(
                            "failed to eagerly persist refreshed session; deferring to \
                             post-response persist: {}",
                            error_chain(&e)
                        );
                        LoadedSession::ActivePending {
                            session,
                            token_response: Box::new(token_response),
                        }
                    }
                }
            }
            // Re-read the clock: the retry loop slept, and the token may have
            // expired while we were waiting.
            Err(e) if e.is_retryable() && SystemTime::now() < session.token_expiry() => {
                log::warn!(
                    "token refresh failed transiently; retaining session while access token \
                     is still valid: {}",
                    error_chain(&e)
                );
                self.record_refresh(&RefreshResult::FailedRetained);
                // Rare transient path — retain as-is without an activity touch;
                // the next request re-evaluates liveness.
                LoadedSession::Active {
                    session,
                    set_cookies: vec![],
                }
            }
            // Transient failure past token expiry: authentication can be
            // neither confirmed nor refuted, so fail the *request*, not the
            // session. Deleting here would permanently destroy a session (and
            // its refresh token) that resumes by itself once the authorization
            // server recovers — an AS blip at the wrong moment must not force
            // every idle user back through login.
            Err(e) if e.is_retryable() => {
                log::warn!(
                    "token refresh unavailable; retaining session for a later retry: {}",
                    error_chain(&e)
                );
                self.record_refresh(&RefreshResult::FailedUnavailable);
                LoadedSession::RefreshUnavailable
            }
            // Conclusive rejection (e.g. `invalid_grant`, possibly
            // reuse-detection revocation): the AS disowned the refresh token,
            // so the session is dead — tear it down.
            Err(e) => {
                log::error!("token refresh failed: {}", error_chain(&e));
                let reason = TeardownReason::RefreshRejected;
                let clears = self.delete_best_effort(&session, headers).await;
                self.record_refresh(&RefreshResult::Failed);
                self.record_teardown(reason);
                LoadedSession::Cleared { reason, clears }
            }
        }
    }

    /// Calls `session_store.delete`, logging on failure and returning an empty
    /// vec so callers can `.extend(...)` unconditionally.
    async fn delete_best_effort(
        &self,
        session: &SD::SessionType,
        headers: &HeaderMap,
    ) -> Vec<HeaderValue> {
        match self.session_store.delete(session, headers).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("failed to delete session: {}", error_chain(&e));
                vec![]
            }
        }
    }

    /// Exchanges the refresh token up to [`REFRESH_MAX_ATTEMPTS`] times,
    /// retrying retryable errors with exponential backoff plus jitter
    /// ([`refresh_retry_delay`]); non-retryable errors return immediately.
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
                Err(e) if attempt < REFRESH_MAX_ATTEMPTS && e.is_retryable() => {
                    let delay = refresh_retry_delay(attempt);
                    log::warn!(
                        "token refresh failed (attempt {attempt}/{REFRESH_MAX_ATTEMPTS}, retrying in {delay:?}): {e}"
                    );
                    sleep(delay).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn record_login_start(&self, result: &LoginStartResult) {
        if let Some(m) = &self.metrics {
            m.record_login_start(result);
        }
    }

    fn record_login_complete(&self, result: &LoginCompleteResult, as_error: Option<&str>) {
        if let Some(m) = &self.metrics {
            m.record_login_complete(result, as_error);
        }
    }

    fn record_refresh(&self, result: &RefreshResult) {
        if let Some(m) = &self.metrics {
            m.record_refresh(result);
        }
    }

    fn record_teardown(&self, reason: TeardownReason) {
        if let Some(m) = &self.metrics {
            m.record_teardown(&reason);
        }
    }

    /// Commits the refresh owed by a [`LoadedSession::ActivePending`] after the
    /// inner service responded, returning `Set-Cookie` values to append. Pass
    /// the variant's `session` and `token_response` back in; the refresh is
    /// re-committed through the same merge-safe path as the eager persist, so
    /// a concurrent [`StoreBackedSessionStore::update`] landing in between is
    /// preserved. On success `session` is the committed (merged) session.
    /// `request_headers` are the original request cookies (used by
    /// cookie-backed stores to clear stale slots); see
    /// [`load_session`](Self::load_session) on caching.
    ///
    /// [`StoreBackedSessionStore::update`]: crate::StoreBackedSessionStore::update
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the session store fails to write.
    pub async fn persist_session(
        &self,
        session: &mut SD::SessionType,
        token_response: &TokenResponse,
        request_headers: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.session_store
            .apply_refresh_and_save(
                session,
                token_response,
                self.config.default_token_lifetime,
                request_headers,
            )
            .await
    }

    /// Deletes a session, returning `Set-Cookie` values that clear the session
    /// cookies. See [`persist_session`](Self::persist_session) for
    /// `request_headers`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the session store fails to delete.
    pub async fn delete_session(
        &self,
        session: &SD::SessionType,
        request_headers: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.session_store.delete(session, request_headers).await
    }

    /// Explicitly and unconditionally saves a session (e.g. after the
    /// application mutated it), returning `Set-Cookie` values; unlike the
    /// deferred [`persist_session`](Self::persist_session). See
    /// [`persist_session`](Self::persist_session) for `request_headers`.
    ///
    /// This is a whole-session, last-writer-wins write: it overwrites changes
    /// committed concurrently by other requests. For store-backed sessions
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
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.session_store.save(session, request_headers).await
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

/// Wait before retry `attempt` (1-indexed): `base * 2^(attempt-1) + jitter`,
/// jitter uniform in `[0, REFRESH_RETRY_JITTER_MAX)`.
fn refresh_retry_delay(attempt: u32) -> Duration {
    let base = REFRESH_RETRY_BASE_DELAY * (1u32 << (attempt - 1).min(16));
    let jitter_max_ms = u64::try_from(REFRESH_RETRY_JITTER_MAX.as_millis()).unwrap_or(u64::MAX);
    let jitter_ms = rand::rng().random_range(0..jitter_max_ms);
    base + Duration::from_millis(jitter_ms)
}

/// Maximum tolerated clock skew when validating session timestamps. A session
/// whose `created_at` is further than this ahead of the wall clock is treated
/// as corrupted and expired.
const MAX_CLOCK_SKEW: Duration = Duration::from_mins(1);

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

/// Returns `true` for a CORS preflight (`OPTIONS` + `Access-Control-Request-Method`).
pub fn is_cors_preflight(method: &Method, headers: &HeaderMap) -> bool {
    *method == Method::OPTIONS && headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
}

/// Returns `true` if this looks like a top-level browser navigation, using
/// fetch-metadata headers (`Sec-Fetch-Mode`/`-Dest`/`-User`,
/// `X-Requested-With`) with an `Accept: text/html` fallback for older clients.
pub fn is_navigation_request(headers: &HeaderMap) -> bool {
    // Classic XHR signal — never a top-level navigation.
    if headers
        .get(&*X_REQUESTED_WITH)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"XMLHttpRequest"))
    {
        return false;
    }

    // Fetch Metadata (all modern browsers send both).
    if let Some(mode) = headers.get(&*SEC_FETCH_MODE) {
        return mode.as_bytes() == b"navigate";
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
