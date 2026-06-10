//! Framework-agnostic login engine.
//!
//! [`LoginEngine`] exposes the OAuth 2.0 Authorization Code Grant as a set of
//! composable primitives:
//!
//! - [`try_handle_login_route`](LoginEngine::try_handle_login_route) — handle
//!   the configured `/callback` and `/logout` paths.
//! - [`load_session`](LoginEngine::load_session) — load and validate the
//!   session cookie (refreshing tokens if needed), without ever redirecting.
//! - [`persist_session`](LoginEngine::persist_session) — write the session
//!   back to the store after the inner handler returned.
//! - [`redirect_to_login`](LoginEngine::redirect_to_login) — produce a
//!   response that asks the client to authenticate (302 to AS for browser
//!   navigation, 401 for XHR).
//!
//! Framework adapters (huskarl-axum, huskarl-pingora) compose these into
//! middleware appropriate for the framework's routing model.

use std::{
    sync::{Arc, LazyLock},
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use huskarl::{
    core::{
        BoxedError, Error as _,
        crypto::cipher::{AeadV1Sealer, AeadV1Unsealer, BoxedAeadCipher},
        http::HttpClient,
    },
    grant::{authorization_code::PendingState, core::TokenResponse},
    token::RefreshToken,
};
use rand::RngExt as _;
use serde::{Deserialize, Serialize};

use crate::{
    DefaultErrorPage, ErrorPage, LoginConfig, LoginGrant, Session, SessionDriver, SessionError,
    metrics::{
        ActivityOutcome, LoginCompleteResult, LoginEngineMetrics, LoginStartResult, RefreshResult,
    },
};

mod callback;
mod logout;
mod redirect;

#[cfg(test)]
mod tests;

type EngineError = Box<dyn std::error::Error + Send + Sync>;

// ── Public types ──────────────────────────────────────────────────────────────

/// A framework-neutral HTTP response produced by the login engine.
///
/// Framework adapters convert this into their native response type.
pub struct LoginResponse {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response headers (may contain multiple values for the same name,
    /// e.g. multiple `Set-Cookie` headers).
    pub headers: Vec<(HeaderName, HeaderValue)>,
    /// Response body (empty for redirects).
    pub body: Bytes,
}

/// The result of [`LoginEngine::load_session`].
pub struct LoadedSession<S> {
    /// The loaded session and how the adapter should persist it after the
    /// inner handler returns.
    ///
    /// `None` when no cookie was present, the session was expired, or token
    /// refresh failed. In those cases [`clear_cookies`](Self::clear_cookies)
    /// may carry headers to drop the now-stale session cookie.
    pub session: Option<(S, SessionPersistence)>,
    /// `Set-Cookie` headers (always cookie clears) the framework adapter
    /// must append to the final response. Empty in the happy path.
    pub clear_cookies: Vec<HeaderValue>,
}

/// How to persist the session after the inner service responds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPersistence {
    /// The token was refreshed — call save.
    Save,
    /// Just record activity — call touch.
    Touch,
    /// No persistence needed for this request — the activity update was
    /// throttled by [`LoginConfig::touch_min_interval`]. The framework adapter
    /// can skip the post-response persist call.
    Skip,
}

/// Decides how a framework adapter should react when persisting the session
/// fails *after* the inner handler has already produced a response.
///
/// Return `Some(LoginResponse)` to replace the handler's response, or `None`
/// to let it pass through unchanged.
///
/// # Idempotency
///
/// By the time this is called the inner handler has already run, including any
/// side effects (DB writes, queued jobs, etc.). Returning a replacement
/// response will cause well-behaved clients to retry — design handlers
/// accordingly.
pub trait PersistFailurePolicy: Send + Sync + 'static {
    /// Decide what to do after a persist failure.
    ///
    /// Returning `Some(response)` replaces the inner handler's response; `None`
    /// lets it pass through unchanged. `persistence` indicates which operation
    /// failed (save/touch/skip); `error` is the underlying store error.
    fn handle(
        &self,
        persistence: SessionPersistence,
        error: &dyn std::error::Error,
    ) -> Option<LoginResponse>;
}

/// Default policy: fail closed on [`SessionPersistence::Save`] (token refresh)
/// and fail open on [`SessionPersistence::Touch`] / [`SessionPersistence::Skip`].
///
/// `Save` is the path where the engine refreshed the access token; if the
/// handler response is allowed through without persisting the new tokens the
/// client is stranded on stale state — and with refresh-token rotation, often
/// locked out entirely. A 503 forces a clean retry.
///
/// `Touch` only updates the session's last-active timestamp. Losing one is
/// cheap and not worth a 5xx over a transient store blip.
pub struct DefaultPersistFailurePolicy;

impl PersistFailurePolicy for DefaultPersistFailurePolicy {
    fn handle(
        &self,
        persistence: SessionPersistence,
        _error: &dyn std::error::Error,
    ) -> Option<LoginResponse> {
        match persistence {
            SessionPersistence::Save => Some(LoginResponse {
                status: StatusCode::SERVICE_UNAVAILABLE,
                headers: Vec::new(),
                body: Bytes::new(),
            }),
            SessionPersistence::Touch | SessionPersistence::Skip => None,
        }
    }
}

// ── Internal types ────────────────────────────────────────────────────────────

/// Encrypted payload stored in the per-flow login-state cookie.
///
/// The flow's `state` value is used as AEAD associated data, binding the cookie
/// to the specific authorization request.
#[derive(Serialize, Deserialize)]
struct LoginStateCookie {
    original_url: String,
    pending_state: PendingState,
}

// ── LoginEngine ───────────────────────────────────────────────────────────────

/// Framework-agnostic login engine.
///
/// See the [module documentation](self) for the set of primitives this
/// engine exposes; framework adapters compose them into middleware.
pub struct LoginEngine<G, SD, H> {
    config: LoginConfig,
    grant: G,
    session_store: SD,
    sealer: AeadV1Sealer<BoxedAeadCipher>,
    unsealer: AeadV1Unsealer<BoxedAeadCipher>,
    http_client: H,
    error_page: Box<dyn ErrorPage>,
    metrics: Option<Arc<dyn LoginEngineMetrics>>,
}

// ── Constructor ───────────────────────────────────────────────────────────────

#[bon::bon]
impl<G, SD, H> LoginEngine<G, SD, H>
where
    G: LoginGrant,
    SD: SessionDriver,
    H: HttpClient + Send + Sync,
{
    /// Creates a new `LoginEngine`.
    ///
    /// The `cipher` is used only for the short-lived login-state cookie (CSRF
    /// protection during the OAuth flow). Session persistence is handled
    /// entirely by the session store.
    #[builder]
    pub fn new(
        config: LoginConfig,
        grant: G,
        session_store: SD,
        cipher: BoxedAeadCipher,
        http_client: H,
        /// Custom error page renderer. Defaults to [`DefaultErrorPage`].
        #[builder(default = Box::new(DefaultErrorPage) as Box<dyn ErrorPage>)]
        error_page: Box<dyn ErrorPage>,
        /// Optional metrics observer for login-flow events.
        metrics: Option<Arc<dyn LoginEngineMetrics>>,
    ) -> Self {
        Self {
            config,
            grant,
            session_store,
            sealer: AeadV1Sealer::new(cipher.clone()),
            unsealer: AeadV1Unsealer::new(cipher),
            http_client,
            error_page,
            metrics,
        }
    }
}

// ── Accessors (no trait bounds needed) ────────────────────────────────────────

impl<G, SD, H> LoginEngine<G, SD, H> {
    /// Returns a reference to the login configuration.
    pub fn config(&self) -> &LoginConfig {
        &self.config
    }

    /// Returns a reference to the session store.
    pub fn session_store(&self) -> &SD {
        &self.session_store
    }
}

// ── Core logic ────────────────────────────────────────────────────────────────

impl<G, SD, H> LoginEngine<G, SD, H>
where
    G: LoginGrant,
    SD: SessionDriver,
    H: HttpClient + Send + Sync,
{
    /// If `path` is the configured callback or logout path, returns the
    /// corresponding response. Otherwise returns `None` and the framework
    /// adapter should fall through to the next layer.
    pub async fn try_handle_login_route(
        &self,
        path: &str,
        _method: &Method,
        headers: &HeaderMap,
        uri: &Uri,
    ) -> Option<LoginResponse> {
        if path == self.config.callback_path {
            return Some(self.handle_callback(uri, headers).await);
        }
        if self
            .config
            .logout_path
            .as_deref()
            .is_some_and(|p| path == p)
        {
            return Some(self.handle_logout(headers).await);
        }
        None
    }

    /// Loads and validates the session from request cookies, refreshing
    /// the access token if it's near expiry.
    ///
    /// Never redirects or returns an error response — the framework adapter
    /// decides what to do when no session is present (a downstream gate may
    /// call [`redirect_to_login`](Self::redirect_to_login), or the request
    /// may simply proceed unauthenticated).
    ///
    /// On infrastructure failure (e.g. the session store is unreachable) the
    /// underlying error is returned; the adapter typically maps that to a
    /// 5xx response.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the underlying session store fails to load
    /// the session (e.g. transport error against an external store).
    pub async fn load_session(
        &self,
        headers: &HeaderMap,
    ) -> Result<LoadedSession<SD::SessionType>, SessionError> {
        let Some(mut session) = self.session_store.load(headers).await? else {
            return Ok(LoadedSession {
                session: None,
                clear_cookies: vec![],
            });
        };

        let now = SystemTime::now();

        if self.session_is_expired(&session, now) {
            let clear_cookies = self.delete_best_effort(&session, headers).await;
            return Ok(LoadedSession {
                session: None,
                clear_cookies,
            });
        }

        if now + self.config.token_refresh_margin >= session.token_expiry() {
            return Ok(self.refresh_or_clear(session, headers).await);
        }

        let persistence = self.touch_or_skip(&mut session, now);
        Ok(LoadedSession {
            session: Some((session, persistence)),
            clear_cookies: vec![],
        })
    }

    /// Produces a response that asks the client to authenticate.
    ///
    /// - Browser navigation: `302 Found` to the authorization server, with
    ///   the current URL stored in a sealed cookie so the user returns here
    ///   after callback.
    /// - API/XHR requests: `401 Unauthorized`.
    pub async fn redirect_to_login(&self, headers: &HeaderMap, uri: &Uri) -> LoginResponse {
        if !is_navigation_request(headers) {
            return self.build_error_response(StatusCode::UNAUTHORIZED, "authentication required");
        }
        match self.redirect_to_as(headers, uri, None).await {
            Ok(resp) => {
                self.record_login_start(&LoginStartResult::Ok);
                resp
            }
            Err(e) => {
                log::error!(
                    "failed to redirect to authorization server: {}",
                    error_chain(&*e)
                );
                self.record_login_start(&LoginStartResult::Error);
                self.build_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to start login",
                )
            }
        }
    }

    /// Returns `true` when the session should be torn down rather than served:
    /// clock-skew corruption, absolute lifetime exceeded, or idle past timeout.
    fn session_is_expired(&self, session: &SD::SessionType, now: SystemTime) -> bool {
        if is_too_far_future(session.created_at(), now)
            || is_too_far_future(session.last_active(), now)
        {
            log::warn!("session timestamps are too far in the future — treating as expired");
            return true;
        }
        if let Some(max_lifetime) = self.config.max_lifetime
            && elapsed_since(session.created_at(), now) > max_lifetime
        {
            return true;
        }
        if let Some(idle_timeout) = self.config.idle_timeout
            && elapsed_since(session.last_active(), now) > idle_timeout
        {
            return true;
        }
        false
    }

    /// Token (or refresh window) elapsed — exchange the refresh token, or
    /// emit cookie clears if refresh is unavailable / fails.
    async fn refresh_or_clear(
        &self,
        mut session: SD::SessionType,
        headers: &HeaderMap,
    ) -> LoadedSession<SD::SessionType> {
        let Some(rt) = session.refresh_token().cloned() else {
            let clear_cookies = self.delete_best_effort(&session, headers).await;
            self.record_refresh(&RefreshResult::NoRefreshToken);
            return LoadedSession {
                session: None,
                clear_cookies,
            };
        };
        match self.refresh_with_retry(&rt).await {
            Ok(token_response) => {
                session.apply_refresh(&token_response, self.config.default_token_lifetime);
                self.record_refresh(&RefreshResult::Ok);
                LoadedSession {
                    session: Some((session, SessionPersistence::Save)),
                    clear_cookies: vec![],
                }
            }
            Err(e) => {
                log::error!("token refresh failed: {}", error_chain(&e));
                let clear_cookies = self.delete_best_effort(&session, headers).await;
                self.record_refresh(&RefreshResult::Failed);
                LoadedSession {
                    session: None,
                    clear_cookies,
                }
            }
        }
    }

    /// Calls `session_store.delete`, logging on failure and returning an
    /// empty vec so callers can `.extend(...)` unconditionally.
    async fn delete_best_effort(
        &self,
        session: &SD::SessionType,
        headers: &HeaderMap,
    ) -> Vec<HeaderValue> {
        match self.session_store.delete(session, headers).await {
            Ok(c) => c,
            Err(e) => {
                log::error!("failed to delete session: {}", error_chain(&*e));
                vec![]
            }
        }
    }

    /// Calls the grant's refresh up to [`REFRESH_MAX_ATTEMPTS`] times, retrying
    /// only when the underlying error advertises itself as retryable (transient
    /// transport failures). Non-retryable errors (e.g. `invalid_grant` from the
    /// authorization server) are returned immediately so we don't waste calls —
    /// or risk tripping AS-side rate limiting — on a refresh token the AS has
    /// already rejected.
    ///
    /// Retries use exponential backoff with jitter ([`refresh_retry_delay`]) so
    /// a brief AS outage doesn't produce a synchronized thundering herd when
    /// every in-flight refresh retries at the same moment.
    async fn refresh_with_retry(&self, rt: &RefreshToken) -> Result<TokenResponse, BoxedError> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            match self.grant.refresh(&self.http_client, rt).await {
                Ok(tr) => return Ok(tr),
                Err(e) if attempt < REFRESH_MAX_ATTEMPTS && e.is_retryable() => {
                    let delay = refresh_retry_delay(attempt);
                    log::warn!(
                        "token refresh failed (attempt {attempt}/{REFRESH_MAX_ATTEMPTS}, retrying in {delay:?}): {e}"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Decides whether this request should record activity (subject to
    /// `touch_min_interval` throttling) or skip persistence entirely.
    fn touch_or_skip(&self, session: &mut SD::SessionType, now: SystemTime) -> SessionPersistence {
        if elapsed_since(session.last_active(), now) >= self.config.touch_min_interval {
            session.record_activity();
            self.record_activity(&ActivityOutcome::Touch);
            SessionPersistence::Touch
        } else {
            self.record_activity(&ActivityOutcome::Skip);
            SessionPersistence::Skip
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

    fn record_activity(&self, outcome: &ActivityOutcome) {
        if let Some(m) = &self.metrics {
            m.record_activity(outcome);
        }
    }

    /// Persists a session after the inner service has responded.
    ///
    /// Returns `Set-Cookie` header values to append to the response.
    ///
    /// `request_headers` are the cookies the browser sent on the original
    /// request — cookie-backed session stores use them to clear any stale
    /// chunked-cookie slots that the new session no longer occupies.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the underlying session store fails to write
    /// the session (e.g. transport error against an external store).
    pub async fn persist_session(
        &self,
        session: &SD::SessionType,
        persistence: SessionPersistence,
        request_headers: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        match persistence {
            SessionPersistence::Save => self.session_store.save(session, request_headers).await,
            SessionPersistence::Touch => self.session_store.touch(session, request_headers).await,
            SessionPersistence::Skip => Ok(vec![]),
        }
    }

    /// Deletes a session, returning `Set-Cookie` header values that clear
    /// the session cookies. See [`persist_session`](Self::persist_session)
    /// for the role of `request_headers`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the underlying session store fails to
    /// delete the session.
    pub async fn delete_session(
        &self,
        session: &SD::SessionType,
        request_headers: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.session_store.delete(session, request_headers).await
    }

    /// Saves a session, returning `Set-Cookie` header values. See
    /// [`persist_session`](Self::persist_session) for the role of `request_headers`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the underlying session store fails to save
    /// the session.
    pub async fn save_session(
        &self,
        session: &SD::SessionType,
        request_headers: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.session_store.save(session, request_headers).await
    }

    /// Touches a session (TTL extension), returning `Set-Cookie` header values.
    /// See [`persist_session`](Self::persist_session) for the role of `request_headers`.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the underlying session store fails to
    /// touch the session.
    pub async fn touch_session(
        &self,
        session: &SD::SessionType,
        request_headers: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.session_store.touch(session, request_headers).await
    }

    /// Renders an error response through the configured [`ErrorPage`].
    ///
    /// Framework adapters use this to keep server-side error pages (e.g. 500
    /// when session loading fails) consistent with the error pages produced
    /// inside the OAuth flow itself.
    pub fn render_error(&self, status: StatusCode, message: &str) -> LoginResponse {
        self.build_error_response(status, message)
    }

    fn build_error_response(&self, status: StatusCode, message: &str) -> LoginResponse {
        let rendered = self.error_page.render(status, message);
        LoginResponse {
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
/// Only retryable transport errors trigger a retry; AS-rejection errors return
/// immediately. Three attempts cover the typical transient-failure window (e.g.
/// a single retransmit after a brief network hiccup) without amplifying load
/// on a healthy AS.
const REFRESH_MAX_ATTEMPTS: u32 = 3;

/// Base delay for the first refresh retry; doubled on each subsequent attempt.
/// With `REFRESH_MAX_ATTEMPTS = 3` the un-jittered waits are 100ms then 200ms,
/// well below typical request budgets.
const REFRESH_RETRY_BASE_DELAY: Duration = Duration::from_millis(100);

/// Maximum random jitter added on top of the exponential base. Decorrelates
/// retries across a fleet that all entered the refresh window at the same
/// moment so they don't synchronize their retransmits on a flapping AS.
const REFRESH_RETRY_JITTER_MAX: Duration = Duration::from_millis(50);

/// Wait before retry `attempt` (1-indexed): `base * 2^(attempt-1) + jitter`,
/// where jitter is uniform random in `[0, REFRESH_RETRY_JITTER_MAX)`.
///
/// `.min(16)` on the shift is paranoia against a future bump to
/// [`REFRESH_MAX_ATTEMPTS`]; with the current value of 3 it's never reached.
fn refresh_retry_delay(attempt: u32) -> Duration {
    let base = REFRESH_RETRY_BASE_DELAY * (1u32 << (attempt - 1).min(16));
    let jitter_max_ms = u64::try_from(REFRESH_RETRY_JITTER_MAX.as_millis()).unwrap_or(u64::MAX);
    let jitter_ms = rand::rng().random_range(0..jitter_max_ms);
    base + Duration::from_millis(jitter_ms)
}

/// Maximum tolerated clock skew when validating session timestamps.
///
/// A session whose `created_at` or `last_active` is more than this far ahead
/// of the server's wall clock is treated as corrupted and expired, rather
/// than silently bypassing the `max_lifetime` / `idle_timeout` checks.
///
/// Sized to absorb realistic NTP drift and short-lived clock jumps without
/// false-positives.
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

/// Browser fetch-metadata header names. Not in `http::header::*` constants, so
/// we materialize them once at first use rather than re-parsing on every request.
static SEC_FETCH_MODE: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("sec-fetch-mode"));
static SEC_FETCH_DEST: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("sec-fetch-dest"));
static X_REQUESTED_WITH: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("x-requested-with"));

/// Returns `true` for a CORS preflight (`OPTIONS` + `Access-Control-Request-Method`).
///
/// Framework adapters typically short-circuit these requests so they reach
/// the application's CORS layer without going through session handling or
/// auth gates.
pub fn is_cors_preflight(method: &Method, headers: &HeaderMap) -> bool {
    *method == Method::OPTIONS && headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
}

/// Returns `true` if this looks like a top-level browser navigation.
///
/// Uses a multi-layer detection algorithm:
///
/// 1. `X-Requested-With: XMLHttpRequest` — classic XHR signal, always
///    indicates a non-navigation request.
/// 2. `Sec-Fetch-Mode` — definitive in all modern browsers; only `navigate`
///    is a top-level navigation.
/// 3. `Sec-Fetch-Dest` — backup if `Sec-Fetch-Mode` is stripped by an
///    intermediary; only `document` is a page load.
/// 4. `Accept` header — fallback for older clients; the presence of
///    `text/html` or `application/xhtml+xml` usually means a page load.
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

    // Fallback for older clients.
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html") || v.contains("application/xhtml+xml"))
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
