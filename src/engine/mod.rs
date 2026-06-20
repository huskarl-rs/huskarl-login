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
/// Modelled as a sum type so the two response shapes the engine actually
/// produces can't be mixed up: a [`Redirect`](Self::Redirect) *always* carries
/// a `Location` (a 302 without one is unrepresentable), and a
/// [`Rendered`](Self::Rendered) response *always* carries its own status and
/// body. Framework adapters lower this into their native response type via
/// [`into_parts`](Self::into_parts) at the response boundary.
#[must_use]
pub enum LoginResponse {
    /// A `302 Found` redirect. The `Location` is typed, so the engine cannot
    /// emit a redirect without one. `set_cookies` are the session/login-state
    /// `Set-Cookie` values that ride along; the boundary also emits
    /// `Cache-Control: no-store`, since these redirects carry session-bearing
    /// cookies (RFC 6749 §5.1).
    Redirect {
        /// The `Location` to redirect to.
        location: HeaderValue,
        /// `Set-Cookie` values to emit alongside the redirect.
        set_cookies: Vec<HeaderValue>,
    },
    /// A response rendered with an explicit status, header set, and body —
    /// error pages, `401`, `403`, `405`, and `5xx`.
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
            Self::Redirect { .. } => StatusCode::FOUND,
            Self::Rendered { status, .. } => *status,
        }
    }

    /// Lowers this semantic response into concrete HTTP parts: status code,
    /// the full header list, and body. For a [`Redirect`](Self::Redirect) the
    /// `Location`, `Cache-Control: no-store`, and `Set-Cookie` headers are
    /// materialized here. Framework adapters call this at the response
    /// boundary; the typed variants guarantee the parts are always coherent
    /// (a redirect can never be lowered without a `Location`).
    #[must_use]
    pub fn into_parts(self) -> (StatusCode, Vec<(HeaderName, HeaderValue)>, Bytes) {
        match self {
            Self::Redirect {
                location,
                set_cookies,
            } => {
                let mut headers = Vec::with_capacity(set_cookies.len() + 2);
                headers.push((header::LOCATION, location));
                headers.push((header::CACHE_CONTROL, HeaderValue::from_static("no-store")));
                for c in set_cookies {
                    headers.push((header::SET_COOKIE, c));
                }
                (StatusCode::FOUND, headers, Bytes::new())
            }
            Self::Rendered {
                status,
                headers,
                body,
            } => (status, headers, body),
        }
    }

    /// The full header list this response is served with, materialized
    /// (cloning) — including a redirect's synthesized `Location`,
    /// `Cache-Control: no-store`, and `Set-Cookie`s. Convenience for
    /// inspection; the response boundary should prefer
    /// [`into_parts`](Self::into_parts), which avoids the clone.
    #[must_use]
    pub fn headers(&self) -> Vec<(HeaderName, HeaderValue)> {
        match self {
            Self::Redirect {
                location,
                set_cookies,
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

    /// Appends a header to a [`Rendered`](Self::Rendered) response. Used by the
    /// error-path builders, which always operate on `Rendered`; a no-op on
    /// `Redirect`, whose header set is fixed and materialized at the boundary.
    fn push_rendered_header(&mut self, name: HeaderName, value: HeaderValue) {
        if let Self::Rendered { headers, .. } = self {
            headers.push((name, value));
        }
    }
}

/// The result of [`LoginEngine::load_session`] — one variant per session
/// state the adapter can observe.
///
/// A *transient* refresh failure while the access token is still valid does
/// not clear the session — it surfaces as [`Active`](Self::Active) or
/// [`ActivePending`](Self::ActivePending) and the refresh is retried on a
/// later request.
///
/// This enum is deliberately **not** `#[non_exhaustive]`: an adapter must
/// handle every session state, so a future state should be a compile error
/// at every call site rather than fall through a wildcard arm.
#[must_use]
pub enum LoadedSession<S> {
    /// The request carried no session cookie.
    Missing,
    /// A session was presented but torn down — expired, or token refresh
    /// failed conclusively. `clears` must reach the final response to drop
    /// the now-stale session cookies.
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
        /// `Set-Cookie` headers that must reach the final response: the
        /// re-sealed session cookies when a token refresh was persisted
        /// eagerly, empty otherwise. When non-empty these carry a live session
        /// cookie, so the response they ride on must not be cached by shared
        /// caches — see [`load_session`](LoginEngine::load_session)'s *Response
        /// caching* note.
        set_cookies: Vec<HeaderValue>,
    },
    /// Authenticated, with a save owed after the inner handler responds —
    /// call [`LoginEngine::persist_session`].
    ///
    /// Only arises when the eager persist of a refreshed session failed; the
    /// post-response save (and its [`PersistFailurePolicy`]) is the retry.
    /// Never carries cookies: the save produces its cookies when it runs.
    ActivePending {
        /// The loaded session.
        session: S,
    },
}

impl<S> LoadedSession<S> {
    /// Convenience accessor: the session, when the request is authenticated.
    pub fn session(&self) -> Option<&S> {
        match self {
            Self::Missing | Self::Cleared { .. } => None,
            Self::Active { session, .. } | Self::ActivePending { session } => Some(session),
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
///
/// Carried on [`LoadedSession::Cleared`] and reported to
/// [`LoginEngineMetrics::record_teardown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum TeardownReason {
    /// [`LoginConfig::max_lifetime`](crate::LoginConfig::max_lifetime) exceeded.
    MaxLifetime,
    /// Idle timeout exceeded — the server-side liveness verdict was
    /// [`crate::LivenessVerdict::Expired`]. See
    /// [`LivenessConfig::idle_timeout`](crate::LivenessConfig::idle_timeout).
    IdleTimeout,
    /// Session timestamps too far in the future — corrupt or forged.
    ClockSkew,
    /// The authorization server conclusively rejected the refresh token
    /// (e.g. `invalid_grant`).
    RefreshRejected,
    /// Token refresh failed transiently, but the access token had already
    /// expired — there is nothing valid left to serve.
    RefreshUnavailable,
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

/// Decides how a framework adapter should react when the post-response save of
/// a refreshed session fails.
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
pub trait PersistFailurePolicy: MaybeSendSync + 'static {
    /// Decide what to do after a [`LoadedSession::ActivePending`] save failed.
    ///
    /// Returning `Some(response)` replaces the inner handler's response; `None`
    /// lets it pass through unchanged. `error` is the underlying store error;
    /// downcast it to [`SessionError`] to branch on
    /// [`kind`](SessionError::kind).
    fn handle(&self, error: &(dyn std::error::Error + 'static)) -> Option<LoginResponse>;
}

/// Default policy: fail closed when the refreshed-session save fails.
///
/// `ActivePending` only arises when the engine refreshed the access token but
/// the eager persist inside [`LoginEngine::load_session`] failed; if the
/// handler response is allowed through without persisting the new tokens the
/// client is stranded on stale state — and with refresh-token rotation, often
/// locked out entirely. Replacing the response forces a clean retry.
///
/// The replacement status is derived from the error's [`SessionErrorKind`] when
/// the error is a [`SessionError`]: a [`Conflict`](SessionErrorKind::Conflict)
/// becomes `409`, a genuine [`Crypto`](SessionErrorKind::Crypto) or
/// [`Store`](SessionErrorKind::Store) fault becomes `500`, and everything else
/// (transient [`Unavailable`](SessionErrorKind::Unavailable), `Gone`, or a
/// non-`SessionError` cause) falls back to `503`.
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
            headers: Vec::new(),
            body: Bytes::new(),
        })
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
    /// When the flow started. Lets the engine enforce
    /// [`LoginConfig::login_state_ttl`] server-side (the cookie's `Max-Age`
    /// only enforces it browser-side). Cookies sealed before this field
    /// existed decode as the epoch, which uniformly classifies them as
    /// expired — exactly the re-login behavior a format change is documented
    /// to produce.
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
/// Build one with `LoginEngine::builder()`; framework adapters compose its
/// primitives into middleware. See the [module documentation](self) for the
/// full set of primitives.
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
    /// The `grant` drives the OAuth flow itself — PAR, JAR, `DPoP`, PKCE, and
    /// state/nonce generation all follow the grant's own configuration, and
    /// the grant carries its own HTTP client.
    ///
    /// The `cipher` is used only for the short-lived login-state cookie (CSRF
    /// protection during the OAuth flow). Session persistence is handled
    /// entirely by the session store.
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
    /// If the request URI's path is the configured callback or logout path,
    /// returns the corresponding response. Otherwise returns `None` and the
    /// framework adapter should fall through to the next layer.
    ///
    /// The path is taken from `uri` — pass the same engine-side URI the
    /// request arrived with (including any front-proxy `strip_prefix`).
    ///
    /// The callback only accepts `GET` — the authorization server delivers the
    /// response as a query-string redirect (top-level navigation). Logout
    /// accepts only `POST` (submitted from a form): logout is state-changing,
    /// so restricting it to `POST` keeps it from being triggered by a `GET`
    /// the user never intended — a cross-site link, an `<img>` tag, a
    /// prefetch. Other methods on these paths get a `405 Method Not Allowed`
    /// with an `Allow` header rather than falling through, since the paths are
    /// reserved for the engine.
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

    /// Builds a `405 Method Not Allowed` response advertising the allowed
    /// methods (RFC 9110 §15.5.6 requires the `Allow` header).
    fn method_not_allowed(&self, allow: &'static str) -> LoginResponse {
        let mut resp =
            self.build_error_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
        resp.push_rendered_header(header::ALLOW, HeaderValue::from_static(allow));
        resp
    }

    /// Loads and validates the session from request cookies, refreshing
    /// the access token if it's near expiry.
    ///
    /// Never redirects or returns an error response — the framework adapter
    /// decides what to do when no session is present (a downstream gate may
    /// call [`redirect_to_login`](Self::redirect_to_login), or the request
    /// may simply proceed unauthenticated).
    ///
    /// # Eager persistence after refresh
    ///
    /// A successful token refresh is persisted *here*, before this method
    /// returns, rather than deferred to the adapter's post-response
    /// [`persist_session`](Self::persist_session) call — with refresh-token
    /// rotation, a deferred save that never runs (the adapter skips the
    /// persist phase, the connection drops, the handler panics) would strand
    /// the rotated token and lock the session out. The session is then
    /// returned as [`LoadedSession::Active`] with the re-sealed session
    /// cookies in its `set_cookies`. If the eager persist fails, the session
    /// is returned as [`LoadedSession::ActivePending`] so the post-response
    /// persist (and its [`PersistFailurePolicy`]) acts as the retry.
    ///
    /// # Concurrent refresh and refresh-token rotation
    ///
    /// Two in-flight requests — or two replicas in a distributed deployment —
    /// can enter the refresh window for the same session at once, and each
    /// will exchange the session's refresh token independently. When the
    /// authorization server rotates refresh tokens, the expected deployment
    /// shape is:
    ///
    /// - a **shared refresh-token cache** across replicas (implement
    ///   `huskarl::cache::TokenCache` / `RefreshTokenStore` over shared
    ///   storage) so concurrent refreshes converge on the rotated token
    ///   instead of racing each other, and
    /// - an authorization server configured with a **rotation grace period**,
    ///   so reuse of the just-rotated token inside the race window is honored
    ///   rather than treated as token theft (which would revoke the token
    ///   family and log the user out).
    ///
    /// The race window is the length of the read → exchange → save-back
    /// workflow. The save-back happens eagerly inside this method (see
    /// above), so the window is roughly the token-exchange round trip plus
    /// the store write — the inner handler's latency is not part of it.
    /// Only when the eager persist fails does the save-back fall to
    /// [`persist_session`](Self::persist_session) after the handler has
    /// responded.
    ///
    /// Without both, occasional concurrent refreshes will lose the race and
    /// surface as [`RefreshResult::Failed`] teardowns — most visibly with
    /// cookie sessions, where the refresh token lives in the cookie and the
    /// last writer wins.
    ///
    /// On infrastructure failure (e.g. the session store is unreachable) the
    /// underlying error is returned; the adapter typically maps that to a
    /// 5xx response.
    ///
    /// # Response caching
    ///
    /// A [`LoadedSession::Active`] returned after an eager refresh carries the
    /// re-sealed session cookies in its `set_cookies`, and the adapter attaches
    /// them to the **inner handler's** response — whose caching the engine does
    /// not control. The engine marks its *own* redirects and error pages
    /// `Cache-Control: no-store`, but a refreshed session cookie riding on a
    /// cacheable handler response could be stored by a shared cache and later
    /// replayed to a different user. Adapters MUST ensure any response carrying
    /// session `Set-Cookie` values — these, or those returned by
    /// [`persist_session`](Self::persist_session) — is non-cacheable
    /// (`Cache-Control: no-store`, or at minimum `private`). The same applies
    /// to the cookie clears on [`LoadedSession::Cleared`].
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the underlying session store fails to load
    /// the session (e.g. transport error against an external store).
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

    /// Returns the reason the session should be torn down rather than served
    /// — clock-skew corruption or absolute lifetime exceeded — or `None` when
    /// the session is still good by these absolute checks.
    ///
    /// Idle timeout is handled separately, server-side, via
    /// [`SessionDriver::check_liveness`]; it is not enforced here because
    /// `last_active` is no longer carried on the session.
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

    /// Token (or refresh window) elapsed — exchange the refresh token, or
    /// emit cookie clears if refresh is unavailable / fails.
    ///
    /// One failure mode is softened: a *transient* refresh failure while the
    /// access token is still valid (we entered the refresh window early)
    /// retains the session instead of tearing it down — a brief AS blip
    /// shouldn't log users out while their token still works. A later request
    /// re-enters the refresh window and retries. Conclusive failures (the AS
    /// rejected the refresh token, e.g. `invalid_grant`) and failures after
    /// actual token expiry still tear the session down.
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
                session.apply_refresh(&token_response, self.config.default_token_lifetime);
                self.record_refresh(&RefreshResult::Ok);
                // Persist eagerly rather than waiting for the adapter's
                // post-response phase: with refresh-token rotation, a later
                // phase that is skipped or fails would strand the rotated
                // token and lock the session out. On failure, fall back to
                // a pending `Save` so the adapter's persist step (and its
                // `PersistFailurePolicy`) gets a second attempt.
                match self.session_store.save(&session, headers).await {
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
                        LoadedSession::ActivePending { session }
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
            Err(e) => {
                log::error!("token refresh failed: {}", error_chain(&e));
                let reason = if e.is_retryable() {
                    TeardownReason::RefreshUnavailable
                } else {
                    TeardownReason::RefreshRejected
                };
                let clears = self.delete_best_effort(&session, headers).await;
                self.record_refresh(&RefreshResult::Failed);
                self.record_teardown(reason);
                LoadedSession::Cleared { reason, clears }
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
                log::error!("failed to delete session: {}", error_chain(&e));
                vec![]
            }
        }
    }

    /// Exchanges the refresh token up to [`REFRESH_MAX_ATTEMPTS`] times,
    /// retrying only when the underlying error advertises itself as retryable
    /// (transient transport failures). Non-retryable errors (e.g.
    /// `invalid_grant` from the authorization server) are returned immediately
    /// so we don't waste calls — or risk tripping AS-side rate limiting — on a
    /// refresh token the AS has already rejected.
    ///
    /// Retries use exponential backoff with jitter ([`refresh_retry_delay`]) so
    /// a brief AS outage doesn't produce a synchronized thundering herd when
    /// every in-flight refresh retries at the same moment.
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

    /// Saves the session owed by a [`LoadedSession::ActivePending`]
    /// after the inner service has responded.
    ///
    /// Returns `Set-Cookie` header values to append to the response.
    ///
    /// `request_headers` are the cookies the browser sent on the original
    /// request — cookie-backed session stores use them to clear any stale
    /// chunked-cookie slots that the new session no longer occupies.
    ///
    /// The returned `Set-Cookie` values may carry a re-sealed session cookie,
    /// so the response they attach to must not be cached by shared caches — see
    /// [`load_session`](Self::load_session)'s *Response caching* note.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the underlying session store fails to write
    /// the session (e.g. transport error against an external store).
    pub async fn persist_session(
        &self,
        session: &SD::SessionType,
        request_headers: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.session_store.save(session, request_headers).await
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

    /// Saves a session, returning `Set-Cookie` header values — an explicit,
    /// unconditional save (e.g. after the application mutated the session), as
    /// opposed to the deferred [`persist_session`](Self::persist_session) owed by
    /// a [`LoadedSession::ActivePending`].
    ///
    /// See [`persist_session`](Self::persist_session) for the role of
    /// `request_headers`. As there, the returned values may carry a re-sealed
    /// session cookie, so the response must not be cached by shared caches — see
    /// [`load_session`](Self::load_session)'s *Response caching* note.
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
/// A session whose `created_at` is more than this far ahead of the server's
/// wall clock is treated as corrupted and expired, rather than silently
/// bypassing the `max_lifetime` check.
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
static SEC_FETCH_SITE: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("sec-fetch-site"));
static SEC_FETCH_USER: LazyLock<HeaderName> =
    LazyLock::new(|| HeaderName::from_static("sec-fetch-user"));
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
/// 4. `Sec-Fetch-User` — affirmative signal sent only on user-activated
///    top-level navigations (always `?1`); a precise last-ditch rescue for a
///    navigation whose `Sec-Fetch-Mode`/`Sec-Fetch-Dest` were stripped, before
///    falling through to the weaker `Accept` heuristic.
/// 5. `Accept` header — fallback for older clients; the presence of
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

/// Returns `true` when fetch metadata identifies the request as cross-site.
///
/// Session cookies are `SameSite=Lax`, so they accompany cross-site top-level
/// navigations — any page on the web can steer a user's browser at a
/// state-changing endpoint (e.g. the logout path) with their session attached.
/// All modern browsers send `Sec-Fetch-Site` on every request; rejecting
/// `cross-site` blocks that forgery. Requests without the header (older
/// clients, non-browser agents, direct navigation) are not considered
/// cross-site.
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
