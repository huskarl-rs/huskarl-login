//! Session persistence boundary used by the login engine.
//!
//! [`SessionDriver`] is sealed and implemented by the two built-in drivers.
//! Applications choose a driver rather than implementing this trait directly;
//! implement [`ExternalSessionStore`](crate::ExternalSessionStore) to add a
//! server-side backend.

use std::{fmt, sync::Arc};

use http::HeaderValue;

use crate::{
    ConfigError, RoutePath,
    client::grant::core::TokenResponse,
    completed_login::CompletedLogin,
    core::{
        crypto::seal::AeadSealerUnsealer,
        platform::{MaybeSend, MaybeSendSync, SystemTime},
    },
    liveness::LivenessVerdict,
    session_state::Session,
};

/// Engine-derived policy applied to a session driver at construction.
///
/// The engine is the only constructor. Keeping the route and cookie policy in
/// one value lets a driver validate that its cookie is visible on every route
/// which must observe or clear it.
#[derive(Debug, Clone)]
pub struct SessionPolicy {
    secure: bool,
    max_lifetime: Option<std::time::Duration>,
    metrics_name: Option<String>,
    browser_callback_path: RoutePath,
    browser_logout_path: Option<RoutePath>,
}

/// Result of inspecting request cookies for a session.
///
/// `Absent` means no session-shaped cookie was presented. `Invalid` means the
/// browser did present session state, but it cannot authenticate and should be
/// cleared rather than treated as anonymous indefinitely.
#[derive(Debug)]
pub enum DriverLoad<S> {
    /// No session cookie was presented.
    Absent,
    /// A valid session was loaded.
    Valid(S),
    /// Session-shaped browser state was present but unusable.
    Invalid(InvalidSessionReason),
}

impl<S> DriverLoad<S> {
    /// Test helper for extracting a valid session after the classification was
    /// already asserted. Production code must match all variants explicitly.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn into_valid(self) -> Option<S> {
        match self {
            Self::Valid(session) => Some(session),
            Self::Absent | Self::Invalid(_) => None,
        }
    }
}

/// Why presented browser session state could not be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum InvalidSessionReason {
    /// Cookie chunks were missing or non-contiguous.
    IncompleteChunks,
    /// A cookie value was not valid base64url.
    BadEncoding,
    /// The sealed cookie could not be authenticated or decrypted.
    DecryptionFailed,
    /// The decrypted payload had the wrong shape.
    InvalidPayload,
    /// A valid store pointer referenced no session record.
    SessionNotFound,
}

impl InvalidSessionReason {
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

impl SessionPolicy {
    pub(crate) fn new(
        secure: bool,
        max_lifetime: Option<std::time::Duration>,
        metrics_name: Option<&str>,
        browser_callback_path: RoutePath,
        browser_logout_path: Option<RoutePath>,
    ) -> Self {
        Self {
            secure,
            max_lifetime,
            metrics_name: metrics_name.map(str::to_owned),
            browser_callback_path,
            browser_logout_path,
        }
    }

    pub(crate) fn secure(&self) -> bool {
        self.secure
    }

    pub(crate) fn max_lifetime(&self) -> Option<std::time::Duration> {
        self.max_lifetime
    }

    pub(crate) fn metrics_name(&self) -> Option<&str> {
        self.metrics_name.as_deref()
    }

    fn validate_cookie_path_for_route(
        cookie_path: &RoutePath,
        route: &'static str,
        route_path: &RoutePath,
    ) -> Result<(), ConfigError> {
        cookie_path
            .strip_from(route_path.as_str())
            .is_some()
            .then_some(())
            .ok_or_else(|| ConfigError::InvalidSessionCookiePath {
                path: cookie_path.as_str().to_owned(),
                route,
                route_path: route_path.as_str().to_owned(),
            })
    }

    pub(crate) fn validate_callback_cookie_path(
        &self,
        cookie_path: &RoutePath,
    ) -> Result<(), ConfigError> {
        Self::validate_cookie_path_for_route(cookie_path, "callback", &self.browser_callback_path)
    }

    pub(crate) fn validate_logout_cookie_path(
        &self,
        cookie_path: &RoutePath,
    ) -> Result<(), ConfigError> {
        if let Some(logout_path) = &self.browser_logout_path {
            Self::validate_cookie_path_for_route(cookie_path, "logout", logout_path)?;
        }
        Ok(())
    }
}

/// A type-erased session-error cause (`Send + Sync` except on WASM).
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedSource = Box<dyn std::error::Error + Send + Sync + 'static>;
/// A type-erased session-error cause (`Send + Sync` except on WASM).
#[cfg(target_arch = "wasm32")]
pub type BoxedSource = Box<dyn std::error::Error + 'static>;

/// A request-time session-store failure.
///
/// Handle it through [`kind`](Self::kind) and [`is_retryable`](Self::is_retryable).
#[derive(Debug)]
pub struct SessionError {
    kind: SessionErrorKind,
    context: Option<String>,
    source: Option<BoxedSource>,
}

/// Classification of a [`SessionError`]. Match with a wildcard arm.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionErrorKind {
    /// The backing store is unreachable or failed transiently. This is the
    /// only [retryable](SessionError::is_retryable) kind.
    Unavailable,
    /// A compare-and-swap retry budget was exhausted under concurrent rewrites.
    Conflict,
    /// The session was deleted or expired between load and update.
    Gone,
    /// A cookie seal/unseal or other cryptographic operation failed.
    Crypto,
    /// A value could not be encoded into its cookie or header representation
    /// (serialization failure, invalid header bytes, or an oversized session).
    Encoding,
    /// The store violated its contract (deserialize failure, invalid header, etc.).
    Store,
}

impl SessionError {
    /// Create an error of the given kind caused by `source`.
    pub fn new(kind: SessionErrorKind, source: impl Into<BoxedSource>) -> Self {
        Self {
            kind,
            context: None,
            source: Some(source.into()),
        }
    }

    /// The classification of this error.
    #[must_use]
    pub fn kind(&self) -> SessionErrorKind {
        self.kind
    }

    /// Whether the failure is transient and may succeed on retry.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self.kind, SessionErrorKind::Unavailable)
    }

    /// Attach human-readable context, shown as a prefix in `Display` (layers outermost-first).
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(match self.context {
            Some(existing) => format!("{}: {existing}", context.into()),
            None => context.into(),
        });
        self
    }
}

impl From<SessionErrorKind> for SessionError {
    fn from(kind: SessionErrorKind) -> Self {
        Self {
            kind,
            context: None,
            source: None,
        }
    }
}

impl From<crate::core::Error> for SessionError {
    /// Carry a huskarl error as a session error, preserving its retryability.
    fn from(err: crate::core::Error) -> Self {
        let kind = if advises_retry(&err) {
            SessionErrorKind::Unavailable
        } else {
            SessionErrorKind::Store
        };
        Self::new(kind, err)
    }
}

/// Whether a huskarl error advises retrying the failed operation.
///
/// [`RetryAdvice`](crate::core::RetryAdvice) is `#[non_exhaustive]`; an unknown
/// variant is treated conservatively, like `No`.
pub(crate) fn advises_retry(err: &crate::core::Error) -> bool {
    matches!(err.retry_advice(), crate::core::RetryAdvice::Retry { .. })
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(context) = &self.context {
            write!(f, "{context}: ")?;
        }
        self.kind.fmt(f)
    }
}

impl fmt::Display for SessionErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "session store unavailable",
            Self::Conflict => "session update conflict",
            Self::Gone => "session no longer exists",
            Self::Crypto => "session cryptographic operation failed",
            Self::Encoding => "session could not be encoded for cookies or headers",
            Self::Store => "session store failure",
        })
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// Box a store's own error as an [`Unavailable`](SessionErrorKind::Unavailable) session error.
pub(crate) fn to_session_err(e: impl std::error::Error + MaybeSendSync + 'static) -> SessionError {
    SessionError::new(SessionErrorKind::Unavailable, e)
}

/// Sealed trait marker module.
#[doc(hidden)]
pub mod sealed {
    pub trait Sealed {}
}

/// Engine-facing persistence interface implemented by the built-in stores.
///
/// This trait is sealed. Choose [`CookieSessionStore`](crate::CookieSessionStore)
/// for browser-held sessions or
/// [`StoreBackedSessionStore`](crate::StoreBackedSessionStore) with a custom
/// [`ExternalSessionStore`](crate::ExternalSessionStore) for server-held
/// sessions. Framework adapters normally use [`LoginEngine`](crate::engine::LoginEngine)
/// rather than calling driver methods directly.
pub trait SessionDriver: sealed::Sealed + MaybeSendSync {
    /// The session type stored and retrieved by this driver.
    ///
    /// `Clone` because
    /// [`PendingPersist::commit`](crate::engine::PendingPersist::commit)
    /// persists from a clone.
    type SessionType: Session + Clone + MaybeSendSync + 'static;

    /// The error type returned by [`load`](Self::load).
    type LoadError: std::error::Error + MaybeSendSync + 'static;

    /// Stamp the engine-derived session policy onto this driver. Called once
    /// at engine construction, so the values cannot drift from the config:
    /// `secure` (from the `base_url` scheme) fixes `__Host-`/`__Secure-`
    /// naming and the `Secure` attribute; `max_lifetime` (the
    /// [`SessionLifetime::Bounded`](crate::SessionLifetime) cap, `None` when
    /// delegated) clamps the cookie `Max-Age`, so no session cookie outlives
    /// the session cap; `metrics_name` becomes the `name` label on every
    /// counter the driver emits (`None` omits it).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the driver's cookie scope cannot cover a
    /// browser route that must receive or clear the session cookie.
    fn apply_session_policy(&mut self, policy: &SessionPolicy) -> Result<(), ConfigError>;

    /// The sealer this driver seals session data with (AAD-domain-separated
    /// from the login-state seal, so the underlying key may be shared).
    fn session_sealer(&self) -> Arc<dyn AeadSealerUnsealer>;

    /// Create and persist a new session from a completed login, returning it
    /// with the `Set-Cookie` values for the callback response.
    ///
    /// `default_lifetime` is the assumed access-token lifetime when the token
    /// response omits `expires_in`. `headers` carries request cookies so the
    /// driver can clean up what the new login supersedes: cookie stores clear
    /// stale session chunks, store-backed stores delete the record a
    /// still-valid pointer cookie references.
    fn create(
        &self,
        completed: CompletedLogin,
        default_lifetime: std::time::Duration,
        headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<(Self::SessionType, Vec<HeaderValue>), SessionError>> + MaybeSend;

    /// Inspect and load a session from the request's cookie headers.
    fn load(
        &self,
        headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<DriverLoad<Self::SessionType>, Self::LoadError>> + MaybeSend;

    /// Persist updated session state, returning any `Set-Cookie` header values
    /// (re-encrypted cookies plus `Max-Age=0` clears for now-unused chunks; none
    /// for store-backed sessions whose pointer cookie is unchanged).
    ///
    /// This is a whole-session write. The store-backed driver checks the
    /// refresh revision, refresh token, and expiry against stored state and
    /// commits through CAS, rejecting mismatches with
    /// [`SessionErrorKind::Conflict`]. Expiry is compared at serialized
    /// whole-second precision and the stored value is preserved. Application
    /// fields remain last-writer-wins within a refresh generation. The
    /// engine's refresh persist goes through
    /// [`apply_refresh_and_save`](Self::apply_refresh_and_save) instead, so it
    /// never overwrites a concurrent
    /// [`update`](crate::StoreBackedSessionStore::update).
    /// An uncontended store-backed save makes two backend calls: a load and
    /// a compare-and-swap. A CAS conflict repeats both calls and all refresh
    /// state checks, up to the driver's retry budget. A refresh-state mismatch
    /// returns `Conflict` without writing. Use
    /// [`StoreBackedSessionStore::update`](crate::StoreBackedSessionStore::update)
    /// for merge-safe application changes;
    /// application updates must preserve refresh fields and the revision.
    /// Direct backend writes bypass these checks.
    ///
    /// A changed refresh token or expiry from `ActivePending` is rejected even
    /// if the revision matches. Use
    /// [`PendingPersist::commit`](crate::engine::PendingPersist::commit).
    fn save(
        &self,
        session: &Self::SessionType,
        headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<Vec<HeaderValue>, SessionError>> + MaybeSend;

    /// Apply a token-refresh response to `session` (via
    /// [`Session::apply_refresh`]) and persist the result, returning any
    /// `Set-Cookie` header values.
    ///
    /// The default implementation mutates `session` and calls
    /// [`save`](Self::save) — correct for cookie sessions, which are inherently
    /// last-writer-wins in the browser. [`StoreBackedSessionStore`] overrides
    /// this to commit the refresh as a replayable mutation through
    /// compare-and-swap, so a concurrent
    /// [`update`](crate::StoreBackedSessionStore::update) is merged rather than
    /// silently overwritten; on success `session` is replaced with the
    /// committed (merged) session. `expected_refresh_revision` is captured
    /// before the token exchange and must be reused for any deferred retry.
    /// The store-backed driver discards the response if another refresh has
    /// advanced the revision, returning the current stored session instead.
    ///
    /// On error the refresh has been applied to `session` in memory; persistence
    /// may have failed or its acknowledgement may have been lost. Retry with
    /// the original expected revision (see
    /// [`LoadedSession::ActivePending`](crate::engine::LoadedSession::ActivePending)).
    ///
    /// [`StoreBackedSessionStore`]: crate::StoreBackedSessionStore
    fn apply_refresh_and_save(
        &self,
        session: &mut Self::SessionType,
        token_response: &TokenResponse,
        _expected_refresh_revision: u64,
        default_lifetime: std::time::Duration,
        headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<Vec<HeaderValue>, SessionError>> + MaybeSend {
        async move {
            session.apply_refresh(token_response, default_lifetime);
            self.save(session, headers).await
        }
    }

    /// Evaluate session liveness, recording activity when `record_activity` is set.
    ///
    /// Server-side only; defaults to [`LivenessVerdict::Untracked`]. Stores with
    /// a [`LivenessStore`](crate::LivenessStore) override this, failing open.
    /// `expire_at` is the session's absolute deadline, if any.
    fn check_liveness(
        &self,
        _session: &Self::SessionType,
        _now: SystemTime,
        _record_activity: bool,
        _expire_at: Option<SystemTime>,
    ) -> impl Future<Output = Result<LivenessVerdict, SessionError>> + MaybeSend {
        async { Ok(LivenessVerdict::Untracked) }
    }

    /// Builds `Set-Cookie` values that invalidate this driver's session
    /// cookies in the current browser, without loading or deleting server-side
    /// state.
    ///
    /// Logout emits these clears even when a backing store is unavailable, so
    /// browser-local logout does not depend on server-side revocation. For a
    /// store-backed session, copied pointer cookies remain usable until the
    /// backing record is deleted or expires.
    fn clear_session_cookies(&self, headers: &http::HeaderMap) -> Vec<HeaderValue>;

    /// Removes this driver's browser credentials from request `Cookie`
    /// headers while preserving unrelated application cookies.
    ///
    /// Reverse proxies call this before forwarding a request upstream so the
    /// replayable session credential remains at the authentication boundary.
    /// Implementations own the exact cookie-name knowledge, including chunked
    /// cookies and key-id sidecars.
    fn strip_session_credentials(&self, headers: &mut http::HeaderMap);

    /// Revoke a session's authoritative state.
    ///
    /// Browser clearing is deliberately separate through
    /// [`clear_session_cookies`](Self::clear_session_cookies), so a backend
    /// failure can never prevent local logout. Cookie-backed sessions have no
    /// authoritative server state and implement this as a no-op.
    fn revoke(
        &self,
        session: &Self::SessionType,
    ) -> impl Future<Output = Result<(), SessionError>> + MaybeSend;
}
