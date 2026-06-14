//! Sealed session driver trait.
//!
//! [`SessionDriver`] abstracts session persistence so that the login middleware
//! can work with any session backend. The trait is **sealed** — pick from the
//! built-in implementations ([`CookieSessionStore`](crate::CookieSessionStore)
//! or [`StoreBackedSessionStore`](crate::StoreBackedSessionStore)) or provide
//! custom persistence via [`ExternalSessionStore`](crate::ExternalSessionStore).
//!
//! Methods that modify session state return `Vec<HeaderValue>` of Set-Cookie
//! values. Framework integrations append them to the HTTP response.

use std::{fmt, sync::Arc};

use http::HeaderValue;
use huskarl::core::{
    crypto::cipher::AeadCipher,
    platform::{MaybeSend, MaybeSendSync, SystemTime},
};

use crate::{completed_login::CompletedLogin, liveness::LivenessVerdict, session_state::Session};

/// A type-erased session-error cause.
///
/// `Send + Sync` except on WASM (assumed single-threaded), mirroring
/// `huskarl::core::platform`'s `MaybeSendSync` and `huskarl::core::BoxedSource`.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedSource = Box<dyn std::error::Error + Send + Sync + 'static>;
/// A type-erased session-error cause.
///
/// `Send + Sync` except on WASM (assumed single-threaded), mirroring
/// `huskarl::core::platform`'s `MaybeSendSync` and `huskarl::core::BoxedSource`.
#[cfg(target_arch = "wasm32")]
pub type BoxedSource = Box<dyn std::error::Error + 'static>;

/// A request-time session-store failure.
///
/// Follows the same model as [`huskarl::core::Error`]: one non-generic struct
/// carrying a matchable [`SessionErrorKind`], optional context, and a
/// type-erased cause. Programmatic handling goes through [`kind`](Self::kind)
/// and [`is_retryable`](Self::is_retryable) — they are the stable contract;
/// downcasting the [`source`](std::error::Error::source) is not supported API.
#[derive(Debug)]
pub struct SessionError {
    kind: SessionErrorKind,
    context: Option<String>,
    source: Option<BoxedSource>,
}

/// Classification of a [`SessionError`].
///
/// Marked `#[non_exhaustive]`: match with a wildcard arm. The kinds map onto
/// the dispositions an adapter cares about — retry (`Unavailable`), conflict
/// (`Conflict`), gone (`Gone`), or a genuine fault (`Crypto`/`Store`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionErrorKind {
    /// The backing store is unreachable or failed transiently; retrying the
    /// same operation may succeed. The only [retryable](SessionError::is_retryable)
    /// kind. Adapters typically map this to `503 Service Unavailable`.
    Unavailable,
    /// A compare-and-swap retry budget was exhausted: the session was
    /// concurrently rewritten on every attempt. Adapters typically map this to
    /// `409 Conflict`.
    Conflict,
    /// The session vanished mid-operation (deleted or expired between load and
    /// update). The engine treats this like a missing session — re-authentication.
    Gone,
    /// A cookie seal/unseal or other cryptographic operation failed. A genuine
    /// fault, not retryable; adapters typically map this to `500`.
    Crypto,
    /// The store violated its contract: a deserialize failure, an invalid
    /// header value, or other unexpected shape. A genuine fault, not retryable;
    /// adapters typically map this to `500`.
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

    /// If true, the failure is transient and the same operation may succeed if
    /// re-attempted. Only [`SessionErrorKind::Unavailable`] is retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self.kind, SessionErrorKind::Unavailable)
    }

    /// Attach human-readable context about the failed operation. Shown as a
    /// prefix in the `Display` output; layers outermost-first like
    /// [`huskarl::core::Error::with_context`].
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

impl From<huskarl::core::Error> for SessionError {
    /// Carry a huskarl error (e.g. from a `UserInfo` call inside an enricher)
    /// as a session error, preserving its retryability and concrete cause.
    fn from(err: huskarl::core::Error) -> Self {
        let kind = if err.is_retryable() {
            SessionErrorKind::Unavailable
        } else {
            SessionErrorKind::Store
        };
        Self::new(kind, err)
    }
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

/// Box a store's own error as an [`Unavailable`](SessionErrorKind::Unavailable)
/// session error — the default classification for an opaque backing-store
/// failure, which is far more often transient (network, timeout) than a
/// permanent fault. Framework sites that *know* the failure is a conflict,
/// gone, or crypto/store fault construct [`SessionError::new`] with the precise
/// kind instead.
pub(crate) fn to_session_err(e: impl std::error::Error + MaybeSendSync + 'static) -> SessionError {
    SessionError::new(SessionErrorKind::Unavailable, e)
}

/// Sealed trait marker module.
///
/// This module is `#[doc(hidden)]` public so that downstream crates can
/// implement sealed traits for testing purposes.
#[doc(hidden)]
pub mod sealed {
    pub trait Sealed {}
}

/// Session driver trait implemented by the built-in session stores.
///
/// This trait is **sealed** — it cannot be implemented outside this crate.
/// Users pick a session mode by constructing either a
/// [`CookieSessionStore`](crate::CookieSessionStore) or a
/// [`StoreBackedSessionStore`](crate::StoreBackedSessionStore).
///
/// To provide custom session persistence, implement
/// [`ExternalSessionStore`](crate::ExternalSessionStore) and wrap it in a
/// [`StoreBackedSessionStore`](crate::StoreBackedSessionStore).
///
/// Methods that modify session state return `Vec<HeaderValue>` containing
/// `Set-Cookie` values. The middleware appends these to the HTTP response.
pub trait SessionDriver: sealed::Sealed + MaybeSendSync {
    /// The session type stored and retrieved by this driver.
    type SessionType: Session + MaybeSendSync + 'static;

    /// The error type returned by [`load`](Self::load).
    type LoadError: std::error::Error + MaybeSendSync + 'static;

    /// Stamp the deployment's cookie-security policy onto this driver.
    ///
    /// Called once by [`LoginEngine`](crate::engine::LoginEngine) at
    /// construction, with the value derived from
    /// [`LoginConfig::base_url`](crate::LoginConfig::base_url) (`true` for an
    /// `https` scheme). The built-in cookie stores use it to finalize their
    /// session-cookie naming (`__Host-`/`__Secure-` prefix) and the `Secure`
    /// attribute, so the session cookies match the login-state cookies the
    /// engine issues — there is no separate `secure` knob to keep in sync.
    ///
    /// Sealed: implemented only by this crate's built-in stores.
    fn apply_cookie_secure(&mut self, secure: bool);

    /// The AEAD cipher this driver seals session data with.
    ///
    /// Every session driver seals with AEAD — cookie stores seal the session
    /// itself, store-backed stores seal the pointer cookie — so this is a hard
    /// requirement, not an optional capability.
    ///
    /// Exposed so convenience layers (e.g. `huskarl-axum`'s `LoginLayer`) can
    /// default the engine's *separate* login-state cipher to the same key when
    /// a deployment only wants one. The two seals are AAD-domain-separated
    /// (`b"session"` / `b"session_ptr"` vs the OAuth `state`), so sharing a key
    /// is safe; a deployment that wants distinct keys — e.g. a KMS-backed
    /// login-state key and a local per-request session key — passes the
    /// login-state cipher to the engine explicitly instead.
    fn session_aead_cipher(&self) -> Arc<dyn AeadCipher>;

    /// Create a new session from a completed login.
    ///
    /// The driver's attached [`SessionEnricher`](crate::SessionEnricher)
    /// builds the session from the framework-prepared seed, then the driver
    /// persists it via its backing store (cookie or external) and returns
    /// both the session and the `Set-Cookie` header values the framework
    /// should attach to the callback response (the session cookies for
    /// cookie-backed stores, the pointer cookie for store-backed sessions).
    ///
    /// `default_lifetime` is the assumed access-token lifetime when the
    /// authorization server's token response omits `expires_in`.
    ///
    /// `headers` carries the request's cookies so cookie-backed stores can
    /// clear any stale session chunks left over from a previous flow.
    fn create(
        &self,
        completed: CompletedLogin,
        default_lifetime: std::time::Duration,
        headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<(Self::SessionType, Vec<HeaderValue>), SessionError>> + MaybeSend;

    /// Load a session from the request's cookie headers.
    fn load(
        &self,
        headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<Option<Self::SessionType>, Self::LoadError>> + MaybeSend;

    /// Persist updated session state, returning any `Set-Cookie` header values.
    ///
    /// Called after a token refresh changes session data. Stores whose data
    /// sink is the cookie return the (re-encrypted) session cookies; stores
    /// whose data sink is external return no cookies because the pointer
    /// cookie's value is unchanged.
    ///
    /// `headers` are the request headers; cookie-backed stores enumerate the
    /// chunked session cookies the browser sent so they can emit `Max-Age=0`
    /// clears for any slots the new payload no longer uses.
    fn save(
        &self,
        session: &Self::SessionType,
        headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<Vec<HeaderValue>, SessionError>> + MaybeSend;

    /// Evaluate session liveness for this request, recording the activity as a
    /// side effect when `record_activity` is set.
    ///
    /// Liveness is **server-side only**, so the default implementation returns
    /// [`LivenessVerdict::Untracked`] — cookie sessions and store-backed
    /// sessions without a [`LivenessStore`](crate::LivenessStore) neither
    /// enforce an idle timeout nor record activity. `StoreBackedSessionStore`
    /// overrides this when liveness is configured: it reads `last_active` and
    /// returns the [`LivenessConfig`](crate::LivenessConfig) idle verdict
    /// (always, so idle expiry is enforced on every request), and — only when
    /// `record_activity` is `true` and the session is live — records activity
    /// via the store's (throttled) `touch`, best-effort. It fails open: a read
    /// error or missing entry yields [`LivenessVerdict::Active`], so a liveness
    /// outage never tears sessions down. The engine acts only on
    /// [`LivenessVerdict::Expired`].
    ///
    /// `record_activity` is the engine's per-request
    /// [`ActivityPolicy`](crate::ActivityPolicy) classification — e.g. a
    /// cross-site embed or background poll may be excluded so it doesn't keep an
    /// abandoned session alive.
    ///
    /// `expire_at` is the session's absolute deadline (`created_at +
    /// max_lifetime`, or `None` when unbounded), passed through to the liveness
    /// store so its entry expires exactly when the session can no longer be
    /// valid.
    fn check_liveness(
        &self,
        _session: &Self::SessionType,
        _now: SystemTime,
        _record_activity: bool,
        _expire_at: Option<SystemTime>,
    ) -> impl Future<Output = Result<LivenessVerdict, SessionError>> + MaybeSend {
        async { Ok(LivenessVerdict::Untracked) }
    }

    /// Delete a session, returning `Set-Cookie` header values that clear
    /// the session cookies.
    ///
    /// `headers` lets cookie-backed stores emit clears only for the chunked
    /// cookies the browser actually has, rather than a fixed-size sweep.
    fn delete(
        &self,
        session: &Self::SessionType,
        headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<Vec<HeaderValue>, SessionError>> + MaybeSend;
}
