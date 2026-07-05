//! Sealed [`SessionDriver`] trait abstracting session persistence.

use std::{fmt, sync::Arc};

use http::HeaderValue;
use huskarl::{
    core::{
        crypto::cipher::AeadCipher,
        platform::{MaybeSend, MaybeSendSync, SystemTime},
    },
    grant::core::TokenResponse,
};

use crate::{completed_login::CompletedLogin, liveness::LivenessVerdict, session_state::Session};

/// A type-erased session-error cause (`Send + Sync` except on WASM).
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedSource = Box<dyn std::error::Error + Send + Sync + 'static>;
/// A type-erased session-error cause (`Send + Sync` except on WASM).
#[cfg(target_arch = "wasm32")]
pub type BoxedSource = Box<dyn std::error::Error + 'static>;

/// A request-time session-store failure; handle via [`kind`](Self::kind) and [`is_retryable`](Self::is_retryable).
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
    /// The backing store is unreachable or failed transiently. The only [retryable](SessionError::is_retryable) kind.
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

impl From<huskarl::core::Error> for SessionError {
    /// Carry a huskarl error as a session error, preserving its retryability.
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

/// Session driver trait implemented by the built-in session stores.
///
/// Sealed: implemented only by [`CookieSessionStore`](crate::CookieSessionStore)
/// and [`StoreBackedSessionStore`](crate::StoreBackedSessionStore) (the latter
/// wrapping a custom [`ExternalSessionStore`](crate::ExternalSessionStore)).
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
    /// the session cap.
    fn apply_session_policy(&mut self, secure: bool, max_lifetime: Option<std::time::Duration>);

    /// The AEAD cipher this driver seals session data with (AAD-domain-separated
    /// from the login-state seal, so the key may be shared).
    fn session_aead_cipher(&self) -> Arc<dyn AeadCipher>;

    /// Create and persist a new session from a completed login, returning it
    /// with the `Set-Cookie` values for the callback response.
    ///
    /// `default_lifetime` is the assumed access-token lifetime when the token
    /// response omits `expires_in`. `headers` carries request cookies so cookie
    /// stores can clear stale session chunks.
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

    /// Persist updated session state, returning any `Set-Cookie` header values
    /// (re-encrypted cookies plus `Max-Age=0` clears for now-unused chunks; none
    /// for store-backed sessions whose pointer cookie is unchanged).
    ///
    /// This is an unconditional whole-session write (last-writer-wins). The
    /// engine's refresh persist goes through
    /// [`apply_refresh_and_save`](Self::apply_refresh_and_save) instead, so it
    /// never overwrites a concurrent
    /// [`update`](crate::StoreBackedSessionStore::update).
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
    /// committed (merged) session.
    ///
    /// On error the refresh has been applied to `session` in memory but not
    /// persisted — the save is owed (see
    /// [`LoadedSession::ActivePending`](crate::engine::LoadedSession::ActivePending)).
    ///
    /// [`StoreBackedSessionStore`]: crate::StoreBackedSessionStore
    fn apply_refresh_and_save(
        &self,
        session: &mut Self::SessionType,
        token_response: &TokenResponse,
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

    /// Delete a session, returning `Set-Cookie` values that clear its cookies
    /// (only those present in `headers`).
    fn delete(
        &self,
        session: &Self::SessionType,
        headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<Vec<HeaderValue>, SessionError>> + MaybeSend;
}
