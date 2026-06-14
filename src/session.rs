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

use std::sync::Arc;

use http::HeaderValue;
use huskarl::core::{
    crypto::cipher::AeadCipher,
    platform::{MaybeSend, MaybeSendSync, SystemTime},
};

use crate::{completed_login::CompletedLogin, liveness::LivenessVerdict, session_state::Session};

/// A boxed standard error type used by session store methods.
///
/// On non-WASM platforms this is `Box<dyn Error + Send + Sync>`; on WASM
/// (assumed single-threaded) the `Send + Sync` requirement is dropped,
/// mirroring `huskarl::core::platform`'s `MaybeSendSync`. Marker traits can't
/// appear in trait objects, so the split is spelled out per platform.
#[cfg(not(target_arch = "wasm32"))]
pub type SessionError = Box<dyn std::error::Error + Send + Sync>;
/// A boxed standard error type used by session store methods.
///
/// On non-WASM platforms this is `Box<dyn Error + Send + Sync>`; on WASM
/// (assumed single-threaded) the `Send + Sync` requirement is dropped,
/// mirroring `huskarl::core::platform`'s `MaybeSendSync`. Marker traits can't
/// appear in trait objects, so the split is spelled out per platform.
#[cfg(target_arch = "wasm32")]
pub type SessionError = Box<dyn std::error::Error>;

pub(crate) fn to_session_err(e: impl std::error::Error + MaybeSendSync + 'static) -> SessionError {
    Box::new(e)
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
