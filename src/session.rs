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

use http::HeaderValue;

use crate::{grant::CompletedLogin, session_state::Session};

/// A boxed standard error type used by session store methods.
pub type SessionError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) fn to_session_err(e: impl std::error::Error + Send + Sync + 'static) -> SessionError {
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
pub trait SessionDriver: sealed::Sealed + Send + Sync {
    /// The session type stored and retrieved by this driver.
    type SessionType: Session + Send + Sync + 'static;

    /// The error type returned by [`load`](Self::load).
    type LoadError: std::error::Error + Send + Sync + 'static;

    /// Create a new session from a completed login.
    ///
    /// Persists the session via this driver's backing store (cookie or
    /// external) and returns both the session and the `Set-Cookie` header
    /// values the framework should attach to the callback response (the
    /// session cookies for cookie-backed stores, the pointer cookie for
    /// store-backed sessions).
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
    ) -> impl Future<Output = Result<(Self::SessionType, Vec<HeaderValue>), SessionError>> + Send;

    /// Load a session from the request's cookie headers.
    fn load(
        &self,
        headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<Option<Self::SessionType>, Self::LoadError>> + Send;

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
    ) -> impl Future<Output = Result<Vec<HeaderValue>, SessionError>> + Send;

    /// Record a lightweight touch — persist the updated `last_active`
    /// timestamp and (where applicable) extend the storage TTL, returning any
    /// `Set-Cookie` header values.
    ///
    /// The engine throttles how often this is called via
    /// [`LoginConfig::touch_min_interval`](crate::LoginConfig::touch_min_interval).
    /// Implementations should still treat each call as potentially expensive
    /// and avoid extra work when nothing changed.
    ///
    /// `CookieSessionStore` implements this as a full re-save (so `last_active`
    /// reaches the browser), since cookie sessions have no server-side TTL.
    /// `StoreBackedSessionStore` extends the external record's TTL and returns
    /// no cookies, since the pointer cookie's value is unchanged.
    fn touch(
        &self,
        _session: &Self::SessionType,
        _headers: &http::HeaderMap,
    ) -> impl Future<Output = Result<Vec<HeaderValue>, SessionError>> + Send {
        async { Ok(vec![]) }
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
    ) -> impl Future<Output = Result<Vec<HeaderValue>, SessionError>> + Send;
}
