//! Session construction from a completed login.
//!
//! [`SessionEnricher`] is the single hook through which the application's
//! session type is built after a successful OAuth callback, regardless of
//! where the session is stored. The framework prepares a *seed* — the data it
//! manages on the application's behalf — and the enricher turns seed plus
//! [`CompletedLogin`] into the session type:
//!
//! - For [`CookieSessionStore`](crate::CookieSessionStore) the seed is
//!   [`SessionState`] and the result is sealed into the browser cookie.
//! - For [`StoreBackedSessionStore`](crate::StoreBackedSessionStore) the seed
//!   is [`PersistedSessionState`](crate::PersistedSessionState) (the session
//!   state plus the generated session key) and the result is handed to the
//!   external store to persist.
//!
//! The default enricher, [`NoEnrichment`], converts the seed directly into
//! the session type via [`From`] — covering the built-in
//! [`CookieSession`](crate::CookieSession) and bare
//! [`PersistedSessionState`](crate::PersistedSessionState) sessions with no
//! further code.

use std::convert::Infallible;

use huskarl::core::platform::{MaybeSend, MaybeSendSync};

use crate::grant::CompletedLogin;

/// Asynchronously builds the session type from framework-prepared seed data
/// and the completed login.
///
/// An enricher is a **value** the application constructs and attaches to its
/// session store via `with_enricher` — so it can own whatever clients it
/// needs (an OIDC `UserInfo` client, a database pool) and await them while
/// building the session. Clients in the huskarl ecosystem are self-contained;
/// there is no transport parameter to thread through.
///
/// `Seed` is what the framework manages for you:
/// [`SessionState`](crate::SessionState) for cookie sessions,
/// [`PersistedSessionState`](crate::PersistedSessionState) (which adds the
/// session key) for store-backed sessions. Embed the seed in the session you
/// return.
///
/// A failed enrichment fails session creation: the callback responds with a
/// 500 and no session is established. Enrichers that consider their data
/// optional should catch their own errors and return a partially-populated
/// session instead.
///
/// # Mapping ID token claims
///
/// The simplest enrichers need no I/O at all — they copy claims from the
/// validated ID token into the session:
///
/// ```ignore
/// struct ClaimsEnricher;
///
/// impl SessionEnricher<SessionState, MySession> for ClaimsEnricher {
///     type Error = Infallible;
///
///     async fn build_session(
///         &self,
///         seed: SessionState,
///         completed: &CompletedLogin,
///     ) -> Result<MySession, Infallible> {
///         let claims = completed.id_token_claims();
///         Ok(MySession {
///             state: seed,
///             email: claims.and_then(|c| c.email.clone()),
///             name: claims.and_then(|c| c.name.clone()),
///         })
///     }
/// }
/// ```
///
/// For non-standard claims, use `claims.extra.get("…")`.
///
/// # Calling the `UserInfo` endpoint
///
/// Enrichers that need claims the ID token doesn't carry own their clients
/// and await them:
///
/// ```ignore
/// struct UserInfoEnricher {
///     userinfo: UserInfoClient<NoDPoP>,
/// }
///
/// impl SessionEnricher<SessionState, MySession> for UserInfoEnricher {
///     type Error = MyError;
///
///     async fn build_session(
///         &self,
///         seed: SessionState,
///         completed: &CompletedLogin,
///     ) -> Result<MySession, MyError> {
///         let sub = seed.sub.clone().ok_or(MyError::NoSubject)?;
///         let info = self
///             .userinfo
///             .get(completed.token_response().access_token(), &sub)
///             .await?;
///         Ok(MySession {
///             state: seed,
///             email: info.email,
///             name: info.name,
///         })
///     }
/// }
///
/// let store = CookieSessionStore::<MySession>::builder()
///     .cipher(cipher)
///     .cookie_name("session")
///     .secure(true)
///     .cookie_path("/")
///     .build()
///     .with_enricher(UserInfoEnricher { userinfo });
/// ```
///
/// The same enricher type can serve a store-backed deployment by implementing
/// `SessionEnricher<PersistedSessionState, MySession>` — only the seed type
/// changes.
pub trait SessionEnricher<Seed, S>: MaybeSendSync {
    /// Error type returned by [`build_session`](Self::build_session).
    type Error: std::error::Error + MaybeSendSync + 'static;

    /// Build the session from the framework-prepared `seed` and the completed
    /// login.
    ///
    /// The seed carries the standard token/timing fields (including
    /// `sub`/`sid` from the ID token); `completed` exposes the token response
    /// (e.g. the access token for a `UserInfo` call) and validated ID token
    /// claims.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the session can't be built; session creation
    /// fails and no session is established.
    fn build_session(
        &self,
        seed: Seed,
        completed: &CompletedLogin,
    ) -> impl Future<Output = Result<S, Self::Error>> + MaybeSend;
}

/// The default enricher: no I/O, no extra data — the session *is* the seed,
/// converted via [`From`].
///
/// This covers [`CookieSession`](crate::CookieSession) (`From<SessionState>`)
/// and bare [`PersistedSessionState`](crate::PersistedSessionState) sessions
/// (reflexive `From`). Any custom session type constructible from the seed
/// alone can opt in by implementing `From<Seed>`; sessions that need claims
/// or I/O implement [`SessionEnricher`] instead.
pub struct NoEnrichment;

impl<Seed: MaybeSend, S: From<Seed>> SessionEnricher<Seed, S> for NoEnrichment {
    type Error = Infallible;

    async fn build_session(
        &self,
        seed: Seed,
        _completed: &CompletedLogin,
    ) -> Result<S, Infallible> {
        Ok(seed.into())
    }
}
