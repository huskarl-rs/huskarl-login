//! Session construction from a completed login.
//!
//! [`SessionEnricher`] is the single hook through which the application's
//! session type is built after a successful OAuth callback, regardless of
//! where the session is stored. The framework prepares a *seed* — the data it
//! manages on the application's behalf — and the enricher turns seed plus
//! [`CompletedLogin`] into the session type:
//!
//! - For [`CookieSessionStore`](crate::CookieSessionStore) the seed is
//!   [`SessionState`](crate::SessionState) and the result is sealed into the
//!   browser cookie.
//! - For [`StoreBackedSessionStore`](crate::StoreBackedSessionStore) the seed
//!   is [`PersistedSessionState`](crate::PersistedSessionState) (the session
//!   state plus the generated session key) and the result is handed to the
//!   external store to persist.
//!
//! The default enricher, [`NoEnrichment`], converts the seed directly into
//! the session type via [`From`] — the store builders' `build()` finisher
//! uses it implicitly. Sessions that need claims or I/O are built by passing
//! a custom enricher to the builders' `build_with_enricher(…)` finisher
//! instead.

use huskarl::core::platform::{MaybeSend, MaybeSendBoxFuture, MaybeSendSync};

use crate::{completed_login::CompletedLogin, session::SessionError};

/// Asynchronously builds the session type from framework-prepared seed data
/// and the completed login.
///
/// An enricher is a **value** the application passes to its session store
/// builder's `build_with_enricher` finisher — so it can own whatever clients
/// it needs (an OIDC `UserInfo` client, a database pool) and await them while
/// building the session. Clients in the huskarl ecosystem are self-contained;
/// there is no transport parameter to thread through.
///
/// `Seed` is what the framework manages for you:
/// [`SessionState`](crate::SessionState) for cookie sessions,
/// [`PersistedSessionState`](crate::PersistedSessionState) (which adds the
/// session key) for store-backed sessions. Embed the seed in the session you
/// return.
///
/// This trait is dyn-capable: the session stores hold it as
/// `Box<dyn SessionEnricher<Seed, S>>`, so attaching an enricher does not
/// change the store's type. Write the `build_session` body as
/// `Box::pin(async move { ... })`.
///
/// A failed enrichment fails session creation: the callback responds with a
/// 500 and no session is established. [`SessionError`] is a boxed standard
/// error, so `?` converts any error type. Enrichers that consider their data
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
///     fn build_session<'a>(
///         &'a self,
///         seed: SessionState,
///         completed: &'a CompletedLogin,
///     ) -> MaybeSendBoxFuture<'a, Result<MySession, SessionError>> {
///         Box::pin(async move {
///             let claims = completed.id_token_claims();
///             Ok(MySession {
///                 state: seed,
///                 email: claims.and_then(|c| c.profile.email.clone()),
///                 name: claims.and_then(|c| c.profile.name.clone()),
///             })
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
///     http_client: MyHttpClient,
///     userinfo: UserInfoClient,
/// }
///
/// impl SessionEnricher<SessionState, MySession> for UserInfoEnricher {
///     fn build_session<'a>(
///         &'a self,
///         seed: SessionState,
///         completed: &'a CompletedLogin,
///     ) -> MaybeSendBoxFuture<'a, Result<MySession, SessionError>> {
///         Box::pin(async move {
///             let sub = seed.sub.clone().ok_or(MyError::NoSubject)?;
///             let info = self
///                 .userinfo
///                 .get(&self.http_client, completed.token_response().access_token(), &sub)
///                 .await?;
///             Ok(MySession {
///                 state: seed,
///                 email: info.profile.email,
///                 name: info.profile.name,
///             })
///         })
///     }
/// }
///
/// let store = CookieSessionStore::<MySession>::builder()
///     .cipher(cipher)
///     .cookie_name("session")
///     .secure(true)
///     .cookie_path("/")
///     .build_with_enricher(UserInfoEnricher { userinfo });
/// ```
///
/// The same enricher type can serve a store-backed deployment by implementing
/// `SessionEnricher<PersistedSessionState, MySession>` — only the seed type
/// changes.
pub trait SessionEnricher<Seed, S>: MaybeSendSync {
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
    /// Returns [`SessionError`] if the session can't be built; session
    /// creation fails and no session is established.
    fn build_session<'a>(
        &'a self,
        seed: Seed,
        completed: &'a CompletedLogin,
    ) -> MaybeSendBoxFuture<'a, Result<S, SessionError>>;
}

/// The default enricher: no I/O, no extra data — the session *is* the seed,
/// converted via [`From`].
///
/// This covers [`CookieSession`](crate::CookieSession) (`From<SessionState>`)
/// and bare [`PersistedSessionState`](crate::PersistedSessionState) sessions
/// (reflexive `From`). Any custom session type constructible from the seed
/// alone can opt in by implementing `From<Seed>`; sessions that need claims
/// or I/O implement [`SessionEnricher`] instead. The store builders' `build()`
/// finisher uses this enricher implicitly.
pub struct NoEnrichment;

impl<Seed, S> SessionEnricher<Seed, S> for NoEnrichment
where
    Seed: MaybeSend + 'static,
    S: From<Seed>,
{
    fn build_session<'a>(
        &'a self,
        seed: Seed,
        _completed: &'a CompletedLogin,
    ) -> MaybeSendBoxFuture<'a, Result<S, SessionError>> {
        Box::pin(async move { Ok(seed.into()) })
    }
}
