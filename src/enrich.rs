//! Session construction from a completed login.
//!
//! A [`SessionEnricher`] turns a framework-managed seed plus the
//! [`CompletedLogin`] into the application's session type. The seed is
//! [`SessionState`](crate::SessionState) for
//! [`CookieSessionStore`](crate::CookieSessionStore) and
//! [`PersistedSessionState`](crate::PersistedSessionState) for
//! [`StoreBackedSessionStore`](crate::StoreBackedSessionStore). The default
//! [`NoEnrichment`] converts the seed via [`From`].

use crate::{
    completed_login::CompletedLogin,
    core::platform::{MaybeSend, MaybeSendBoxFuture, MaybeSendSync},
    session::SessionError,
};

/// Builds an application session from framework-managed state and a completed
/// login.
///
/// Pass an enricher to a session store builder's
/// `build_with_enricher` method. It can own clients (an OIDC `UserInfo`
/// client, a database pool) and await them while building the session. `Seed`
/// is [`SessionState`](crate::SessionState) for cookie sessions or
/// [`PersistedSessionState`](crate::PersistedSessionState) for store-backed
/// sessions. Preserve the seed in the session you return so the engine can
/// continue to enforce token and lifetime policy.
///
/// The trait is dyn-capable (`Box<dyn SessionEnricher<Seed, S>>`); write the
/// body as `Box::pin(async move { ... })`. A failed enrichment fails session
/// creation (the callback responds 500). For the common no-I/O case — mapping
/// a few ID token claims — pass a synchronous closure to the builder's
/// `build_with_claims` method instead of implementing this trait.
///
/// Enrichment runs when a session is created after login, not on each request
/// or token refresh. To update token-derived fields during refresh, implement
/// [`Session::apply_refresh`](crate::Session::apply_refresh).
///
/// # Example
///
/// This named enricher builds a cookie session from an ID-token claim. An
/// implementation that needs I/O can await its client inside the same future.
///
/// ```
/// use huskarl_login::{
///     CompletedLogin, Session, SessionEnricher, SessionError, SessionState,
///     core::platform::MaybeSendBoxFuture,
/// };
///
/// #[derive(Clone, serde::Serialize, serde::Deserialize)]
/// struct AppSession {
///     state: SessionState,
///     display_name: Option<String>,
/// }
///
/// impl Session for AppSession {
///     fn state(&self) -> &SessionState {
///         &self.state
///     }
///     fn set_state(&mut self, state: SessionState) {
///         self.state = state;
///     }
/// }
///
/// struct ProfileEnricher;
///
/// impl SessionEnricher<SessionState, AppSession> for ProfileEnricher {
///     fn build_session<'a>(
///         &'a self,
///         seed: SessionState,
///         completed: &'a CompletedLogin,
///     ) -> MaybeSendBoxFuture<'a, Result<AppSession, SessionError>> {
///         Box::pin(async move {
///             Ok(AppSession {
///                 state: seed,
///                 display_name: completed
///                     .id_token_claims()
///                     .and_then(|claims| claims.profile.name.clone()),
///             })
///         })
///     }
/// }
/// ```
///
/// Attach it with `.build_with_enricher(ProfileEnricher)` on a
/// `CookieSessionStore::<AppSession>::builder()`. For complete wiring and a
/// `UserInfo` request, see [Build an application session](crate::_docs::how_to::enrichment).
pub trait SessionEnricher<Seed, S>: MaybeSendSync {
    /// Build the session from the framework-managed `seed` and the completed
    /// login.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError`] if the session can't be built; session
    /// creation then fails.
    fn build_session<'a>(
        &'a self,
        seed: Seed,
        completed: &'a CompletedLogin,
    ) -> MaybeSendBoxFuture<'a, Result<S, SessionError>>;
}

/// The default enricher: the session *is* the seed, converted via [`From`].
///
/// Used implicitly by the store builders' `build()` method. Any session type
/// constructible from the seed alone can opt in by implementing `From<Seed>`.
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

/// Adapts a synchronous claim-mapping closure into a [`SessionEnricher`].
///
/// Constructed by the store builders' `build_with_claims` method; never
/// named in application code.
pub(crate) struct ClaimsFn<F>(pub(crate) F);

impl<Seed, S, F> SessionEnricher<Seed, S> for ClaimsFn<F>
where
    Seed: MaybeSend + 'static,
    F: Fn(Seed, &CompletedLogin) -> Result<S, SessionError> + MaybeSendSync + 'static,
{
    fn build_session<'a>(
        &'a self,
        seed: Seed,
        completed: &'a CompletedLogin,
    ) -> MaybeSendBoxFuture<'a, Result<S, SessionError>> {
        // No `await` inside: the only value held across the (trivial) future
        // is `seed`, hence the `Seed: MaybeSend` bound mirrors `NoEnrichment`.
        Box::pin(async move { (self.0)(seed, completed) })
    }
}
