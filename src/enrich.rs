//! Session construction from a completed login.
//!
//! A [`SessionEnricher`] turns a framework-prepared seed plus the
//! [`CompletedLogin`] into the application's session type. The seed is
//! [`SessionState`](crate::SessionState) for
//! [`CookieSessionStore`](crate::CookieSessionStore) and
//! [`PersistedSessionState`](crate::PersistedSessionState) for
//! [`StoreBackedSessionStore`](crate::StoreBackedSessionStore). The default
//! [`NoEnrichment`] converts the seed via [`From`].

use huskarl::core::platform::{MaybeSend, MaybeSendBoxFuture, MaybeSendSync};

use crate::{completed_login::CompletedLogin, session::SessionError};

/// Asynchronously builds the session type from framework-prepared seed data
/// and the completed login.
///
/// An enricher is a value passed to a session store builder's
/// `build_with_enricher` finisher, so it can own clients (an OIDC `UserInfo`
/// client, a database pool) and await them while building the session. `Seed`
/// is [`SessionState`](crate::SessionState) for cookie sessions or
/// [`PersistedSessionState`](crate::PersistedSessionState) for store-backed
/// sessions; embed it in the session you return.
///
/// The trait is dyn-capable (`Box<dyn SessionEnricher<Seed, S>>`); write the
/// body as `Box::pin(async move { ... })`. A failed enrichment fails session
/// creation (the callback responds 500). For the common no-I/O case — mapping
/// a few ID token claims — pass a synchronous closure to the builder's
/// `build_with_claims` finisher instead of implementing this trait.
pub trait SessionEnricher<Seed, S>: MaybeSendSync {
    /// Build the session from the framework-prepared `seed` and the completed
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
/// Used implicitly by the store builders' `build()` finisher. Any session type
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
/// Constructed by the store builders' `build_with_claims` finisher; never
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
