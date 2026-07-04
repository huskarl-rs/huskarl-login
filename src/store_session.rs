//! External-store-backed session storage.
//!
//! [`StoreBackedSessionStore`] keeps an encrypted pointer cookie in the browser
//! and delegates session data to an [`ExternalSessionStore`] (Redis, a database,
//! etc.).

use std::{borrow::Cow, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderValue;
use huskarl::{
    core::{
        crypto::cipher::{AeadCipher, AeadSealer as _, CipherMatch},
        platform::{MaybeSend, MaybeSendSync, SystemTime},
    },
    grant::core::TokenResponse,
};
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use uuid::Uuid;

use crate::{
    config::RoutePath,
    cookie::{
        CookieName, CookieSealer, DEFAULT_COOKIE_MAX_AGE, get_cookie, get_kid_cookie,
        kid_cookie_name, unseal_with_kid_fallback,
    },
    enrich::{NoEnrichment, SessionEnricher},
    liveness::{LivenessConfig, LivenessStore, LivenessVerdict},
    metrics::{DecryptResult, SessionCookieMetrics},
    session::{SessionDriver, SessionError, SessionErrorKind, to_session_err},
    session_state::{Session, SessionState},
};

/// Pure-storage backend (Redis, SQL, …) for a [`StoreBackedSessionStore`]:
/// insert, load, save, compare-and-swap, delete.
///
/// Session construction from a completed login is handled by the
/// [`SessionEnricher`](crate::SessionEnricher) attached to the store, not here.
pub trait ExternalSessionStore: MaybeSendSync {
    /// The session type returned by this store. Must implement [`Session`] and
    /// [`PersistedSession`].
    type SessionType: Session + PersistedSession + MaybeSendSync + 'static;

    /// The backend's own error type (e.g. `sqlx::Error`); transport-failure
    /// channel only. Boxed into
    /// [`SessionErrorKind::Unavailable`](crate::SessionErrorKind::Unavailable).
    type Error: std::error::Error + MaybeSendSync + 'static;

    /// Persist a newly created session. Called once per login, after
    /// enrichment. The retention contract on [`save`](Self::save) applies.
    fn insert(
        &self,
        session: &Self::SessionType,
    ) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;

    /// Load a session by its key. Returns `None` if the key does not exist.
    fn load(
        &self,
        session_key: Uuid,
    ) -> impl Future<Output = Result<Option<Self::SessionType>, Self::Error>> + MaybeSend;

    /// Save a session unconditionally (last-writer-wins), advancing the stored
    /// [`version`](PersistedSessionState::version).
    ///
    /// Retain the record until **at least**
    /// [`Session::expire_at`](crate::Session::expire_at), re-applying the TTL
    /// on **every** write and never as a sliding window; `None` means no
    /// deadline. The TTL is garbage collection, not enforcement — see [the
    /// external-store guide](crate::_docs::guide::external_store).
    fn save(
        &self,
        session: &Self::SessionType,
    ) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;

    /// Save `session` only if the stored
    /// [`version`](PersistedSessionState::version) still equals `expected`,
    /// advancing it on success; otherwise returns [`SaveOutcome::Conflict`]
    /// without writing. Version is compared by equality only. The retention
    /// contract on [`save`](Self::save) applies.
    fn compare_and_swap(
        &self,
        session: &Self::SessionType,
        expected: i32,
    ) -> impl Future<Output = Result<SaveOutcome, Self::Error>> + MaybeSend;

    /// Delete the session's stored record. Idempotent: a missing record is
    /// `Ok(())`.
    fn delete(
        &self,
        session: &Self::SessionType,
    ) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;
}

/// Outcome of [`ExternalSessionStore::compare_and_swap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveOutcome {
    /// The version matched; the session was written and the version advanced.
    Committed,
    /// Another writer advanced the version first; nothing was written.
    Conflict,
}

/// [`StoreBackedSessionStore::update`] found no session for the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("session not found"))]
pub struct SessionNotFound;

/// [`StoreBackedSessionStore::update`] exhausted its retry budget under
/// sustained concurrent rewrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("session update conflict: the session was modified concurrently"))]
pub struct VersionConflict;

/// Framework-managed session state carried by every store-backed session, and
/// the seed passed to the [`SessionEnricher`](crate::SessionEnricher) after
/// login.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, bon::Builder)]
pub struct PersistedSessionState {
    /// Primary lookup key in the external store. A time-ordered `UUIDv7`.
    pub session_key: Uuid,
    /// Shared token and timing state. See [`SessionState`] for the field set.
    pub state: SessionState,
    /// Optimistic-concurrency version, advanced on every write; `0` at insert,
    /// set by the store on [`load`](ExternalSessionStore::load). Compared by
    /// equality only.
    #[serde(default)]
    #[builder(default)]
    pub version: i32,
}

impl Session for PersistedSessionState {
    fn state(&self) -> &SessionState {
        &self.state
    }
    fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }
}

/// Exposes the embedded [`PersistedSessionState`] to the framework. Implemented
/// by every store-backed session type, forwarding to its embedded field.
pub trait PersistedSession {
    /// Returns a shared reference to the embedded [`PersistedSessionState`].
    fn persisted(&self) -> &PersistedSessionState;

    /// Returns a mutable reference to the embedded [`PersistedSessionState`].
    fn persisted_mut(&mut self) -> &mut PersistedSessionState;
}

impl PersistedSession for PersistedSessionState {
    fn persisted(&self) -> &PersistedSessionState {
        self
    }
    fn persisted_mut(&mut self) -> &mut PersistedSessionState {
        self
    }
}

/// Generates a time-ordered session key using UUID v7.
fn generate_session_key() -> Uuid {
    Uuid::now_v7()
}

/// Attempts an optimistic [`update`](StoreBackedSessionStore::update) makes
/// before giving up with [`VersionConflict`].
const UPDATE_MAX_ATTEMPTS: u32 = 5;

/// A session store that keeps an encrypted pointer cookie (the session key) in
/// the browser and stores session data in an [`ExternalSessionStore`].
///
/// The session is built after login by a [`SessionEnricher`] from the
/// [`PersistedSessionState`] seed; `build()` uses [`NoEnrichment`],
/// `build_with_enricher(…)` supplies a custom one. The engine stamps on the
/// `Secure` attribute and `__Host-` prefix, so this store takes no `secure`
/// setting.
pub struct StoreBackedSessionStore<E: ExternalSessionStore> {
    external: E,
    enricher: Box<dyn SessionEnricher<PersistedSessionState, E::SessionType>>,
    /// Cookie-sealing machinery for the pointer cookie — see [`CookieSealer`].
    sealer: CookieSealer,
    /// Optional server-side liveness (idle) tracking; `None` disables it.
    /// Attached via [`with_liveness`](Self::with_liveness).
    liveness: Option<(Box<dyn LivenessStore>, LivenessConfig)>,
    /// The [`SessionLifetime::Bounded`](crate::SessionLifetime) cap, stamped
    /// by the engine at construction; frozen into each new session's
    /// [`SessionState::expire_at`](crate::SessionState) at login. `None`
    /// until stamped (or when the lifetime is delegated).
    max_lifetime: Option<Duration>,
}

#[bon::bon]
impl<E: ExternalSessionStore> StoreBackedSessionStore<E> {
    /// Creates a new store-backed session store. Finish with `build()` (uses
    /// [`NoEnrichment`]) or `build_with_enricher(…)`.
    #[builder(state_mod(name = "store_builder"), finish_fn(vis = "", name = build_internal))]
    pub fn new(
        #[builder(finish_fn)] enricher: Box<
            dyn SessionEnricher<PersistedSessionState, E::SessionType>,
        >,
        external: E,
        #[builder(with = |cipher: impl AeadCipher + 'static| Arc::new(cipher) as Arc<dyn AeadCipher>)]
        cipher: Arc<dyn AeadCipher>,
        /// Base name for the session cookie.
        cookie_name: CookieName,
        /// Cookie `Path` scope.
        cookie_path: RoutePath,
        /// Cookie `Max-Age`; defaults to 400 days. The engine clamps it to the
        /// [`SessionLifetime::Bounded`](crate::SessionLifetime) cap at
        /// construction; set it explicitly only to go *shorter*.
        #[builder(default = DEFAULT_COOKIE_MAX_AGE)]
        max_age: Duration,
        /// Optional metrics observer for encrypt/decrypt events.
        metrics: Option<Arc<dyn SessionCookieMetrics>>,
    ) -> Self {
        Self {
            external,
            enricher,
            sealer: CookieSealer::new(cipher, cookie_name, cookie_path, max_age, metrics),
            liveness: None,
            max_lifetime: None,
        }
    }
}

impl<E: ExternalSessionStore, S: store_builder::IsComplete> StoreBackedSessionStoreBuilder<E, S> {
    /// Finishes the builder with [`NoEnrichment`] (`From<PersistedSessionState>`).
    #[must_use]
    pub fn build(self) -> StoreBackedSessionStore<E>
    where
        E::SessionType: From<PersistedSessionState>,
    {
        self.build_internal(Box::new(NoEnrichment))
    }

    /// Finishes the builder with a custom [`SessionEnricher`], for sessions that
    /// need ID token claims or I/O to construct. Seed type is
    /// [`PersistedSessionState`].
    #[must_use]
    pub fn build_with_enricher(
        self,
        enricher: impl SessionEnricher<PersistedSessionState, E::SessionType> + 'static,
    ) -> StoreBackedSessionStore<E> {
        self.build_internal(Box::new(enricher))
    }

    /// Finishes the builder with a synchronous claim-mapper that builds the
    /// session from the seed and the [`CompletedLogin`](crate::CompletedLogin)
    /// without I/O. For `await`ing enrichment use
    /// [`build_with_enricher`](Self::build_with_enricher).
    #[must_use]
    pub fn build_with_claims<F>(self, f: F) -> StoreBackedSessionStore<E>
    where
        F: Fn(
                PersistedSessionState,
                &crate::CompletedLogin,
            ) -> Result<E::SessionType, SessionError>
            + MaybeSendSync
            + 'static,
    {
        self.build_internal(Box::new(crate::enrich::ClaimsFn(f)))
    }
}

impl<E: ExternalSessionStore> StoreBackedSessionStore<E> {
    /// Returns the active cipher's key ID, if the key has an identity.
    pub fn key_id(&self) -> Option<Cow<'_, str>> {
        self.sealer.key_id()
    }

    /// Attach server-side liveness (idle-timeout) tracking, backed by the given
    /// [`LivenessStore`] and configured by `config`. Returns `self`. See
    /// [`crate::liveness`] for the fail-open / monotonic contract.
    #[must_use]
    pub fn with_liveness(
        mut self,
        store: impl LivenessStore + 'static,
        config: LivenessConfig,
    ) -> Self {
        self.liveness = Some((Box::new(store), config));
        self
    }

    /// Atomically apply `mutate` to the stored session, retrying on concurrent
    /// writes (optimistic concurrency control) via
    /// [`compare_and_swap`](ExternalSessionStore::compare_and_swap). Returns the
    /// committed session.
    ///
    /// `mutate` may run more than once against freshly-loaded state, so it must
    /// be replayable: compute the new state from the session it is given, never
    /// from a value captured before the load.
    ///
    /// # Errors
    ///
    /// [`SessionErrorKind::Gone`] (no session), [`SessionErrorKind::Conflict`]
    /// (retry budget exhausted), or [`SessionErrorKind::Unavailable`] (store
    /// error).
    pub async fn update<F>(
        &self,
        session_key: Uuid,
        mutate: F,
    ) -> Result<E::SessionType, SessionError>
    where
        F: Fn(&mut E::SessionType) + MaybeSend,
    {
        self.try_update(session_key, move |session| {
            mutate(session);
            Ok(())
        })
        .await
    }

    /// Like [`update`](Self::update), for mutations that can fail: `mutate`
    /// returning `Err` aborts the update — nothing is written — and the error
    /// is returned as-is. The same replayability contract applies: `mutate`
    /// may run more than once against freshly-loaded state.
    ///
    /// # Errors
    ///
    /// Whatever `mutate` returned, or the same errors as
    /// [`update`](Self::update).
    pub async fn try_update<F>(
        &self,
        session_key: Uuid,
        mutate: F,
    ) -> Result<E::SessionType, SessionError>
    where
        F: Fn(&mut E::SessionType) -> Result<(), SessionError> + MaybeSend,
    {
        for _ in 0..UPDATE_MAX_ATTEMPTS {
            let Some(mut session) = self
                .external
                .load(session_key)
                .await
                .map_err(to_session_err)?
            else {
                return Err(SessionError::new(SessionErrorKind::Gone, SessionNotFound));
            };
            let expected = session.persisted().version;
            mutate(&mut session)?;
            // Advance the version on the session so stores that persist it from
            // the record's body see the new value; column-based stores that do
            // `version + 1` arrive at the same value (stored == expected).
            session.persisted_mut().version = expected.wrapping_add(1);
            match self
                .external
                .compare_and_swap(&session, expected)
                .await
                .map_err(to_session_err)?
            {
                SaveOutcome::Committed => return Ok(session),
                SaveOutcome::Conflict => {}
            }
        }
        Err(SessionError::new(
            SessionErrorKind::Conflict,
            VersionConflict,
        ))
    }

    /// Encrypt the pointer cookie (the UUID's 16 raw bytes) and emit it
    /// alongside the kid sidecar (a `Max-Age=0` clear when there is no identity).
    async fn pointer_cookie_headers(
        &self,
        session_key: Uuid,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        let aad = self.sealer.aad("session_ptr");
        let bundle = self
            .sealer
            .cipher
            .seal(session_key.as_bytes(), &aad)
            .await
            .map_err(|e| SessionError::new(SessionErrorKind::Crypto, e))?;
        // See cookie_session.rs for the rationale on reading `key_id()` from
        // the same cipher that just sealed the bundle: stable for single-key
        // ciphers; if multi-key sealers land, switch to `AeadCipherSelector`.
        let kid = self.sealer.key_id();
        self.sealer.record_encrypt(kid.as_deref());
        let cookie_value = URL_SAFE_NO_PAD.encode(&bundle);
        let attrs = self.sealer.cookie_attrs();
        let pointer = HeaderValue::from_str(&format!(
            "{}={cookie_value}; {attrs}",
            self.sealer.cookie_name
        ))
        .map_err(|e| SessionError::new(SessionErrorKind::Encoding, e))?;
        let kid_header = self.sealer.build_kid_header(kid.as_deref())?;
        Ok(vec![pointer, kid_header])
    }

    /// Read and decrypt the pointer cookie to get the session key.
    async fn read_pointer_cookie(&self, headers: &http::HeaderMap) -> Option<Uuid> {
        let encoded = get_cookie(headers, &self.sealer.cookie_name)?;

        // A pointer-cookie-shaped value is present — record the outcome.
        let kid = get_kid_cookie(headers, &self.sealer.cookie_name);

        let Ok(bundle) = URL_SAFE_NO_PAD.decode(encoded) else {
            self.sealer
                .record_decrypt(kid.as_deref(), &DecryptResult::BadEncoding);
            return None;
        };
        let cipher_match = kid
            .as_deref()
            .map(|k| CipherMatch::builder().kid(k).build());
        let aad = self.sealer.aad("session_ptr");
        let Some(plaintext) =
            unseal_with_kid_fallback(&self.sealer.cipher, cipher_match.as_ref(), &bundle, &aad)
                .await
        else {
            self.sealer
                .record_decrypt(kid.as_deref(), &DecryptResult::DecryptFailed);
            return None;
        };
        // Must be exactly 16 bytes (UUID); anything else is a corrupted cookie.
        if let Ok(bytes) = <[u8; 16]>::try_from(plaintext) {
            self.sealer
                .record_decrypt(kid.as_deref(), &DecryptResult::Ok);
            Some(Uuid::from_bytes(bytes))
        } else {
            self.sealer
                .record_decrypt(kid.as_deref(), &DecryptResult::PayloadInvalid);
            None
        }
    }
}

// -- Internal methods --

impl<E: ExternalSessionStore> StoreBackedSessionStore<E> {
    pub(crate) async fn create_session(
        &self,
        completed: &crate::CompletedLogin,
        default_lifetime: std::time::Duration,
    ) -> Result<(E::SessionType, Vec<HeaderValue>), SessionError> {
        let seed = PersistedSessionState {
            session_key: generate_session_key(),
            state: SessionState::from_completed(completed, default_lifetime, self.max_lifetime),
            version: 0,
        };

        let session = self.enricher.build_session(seed, completed).await?;
        self.external
            .insert(&session)
            .await
            .map_err(to_session_err)?;
        let cookies = self
            .pointer_cookie_headers(session.persisted().session_key)
            .await?;
        Ok((session, cookies))
    }

    pub(crate) async fn load_session(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<Option<E::SessionType>, E::Error> {
        let Some(session_key) = self.read_pointer_cookie(headers).await else {
            return Ok(None);
        };

        self.external.load(session_key).await
    }

    pub(crate) async fn save_session(
        &self,
        session: &E::SessionType,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.external.save(session).await.map_err(to_session_err)?;
        // The pointer cookie's value (the session_key) doesn't change after
        // creation, so subsequent saves don't reissue it. The initial cookie
        // is emitted by `create_session`.
        Ok(vec![])
    }

    pub(crate) async fn delete_session(
        &self,
        session: &E::SessionType,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.external
            .delete(session)
            .await
            .map_err(to_session_err)?;
        // Best-effort: drop the liveness entry too. A failure here just leaves a
        // stale entry that expires under its own TTL; it must not fail logout.
        if let Some((liveness, _)) = &self.liveness {
            let key = session.persisted().session_key;
            if let Err(e) = liveness.clear(key).await {
                log::warn!("failed to clear liveness entry on delete: {e}");
            }
        }
        // Clear the pointer cookie and the kid sidecar.
        let clear_attrs = format!("{}; Max-Age=0", self.sealer.base_cookie_attrs());
        let mut headers = Vec::new();
        if let Ok(v) =
            HeaderValue::from_str(&format!("{}=; {clear_attrs}", self.sealer.cookie_name))
        {
            headers.push(v);
        }
        let kid_name = kid_cookie_name(&self.sealer.cookie_name);
        if let Ok(v) = HeaderValue::from_str(&format!("{kid_name}=; {clear_attrs}")) {
            headers.push(v);
        }
        Ok(headers)
    }
}

impl<E: ExternalSessionStore> crate::session::sealed::Sealed for StoreBackedSessionStore<E> {}

impl<E: ExternalSessionStore> SessionDriver for StoreBackedSessionStore<E> {
    type SessionType = E::SessionType;
    type LoadError = E::Error;

    fn apply_session_policy(&mut self, secure: bool, max_lifetime: Option<std::time::Duration>) {
        self.sealer.apply_secure(secure);
        if let Some(cap) = max_lifetime {
            self.sealer.clamp_max_age(cap);
        }
        // Retained to freeze `SessionState::expire_at` into new sessions.
        self.max_lifetime = max_lifetime;
    }

    fn session_aead_cipher(&self) -> Arc<dyn AeadCipher> {
        self.sealer.aead.clone()
    }

    async fn create(
        &self,
        completed: crate::CompletedLogin,
        default_lifetime: std::time::Duration,
        _headers: &http::HeaderMap,
    ) -> Result<(E::SessionType, Vec<HeaderValue>), SessionError> {
        self.create_session(&completed, default_lifetime).await
    }

    async fn load(&self, headers: &http::HeaderMap) -> Result<Option<E::SessionType>, E::Error> {
        self.load_session(headers).await
    }

    async fn save(
        &self,
        session: &E::SessionType,
        _headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.save_session(session).await
    }

    async fn apply_refresh_and_save(
        &self,
        session: &mut E::SessionType,
        token_response: &TokenResponse,
        default_lifetime: std::time::Duration,
        _headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        // Commit through the CAS loop rather than saving this request's
        // snapshot wholesale: an [`update`](Self::update) committed since this
        // request loaded must survive the refresh. Replaying `apply_refresh`
        // against the freshly-loaded session touches exactly what the refresh
        // response justifies (plus any custom `Session::apply_refresh`
        // override) and nothing else.
        let key = session.persisted().session_key;
        match self
            .update(key, |fresh| {
                fresh.apply_refresh(token_response, default_lifetime);
            })
            .await
        {
            Ok(committed) => {
                *session = committed;
                // A refresh never changes the session key, so the pointer
                // cookie is unchanged.
                Ok(vec![])
            }
            Err(e) => {
                // Keep the trait contract: on error the refresh is applied in
                // memory (the request can still serve the new tokens) and the
                // persist is owed.
                session.apply_refresh(token_response, default_lifetime);
                Err(e)
            }
        }
    }

    async fn check_liveness(
        &self,
        session: &E::SessionType,
        now: SystemTime,
        record_activity: bool,
        expire_at: Option<SystemTime>,
    ) -> Result<LivenessVerdict, SessionError> {
        let Some((liveness, config)) = &self.liveness else {
            return Ok(LivenessVerdict::Untracked);
        };
        let key = session.persisted().session_key;
        // Fail open: a read failure must not tear the session down (and leaves
        // us without a timestamp to throttle against, so we skip the write).
        // Idle enforcement degrades to the absolute lifetime bound (crate- or
        // AS-side) until the store recovers.
        let last_active = match liveness.last_active(key).await {
            Ok(last_active) => last_active,
            Err(e) => {
                log::warn!("liveness read failed; treating session as active: {e}");
                return Ok(LivenessVerdict::Active);
            }
        };
        let verdict = config.verdict(last_active, now);

        // Record activity for a live request, throttled against the persisted
        // `last_active` (so steady traffic is one write per `touch_min_interval`,
        // shared across servers). Skipped when the engine classified this
        // request as non-activity (cross-site embed, background poll, …). The
        // write is best-effort and monotonic — a failure just delays the next
        // advance.
        let due = match last_active {
            None => true, // no entry yet — establish one
            Some(prev) => {
                now.duration_since(prev).unwrap_or(Duration::ZERO) >= config.touch_min_interval
            }
        };
        if record_activity
            && verdict == LivenessVerdict::Active
            && due
            && let Err(e) = liveness.touch(key, now, expire_at).await
        {
            log::warn!("liveness touch failed (best-effort): {e}");
        }
        Ok(verdict)
    }

    async fn delete(
        &self,
        session: &E::SessionType,
        _headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.delete_session(session).await
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use huskarl::core::{crypto::cipher::AeadV1Cipher, platform::MaybeSendBoxFuture};

    use super::*;
    use crate::{
        cookie::encode_kid,
        session_state::{Session, SessionState},
        test_support::{aes_key_with_kid, test_cipher, test_cipher_with_kid},
    };

    #[derive(Clone)]
    struct MinimalSession {
        persisted: PersistedSessionState,
    }

    impl Session for MinimalSession {
        fn state(&self) -> &SessionState {
            self.persisted.state()
        }
        fn set_state(&mut self, s: SessionState) {
            self.persisted.set_state(s);
        }
    }

    impl PersistedSession for MinimalSession {
        fn persisted(&self) -> &PersistedSessionState {
            &self.persisted
        }
        fn persisted_mut(&mut self) -> &mut PersistedSessionState {
            &mut self.persisted
        }
    }

    /// Lets the plain `build()` finisher (`NoEnrichment`) construct the
    /// session directly from the seed.
    impl From<PersistedSessionState> for MinimalSession {
        fn from(persisted: PersistedSessionState) -> Self {
            Self { persisted }
        }
    }

    struct MinimalExternalStore(MinimalSession);

    // Test stub: the async method signatures are mandated by the trait; the
    // bodies are synchronous.
    #[allow(clippy::unused_async_trait_impl)]
    impl ExternalSessionStore for MinimalExternalStore {
        type SessionType = MinimalSession;
        type Error = Infallible;

        async fn insert(&self, _: &MinimalSession) -> Result<(), Infallible> {
            Ok(())
        }

        async fn load(&self, _: Uuid) -> Result<Option<MinimalSession>, Infallible> {
            Ok(Some(self.0.clone()))
        }

        async fn save(&self, _: &MinimalSession) -> Result<(), Infallible> {
            Ok(())
        }

        async fn compare_and_swap(
            &self,
            _: &MinimalSession,
            _: i32,
        ) -> Result<SaveOutcome, Infallible> {
            Ok(SaveOutcome::Committed)
        }

        async fn delete(&self, _: &MinimalSession) -> Result<(), Infallible> {
            Ok(())
        }
    }

    fn test_session() -> MinimalSession {
        let now = std::time::SystemTime::now();
        MinimalSession {
            persisted: PersistedSessionState {
                session_key: Uuid::now_v7(),
                state: SessionState::builder()
                    .token_expiry(now + std::time::Duration::from_hours(1))
                    .created_at(now)
                    .build(),
                version: 0,
            },
        }
    }

    /// Builds `MinimalSession` from the `PersistedSessionState` seed.
    struct MinimalEnricher;

    impl SessionEnricher<PersistedSessionState, MinimalSession> for MinimalEnricher {
        fn build_session<'a>(
            &'a self,
            seed: PersistedSessionState,
            _completed: &'a crate::CompletedLogin,
        ) -> MaybeSendBoxFuture<'a, Result<MinimalSession, SessionError>> {
            Box::pin(async move { Ok(MinimalSession { persisted: seed }) })
        }
    }

    fn assert_session_driver<T: SessionDriver>(_: &T) {}

    #[tokio::test]
    async fn enriched_store_satisfies_session_driver() {
        // A store finished with a custom enricher drives the engine the same
        // as the default — the enricher is type-erased, so the store type is
        // identical either way.
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session))
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build_with_enricher(MinimalEnricher);
        assert_session_driver(&store);
    }

    /// In-memory [`LivenessStore`] that records every write, shareable for
    /// inspection.
    #[derive(Clone, Default)]
    struct FakeLiveness {
        entries: Arc<std::sync::Mutex<std::collections::HashMap<Uuid, SystemTime>>>,
    }

    impl FakeLiveness {
        fn set(&self, key: Uuid, at: SystemTime) {
            self.entries.lock().unwrap().insert(key, at);
        }
        fn get(&self, key: Uuid) -> Option<SystemTime> {
            self.entries.lock().unwrap().get(&key).copied()
        }
    }

    impl LivenessStore for FakeLiveness {
        fn last_active(
            &self,
            key: Uuid,
        ) -> MaybeSendBoxFuture<'_, Result<Option<SystemTime>, SessionError>> {
            let v = self.get(key);
            Box::pin(async move { Ok(v) })
        }
        fn touch(
            &self,
            key: Uuid,
            now: SystemTime,
            _expire_at: Option<SystemTime>,
        ) -> MaybeSendBoxFuture<'_, Result<(), SessionError>> {
            self.set(key, now);
            Box::pin(async move { Ok(()) })
        }
        fn clear(&self, key: Uuid) -> MaybeSendBoxFuture<'_, Result<(), SessionError>> {
            self.entries.lock().unwrap().remove(&key);
            Box::pin(async move { Ok(()) })
        }
    }

    async fn liveness_store(
        session: MinimalSession,
        liveness: FakeLiveness,
        config: LivenessConfig,
    ) -> StoreBackedSessionStore<MinimalExternalStore> {
        StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session))
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
            .with_liveness(liveness, config)
    }

    #[tokio::test]
    async fn without_liveness_is_untracked() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();

        let verdict = store
            .check_liveness(&session, SystemTime::now(), true, None)
            .await
            .unwrap();
        assert_eq!(verdict, LivenessVerdict::Untracked);
    }

    #[tokio::test]
    async fn liveness_active_and_records_activity_on_check() {
        let session = test_session();
        let key = session.persisted.session_key;
        let liveness = FakeLiveness::default();
        let store =
            liveness_store(session.clone(), liveness.clone(), LivenessConfig::default()).await;

        // No entry yet → fail-open Active, and check_liveness records activity
        // (the store throttles; this raw fake writes every time).
        let now = SystemTime::now();
        assert_eq!(
            store
                .check_liveness(&session, now, true, None)
                .await
                .unwrap(),
            LivenessVerdict::Active
        );
        assert_eq!(
            liveness.get(key),
            Some(now),
            "check_liveness records activity as a side effect"
        );
    }

    #[tokio::test]
    async fn liveness_does_not_record_when_not_activity() {
        let session = test_session();
        let key = session.persisted.session_key;
        let liveness = FakeLiveness::default();
        let store =
            liveness_store(session.clone(), liveness.clone(), LivenessConfig::default()).await;

        // Non-activity request (record_activity = false): still Active (idle is
        // enforced), but last_active is not advanced.
        assert_eq!(
            store
                .check_liveness(&session, SystemTime::now(), false, None)
                .await
                .unwrap(),
            LivenessVerdict::Active
        );
        assert!(
            liveness.get(key).is_none(),
            "a non-activity request must not advance last_active"
        );
    }

    #[tokio::test]
    async fn liveness_idle_past_timeout_expires_and_does_not_record() {
        let session = test_session();
        let key = session.persisted.session_key;
        let liveness = FakeLiveness::default();
        let config = LivenessConfig::builder()
            .idle_timeout(Duration::from_secs(60))
            .build()
            .unwrap();
        let store = liveness_store(session.clone(), liveness.clone(), config).await;

        let now = SystemTime::now();
        let stale = now - Duration::from_secs(120);
        liveness.set(key, stale);
        assert_eq!(
            store
                .check_liveness(&session, now, true, None)
                .await
                .unwrap(),
            LivenessVerdict::Expired
        );
        // An expired session is being torn down — no activity is recorded.
        assert_eq!(
            liveness.get(key),
            Some(stale),
            "expired check must not touch"
        );
    }

    /// A [`LivenessStore`] whose reads always fail, to exercise fail-open.
    struct FailingLiveness;
    impl LivenessStore for FailingLiveness {
        fn last_active(
            &self,
            _key: Uuid,
        ) -> MaybeSendBoxFuture<'_, Result<Option<SystemTime>, SessionError>> {
            Box::pin(async {
                Err(SessionError::new(
                    SessionErrorKind::Unavailable,
                    "liveness backend down",
                ))
            })
        }
        fn touch(
            &self,
            _key: Uuid,
            _now: SystemTime,
            _expire_at: Option<SystemTime>,
        ) -> MaybeSendBoxFuture<'_, Result<(), SessionError>> {
            Box::pin(async {
                Err(SessionError::new(
                    SessionErrorKind::Unavailable,
                    "liveness backend down",
                ))
            })
        }
        fn clear(&self, _key: Uuid) -> MaybeSendBoxFuture<'_, Result<(), SessionError>> {
            Box::pin(async {
                Err(SessionError::new(
                    SessionErrorKind::Unavailable,
                    "liveness backend down",
                ))
            })
        }
    }

    #[tokio::test]
    async fn liveness_read_failure_fails_open() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
            // A short idle timeout that *would* expire if the read succeeded.
            .with_liveness(
                FailingLiveness,
                LivenessConfig::builder()
                    .idle_timeout(Duration::from_secs(1))
                    .build()
                    .unwrap(),
            );

        // Read errors must never expire a session — fail open to Active. The
        // subsequent (also failing) activity touch is swallowed best-effort, so
        // check_liveness still returns Ok.
        assert_eq!(
            store
                .check_liveness(&session, SystemTime::now(), true, None)
                .await
                .unwrap(),
            LivenessVerdict::Active
        );
    }

    #[tokio::test]
    async fn liveness_cleared_on_delete() {
        let session = test_session();
        let key = session.persisted.session_key;
        let liveness = FakeLiveness::default();
        let store =
            liveness_store(session.clone(), liveness.clone(), LivenessConfig::default()).await;

        liveness.set(key, SystemTime::now());
        store
            .delete(&session, &http::HeaderMap::new())
            .await
            .unwrap();
        assert!(
            liveness.get(key).is_none(),
            "delete clears the liveness entry"
        );
    }

    // ── Optimistic update (OCC) ───────────────────────────────────────────

    /// A stateful external store that honours [`compare_and_swap`] versioning,
    /// so the [`StoreBackedSessionStore::update`] retry loop can be exercised.
    struct VersioningStore {
        stored: std::sync::Mutex<Option<MinimalSession>>,
        /// When `true`, every `compare_and_swap` reports a conflict.
        always_conflict: bool,
        /// A simulated concurrent writer applied just before the first
        /// `compare_and_swap`, to force one conflict-then-retry.
        inject_once: std::sync::Mutex<Option<fn(&mut MinimalSession)>>,
    }

    impl VersioningStore {
        fn with(session: MinimalSession) -> Self {
            Self {
                stored: std::sync::Mutex::new(Some(session)),
                always_conflict: false,
                inject_once: std::sync::Mutex::new(None),
            }
        }
    }

    #[allow(clippy::unused_async_trait_impl)]
    impl ExternalSessionStore for VersioningStore {
        type SessionType = MinimalSession;
        type Error = Infallible;

        async fn insert(&self, s: &MinimalSession) -> Result<(), Infallible> {
            *self.stored.lock().unwrap() = Some(s.clone());
            Ok(())
        }
        async fn load(&self, _: Uuid) -> Result<Option<MinimalSession>, Infallible> {
            Ok(self.stored.lock().unwrap().clone())
        }
        async fn save(&self, s: &MinimalSession) -> Result<(), Infallible> {
            *self.stored.lock().unwrap() = Some(s.clone());
            Ok(())
        }
        async fn compare_and_swap(
            &self,
            s: &MinimalSession,
            expected: i32,
        ) -> Result<SaveOutcome, Infallible> {
            if self.always_conflict {
                return Ok(SaveOutcome::Conflict);
            }
            let mut stored = self.stored.lock().unwrap();
            // A concurrent writer landing just before our CAS.
            if let Some(inject) = self.inject_once.lock().unwrap().take()
                && let Some(cur) = stored.as_mut()
            {
                inject(cur);
            }
            match stored.as_ref() {
                Some(cur) if cur.persisted.version == expected => {
                    *stored = Some(s.clone());
                    Ok(SaveOutcome::Committed)
                }
                _ => Ok(SaveOutcome::Conflict),
            }
        }
        async fn delete(&self, _: &MinimalSession) -> Result<(), Infallible> {
            *self.stored.lock().unwrap() = None;
            Ok(())
        }
    }

    async fn store_over(external: VersioningStore) -> StoreBackedSessionStore<VersioningStore> {
        StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
    }

    #[tokio::test]
    async fn create_freezes_expire_at_from_stamped_policy() {
        let cap = Duration::from_hours(8);
        let mut store = store_over(VersioningStore::with(test_session())).await;
        store.apply_session_policy(true, Some(cap));

        // The deadline is frozen into the record at login (created_at + cap),
        // giving external stores the retention deadline for every write.
        let (session, _cookies) = store
            .create_session(
                &completed_with_email("a@example.com"),
                Duration::from_hours(1),
            )
            .await
            .unwrap();
        assert_eq!(session.expire_at(), Some(session.created_at() + cap));

        // The frozen deadline is preserved through later writes.
        let updated = store
            .update(session.persisted().session_key, |_| {})
            .await
            .unwrap();
        assert_eq!(updated.expire_at(), session.expire_at());
    }

    #[tokio::test]
    async fn create_under_delegated_lifetime_has_no_expire_at() {
        let mut store = store_over(VersioningStore::with(test_session())).await;
        store.apply_session_policy(true, None);

        // Delegated lifetime: the AS bounds the session, so there is no
        // deadline to freeze — and no record TTL for the backend to apply.
        let (session, _cookies) = store
            .create_session(
                &completed_with_email("a@example.com"),
                Duration::from_hours(1),
            )
            .await
            .unwrap();
        assert_eq!(session.expire_at(), None);
    }

    #[tokio::test]
    async fn update_applies_mutation_and_bumps_version() {
        let session = test_session();
        let key = session.persisted.session_key;
        let store = store_over(VersioningStore::with(session)).await;

        let updated = store
            .update(key, |s| s.persisted.state.sub = Some("mine".to_owned()))
            .await
            .unwrap();

        assert_eq!(updated.persisted.state.sub.as_deref(), Some("mine"));
        assert_eq!(updated.persisted.version, 1);
    }

    #[tokio::test]
    async fn update_retries_and_preserves_concurrent_change() {
        let session = test_session(); // version 0
        let key = session.persisted.session_key;
        let mut ext = VersioningStore::with(session);
        // A concurrent writer bumps to v1 and sets `sid` just before our first CAS.
        *ext.inject_once.get_mut().unwrap() = Some(|s| {
            s.persisted.version = s.persisted.version.wrapping_add(1);
            s.persisted.state.sid = Some("concurrent".to_owned());
        });
        let store = store_over(ext).await;

        let updated = store
            .update(key, |s| s.persisted.state.sub = Some("mine".to_owned()))
            .await
            .unwrap();

        // The first CAS conflicts; the reload + replay keeps BOTH changes.
        assert_eq!(updated.persisted.state.sub.as_deref(), Some("mine"));
        assert_eq!(updated.persisted.state.sid.as_deref(), Some("concurrent"));
        assert_eq!(updated.persisted.version, 2);
    }

    #[tokio::test]
    async fn update_exhausts_retries_with_version_conflict() {
        let session = test_session();
        let key = session.persisted.session_key;
        let ext = VersioningStore {
            always_conflict: true,
            ..VersioningStore::with(session)
        };
        let store = store_over(ext).await;

        let result = store
            .update(key, |s| s.persisted.state.sub = Some("x".to_owned()))
            .await;
        let conflicted = result
            .as_ref()
            .err()
            .is_some_and(|e| e.kind() == SessionErrorKind::Conflict);
        assert!(
            conflicted,
            "expected VersionConflict under sustained conflict"
        );
    }

    #[tokio::test]
    async fn try_update_mutation_error_aborts_without_writing() {
        let session = test_session();
        let key = session.persisted.session_key;
        let store = store_over(VersioningStore::with(session)).await;

        let result = store
            .try_update(key, |_| {
                Err(SessionError::new(
                    SessionErrorKind::Store,
                    "app rule violated",
                ))
            })
            .await;
        // The closure's error comes back as-is (the session types here aren't
        // `Debug`, so assert on the `Err` arm directly), and nothing was written.
        let aborted = result
            .as_ref()
            .err()
            .is_some_and(|e| e.kind() == SessionErrorKind::Store);
        assert!(aborted, "closure error must propagate");
        let stored = store.external.stored.lock().unwrap().clone().unwrap();
        assert_eq!(stored.persisted.version, 0, "no write on mutation error");
    }

    #[tokio::test]
    async fn try_update_ok_commits_like_update() {
        let session = test_session();
        let key = session.persisted.session_key;
        let store = store_over(VersioningStore::with(session)).await;

        let updated = store
            .try_update(key, |s| {
                s.persisted.state.sub = Some("mine".to_owned());
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(updated.persisted.state.sub.as_deref(), Some("mine"));
        assert_eq!(updated.persisted.version, 1);
    }

    // ── apply_refresh_and_save (engine refresh persist) ───────────────────

    /// A refresh-style token response with no `expires_in`, so the new expiry
    /// comes from the `default_lifetime` handed to `apply_refresh`.
    fn refresh_token_response() -> TokenResponse {
        huskarl::grant::core::RawTokenResponse::builder()
            .access_token(huskarl::core::secrets::SecretString::new(
                "refreshed-access-token",
            ))
            .token_type("Bearer")
            .build()
            .into_token_response(None, std::time::SystemTime::now())
            .unwrap()
    }

    #[tokio::test]
    async fn refresh_save_preserves_concurrent_update() {
        // The regression this guards: the engine's refresh persist must not
        // write back its request-scoped snapshot wholesale — an `update`
        // committed by another request in the meantime has to survive.
        let session = test_session(); // version 0, no sid
        let mut ext = VersioningStore::with(session.clone());
        // A concurrent writer commits `sid` just before our first CAS.
        *ext.inject_once.get_mut().unwrap() = Some(|s| {
            s.persisted.version = s.persisted.version.wrapping_add(1);
            s.persisted.state.sid = Some("concurrent".to_owned());
        });
        let store = store_over(ext).await;

        let mut snapshot = session;
        let lifetime = Duration::from_hours(2);
        let cookies = store
            .apply_refresh_and_save(
                &mut snapshot,
                &refresh_token_response(),
                lifetime,
                &http::HeaderMap::new(),
            )
            .await
            .unwrap();

        // No Set-Cookie: the pointer cookie is unchanged by a refresh.
        assert!(cookies.is_empty());
        // The caller's session was replaced with the committed merge: the
        // concurrent `sid` write survived AND the refresh was applied.
        assert_eq!(snapshot.persisted.state.sid.as_deref(), Some("concurrent"));
        assert!(
            snapshot.state().token_expiry > std::time::SystemTime::now() + Duration::from_mins(90),
            "refresh must extend token_expiry via default_lifetime"
        );
        assert_eq!(snapshot.persisted.version, 2);
        // The store holds the same merged state.
        let stored = store.external.stored.lock().unwrap().clone().unwrap();
        assert_eq!(stored.persisted.state.sid.as_deref(), Some("concurrent"));
        assert_eq!(stored.persisted.version, 2);
    }

    #[tokio::test]
    async fn refresh_save_failure_applies_refresh_in_memory() {
        // On a persist failure the trait contract is "refresh applied in
        // memory, save owed" — the engine serves the request from `snapshot`
        // and retries via persist_session.
        let session = test_session();
        let ext = VersioningStore {
            always_conflict: true,
            ..VersioningStore::with(session.clone())
        };
        let store = store_over(ext).await;

        let mut snapshot = session;
        let err = store
            .apply_refresh_and_save(
                &mut snapshot,
                &refresh_token_response(),
                Duration::from_hours(2),
                &http::HeaderMap::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.kind(), SessionErrorKind::Conflict);
        assert!(
            snapshot.state().token_expiry > std::time::SystemTime::now() + Duration::from_mins(90),
            "the in-memory session must carry the refreshed tokens"
        );
    }

    #[tokio::test]
    async fn update_missing_session_is_not_found() {
        let ext = VersioningStore {
            stored: std::sync::Mutex::new(None),
            ..VersioningStore::with(test_session())
        };
        let store = store_over(ext).await;

        let result = store.update(Uuid::now_v7(), |_| {}).await;
        let not_found = result
            .as_ref()
            .err()
            .is_some_and(|e| e.kind() == SessionErrorKind::Gone);
        assert!(not_found, "expected SessionNotFound for a missing key");
    }

    #[tokio::test]
    async fn pointer_cookie_roundtrips_uuid() {
        let session = test_session();
        let original_key = session.persisted.session_key;
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();

        // Seal a pointer cookie, then read it back through the request-side path.
        let headers_out = store.pointer_cookie_headers(original_key).await.unwrap();
        // The pointer cookie is the one whose value is non-empty (the kid
        // sidecar is a Max-Age=0 clear for the no-identity test cipher).
        let pointer = headers_out
            .iter()
            .find(|h| {
                let s = h.to_str().unwrap();
                let value_part = s.split(';').next().unwrap();
                let (name, value) = value_part.split_once('=').unwrap();
                name.trim() == "__Host-session" && !value.is_empty()
            })
            .expect("pointer cookie present");
        let cookie_value = pointer
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;
        let mut req_headers = http::HeaderMap::new();
        req_headers.insert(
            http::header::COOKIE,
            format!("__Host-session={cookie_value}").parse().unwrap(),
        );

        let recovered = store
            .read_pointer_cookie(&req_headers)
            .await
            .expect("decodes");
        assert_eq!(recovered, original_key);
    }

    #[tokio::test]
    async fn pointer_cookie_emits_kid_sidecar_when_cipher_has_identity() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher_with_kid("kid-7").await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();

        let headers_out = store
            .pointer_cookie_headers(session.persisted.session_key)
            .await
            .unwrap();
        let expected_value = URL_SAFE_NO_PAD.encode("kid-7".as_bytes());
        let sidecar_set = headers_out.iter().any(|h| {
            let s = h.to_str().unwrap();
            s.starts_with(&format!("__Host-session.kid={expected_value};"))
        });
        assert!(
            sidecar_set,
            "expected kid sidecar set to base64url(identity)"
        );
    }

    #[tokio::test]
    async fn read_pointer_cookie_falls_back_when_kid_names_wrong_configured_key() {
        use huskarl::core::crypto::cipher::{AeadDecryptor, MultiKeyCipher, MultiKeyDecryptor};

        // Rotation-shaped cipher: seals under "v2", unseals under {"v1","v2"}.
        let decryptor = MultiKeyDecryptor::new(vec![
            Arc::new(aes_key_with_kid("v1", 1).await) as Arc<dyn AeadDecryptor>,
            Arc::new(aes_key_with_kid("v2", 2).await) as Arc<dyn AeadDecryptor>,
        ]);
        let cipher = MultiKeyCipher::new(aes_key_with_kid("v2", 2).await, decryptor);

        let session = test_session();
        let original_key = session.persisted.session_key;
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session))
            .cipher(cipher)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();

        let headers_out = store.pointer_cookie_headers(original_key).await.unwrap();
        let pointer_value = headers_out
            .iter()
            .find_map(|h| {
                let s = h.to_str().ok()?;
                let pair = s.split(';').next()?;
                let (name, value) = pair.split_once('=')?;
                (name.trim() == "__Host-session" && !value.is_empty()).then(|| value.to_owned())
            })
            .expect("pointer cookie present");

        // The sidecar names "v1" while the pointer was sealed under "v2" —
        // the kid is a hint, not a filter, so the read must still succeed.
        let mut req = http::HeaderMap::new();
        req.insert(
            http::header::COOKIE,
            format!(
                "__Host-session={pointer_value}; __Host-session.kid={}",
                encode_kid("v1")
            )
            .parse()
            .unwrap(),
        );
        assert_eq!(store.read_pointer_cookie(&req).await, Some(original_key));
    }

    // ── build_with_claims ─────────────────────────────────────────────────

    /// A store-backed session enriched with an `email` claim. Has no
    /// `From<PersistedSessionState>`, so it can only be built by an enricher
    /// or the synchronous claim-mapper.
    #[derive(Clone)]
    struct EnrichedStoreSession {
        persisted: PersistedSessionState,
        email: String,
    }

    impl Session for EnrichedStoreSession {
        fn state(&self) -> &SessionState {
            self.persisted.state()
        }
        fn set_state(&mut self, s: SessionState) {
            self.persisted.set_state(s);
        }
    }

    impl PersistedSession for EnrichedStoreSession {
        fn persisted(&self) -> &PersistedSessionState {
            &self.persisted
        }
        fn persisted_mut(&mut self) -> &mut PersistedSessionState {
            &mut self.persisted
        }
    }

    /// External store that records the email of the session handed to `insert`,
    /// so the test can confirm the claim-mapper ran before persistence.
    struct EnrichedExternalStore(std::sync::Arc<std::sync::Mutex<Option<String>>>);

    // Test stub: the async method signatures are mandated by the trait; the
    // bodies are synchronous.
    #[allow(clippy::unused_async_trait_impl)]
    impl ExternalSessionStore for EnrichedExternalStore {
        type SessionType = EnrichedStoreSession;
        type Error = Infallible;

        async fn insert(&self, s: &EnrichedStoreSession) -> Result<(), Infallible> {
            *self.0.lock().unwrap() = Some(s.email.clone());
            Ok(())
        }
        async fn load(&self, _: Uuid) -> Result<Option<EnrichedStoreSession>, Infallible> {
            Ok(None)
        }
        async fn save(&self, _: &EnrichedStoreSession) -> Result<(), Infallible> {
            Ok(())
        }
        async fn compare_and_swap(
            &self,
            _: &EnrichedStoreSession,
            _: i32,
        ) -> Result<SaveOutcome, Infallible> {
            Ok(SaveOutcome::Committed)
        }
        async fn delete(&self, _: &EnrichedStoreSession) -> Result<(), Infallible> {
            Ok(())
        }
    }

    /// A completed login carrying an `email` profile claim.
    fn completed_with_email(email: &str) -> crate::CompletedLogin {
        let token_response = huskarl::grant::core::RawTokenResponse::builder()
            // A fixture token value, not a key — `SecretString::new` is the
            // value wrapper, distinct from the `Secret` key-source layer.
            .access_token(huskarl::core::secrets::SecretString::new("access-token"))
            .token_type("Bearer")
            .build()
            .into_token_response(None, std::time::SystemTime::now())
            .unwrap();
        let mut claims = huskarl::token::id_token::IdTokenClaims::default();
        claims.profile.email = Some(email.to_owned());
        crate::CompletedLogin::builder()
            .token_response(token_response)
            .id_token_claims(claims)
            .build()
    }

    #[tokio::test]
    async fn build_with_claims_maps_claims_and_inserts() {
        // Same closure shape as the cookie store, only the seed type differs
        // (PersistedSessionState) — the uniformity the finisher is meant to
        // preserve.
        let inserted = std::sync::Arc::new(std::sync::Mutex::new(None));
        let store = StoreBackedSessionStore::builder()
            .external(EnrichedExternalStore(inserted.clone()))
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build_with_claims(|seed, completed| {
                Ok(EnrichedStoreSession {
                    persisted: seed,
                    email: completed
                        .id_token_claims()
                        .and_then(|c| c.profile.email.clone())
                        .ok_or_else(|| {
                            SessionError::new(SessionErrorKind::Store, "missing email claim")
                        })?,
                })
            });

        let (session, cookies) = store
            .create_session(
                &completed_with_email("user@example.com"),
                Duration::from_hours(1),
            )
            .await
            .expect("create succeeds");
        assert_eq!(session.email, "user@example.com");
        // The enriched session reached the external store, and a pointer
        // cookie was emitted.
        assert_eq!(
            inserted.lock().unwrap().as_deref(),
            Some("user@example.com")
        );
        assert!(!cookies.is_empty(), "pointer cookie emitted");
    }

    #[tokio::test]
    async fn build_with_claims_error_fails_session_creation() {
        let store = StoreBackedSessionStore::builder()
            .external(EnrichedExternalStore(std::sync::Arc::new(
                std::sync::Mutex::new(None),
            )))
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build_with_claims(|_seed, _completed| {
                Err(SessionError::new(
                    SessionErrorKind::Store,
                    "enrichment boom",
                ))
            });
        // The session types here aren't `Debug`, so assert on the `Err` arm
        // directly rather than via `expect_err`.
        let result = store
            .create_session(
                &completed_with_email("user@example.com"),
                Duration::from_hours(1),
            )
            .await;
        assert!(
            matches!(&result, Err(e)
                if e.kind() == SessionErrorKind::Store
                    && std::error::Error::source(e)
                        .is_some_and(|s| s.to_string().contains("enrichment boom"))),
            "enricher error must propagate",
        );
    }

    #[tokio::test]
    async fn session_aead_cipher_returns_the_configured_cipher() {
        // The accessor a convenience layer uses to default the login-state
        // cipher: it must hand back the store's actual configured cipher
        // (matched here by reported key id), not a re-wrapped or empty one.
        use huskarl::core::crypto::cipher::AeadEncryptor as _;
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session))
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();
        let cipher = SessionDriver::session_aead_cipher(&store);
        assert_eq!(cipher.key_id().as_deref(), Some("v5"));
    }

    #[tokio::test]
    async fn delete_clears_pointer_and_kid_sidecar() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();

        let clears = store.delete_session(&session).await.unwrap();
        let bare = clears.iter().any(|h| {
            let s = h.to_str().unwrap();
            s.starts_with("__Host-session=;") && s.contains("Max-Age=0")
        });
        let kid = clears.iter().any(|h| {
            let s = h.to_str().unwrap();
            s.starts_with("__Host-session.kid=;") && s.contains("Max-Age=0")
        });
        assert!(bare, "expected pointer cookie clear");
        assert!(kid, "expected kid sidecar clear");
    }

    // ── SessionCookieMetrics ──────────────────────────────────────────────

    use std::sync::{Arc, Mutex};

    use crate::metrics::{DecryptResult, SessionCookieMetrics};

    #[derive(Default)]
    struct RecordingMetrics {
        encrypts: Mutex<Vec<Option<String>>>,
        decrypts: Mutex<Vec<(Option<String>, &'static str)>>,
    }

    impl SessionCookieMetrics for RecordingMetrics {
        fn record_decrypt(&self, _: &str, kid: Option<&str>, result: &DecryptResult) {
            self.decrypts
                .lock()
                .unwrap()
                .push((kid.map(str::to_owned), result.as_str()));
        }
        fn record_encrypt(&self, _: &str, kid: Option<&str>) {
            self.encrypts.lock().unwrap().push(kid.map(str::to_owned));
        }
    }

    impl RecordingMetrics {
        fn encrypts(&self) -> Vec<Option<String>> {
            self.encrypts.lock().unwrap().clone()
        }
        fn decrypts(&self) -> Vec<(Option<String>, &'static str)> {
            self.decrypts.lock().unwrap().clone()
        }
    }

    fn test_session_and_store() -> (MinimalSession, MinimalExternalStore) {
        let s = test_session();
        (s.clone(), MinimalExternalStore(s))
    }

    #[tokio::test]
    async fn metrics_pointer_cookie_records_encrypt() {
        let (session, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        store
            .pointer_cookie_headers(session.persisted.session_key)
            .await
            .unwrap();
        assert_eq!(m.encrypts(), vec![None]);
    }

    #[tokio::test]
    async fn metrics_pointer_cookie_records_kid_when_cipher_has_identity() {
        let (session, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        store
            .pointer_cookie_headers(session.persisted.session_key)
            .await
            .unwrap();
        assert_eq!(m.encrypts(), vec![Some("v5".to_owned())]);
    }

    #[tokio::test]
    async fn metrics_read_pointer_cookie_absent_is_silent() {
        let (_, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        store.read_pointer_cookie(&http::HeaderMap::new()).await;
        assert!(m.decrypts().is_empty());
    }

    #[tokio::test]
    async fn metrics_read_pointer_cookie_bad_encoding() {
        let (_, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "__Host-session=not!!valid!!base64".parse().unwrap(),
        );
        store.read_pointer_cookie(&headers).await;
        assert_eq!(m.decrypts(), vec![(None, "bad_encoding")]);
    }

    #[tokio::test]
    async fn metrics_read_pointer_cookie_tampered_records_decrypt_failed() {
        let (_, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "__Host-session=AAAAAAAAAAAA".parse().unwrap(),
        );
        store.read_pointer_cookie(&headers).await;
        assert_eq!(m.decrypts(), vec![(None, "decrypt_failed")]);
    }

    #[tokio::test]
    async fn metrics_read_pointer_cookie_payload_invalid_when_not_16_bytes() {
        let (_, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        // Seal 17 bytes under session_ptr AAD — AEAD passes but the UUID
        // conversion ([u8; 16]) fails, exercising PayloadInvalid.
        let bundle = AeadV1Cipher::new(test_cipher().await)
            .seal(&[0u8; 17], &store.sealer.aad("session_ptr"))
            .await
            .unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&bundle);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!("__Host-session={encoded}").parse().unwrap(),
        );
        store.read_pointer_cookie(&headers).await;
        assert_eq!(m.decrypts(), vec![(None, "payload_invalid")]);
    }

    #[tokio::test]
    async fn metrics_read_pointer_cookie_success_records_ok_with_kid() {
        let (session, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        let headers_out = store
            .pointer_cookie_headers(session.persisted.session_key)
            .await
            .unwrap();
        // Simulate the browser sending back both the pointer cookie and the kid sidecar.
        let pairs: String = headers_out
            .iter()
            .filter_map(|h| {
                let s = h.to_str().ok()?;
                let pair = s.split(';').next()?;
                let (_, v) = pair.split_once('=')?;
                (!v.is_empty()).then(|| pair.to_owned())
            })
            .collect::<Vec<_>>()
            .join("; ");
        let mut req = http::HeaderMap::new();
        if !pairs.is_empty() {
            req.insert(http::header::COOKIE, pairs.parse().unwrap());
        }
        store.read_pointer_cookie(&req).await;
        assert_eq!(m.decrypts(), vec![(Some("v5".to_owned()), "ok")]);
    }

    #[tokio::test]
    async fn metrics_read_pointer_cookie_forged_kid_is_normalized_to_unknown() {
        // The sidecar is client-supplied: a pointer sealed under "v5" carrying
        // an attacker-chosen kid must not let that value reach the metrics
        // label. The read still succeeds (kid is a hint, not a filter), but the
        // label collapses to "unknown".
        let (session, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        let headers_out = store
            .pointer_cookie_headers(session.persisted.session_key)
            .await
            .unwrap();
        let pointer_value = headers_out
            .iter()
            .find_map(|h| {
                let s = h.to_str().ok()?;
                let pair = s.split(';').next()?;
                let (name, v) = pair.split_once('=')?;
                (name.trim() == "__Host-session" && !v.is_empty()).then(|| v.to_owned())
            })
            .expect("pointer cookie present");
        let mut req = http::HeaderMap::new();
        req.insert(
            http::header::COOKIE,
            format!(
                "__Host-session={pointer_value}; __Host-session.kid={}",
                encode_kid("totally-bogus")
            )
            .parse()
            .unwrap(),
        );
        store.read_pointer_cookie(&req).await;
        assert_eq!(m.decrypts(), vec![(Some("unknown".to_owned()), "ok")]);
    }
}
