//! External-store-backed session storage.
//!
//! [`StoreBackedSessionStore`] keeps an encrypted pointer cookie in the browser
//! and delegates actual session data to an [`ExternalSessionStore`] (Redis, a
//! database, etc.). After a login, the attached
//! [`SessionEnricher`](crate::SessionEnricher) builds the store's `Session`
//! type from the framework-prepared [`PersistedSessionState`] seed; the
//! external store then persists it.

use std::{borrow::Cow, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderValue;
use huskarl::core::{
    crypto::cipher::{AeadCipher, AeadEncryptor as _, AeadSealer as _, AeadV1Cipher, CipherMatch},
    platform::{MaybeSend, MaybeSendSync, SystemTime},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    cookie::{
        DEFAULT_COOKIE_MAX_AGE, SessionCipher, cookie_attrs, encode_kid, get_cookie,
        get_kid_cookie, kid_cookie_name, normalize_kid_label, session_cookie_name,
        unseal_with_kid_fallback,
    },
    enrich::{NoEnrichment, SessionEnricher},
    liveness::{LivenessConfig, LivenessStore, LivenessVerdict},
    metrics::{DecryptResult, SessionCookieMetrics},
    session::{SessionDriver, SessionError, to_session_err},
    session_state::{Session, SessionState},
};

/// Trait for external session data stores (Redis, database, etc.).
///
/// This trait is **pure storage**: insert, load, save, touch, delete. The
/// cookie mechanics (pointer cookie encryption, session key generation) are
/// handled by [`StoreBackedSessionStore`], and session *construction* from a
/// completed login is handled by the
/// [`SessionEnricher`](crate::SessionEnricher) attached to the store — the
/// same hook cookie sessions use.
///
/// The associated [`Session`](Self::SessionType) type is what the middleware works
/// with after login. For the simplest case, use [`PersistedSessionState`]
/// directly. For enriched sessions (e.g. with user profile data), define a
/// custom type that implements [`Session`] and [`PersistedSession`], embedding
/// a `PersistedSessionState`, and build it with a `SessionEnricher`.
pub trait ExternalSessionStore: MaybeSendSync {
    /// The session type returned by this store.
    ///
    /// Must implement [`Session`] so the middleware can inspect token expiry,
    /// refresh tokens, etc., and [`PersistedSession`] so the framework can
    /// reach the embedded [`PersistedSessionState`] (session key plus any
    /// future framework-managed fields).
    type SessionType: Session + PersistedSession + MaybeSendSync + 'static;

    /// The error type returned by store operations.
    type Error: std::error::Error + MaybeSendSync + 'static;

    /// Persist a newly created session.
    ///
    /// Called once per login, after the
    /// [`SessionEnricher`](crate::SessionEnricher) has built the session.
    /// Everything the store needs to persist should be carried on the session
    /// type itself — claim mapping and `UserInfo` lookups belong in the
    /// enricher, not here.
    fn insert(
        &self,
        session: &Self::SessionType,
    ) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;

    /// Load a session by its key. Returns `None` if the key does not exist.
    ///
    /// The key is a `UUIDv7` — passed by value because `Uuid` is `Copy` and
    /// 16 bytes. Implementations that key records by string form should call
    /// `session_key.to_string()` (or `as_simple()` for a hyphen-free form).
    fn load(
        &self,
        session_key: Uuid,
    ) -> impl Future<Output = Result<Option<Self::SessionType>, Self::Error>> + MaybeSend;

    /// Save a session unconditionally, advancing the stored
    /// [`version`](PersistedSessionState::version).
    ///
    /// This is the *last-writer-wins* path used for ambient writes (e.g. the
    /// engine persisting refreshed tokens); a concurrent writer's changes can
    /// be overwritten. For mutations that must not be lost under concurrency,
    /// use [`StoreBackedSessionStore::update`], which goes through
    /// [`compare_and_swap`](Self::compare_and_swap). Bumping the version here
    /// (typically `version + 1`) is what lets a concurrent `update` notice this
    /// write and retry.
    ///
    /// Set the record's storage TTL to the deployment's `max_lifetime` (the
    /// absolute session cap). Idle expiry is no longer this store's concern —
    /// activity is tracked separately by a [`LivenessStore`](crate::LivenessStore),
    /// so there is nothing to extend here per-request.
    fn save(
        &self,
        session: &Self::SessionType,
    ) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;

    /// Save `session` only if the stored
    /// [`version`](PersistedSessionState::version) still equals `expected`,
    /// advancing it on success. Returns [`SaveOutcome::Conflict`] (no write)
    /// when another writer has since advanced the version.
    ///
    /// This is the compare-and-swap primitive behind
    /// [`StoreBackedSessionStore::update`]; the retry loop lives there, so an
    /// implementation only needs the conditional write:
    ///
    /// - SQL: `UPDATE … SET data = ?, version = version + 1 WHERE key = ? AND version = ?`
    ///   — zero rows affected means [`Conflict`](SaveOutcome::Conflict).
    /// - Dynamo: a conditional write with `ConditionExpression: version = :expected`.
    /// - Mongo: `findOneAndUpdate({key, version}, {$set, $inc: {version: 1}})`.
    /// - Redis: `WATCH` the key (or a small Lua CAS).
    ///
    /// The version is compared by **equality only** (never ordered), so a
    /// `version + 1` that wraps is harmless — see
    /// [`PersistedSessionState::version`].
    fn compare_and_swap(
        &self,
        session: &Self::SessionType,
        expected: i32,
    ) -> impl Future<Output = Result<SaveOutcome, Self::Error>> + MaybeSend;

    /// Delete a session.
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
    /// Another writer advanced the version first; nothing was written. The
    /// caller should reload and retry.
    Conflict,
}

/// [`StoreBackedSessionStore::update`] found no session for the key — it was
/// deleted or expired before the update could run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionNotFound;

impl std::fmt::Display for SessionNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("session not found")
    }
}

impl std::error::Error for SessionNotFound {}

/// [`StoreBackedSessionStore::update`] exhausted its retry budget — the session
/// was concurrently rewritten on every attempt. The caller can retry the whole
/// operation or surface a conflict (e.g. HTTP 409) to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionConflict;

impl std::fmt::Display for VersionConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("session update conflict: the session was modified concurrently")
    }
}

impl std::error::Error for VersionConflict {}

/// Framework-managed session state carried by every store-backed session.
///
/// Contains the session key, session state, and any future framework-managed
/// fields (e.g. step-up auth timestamp, MFA assertions, revocation versions).
/// Built by the framework and passed as the *seed* to the
/// [`SessionEnricher`](crate::SessionEnricher) after a successful login.
///
/// The struct is `#[non_exhaustive]` so new framework-managed fields can be
/// added in a minor release without breaking store implementations.
///
/// For simple stores that don't need to enrich sessions, use
/// `PersistedSessionState` directly as your [`ExternalSessionStore::SessionType`]
/// type. For enriched sessions, embed this in your custom type and implement
/// [`PersistedSession`] (and [`Session`]) by forwarding to the embedded value.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, bon::Builder)]
pub struct PersistedSessionState {
    /// The random session key used as the primary lookup key in the external
    /// store. A time-ordered `UUIDv7`.
    pub session_key: Uuid,
    /// Shared token and timing state. See [`SessionState`] for the field set.
    pub state: SessionState,
    /// Optimistic-concurrency version, advanced on every write. `0` at insert;
    /// set by the store on [`load`](ExternalSessionStore::load).
    ///
    /// Used by [`StoreBackedSessionStore::update`] to detect a concurrent
    /// writer: the update reloads and replays its mutation when the stored
    /// version no longer matches the one it loaded. Compared **by equality
    /// only**, never ordered — so its signedness is immaterial and the
    /// `wrapping_add` increment (unreachable short of 2³¹ writes to one session)
    /// is harmless.
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

/// Trait implemented by every store-backed session type, exposing the
/// embedded [`PersistedSessionState`] to the framework.
///
/// `PersistedSessionState` carries the session key plus any framework-managed
/// fields. Requiring this trait on `ExternalSessionStore::SessionType` lets the
/// framework rely on those fields being present without store implementations
/// having to opt in per-capability.
///
/// The default implementation on `PersistedSessionState` itself is trivial;
/// enriched session types implement this by forwarding to their embedded
/// `PersistedSessionState` field.
///
/// # Accessor style
///
/// This trait deliberately differs from [`Session`]'s accessors. [`Session`]
/// uses `state()`/`set_state(value)` — whole-value replacement — because its
/// callers model application-visible *events* (refresh, activity) that
/// produce a new [`SessionState`], matching the load→transform→save flow
/// distributed stores need. `PersistedSession` instead provides
/// `persisted()`/`persisted_mut()` — structural access — because it is
/// framework plumbing: the framework reads and updates individual fields of
/// its own struct (the session key today; step-up/MFA fields later) without
/// every session type having to mirror per-field setters.
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
/// before giving up with [`VersionConflict`]. Five absorbs realistic
/// contention; sustained failure past it signals a hot key worth surfacing.
const UPDATE_MAX_ATTEMPTS: u32 = 5;

/// A session store that keeps an encrypted pointer cookie in the browser and
/// stores session data in an external [`ExternalSessionStore`].
///
/// The pointer cookie contains the encrypted session key (a random string).
/// The actual session data is stored via the external store.
///
/// The session is built after a completed login by a [`SessionEnricher`]
/// from the framework-prepared [`PersistedSessionState`] seed. The builder's
/// `build()` finisher uses [`NoEnrichment`], which converts the seed via
/// `From` — covering `SessionType = PersistedSessionState` (and any session
/// type implementing `From<PersistedSessionState>`). For sessions needing
/// claims or I/O, supply an enricher via the `build_with_enricher(…)`
/// finisher.
///
/// The `Secure` attribute and cookie-name prefix follow the deployment's
/// browser-facing scheme, which the engine derives from
/// [`LoginConfig::base_url`](crate::LoginConfig::base_url) and stamps onto the
/// store at construction (see
/// [`SessionDriver::apply_cookie_secure`](crate::SessionDriver::apply_cookie_secure)).
/// This store therefore takes no `secure` setting of its own. When that
/// derived value is secure and `cookie_path` is `"/"`, the configured cookie
/// name is automatically given the `__Host-` prefix (unless it already
/// starts with `__Host-` or `__Secure-`). The prefix makes the browser
/// reject the cookie if set by a sibling subdomain or over plain HTTP,
/// blocking session fixation by cookie tossing. Note that switching a
/// deployment from `http` to `https` renames the cookie: in-flight sessions
/// under the old name are ignored and users re-login on their next navigation.
pub struct StoreBackedSessionStore<E: ExternalSessionStore> {
    external: E,
    enricher: Box<dyn SessionEnricher<PersistedSessionState, E::SessionType>>,
    cipher: SessionCipher,
    /// The raw cipher behind [`cipher`](Self::cipher), retained so the store
    /// can hand it back via
    /// [`SessionDriver::session_aead_cipher`](crate::SessionDriver::session_aead_cipher)
    /// without re-wrapping it in the v1 bundle envelope.
    aead: Arc<dyn AeadCipher>,
    /// The configured cookie name, before any security prefix is applied.
    /// Retained so [`apply_cookie_secure`](SessionDriver::apply_cookie_secure)
    /// can recompute `cookie_name` once the engine supplies the deployment's
    /// `secure` flag.
    raw_cookie_name: String,
    cookie_name: String,
    secure: bool,
    cookie_path: String,
    max_age: Duration,
    metrics: Option<Arc<dyn SessionCookieMetrics>>,
    /// Optional server-side liveness (idle) tracking. `None` means idle timeout
    /// is not enforced and activity is not recorded. Attached post-construction
    /// via [`with_liveness`](Self::with_liveness) so it does not change the
    /// store's type.
    liveness: Option<(Box<dyn LivenessStore>, LivenessConfig)>,
}

#[bon::bon]
impl<E: ExternalSessionStore> StoreBackedSessionStore<E> {
    /// Creates a new store-backed session store. Finish the builder with
    /// `build()` (uses [`NoEnrichment`]; requires
    /// `E::SessionType: From<PersistedSessionState>`) or
    /// `build_with_enricher(…)` to attach an async [`SessionEnricher`].
    #[builder(state_mod(name = "store_builder"), finish_fn(vis = "", name = build_internal))]
    pub fn new(
        #[builder(finish_fn)] enricher: Box<
            dyn SessionEnricher<PersistedSessionState, E::SessionType>,
        >,
        external: E,
        #[builder(with = |cipher: impl AeadCipher + 'static| Arc::new(cipher) as Arc<dyn AeadCipher>)]
        cipher: Arc<dyn AeadCipher>,
        #[builder(into)] cookie_name: String,
        #[builder(into)] cookie_path: String,
        /// Defaults to 400 days. If `max_lifetime` is configured in `LoginConfig`,
        /// pass it here so the browser discards the cookie when the session can
        /// no longer be valid.
        #[builder(default = DEFAULT_COOKIE_MAX_AGE)]
        max_age: Duration,
        /// Optional metrics observer for encrypt/decrypt events.
        metrics: Option<Arc<dyn SessionCookieMetrics>>,
    ) -> Self {
        // `secure` is supplied by the engine via `apply_cookie_secure` once it
        // knows the deployment's `base_url` scheme. Until then default to the
        // safe choice (secure, `__Host-` prefix); the engine re-derives the
        // cookie name when it stamps the real value.
        let secure = true;
        let raw_cookie_name = cookie_name;
        let cookie_name = session_cookie_name(raw_cookie_name.clone(), secure, &cookie_path);
        Self {
            external,
            enricher,
            aead: cipher.clone(),
            cipher: AeadV1Cipher::new(cipher),
            raw_cookie_name,
            cookie_name,
            secure,
            cookie_path,
            max_age,
            metrics,
            liveness: None,
        }
    }
}

impl<E: ExternalSessionStore, S: store_builder::IsComplete> StoreBackedSessionStoreBuilder<E, S> {
    /// Finishes the builder with the default [`NoEnrichment`] enricher, which
    /// converts the [`PersistedSessionState`] seed into the session via `From`.
    #[must_use]
    pub fn build(self) -> StoreBackedSessionStore<E>
    where
        E::SessionType: From<PersistedSessionState>,
    {
        self.build_internal(Box::new(NoEnrichment))
    }

    /// Finishes the builder with a custom [`SessionEnricher`], for sessions
    /// that need ID token claims or I/O (e.g. the OIDC `UserInfo` endpoint)
    /// to construct. See [`SessionEnricher`] for examples (the seed type here
    /// is [`PersistedSessionState`]).
    #[must_use]
    pub fn build_with_enricher(
        self,
        enricher: impl SessionEnricher<PersistedSessionState, E::SessionType> + 'static,
    ) -> StoreBackedSessionStore<E> {
        self.build_internal(Box::new(enricher))
    }

    /// Finishes the builder with a synchronous claim-mapper: build the session
    /// from the [`PersistedSessionState`] seed and the
    /// [`CompletedLogin`](crate::CompletedLogin) (e.g.
    /// copy ID token claims) without I/O. For enrichment that must `await` —
    /// such as the OIDC `UserInfo` endpoint — use
    /// [`build_with_enricher`](Self::build_with_enricher) instead; for sessions
    /// built from the seed alone, use [`build`](Self::build).
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
    ///
    /// Delegates to
    /// [`AeadEncryptor::key_id`](huskarl::core::crypto::cipher::AeadEncryptor::key_id).
    /// Once reload support is added to `AeadCipher`, this will reflect the key
    /// that will be used for the **next** seal operation — suitable for
    /// updating an active-key gauge from a reload callback.
    pub fn key_id(&self) -> Option<Cow<'_, str>> {
        self.cipher.key_id()
    }

    /// Attach server-side liveness (idle-timeout) tracking, backed by the given
    /// [`LivenessStore`] and configured by `config`.
    ///
    /// Liveness is server-side only and keyed by the session's `Uuid`, so it is
    /// available only on store-backed sessions — there is no cookie-session
    /// equivalent. The store may be a different (cheaper) backend than the
    /// session store; see [`crate::liveness`] for the fail-open / monotonic
    /// contract. Returns `self` so it chains after the builder, without changing
    /// the store's type.
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
    /// writes (optimistic concurrency control).
    ///
    /// Loads the session, runs `mutate` on it, and writes it back only if no
    /// other writer changed it in between (via
    /// [`compare_and_swap`](ExternalSessionStore::compare_and_swap)). On a
    /// conflict it reloads the latest state and **runs `mutate` again**, so the
    /// concurrent change is preserved rather than clobbered. Returns the
    /// committed session.
    ///
    /// Use this for any session mutation that must not be lost under
    /// concurrency — step-up state, stored tokens, counters, app data touched by
    /// more than one request. Ambient writes (the engine persisting refreshed
    /// tokens) go through [`save`](ExternalSessionStore::save) and remain
    /// last-writer-wins.
    ///
    /// # The closure must be replayable
    ///
    /// `mutate` may run more than once, each time against freshly-loaded state,
    /// so it must compute the new state *from the session it is given* — set a
    /// field, append to the loaded collection, recompute from current values.
    /// It must not apply a value captured before the load or accumulate across
    /// calls, or a retry will produce the wrong result.
    ///
    /// # Errors
    ///
    /// - [`SessionNotFound`] if the key has no session (deleted/expired).
    /// - [`VersionConflict`] if the retry budget is exhausted under sustained
    ///   contention.
    /// - the store's error (boxed into [`SessionError`]) on a transport failure.
    pub async fn update<F>(
        &self,
        session_key: Uuid,
        mutate: F,
    ) -> Result<E::SessionType, SessionError>
    where
        F: Fn(&mut E::SessionType) + MaybeSend,
    {
        for _ in 0..UPDATE_MAX_ATTEMPTS {
            let Some(mut session) = self
                .external
                .load(session_key)
                .await
                .map_err(to_session_err)?
            else {
                return Err(Box::new(SessionNotFound));
            };
            let expected = session.persisted().version;
            mutate(&mut session);
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
        Err(Box::new(VersionConflict))
    }

    fn base_cookie_attrs(&self) -> String {
        cookie_attrs(self.secure, &self.cookie_path)
    }

    fn cookie_attrs(&self) -> String {
        format!(
            "{}; Max-Age={}",
            self.base_cookie_attrs(),
            self.max_age.as_secs()
        )
    }

    /// Encrypt the pointer cookie and emit it alongside the kid sidecar.
    ///
    /// The plaintext is the UUID's 16 raw bytes — not the 36-byte hyphenated
    /// string form. This is the same compact representation Postgres uses
    /// for its `uuid` type, and saves ~27 bytes off the wire on every
    /// authenticated request once AEAD overhead and base64 expansion are
    /// accounted for.
    ///
    /// The kid sidecar is set when the sealer reports an active identity, and
    /// emitted as a `Max-Age=0` clear otherwise. The sidecar lets the unsealer
    /// skip trial-decrypt when multiple keys are configured; absence (or any
    /// corruption) degrades gracefully to trial-decrypt.
    async fn pointer_cookie_headers(
        &self,
        session_key: Uuid,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        let bundle = self
            .cipher
            .seal(session_key.as_bytes(), b"session_ptr")
            .await
            .map_err(to_session_err)?;
        // See cookie_session.rs for the rationale on reading `key_id()` from
        // the same cipher that just sealed the bundle: stable for single-key
        // ciphers; if multi-key sealers land, switch to `AeadCipherSelector`.
        let kid = self.cipher.key_id();
        if let Some(m) = &self.metrics {
            m.record_encrypt(&self.cookie_name, kid.as_deref());
        }
        let cookie_value = URL_SAFE_NO_PAD.encode(&bundle);
        let attrs = self.cookie_attrs();
        let pointer =
            HeaderValue::from_str(&format!("{}={cookie_value}; {attrs}", self.cookie_name))
                .map_err(to_session_err)?;
        let kid_header = self.build_kid_header(kid.as_deref())?;
        Ok(vec![pointer, kid_header])
    }

    /// Builds the `Set-Cookie` for the kid sidecar (or a `Max-Age=0` clear
    /// when no identity is available — see [`Self::pointer_cookie_headers`]).
    fn build_kid_header(&self, kid: Option<&str>) -> Result<HeaderValue, SessionError> {
        let name = kid_cookie_name(&self.cookie_name);
        let value = match kid {
            Some(k) => format!("{name}={}; {}", encode_kid(k), self.cookie_attrs()),
            None => format!("{name}=; {}; Max-Age=0", self.base_cookie_attrs()),
        };
        HeaderValue::from_str(&value).map_err(to_session_err)
    }

    /// Read and decrypt the pointer cookie to get the session key.
    async fn read_pointer_cookie(&self, headers: &http::HeaderMap) -> Option<Uuid> {
        let encoded = get_cookie(headers, &self.cookie_name)?;

        // A pointer-cookie-shaped value is present — record the outcome.
        let kid = get_kid_cookie(headers, &self.cookie_name);

        let Ok(bundle) = URL_SAFE_NO_PAD.decode(encoded) else {
            self.record_decrypt(kid.as_deref(), &DecryptResult::BadEncoding);
            return None;
        };
        let cipher_match = kid
            .as_deref()
            .map(|k| CipherMatch::builder().kid(k).build());
        let Some(plaintext) =
            unseal_with_kid_fallback(&self.cipher, cipher_match.as_ref(), &bundle, b"session_ptr")
                .await
        else {
            self.record_decrypt(kid.as_deref(), &DecryptResult::DecryptFailed);
            return None;
        };
        // Must be exactly 16 bytes (UUID); anything else is a corrupted cookie.
        if let Ok(bytes) = <[u8; 16]>::try_from(plaintext) {
            self.record_decrypt(kid.as_deref(), &DecryptResult::Ok);
            Some(Uuid::from_bytes(bytes))
        } else {
            self.record_decrypt(kid.as_deref(), &DecryptResult::PayloadInvalid);
            None
        }
    }

    fn record_decrypt(&self, kid: Option<&str>, result: &DecryptResult) {
        // The kid comes from the client-supplied sidecar cookie; bound it to a
        // configured key (or "unknown") before it becomes a metrics label.
        let label = normalize_kid_label(&*self.aead, &self.cookie_name, kid);
        if let Some(m) = &self.metrics {
            m.record_decrypt(&self.cookie_name, label, result);
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
            state: SessionState::from_completed(completed, default_lifetime),
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
        let clear_attrs = format!("{}; Max-Age=0", self.base_cookie_attrs());
        let mut headers = Vec::new();
        if let Ok(v) = HeaderValue::from_str(&format!("{}=; {clear_attrs}", self.cookie_name)) {
            headers.push(v);
        }
        let kid_name = kid_cookie_name(&self.cookie_name);
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

    fn apply_cookie_secure(&mut self, secure: bool) {
        self.secure = secure;
        self.cookie_name =
            session_cookie_name(self.raw_cookie_name.clone(), secure, &self.cookie_path);
    }

    fn session_aead_cipher(&self) -> Arc<dyn AeadCipher> {
        self.aead.clone()
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
        // Idle enforcement degrades to `max_lifetime` until the store recovers.
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

    use huskarl::core::{
        Error,
        platform::MaybeSendBoxFuture,
        secrets::{Secret, SecretBytes, SecretOutput},
    };
    use huskarl_crypto_native::aead::{AesGcmKey, AesGcmKeyType};

    use super::*;
    use crate::session_state::{Session, SessionState};

    #[derive(Clone)]
    struct TestSecret(SecretBytes);

    impl Secret for TestSecret {
        type Output = SecretBytes;
        fn get_secret_value(
            &self,
        ) -> MaybeSendBoxFuture<'_, Result<SecretOutput<SecretBytes>, Error>> {
            let out = SecretOutput {
                value: self.0.clone(),
                identity: None,
            };
            Box::pin(async move { Ok(out) })
        }
    }

    async fn test_cipher() -> AesGcmKey {
        AesGcmKey::from_secret(
            AesGcmKeyType::Aes256,
            TestSecret(SecretBytes::new(vec![0u8; 32])),
            |_| None,
        )
        .await
        .unwrap()
    }

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

    /// Builds `MinimalSession` (a wrapper around the seed) from the
    /// framework-prepared `PersistedSessionState` — the store-backed analogue
    /// of a cookie-session enricher.
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
            .cookie_name("session")
            .cookie_path("/")
            .build_with_enricher(MinimalEnricher);
        assert_session_driver(&store);
    }

    /// In-memory [`LivenessStore`] that records every write, shareable so a test
    /// can inspect the entries after handing a clone to `with_liveness`.
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
            .cookie_name("session")
            .cookie_path("/")
            .build()
            .with_liveness(liveness, config)
    }

    #[tokio::test]
    async fn without_liveness_is_untracked() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher().await)
            .cookie_name("session")
            .cookie_path("/")
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
            .build();
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
            Box::pin(async { Err("liveness backend down".into()) })
        }
        fn touch(
            &self,
            _key: Uuid,
            _now: SystemTime,
            _expire_at: Option<SystemTime>,
        ) -> MaybeSendBoxFuture<'_, Result<(), SessionError>> {
            Box::pin(async { Err("liveness backend down".into()) })
        }
        fn clear(&self, _key: Uuid) -> MaybeSendBoxFuture<'_, Result<(), SessionError>> {
            Box::pin(async { Err("liveness backend down".into()) })
        }
    }

    #[tokio::test]
    async fn liveness_read_failure_fails_open() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher().await)
            .cookie_name("session")
            .cookie_path("/")
            .build()
            // A short idle timeout that *would* expire if the read succeeded.
            .with_liveness(
                FailingLiveness,
                LivenessConfig::builder()
                    .idle_timeout(Duration::from_secs(1))
                    .build(),
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
            .cookie_name("session")
            .cookie_path("/")
            .build()
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
            stored: std::sync::Mutex::new(Some(session)),
            always_conflict: true,
            inject_once: std::sync::Mutex::new(None),
        };
        let store = store_over(ext).await;

        let result = store
            .update(key, |s| s.persisted.state.sub = Some("x".to_owned()))
            .await;
        let conflicted = result
            .as_ref()
            .err()
            .is_some_and(|e| e.downcast_ref::<VersionConflict>().is_some());
        assert!(
            conflicted,
            "expected VersionConflict under sustained conflict"
        );
    }

    #[tokio::test]
    async fn update_missing_session_is_not_found() {
        let ext = VersioningStore {
            stored: std::sync::Mutex::new(None),
            always_conflict: false,
            inject_once: std::sync::Mutex::new(None),
        };
        let store = store_over(ext).await;

        let result = store.update(Uuid::now_v7(), |_| {}).await;
        let not_found = result
            .as_ref()
            .err()
            .is_some_and(|e| e.downcast_ref::<SessionNotFound>().is_some());
        assert!(not_found, "expected SessionNotFound for a missing key");
    }

    #[tokio::test]
    async fn pointer_cookie_roundtrips_uuid() {
        let session = test_session();
        let original_key = session.persisted.session_key;
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher().await)
            .cookie_name("session")
            .cookie_path("/")
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

    async fn test_cipher_with_kid(kid: &str) -> AesGcmKey {
        let kid_owned = kid.to_owned();
        AesGcmKey::from_secret(
            AesGcmKeyType::Aes256,
            TestSecret(SecretBytes::new(vec![0u8; 32])),
            move |_| Some(kid_owned.clone()),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn pointer_cookie_emits_kid_sidecar_when_cipher_has_identity() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher_with_kid("kid-7").await)
            .cookie_name("session")
            .cookie_path("/")
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
        async fn aes_key_with_kid(kid: &str, byte: u8) -> AesGcmKey {
            let kid_owned = kid.to_owned();
            AesGcmKey::from_secret(
                AesGcmKeyType::Aes256,
                TestSecret(SecretBytes::new(vec![byte; 32])),
                move |_| Some(kid_owned.clone()),
            )
            .await
            .unwrap()
        }
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
            .cookie_name("session")
            .cookie_path("/")
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
            .cookie_name("session")
            .cookie_path("/")
            .build_with_claims(|seed, completed| {
                Ok(EnrichedStoreSession {
                    persisted: seed,
                    email: completed
                        .id_token_claims()
                        .and_then(|c| c.profile.email.clone())
                        .ok_or("missing email claim")?,
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
            .cookie_name("session")
            .cookie_path("/")
            .build_with_claims(|_seed, _completed| Err("enrichment boom".into()));
        // The session types here aren't `Debug`, so assert on the `Err` arm
        // directly rather than via `expect_err`.
        let result = store
            .create_session(
                &completed_with_email("user@example.com"),
                Duration::from_hours(1),
            )
            .await;
        assert!(
            matches!(&result, Err(e) if e.to_string().contains("enrichment boom")),
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
            .cookie_name("session")
            .cookie_path("/")
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
            .cookie_name("session")
            .cookie_path("/")
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
            .cookie_name("session")
            .cookie_path("/")
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
            .cookie_name("session")
            .cookie_path("/")
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
            .cookie_name("session")
            .cookie_path("/")
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
            .cookie_name("session")
            .cookie_path("/")
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
            .cookie_name("session")
            .cookie_path("/")
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
            .cookie_name("session")
            .cookie_path("/")
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        // Seal 17 bytes under session_ptr AAD — AEAD passes but the UUID
        // conversion ([u8; 16]) fails, exercising PayloadInvalid.
        let bundle = AeadV1Cipher::new(test_cipher().await)
            .seal(&[0u8; 17], b"session_ptr")
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
            .cookie_name("session")
            .cookie_path("/")
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
            .cookie_name("session")
            .cookie_path("/")
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
