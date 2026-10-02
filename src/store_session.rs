//! Server-held session storage.
//!
//! [`StoreBackedSessionStore`] keeps an encrypted pointer cookie in the browser
//! and delegates session data to an [`ExternalSessionStore`] (Redis, a database,
//! etc.). This enables server-side revocation, idle tracking, larger sessions,
//! and compare-and-swap updates.

use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use uuid::Uuid;

use crate::{
    client::grant::core::TokenResponse,
    config::RoutePath,
    cookie::{CookieName, CookieSealer, DEFAULT_COOKIE_MAX_AGE, get_cookie},
    core::{
        crypto::seal::AeadSealerUnsealer,
        platform::{MaybeSend, MaybeSendSync, SystemTime},
        prelude::*,
    },
    enrich::{NoEnrichment, SessionEnricher},
    liveness::{LivenessConfig, LivenessStore, LivenessVerdict},
    metrics::{DecryptResult, LivenessFailure, SupersededDeleteResult},
    session::{
        DriverLoad, InvalidSessionReason, SessionDriver, SessionError, SessionErrorKind,
        SessionPolicy, to_session_err,
    },
    session_state::{Session, SessionState, bounded_time_add, storage_deadline},
};

/// Persistence backend for a [`StoreBackedSessionStore`].
///
/// Implement this trait over Redis, SQL, or another server-side store. Its
/// responsibilities are deliberately limited to insert, load,
/// compare-and-swap, delete, and record retention. Session construction is
/// handled by the [`SessionEnricher`] attached to the driver.
///
/// A missing record and a version conflict are normal outcomes, represented
/// by [`LoadOutcome`] and [`SaveOutcome`]. Reserve [`Self::Error`] for backend
/// failures. Every successful write must change [`Self::Version`] and apply
/// the supplied `deadline` as the record's absolute retention deadline.
///
/// ## Versioning contract
///
/// Each record is stored alongside a version — the
/// [`Version`](crate::ExternalSessionStore::Version) associated type — that the
/// store owns entirely. It never appears in the session type; it travels through
/// the trait methods instead:
///
/// - [`load`](crate::ExternalSessionStore::load) returns the stored version with
///   the session, and the driver supplies a loaded version as `expected` when
///   attempting a write.
/// - [`compare_and_swap`](crate::ExternalSessionStore::compare_and_swap) writes
///   only if the stored version still equals `expected`, changing it on success
///   and returning [`SaveOutcome::Conflict`](crate::SaveOutcome) on a version
///   mismatch or [`SaveOutcome::Missing`](crate::SaveOutcome) if the row is gone.
///   Never insert a missing row: logout must not be undone by an in-flight write.
///
/// Version is compared by **equality only**, so any per-write-unique value works:
/// an integer column you `+ 1` on write, a database row version (e.g. Postgres
/// `xmin`), an `ETag`, a fresh UUID per write.
///
/// ## TTL contract
///
/// Every insert and compare-and-swap receives an absolute `deadline` from
/// the driver. It is the sooner of the effective absolute session cap and the
/// activity horizon `max(now, token_expiry) + idle_timeout`; the driver also keeps
/// that idle horizon in lockstep with the [`LivenessConfig`]
/// attached through
/// [`with_liveness`](crate::StoreBackedSessionStore::with_liveness). Apply the
/// supplied deadline as the record's absolute TTL on **every** successful write,
/// erring late:
///
/// - The deadline is measured on the application's clock, so a backend expiring
///   exactly at it by its own clock can already be early — deleting early logs a
///   user out, while a late delete costs storage and stretches the idle bound by
///   at most the skew. Add a margin; rounding up is free.
/// - Re-apply the TTL on **every** write — backends like Redis drop a key's TTL
///   on a plain overwrite.
/// - Never use a sliding window: one shorter than the remaining deadline deletes
///   an idle-but-valid record out from under its user.
/// - On backends whose TTLs are relative (Cassandra, etcd leases), compute
///   `deadline − now` at write time and clamp up to a small positive value rather
///   than deleting.
///
/// The horizon renews with every write: an active session refreshes its tokens
/// (roughly once per access-token lifetime), each refresh writes the record, and
/// the deadline moves out. A session nobody uses stops being written, so its
/// record — refresh token included — expires even under a
/// [delegated](crate::SessionLifetime::DelegatedToAuthorizationServer) lifetime,
/// where `expire_at` is `None`.
///
/// See [Implement an external session store](crate::_docs::how_to::external_store)
/// for a worked implementation.
pub trait ExternalSessionStore: MaybeSendSync {
    /// The session type returned by this store. Must implement [`Session`] and
    /// [`PersistedSession`]. `Clone` because
    /// [`PendingPersist::commit`](crate::engine::PendingPersist::commit)
    /// persists from a clone.
    type SessionType: Session + PersistedSession + Clone + MaybeSendSync + 'static;

    /// Optimistic-concurrency token: returned by [`load`](Self::load) with
    /// the session and handed back unchanged as `expected` to
    /// [`compare_and_swap`](Self::compare_and_swap). Compared by equality
    /// only. See the
    /// [versioning contract](ExternalSessionStore#versioning-contract) for
    /// choosing a representation.
    type Version: MaybeSendSync + 'static;

    /// The backend's own error type (e.g. `sqlx::Error`); transport-failure
    /// channel only. Boxed into
    /// [`SessionErrorKind::Unavailable`].
    type Error: std::error::Error + MaybeSendSync + 'static;

    /// Persist a newly created session. Called once per login, after
    /// enrichment. Apply `deadline` as the record's absolute TTL; the retention
    /// contract on [`compare_and_swap`](Self::compare_and_swap) applies.
    fn insert(
        &self,
        session: &Self::SessionType,
        deadline: SystemTime,
    ) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;

    /// Load a session by its key, together with the stored
    /// [`Version`](Self::Version). Returns `None` if the key does not exist.
    fn load(
        &self,
        session_key: Uuid,
    ) -> impl Future<Output = Result<LoadOutcome<Self>, Self::Error>> + MaybeSend;

    /// Save `session` only if the stored [`Version`](Self::Version) still
    /// equals `expected`, changing it on success. Return
    /// [`SaveOutcome::Conflict`] for a version mismatch or
    /// [`SaveOutcome::Missing`] when the record does not exist, without
    /// writing. Never insert a missing record: this prevents an in-flight
    /// write from resurrecting a session deleted by logout.
    ///
    /// Apply the supplied `deadline` as the record's absolute TTL on **every**
    /// successful write — backends like Redis drop a key's TTL on a plain
    /// overwrite — and never convert it to a sliding duration.
    /// See the [TTL contract](ExternalSessionStore#ttl-contract)
    /// for the full retention contract.
    fn compare_and_swap(
        &self,
        session: &Self::SessionType,
        expected: Self::Version,
        deadline: SystemTime,
    ) -> impl Future<Output = Result<SaveOutcome, Self::Error>> + MaybeSend;

    /// Delete the session's stored record. Idempotent: a missing record is
    /// `Ok(())`.
    fn delete(
        &self,
        session: &Self::SessionType,
    ) -> impl Future<Output = Result<(), Self::Error>> + MaybeSend;
}

/// Outcome of [`ExternalSessionStore::load`]: the session and its stored
/// version, or `None` if the key does not exist.
pub type LoadOutcome<E> = Option<(
    <E as ExternalSessionStore>::SessionType,
    <E as ExternalSessionStore>::Version,
)>;

/// Outcome of an [`ExternalSessionStore::compare_and_swap`] write.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveOutcome {
    /// The version matched; the session was written and the version changed.
    Committed,
    /// Another writer changed the version first; nothing was written.
    Conflict,
    /// The record no longer exists; nothing was written.
    ///
    /// In particular, a save racing logout must return this instead of
    /// recreating the deleted record.
    Missing,
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
/// the seed passed to the [`SessionEnricher`] after
/// login.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, bon::Builder)]
pub struct PersistedSessionState {
    /// Primary lookup key in the external store. A time-ordered `UUIDv7`.
    pub session_key: Uuid,
    /// Shared token and timing state. See [`SessionState`] for the field set.
    pub state: SessionState,
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

/// Stores sessions server-side behind an encrypted browser pointer.
///
/// The session is built after login by a [`SessionEnricher`] from the
/// [`PersistedSessionState`] seed; `build()` uses [`NoEnrichment`],
/// `build_with_enricher(…)` supplies a custom one. The engine stamps on the
/// `Secure` attribute and `__Host-` prefix, so this store takes no `secure`
/// setting. Prefer this driver over [`CookieSessionStore`](crate::CookieSessionStore)
/// when sessions are large or need server-side revocation, liveness tracking,
/// or compare-and-swap updates.
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
    /// Retention horizon used to derive the absolute deadline passed to every
    /// external-store write. Kept in lockstep with liveness configuration.
    retention_idle_timeout: Duration,
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
        #[builder(with = |sealer: impl AeadSealerUnsealer + 'static| Arc::new(sealer) as Arc<dyn AeadSealerUnsealer>)]
        sealer: Arc<dyn AeadSealerUnsealer>,
        /// Base name for the session cookie.
        cookie_name: CookieName,
        /// Cookie `Path` scope. Defaults to `/` — which also enables the
        /// strongest `__Host-` cookie prefix; set a narrower path only
        /// deliberately. It must cover the configured callback and logout
        /// routes so re-login and logout can revoke the referenced record.
        #[builder(default = RoutePath::root())]
        cookie_path: RoutePath,
        /// Cookie `Max-Age`; defaults to 400 days. The engine clamps it to the
        /// [`SessionLifetime::Bounded`](crate::SessionLifetime) cap at
        /// construction; set it explicitly only to go *shorter*.
        #[builder(default = DEFAULT_COOKIE_MAX_AGE)]
        max_age: Duration,
    ) -> Self {
        Self {
            external,
            enricher,
            sealer: CookieSealer::builder()
                .sealer(sealer)
                .cookie_name(cookie_name)
                .cookie_path(cookie_path)
                .max_age(max_age)
                .build(),
            liveness: None,
            max_lifetime: None,
            retention_idle_timeout: crate::liveness::DEFAULT_IDLE_TIMEOUT,
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
    /// Attach server-side liveness (idle-timeout) tracking, backed by the given
    /// [`LivenessStore`] and configured by `config`. Returns `self`. See
    /// [`crate::liveness`] for the fail-open / monotonic contract.
    #[must_use]
    pub fn with_liveness(
        mut self,
        store: impl LivenessStore + 'static,
        config: LivenessConfig,
    ) -> Self {
        self.retention_idle_timeout = config.idle_timeout;
        self.liveness = Some((Box::new(store), config));
        self
    }

    /// Derives the single authoritative absolute retention deadline for a
    /// write, including both the session's frozen cap and a tighter live cap.
    fn write_deadline(&self, session: &E::SessionType, now: SystemTime) -> SystemTime {
        let deadline = storage_deadline(session, now, self.retention_idle_timeout);
        self.max_lifetime.map_or(deadline, |cap| {
            bounded_time_add(session.created_at(), cap).min(deadline)
        })
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
            let Some((mut session, version)) = self
                .external
                .load(session_key)
                .await
                .map_err(to_session_err)?
            else {
                return Err(SessionError::new(SessionErrorKind::Gone, SessionNotFound));
            };
            mutate(&mut session)?;
            match self
                .external
                .compare_and_swap(
                    &session,
                    version,
                    self.write_deadline(&session, SystemTime::now()),
                )
                .await
                .map_err(to_session_err)?
            {
                SaveOutcome::Committed => return Ok(session),
                SaveOutcome::Conflict => {}
                SaveOutcome::Missing => {
                    return Err(SessionError::new(SessionErrorKind::Gone, SessionNotFound));
                }
            }
        }
        Err(SessionError::new(
            SessionErrorKind::Conflict,
            VersionConflict,
        ))
    }

    /// Commit against the refresh generation observed before exchange. CAS
    /// protects each load/check/write; unrelated application writes can retry.
    async fn commit_refresh(
        &self,
        key: Uuid,
        response: &TokenResponse,
        expected_revision: u64,
        lifetime: Duration,
    ) -> Result<E::SessionType, SessionError> {
        for _ in 0..UPDATE_MAX_ATTEMPTS {
            let Some((mut fresh, version)) =
                self.external.load(key).await.map_err(to_session_err)?
            else {
                return Err(SessionError::new(SessionErrorKind::Gone, SessionNotFound));
            };
            if fresh.state().refresh_revision != expected_revision {
                // Another refresh won, including a prior attempt whose write
                // succeeded but whose acknowledgement was lost. Do not write.
                return Ok(fresh);
            }
            let next_revision = expected_revision.checked_add(1).ok_or_else(|| {
                SessionError::from(SessionErrorKind::Store)
                    .with_context("session refresh revision exhausted")
            })?;
            fresh.apply_refresh(response, lifetime);
            // Stamp after custom apply_refresh implementations as well.
            let mut state = fresh.state().clone();
            state.refresh_revision = next_revision;
            fresh.set_state(state);
            match self
                .external
                .compare_and_swap(
                    &fresh,
                    version,
                    self.write_deadline(&fresh, SystemTime::now()),
                )
                .await
                .map_err(to_session_err)?
            {
                SaveOutcome::Committed => return Ok(fresh),
                SaveOutcome::Conflict => {}
                SaveOutcome::Missing => {
                    return Err(SessionError::new(SessionErrorKind::Gone, SessionNotFound));
                }
            }
        }
        Err(SessionError::new(
            SessionErrorKind::Conflict,
            VersionConflict,
        ))
    }

    /// Encrypt the pointer cookie (the UUID's 16 raw bytes) and emit it
    /// alongside the kid sidecar (a `Max-Age=0` clear when there is no identity).
    /// When `deadline` is present, both cookies use its remaining lifetime.
    async fn pointer_cookie_headers_with_deadline(
        &self,
        session_key: Uuid,
        deadline: Option<SystemTime>,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        let aad = self.sealer.aad("session_ptr");
        let sealed = self
            .sealer
            .cipher
            .seal(session_key.as_bytes(), &aad)
            .await
            .map_err(|e| SessionError::new(SessionErrorKind::Crypto, e))?;
        // The seal returns the kid of the key that sealed this bundle, so the
        // sidecar always names the right key even under a multi-key cipher.
        let kid = sealed.kid;
        self.sealer.record_encrypt(kid.as_deref());
        let cookie_value = URL_SAFE_NO_PAD.encode(&sealed.bundle);
        let attrs = if let Some(deadline) = deadline {
            let remaining = deadline
                .duration_since(SystemTime::now())
                .map_err(|_| SessionError::from(SessionErrorKind::Gone))?;
            if remaining == Duration::ZERO {
                return Err(SessionErrorKind::Gone.into());
            }
            self.sealer.cookie_attrs_with_max_age(remaining)
        } else {
            self.sealer.cookie_attrs()
        };
        let pointer = HeaderValue::from_str(&format!(
            "{}={cookie_value}; {attrs}",
            self.sealer.cookie_name
        ))
        .map_err(|e| SessionError::new(SessionErrorKind::Encoding, e))?;
        let kid_header = self
            .sealer
            .build_kid_header_with_attrs(kid.as_deref(), &attrs)?;
        Ok(vec![pointer, kid_header])
    }

    #[cfg(test)]
    async fn pointer_cookie_headers(
        &self,
        session_key: Uuid,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.pointer_cookie_headers_with_deadline(session_key, None)
            .await
    }

    /// Effective absolute cap for browser cookies, combining the frozen
    /// session deadline with the policy currently stamped on the driver.
    fn session_deadline(&self, session: &E::SessionType) -> Option<SystemTime> {
        let configured = self
            .max_lifetime
            .map(|cap| bounded_time_add(session.created_at(), cap));
        match (session.expire_at(), configured) {
            (Some(frozen), Some(configured)) => Some(frozen.min(configured)),
            (frozen, configured) => frozen.or(configured),
        }
    }

    /// Read and decrypt the pointer cookie to get the session key.
    async fn read_pointer_cookie(&self, headers: &http::HeaderMap) -> DriverLoad<Uuid> {
        let Some(encoded) = get_cookie(headers, &self.sealer.cookie_name) else {
            return DriverLoad::Absent;
        };

        let plaintext = match self
            .sealer
            .unseal_cookie_value(headers, encoded, "session_ptr")
            .await
        {
            Ok(plaintext) => plaintext,
            Err(reason) => return DriverLoad::Invalid(reason),
        };
        // Must be exactly 16 bytes (UUID); anything else is a corrupted cookie.
        if let Ok(bytes) = <[u8; 16]>::try_from(plaintext) {
            self.sealer.record_decrypt(&DecryptResult::Ok);
            DriverLoad::Valid(Uuid::from_bytes(bytes))
        } else {
            self.sealer.record_decrypt(&DecryptResult::PayloadInvalid);
            DriverLoad::Invalid(InvalidSessionReason::InvalidPayload)
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
        };

        let session = self.enricher.build_session(seed, completed).await?;
        let deadline = self.session_deadline(&session);
        // Prepare every fallible browser artifact before inserting. Once the
        // record exists, only best-effort superseded-session cleanup remains,
        // so a local seal/encoding failure cannot orphan the new record.
        let cookies = self
            .pointer_cookie_headers_with_deadline(session.persisted().session_key, deadline)
            .await?;
        let now = SystemTime::now();
        if deadline.is_some_and(|deadline| deadline <= now) {
            return Err(SessionErrorKind::Gone.into());
        }
        let retention_deadline = self.write_deadline(&session, now);
        self.external
            .insert(&session, retention_deadline)
            .await
            .map_err(to_session_err)?;
        // Login is the session's first activity. Seed liveness immediately so
        // precise idle tracking starts at creation rather than at the first
        // qualifying request after the callback. This remains best-effort like
        // later activity touches: the record deadline is the fail-open bound.
        if let Some((liveness, _)) = &self.liveness
            && let Err(_error) = liveness
                .touch(
                    session.persisted().session_key,
                    now,
                    Some(retention_deadline),
                )
                .await
        {
            self.record_liveness_failure(&LivenessFailure::Touch);
        }
        Ok((session, cookies))
    }

    /// Counts a failed (best-effort) liveness operation.
    fn record_liveness_failure(&self, failure: &LivenessFailure) {
        crate::metrics::emit_counter(
            "huskarl.session.liveness_failure",
            [("op", failure.as_str())],
            self.sealer.metrics_name.as_deref(),
        );
    }

    pub(crate) async fn load_session(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<DriverLoad<E::SessionType>, E::Error> {
        let session_key = match self.read_pointer_cookie(headers).await {
            DriverLoad::Absent => return Ok(DriverLoad::Absent),
            DriverLoad::Invalid(reason) => return Ok(DriverLoad::Invalid(reason)),
            DriverLoad::Valid(key) => key,
        };

        Ok(match self.external.load(session_key).await? {
            Some((session, _version)) => DriverLoad::Valid(session),
            None => DriverLoad::Invalid(InvalidSessionReason::SessionNotFound),
        })
    }

    pub(crate) async fn save_session(
        &self,
        session: &E::SessionType,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        let key = session.persisted().session_key;
        for _ in 0..UPDATE_MAX_ATTEMPTS {
            let Some((current, version)) = self.external.load(key).await.map_err(to_session_err)?
            else {
                return Err(SessionError::new(SessionErrorKind::Gone, SessionNotFound));
            };
            if !session.state().matches_persisted_refresh(current.state()) {
                return Err(SessionError::new(
                    SessionErrorKind::Conflict,
                    VersionConflict,
                ));
            }
            // Whole-session saves may replace application fields, but may
            // not publish a pending refresh under its old revision. Preserve
            // stored expiry exactly after the wire-precision comparison.
            let mut candidate = session.clone();
            let mut state = candidate.state().clone();
            state.token_expiry = current.state().token_expiry;
            candidate.set_state(state);
            match self
                .external
                .compare_and_swap(
                    &candidate,
                    version,
                    self.write_deadline(&candidate, SystemTime::now()),
                )
                .await
                .map_err(to_session_err)?
            {
                // The session key is unchanged, so no new pointer cookie.
                SaveOutcome::Committed => return Ok(vec![]),
                SaveOutcome::Conflict => {}
                SaveOutcome::Missing => {
                    return Err(SessionError::new(SessionErrorKind::Gone, SessionNotFound));
                }
            }
        }
        Err(SessionError::new(
            SessionErrorKind::Conflict,
            VersionConflict,
        ))
    }

    pub(crate) async fn revoke_session(
        &self,
        session: &E::SessionType,
    ) -> Result<(), SessionError> {
        self.external
            .delete(session)
            .await
            .map_err(to_session_err)?;
        // Best-effort: drop the liveness entry too. A failure here just leaves a
        // stale entry that expires under its own TTL; it must not fail logout.
        if let Some((liveness, _)) = &self.liveness {
            let key = session.persisted().session_key;
            if let Err(_error) = liveness.clear(key).await {
                self.record_liveness_failure(&LivenessFailure::Clear);
            }
        }
        Ok(())
    }

    /// Clears the browser's pointer cookie and key-identity sidecar without
    /// touching the backing store.
    fn clear_session_cookie_headers(&self) -> Vec<HeaderValue> {
        // Clear the pointer cookie and the kid sidecar.
        let mut headers = Vec::with_capacity(2);
        if let Ok(pointer) = self.sealer.build_clear_header(&self.sealer.cookie_name) {
            headers.push(pointer);
        }
        if let Ok(kid) = self.sealer.build_kid_header(None) {
            headers.push(kid);
        }
        headers
    }

    /// Delete the record a still-valid incoming pointer cookie references,
    /// before a new login's cookie overwrites the pointer: a fresh login
    /// supersedes the old session, so an exfiltrated copy of its pointer must
    /// not keep working until the storage deadline reaps it. Best-effort:
    /// failures are logged and must not fail the login.
    async fn delete_superseded_session(&self, headers: &http::HeaderMap) {
        let old_key = match self.read_pointer_cookie(headers).await {
            DriverLoad::Valid(key) => key,
            DriverLoad::Absent | DriverLoad::Invalid(_) => return,
        };
        let result = match self.external.load(old_key).await {
            Ok(Some((old, _version))) => match self.external.delete(&old).await {
                Ok(()) => SupersededDeleteResult::Deleted,
                Err(_error) => SupersededDeleteResult::DeleteFailed,
            },
            Ok(None) => SupersededDeleteResult::NotFound,
            Err(_error) => SupersededDeleteResult::LoadFailed,
        };
        crate::metrics::emit_counter(
            "huskarl.session.superseded_delete",
            [("outcome", result.as_str())],
            self.sealer.metrics_name.as_deref(),
        );
        // Preserve the old liveness verdict when the authoritative record may
        // still exist. Clearing it after a load/delete failure would turn the
        // old record into a fail-open session and reset its idle history on the
        // next request.
        let record_is_gone = matches!(
            result,
            SupersededDeleteResult::Deleted | SupersededDeleteResult::NotFound
        );
        if record_is_gone
            && let Some((liveness, _)) = &self.liveness
            && let Err(_error) = liveness.clear(old_key).await
        {
            self.record_liveness_failure(&LivenessFailure::Clear);
        }
    }
}

impl<E: ExternalSessionStore> crate::session::sealed::Sealed for StoreBackedSessionStore<E> {}

impl<E: ExternalSessionStore> SessionDriver for StoreBackedSessionStore<E> {
    type SessionType = E::SessionType;
    type LoadError = E::Error;

    fn apply_session_policy(&mut self, policy: &SessionPolicy) -> Result<(), crate::ConfigError> {
        // The callback must receive the old pointer so a successful re-login
        // can revoke the superseded server record before replacing the cookie.
        policy.validate_callback_cookie_path(self.sealer.cookie_path())?;
        policy.validate_logout_cookie_path(self.sealer.cookie_path())?;
        self.sealer.apply_session_policy(policy);
        // Retained to freeze `SessionState::expire_at` into new sessions.
        self.max_lifetime = policy.max_lifetime();
        Ok(())
    }

    fn session_sealer(&self) -> Arc<dyn AeadSealerUnsealer> {
        self.sealer.cipher.clone()
    }

    fn clear_session_cookies(&self, _headers: &http::HeaderMap) -> Vec<HeaderValue> {
        self.clear_session_cookie_headers()
    }

    fn strip_session_credentials(&self, headers: &mut http::HeaderMap) {
        let kid_name = crate::cookie::kid_cookie_name(&self.sealer.cookie_name);
        crate::cookie::strip_cookies(headers, |name| {
            name == self.sealer.cookie_name || name == kid_name
        });
    }

    async fn create(
        &self,
        completed: crate::CompletedLogin,
        default_lifetime: std::time::Duration,
        headers: &http::HeaderMap,
    ) -> Result<(E::SessionType, Vec<HeaderValue>), SessionError> {
        let created = self.create_session(&completed, default_lifetime).await?;
        // A failed new-session build leaves the old session untouched. Once
        // the replacement is durable and its cookie is ready, revocation of
        // the superseded record is best-effort and cannot fail the login.
        self.delete_superseded_session(headers).await;
        Ok(created)
    }

    async fn load(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<DriverLoad<E::SessionType>, E::Error> {
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
        expected_refresh_revision: u64,
        default_lifetime: std::time::Duration,
        _headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        let key = session.persisted().session_key;
        match self
            .commit_refresh(
                key,
                token_response,
                expected_refresh_revision,
                default_lifetime,
            )
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
                // memory (the request can still serve the new tokens). The
                // write may have committed before its acknowledgement failed;
                // retries must retain the original expected revision.
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
            Err(_error) => {
                self.record_liveness_failure(&LivenessFailure::Read);
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
        // Entry TTL: the record deadline, tightened by the engine's effective
        // deadline. An entry must not expire before its record — a missing
        // entry reads as active, which would resurrect an idle session whose
        // record is still stored. See the liveness explanation page.
        let horizon = bounded_time_add(session.token_expiry().max(now), config.idle_timeout);
        let deadline = Some(expire_at.map_or(horizon, |e| e.min(horizon)));
        if record_activity
            && verdict == LivenessVerdict::Active
            && due
            && let Err(_error) = liveness.touch(key, now, deadline).await
        {
            self.record_liveness_failure(&LivenessFailure::Touch);
        }
        Ok(verdict)
    }

    async fn revoke(&self, session: &E::SessionType) -> Result<(), SessionError> {
        self.revoke_session(session).await
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use super::*;
    use crate::{
        cookie::encode_kid,
        core::{crypto::seal::AeadV1Sealer, platform::MaybeSendBoxFuture},
        session_state::{Session, SessionState},
        test_support::{
            RevocableExternalStore, aes_key_with_kid, request_cookies, test_sealer,
            test_sealer_with_kid, test_session_policy,
        },
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
        type Version = i32;
        type Error = Infallible;

        async fn insert(&self, _: &MinimalSession, _: SystemTime) -> Result<(), Infallible> {
            Ok(())
        }

        async fn load(&self, _: Uuid) -> Result<Option<(MinimalSession, i32)>, Infallible> {
            Ok(Some((self.0.clone(), 0)))
        }

        async fn compare_and_swap(
            &self,
            _: &MinimalSession,
            _: i32,
            _: SystemTime,
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
            },
        }
    }

    #[tokio::test]
    async fn credential_stripping_removes_pointer_and_kid_but_preserves_app_cookies() {
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(test_session()))
            .sealer(test_sealer().await)
            .cookie_name("huskarl_session".parse().unwrap())
            .build();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "__Host-huskarl_session=pointer; theme=dark; __Host-huskarl_session.kid=key"
                .parse()
                .unwrap(),
        );

        store.strip_session_credentials(&mut headers);

        assert_eq!(headers.get(http::header::COOKIE).unwrap(), "theme=dark");
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

    struct DelayedEnricher(Duration);

    impl SessionEnricher<PersistedSessionState, MinimalSession> for DelayedEnricher {
        fn build_session<'a>(
            &'a self,
            seed: PersistedSessionState,
            _completed: &'a crate::CompletedLogin,
        ) -> MaybeSendBoxFuture<'a, Result<MinimalSession, SessionError>> {
            Box::pin(async move {
                tokio::time::sleep(self.0).await;
                Ok(MinimalSession { persisted: seed })
            })
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
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build_with_enricher(MinimalEnricher);
        assert_session_driver(&store);
    }

    #[tokio::test]
    async fn store_backed_policy_requires_callback_visibility_for_supersession() {
        let mut store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(test_session()))
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/app".parse().unwrap())
            .build();

        let error = store
            .apply_session_policy(
                &SessionPolicy::builder()
                    .secure(true)
                    .browser_callback_path("/oauth/callback".parse().unwrap())
                    .build(),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            crate::ConfigError::InvalidSessionCookiePath {
                route: "callback",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn creation_rejects_a_session_that_expires_during_enrichment() {
        let external = RevocableExternalStore::<MinimalSession>::default();
        let mut store = StoreBackedSessionStore::builder()
            .external(external.clone())
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build_with_enricher(DelayedEnricher(Duration::from_millis(20)));
        store
            .apply_session_policy(&test_session_policy(Some(Duration::from_millis(1))))
            .unwrap();

        let result = store
            .create_session(
                &completed_with_email("a@example.com"),
                Duration::from_hours(1),
            )
            .await;
        let Err(error) = result else {
            panic!("an expired session must not be inserted");
        };

        assert_eq!(error.kind(), SessionErrorKind::Gone);
        assert_eq!(external.calls().inserts, 0);
        assert!(external.is_empty());
    }

    /// `last_active` and the touch deadline, as [`FakeLiveness`] records them.
    type FakeEntries = std::collections::HashMap<Uuid, (SystemTime, Option<SystemTime>)>;

    /// In-memory [`LivenessStore`] that records every write — `last_active`
    /// and the touch deadline — shareable for inspection.
    #[derive(Clone, Default)]
    struct FakeLiveness {
        entries: Arc<std::sync::Mutex<FakeEntries>>,
    }

    impl FakeLiveness {
        fn set(&self, key: Uuid, at: SystemTime) {
            self.entries.lock().unwrap().insert(key, (at, None));
        }
        fn get(&self, key: Uuid) -> Option<SystemTime> {
            self.entries.lock().unwrap().get(&key).map(|(at, _)| *at)
        }
        fn deadline(&self, key: Uuid) -> Option<SystemTime> {
            self.entries.lock().unwrap().get(&key).and_then(|(_, d)| *d)
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
            deadline: Option<SystemTime>,
        ) -> MaybeSendBoxFuture<'_, Result<(), SessionError>> {
            self.entries.lock().unwrap().insert(key, (now, deadline));
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
            .sealer(test_sealer().await)
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
            .sealer(test_sealer().await)
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
            .sealer(test_sealer().await)
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
    async fn liveness_cleared_on_revocation() {
        let session = test_session();
        let key = session.persisted.session_key;
        let liveness = FakeLiveness::default();
        let store =
            liveness_store(session.clone(), liveness.clone(), LivenessConfig::default()).await;

        liveness.set(key, SystemTime::now());
        store.revoke(&session).await.unwrap();
        assert!(
            liveness.get(key).is_none(),
            "revocation clears the liveness entry"
        );
    }

    #[tokio::test]
    async fn liveness_touch_deadline_is_activity_horizon_when_delegated() {
        let session = test_session(); // no expire_at → delegated lifetime
        let key = session.persisted.session_key;
        let liveness = FakeLiveness::default();
        let config = LivenessConfig::default();
        let idle = config.idle_timeout;
        let store = liveness_store(session.clone(), liveness.clone(), config).await;

        let now = SystemTime::now();
        store
            .check_liveness(&session, now, true, None)
            .await
            .unwrap();

        assert_eq!(
            liveness.deadline(key),
            Some(session.token_expiry() + idle),
            "entry TTL anchors at token_expiry so it cannot expire before the record"
        );
    }

    #[tokio::test]
    async fn liveness_touch_deadline_tightened_by_engine_deadline() {
        let session = test_session();
        let key = session.persisted.session_key;
        let liveness = FakeLiveness::default();
        let store =
            liveness_store(session.clone(), liveness.clone(), LivenessConfig::default()).await;

        let now = SystemTime::now();
        let engine_deadline = now + Duration::from_mins(1); // sooner than the horizon
        store
            .check_liveness(&session, now, true, Some(engine_deadline))
            .await
            .unwrap();

        assert_eq!(liveness.deadline(key), Some(engine_deadline));
    }

    // ── Optimistic update (OCC) ───────────────────────────────────────────

    /// A stateful external store that honours [`compare_and_swap`] versioning,
    /// so the [`StoreBackedSessionStore::update`] retry loop can be exercised.
    /// The version is a separate "column" next to the record, as the protocol
    /// intends.
    struct VersioningStore {
        stored: std::sync::Mutex<Option<(MinimalSession, i32)>>,
        deadlines: std::sync::Mutex<Vec<SystemTime>>,
        /// When `true`, every `compare_and_swap` reports a conflict.
        always_conflict: bool,
        /// Commit once, then report an error instead of acknowledging it.
        lose_ack_once: std::sync::Mutex<bool>,
        /// A simulated concurrent writer applied just before the first
        /// `compare_and_swap` (advancing the stored version), to force one
        /// conflict-then-retry.
        inject_once: std::sync::Mutex<Option<fn(&mut MinimalSession)>>,
    }

    impl VersioningStore {
        fn with(session: MinimalSession) -> Self {
            Self {
                stored: std::sync::Mutex::new(Some((session, 0))),
                deadlines: std::sync::Mutex::new(Vec::new()),
                always_conflict: false,
                lose_ack_once: std::sync::Mutex::new(false),
                inject_once: std::sync::Mutex::new(None),
            }
        }

        fn stored_version(&self) -> i32 {
            self.stored.lock().unwrap().as_ref().unwrap().1
        }

        fn last_deadline(&self) -> SystemTime {
            *self.deadlines.lock().unwrap().last().unwrap()
        }
    }

    #[allow(clippy::unused_async_trait_impl)]
    impl ExternalSessionStore for VersioningStore {
        type SessionType = MinimalSession;
        type Version = i32;
        type Error = std::io::Error;

        async fn insert(
            &self,
            s: &MinimalSession,
            deadline: SystemTime,
        ) -> Result<(), std::io::Error> {
            *self.stored.lock().unwrap() = Some((s.clone(), 0));
            self.deadlines.lock().unwrap().push(deadline);
            Ok(())
        }
        async fn load(&self, _: Uuid) -> Result<Option<(MinimalSession, i32)>, std::io::Error> {
            Ok(self.stored.lock().unwrap().clone())
        }
        async fn compare_and_swap(
            &self,
            s: &MinimalSession,
            expected: i32,
            deadline: SystemTime,
        ) -> Result<SaveOutcome, std::io::Error> {
            if self.always_conflict {
                return Ok(SaveOutcome::Conflict);
            }
            let mut stored = self.stored.lock().unwrap();
            // A concurrent writer landing just before our CAS.
            if let Some(inject) = self.inject_once.lock().unwrap().take()
                && let Some((cur, version)) = stored.as_mut()
            {
                inject(cur);
                *version += 1;
            }
            match stored.as_ref() {
                Some((_, version)) if *version == expected => {
                    *stored = Some((s.clone(), expected + 1));
                    self.deadlines.lock().unwrap().push(deadline);
                    if std::mem::take(&mut *self.lose_ack_once.lock().unwrap()) {
                        return Err(std::io::Error::other("lost commit acknowledgement"));
                    }
                    Ok(SaveOutcome::Committed)
                }
                Some(_) => Ok(SaveOutcome::Conflict),
                None => Ok(SaveOutcome::Missing),
            }
        }
        async fn delete(&self, _: &MinimalSession) -> Result<(), std::io::Error> {
            *self.stored.lock().unwrap() = None;
            Ok(())
        }
    }

    async fn store_over(external: VersioningStore) -> StoreBackedSessionStore<VersioningStore> {
        StoreBackedSessionStore::builder()
            .external(external)
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
    }

    #[tokio::test]
    async fn create_initializes_liveness_with_the_record_deadline() {
        let liveness = FakeLiveness::default();
        let store = store_over(VersioningStore::with(test_session()))
            .await
            .with_liveness(liveness.clone(), LivenessConfig::default());

        let (session, _cookies) = store
            .create_session(
                &completed_with_email("a@example.com"),
                Duration::from_hours(1),
            )
            .await
            .unwrap();
        let key = session.persisted().session_key;

        assert!(
            liveness.get(key).is_some(),
            "login must establish the initial last_active timestamp"
        );
        assert_eq!(
            liveness.deadline(key),
            Some(store.external.last_deadline()),
            "the liveness entry and session record must share a deadline"
        );
    }

    #[tokio::test]
    async fn failed_initial_liveness_touch_does_not_fail_login() {
        let store = store_over(VersioningStore::with(test_session()))
            .await
            .with_liveness(FailingLiveness, LivenessConfig::default());

        let result = store
            .create_session(
                &completed_with_email("a@example.com"),
                Duration::from_hours(1),
            )
            .await;

        assert!(result.is_ok(), "liveness initialization must fail open");
        assert!(store.external.stored.lock().unwrap().is_some());
    }

    #[tokio::test]
    async fn create_freezes_expire_at_from_stamped_policy() {
        let cap = Duration::from_hours(8);
        let mut store = store_over(VersioningStore::with(test_session())).await;
        store
            .apply_session_policy(&test_session_policy(Some(cap)))
            .unwrap();

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
    async fn every_external_write_receives_the_driver_derived_absolute_deadline() {
        let now = SystemTime::now();
        let created_at = now - Duration::from_hours(2);
        let session = MinimalSession {
            persisted: PersistedSessionState {
                session_key: Uuid::now_v7(),
                state: SessionState::builder()
                    .token_expiry(now + Duration::from_hours(1))
                    .created_at(created_at)
                    .build(),
            },
        };
        let mut store = store_over(VersioningStore::with(session.clone())).await;
        let cap = Duration::from_hours(8);
        store
            .apply_session_policy(&test_session_policy(Some(cap)))
            .unwrap();

        store.save_session(&session).await.unwrap();

        assert_eq!(store.external.last_deadline(), created_at + cap);
    }

    #[tokio::test]
    async fn save_after_logout_cannot_resurrect_a_store_backed_session() {
        let session = test_session();
        let store = store_over(VersioningStore::with(session.clone())).await;

        store.revoke(&session).await.unwrap();
        let error = store.save_session(&session).await.unwrap_err();

        assert_eq!(error.kind(), SessionErrorKind::Gone);
        assert!(store.external.stored.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn whole_session_save_rejects_stale_refresh_revision() {
        let stale = test_session();
        let mut refreshed = stale.clone();
        let store = store_over(VersioningStore::with(stale.clone())).await;
        let response = crate::test_support::rotating_token_response("new-token", SystemTime::now());
        store
            .apply_refresh_and_save(
                &mut refreshed,
                &response,
                0,
                Duration::from_hours(2),
                &http::HeaderMap::new(),
            )
            .await
            .unwrap();

        let error = store.save_session(&stale).await.unwrap_err();
        assert_eq!(error.kind(), SessionErrorKind::Conflict);
        let (stored, version) = store
            .external
            .load(stale.persisted().session_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(version, 1);
        assert_eq!(stored.state().refresh_revision, 1);
        assert_eq!(stored.refresh_token(), response.refresh_token());
        assert_eq!(stored.token_expiry(), refreshed.token_expiry());
    }

    #[tokio::test]
    async fn pending_whole_save_rejects_uncommitted_refresh() {
        // The AS is uncoordinated: two exchanges of token 0 produce distinct
        // results. Whole-saving B must not publish its pending tokens under
        // the old revision before A commits.
        use crate::test_support::rotating_token_response;

        let now = SystemTime::now();
        let lifetime = Duration::from_hours(1);
        let headers = http::HeaderMap::new();
        let mut a = test_session();
        let mut b = a.clone();
        let mut store = store_over(VersioningStore::with(a.clone())).await;
        let first = rotating_token_response("token-1", now);
        let second = rotating_token_response("token-2", now + lifetime);
        store.external.always_conflict = true;
        let error = store
            .apply_refresh_and_save(&mut b, &second, 0, lifetime, &headers)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), SessionErrorKind::Conflict);
        assert_eq!(b.state().refresh_revision, 0);
        assert_eq!(b.refresh_token(), second.refresh_token());

        store.external.always_conflict = false;
        let error = store.save_session(&b).await.unwrap_err();
        assert_eq!(error.kind(), SessionErrorKind::Conflict);
        let (stored, version) = store
            .external
            .load(b.persisted().session_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(version, 0);
        assert_eq!(stored.state().refresh_revision, 0);
        assert_eq!(stored.refresh_token(), a.refresh_token());

        store
            .apply_refresh_and_save(&mut a, &first, 0, lifetime, &headers)
            .await
            .unwrap();
        // B's deferred commit then adopts A's now-committed generation.
        store
            .apply_refresh_and_save(&mut b, &second, 0, lifetime, &headers)
            .await
            .unwrap();
        assert_eq!(b.state().refresh_revision, 1);
        assert_eq!(b.refresh_token(), first.refresh_token());
        assert_eq!(b.token_expiry(), a.token_expiry());
        assert_eq!(store.external.stored_version(), 1);
    }

    #[tokio::test]
    async fn whole_session_save_rechecks_revision_after_cas_conflict() {
        let snapshot = test_session();
        let mut external = VersioningStore::with(snapshot.clone());
        *external.inject_once.get_mut().unwrap() = Some(|s| {
            s.persisted.state.refresh_revision = 1;
            s.persisted.state.sid = Some("concurrent-refresh".to_owned());
        });
        let store = store_over(external).await;
        let error = store.save_session(&snapshot).await.unwrap_err();
        assert_eq!(error.kind(), SessionErrorKind::Conflict);
        let (stored, version) = store
            .external
            .load(snapshot.persisted().session_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(version, 1);
        assert_eq!(stored.state().refresh_revision, 1);
        assert_eq!(stored.sid(), Some("concurrent-refresh"));
    }

    #[rstest::rstest]
    #[case::rotated_token_only(true)]
    #[case::expiry_only_without_rotation(false)]
    #[tokio::test]
    async fn pending_whole_save_checks_token_and_expiry(#[case] rotates: bool) {
        use crate::test_support::rotating_token_response;

        let now = SystemTime::now();
        let lifetime = Duration::from_hours(1);
        let initial = rotating_token_response("initial", now);
        let mut pending = test_session();
        pending.apply_refresh(&initial, lifetime);
        let original = pending.clone();
        let mut store = store_over(VersioningStore::with(original.clone())).await;
        let response = if rotates {
            rotating_token_response("rotated", now)
        } else {
            refresh_token_response() // expires_in and replacement token absent
        };
        let lifetime = if rotates {
            lifetime
        } else {
            Duration::from_hours(2)
        };
        store.external.always_conflict = true;
        store
            .apply_refresh_and_save(
                &mut pending,
                &response,
                0,
                lifetime,
                &http::HeaderMap::new(),
            )
            .await
            .unwrap_err();
        if rotates {
            assert_eq!(pending.token_expiry(), original.token_expiry());
        } else {
            assert_eq!(pending.refresh_token(), original.refresh_token());
        }
        store.external.always_conflict = false;
        assert_eq!(
            store.save_session(&pending).await.unwrap_err().kind(),
            SessionErrorKind::Conflict
        );
        assert_eq!(store.external.stored_version(), 0);

        // The pending retry remains the supported path and commits normally.
        store
            .apply_refresh_and_save(
                &mut pending,
                &response,
                0,
                lifetime,
                &http::HeaderMap::new(),
            )
            .await
            .unwrap();
        assert_eq!(pending.state().refresh_revision, 1);
        assert_eq!(
            store.save_session(&pending).await.unwrap(),
            [] as [http::HeaderValue; 0]
        );
        assert_eq!(store.external.stored_version(), 2);
    }

    #[rstest::rstest]
    #[case::stored_precision_is_seconds(true)]
    #[case::caller_precision_is_seconds(false)]
    #[tokio::test]
    async fn whole_session_save_accepts_serialized_expiry_precision(
        #[case] stored_roundtripped: bool,
    ) {
        let mut precise = test_session();
        let seconds = precise
            .token_expiry()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        precise.persisted.state.token_expiry =
            SystemTime::UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_millis(123);
        precise.persisted.state.refresh_revision = 1;
        let mut roundtripped = precise.clone();
        roundtripped.persisted.state =
            serde_json::from_slice(&serde_json::to_vec(precise.state()).unwrap()).unwrap();
        let (stored, mut caller) = if stored_roundtripped {
            (roundtripped, precise)
        } else {
            (precise, roundtripped)
        };
        let authoritative_expiry = stored.token_expiry();
        let store = store_over(VersioningStore::with(stored)).await;
        caller.persisted.state.sid = Some("application-update".to_owned());
        store.save_session(&caller).await.unwrap();
        let (saved, _) = store
            .external
            .load(caller.persisted().session_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(saved.token_expiry(), authoritative_expiry);
        assert_eq!(saved.sid(), Some("application-update"));
    }

    #[tokio::test]
    async fn whole_session_save_rechecks_refresh_fields_after_cas_conflict() {
        let snapshot = test_session();
        let mut external = VersioningStore::with(snapshot.clone());
        *external.inject_once.get_mut().unwrap() = Some(|session| {
            session.persisted.state.token_expiry += Duration::from_hours(1);
        });
        let store = store_over(external).await;
        assert_eq!(
            store.save_session(&snapshot).await.unwrap_err().kind(),
            SessionErrorKind::Conflict
        );
        let (saved, version) = store
            .external
            .load(snapshot.persisted().session_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(version, 1);
        assert_eq!(
            saved.token_expiry(),
            snapshot.token_expiry() + Duration::from_hours(1)
        );
    }

    #[tokio::test]
    async fn whole_session_save_retries_unrelated_cas_conflict() {
        let mut snapshot = test_session();
        snapshot.persisted.state.refresh_revision = 4;
        let mut external = VersioningStore::with(snapshot.clone());
        *external.inject_once.get_mut().unwrap() = Some(|s| {
            s.persisted.state.sid = Some("concurrent-app-update".to_owned());
        });
        let store = store_over(external).await;
        snapshot.persisted.state.sid = Some("whole-session-write".to_owned());
        assert_eq!(
            store.save_session(&snapshot).await.unwrap(),
            [] as [http::HeaderValue; 0]
        );
        let (stored, version) = store
            .external
            .load(snapshot.persisted().session_key)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(version, 2);
        assert_eq!(stored.state().refresh_revision, 4);
        // Whole-session saves still replace application fields within the
        // same refresh generation; use update for merge-safe mutations.
        assert_eq!(stored.sid(), Some("whole-session-write"));
    }

    #[tokio::test]
    async fn whole_session_save_bounds_cas_retries() {
        let snapshot = test_session();
        let external = VersioningStore {
            always_conflict: true,
            ..VersioningStore::with(snapshot.clone())
        };
        let store = store_over(external).await;
        let error = store.save_session(&snapshot).await.unwrap_err();
        assert_eq!(error.kind(), SessionErrorKind::Conflict);
        assert_eq!(store.external.stored_version(), 0);
    }

    #[tokio::test]
    async fn create_under_delegated_lifetime_has_no_expire_at() {
        let mut store = store_over(VersioningStore::with(test_session())).await;
        store
            .apply_session_policy(&test_session_policy(None))
            .unwrap();

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

    // ── Superseded-record cleanup on re-login ────────────────────────────

    type MapStore = RevocableExternalStore<MinimalSession>;

    #[tokio::test]
    async fn create_deletes_superseded_record_and_liveness_entry() {
        let old = test_session();
        let old_key = old.persisted.session_key;
        let external = MapStore::default();
        external.seed(&old);
        let liveness = FakeLiveness::default();
        liveness.set(old_key, SystemTime::now());

        let store = StoreBackedSessionStore::builder()
            .external(external.clone())
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
            .with_liveness(liveness.clone(), LivenessConfig::default());

        // A re-login: the request still carries a valid pointer cookie for
        // the old session.
        let req = request_cookies(&store.pointer_cookie_headers(old_key).await.unwrap());
        let (new_session, _cookies) = store
            .create(
                completed_with_email("a@example.com"),
                Duration::from_hours(1),
                &req,
            )
            .await
            .unwrap();

        assert!(
            !external.contains(old_key),
            "superseded record must be deleted, not orphaned"
        );
        assert!(
            external.contains(new_session.persisted.session_key),
            "new record inserted"
        );
        assert!(
            liveness.get(old_key).is_none(),
            "superseded liveness entry cleared"
        );
    }

    #[tokio::test]
    async fn failed_replacement_insert_preserves_the_superseded_session() {
        let old = test_session();
        let old_key = old.persisted.session_key;
        let external = MapStore::default();
        external.seed(&old);
        let store = StoreBackedSessionStore::builder()
            .external(external.clone())
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();
        let request = request_cookies(&store.pointer_cookie_headers(old_key).await.unwrap());
        external.set_fail_inserts(true);

        let result = store
            .create(
                completed_with_email("a@example.com"),
                Duration::from_hours(1),
                &request,
            )
            .await;

        assert!(result.is_err());
        assert_eq!(external.len(), 1);
        assert!(external.contains(old_key));
    }

    #[tokio::test]
    async fn failed_superseded_delete_preserves_its_liveness_entry() {
        let old = test_session();
        let old_key = old.persisted.session_key;
        let external = MapStore::default();
        external.seed(&old);
        external.set_fail_deletes(true);
        let liveness = FakeLiveness::default();
        let last_active = SystemTime::now() - Duration::from_hours(1);
        liveness.set(old_key, last_active);
        let store = StoreBackedSessionStore::builder()
            .external(external.clone())
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build()
            .with_liveness(liveness.clone(), LivenessConfig::default());
        let request = request_cookies(&store.pointer_cookie_headers(old_key).await.unwrap());

        store
            .create(
                completed_with_email("a@example.com"),
                Duration::from_hours(1),
                &request,
            )
            .await
            .unwrap();

        assert!(
            external.contains(old_key),
            "the failed delete leaves the record"
        );
        assert_eq!(
            liveness.get(old_key),
            Some(last_active),
            "the old idle history must survive while its record may still exist"
        );
    }

    #[tokio::test]
    async fn create_without_pointer_cookie_touches_no_other_records() {
        let unrelated = test_session();
        let unrelated_key = unrelated.persisted.session_key;
        let external = MapStore::default();
        external.seed(&unrelated);

        let store = StoreBackedSessionStore::builder()
            .external(external.clone())
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();

        store
            .create(
                completed_with_email("a@example.com"),
                Duration::from_hours(1),
                &http::HeaderMap::new(),
            )
            .await
            .unwrap();

        assert!(
            external.contains(unrelated_key),
            "a login without a pointer cookie must not delete anything"
        );
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
        assert_eq!(store.external.stored_version(), 1);
    }

    #[tokio::test]
    async fn update_retries_and_preserves_concurrent_change() {
        let session = test_session(); // stored at version 0
        let key = session.persisted.session_key;
        let mut ext = VersioningStore::with(session);
        // A concurrent writer sets `sid` just before our first CAS (the store
        // advances the version to 1).
        *ext.inject_once.get_mut().unwrap() = Some(|s| {
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
        assert_eq!(store.external.stored_version(), 2);
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
        assert_eq!(
            store.external.stored_version(),
            0,
            "no write on mutation error"
        );
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
        assert_eq!(store.external.stored_version(), 1);
    }

    // ── apply_refresh_and_save (engine refresh persist) ───────────────────

    #[tokio::test]
    async fn delayed_refresh_save_preserves_newer_generation() {
        // Regression for the TLA+ three-request counterexample. A and B receive the SAME coordinated response
        // for token 0; B's save is delayed until C has installed token 2.
        // Sequential calls explicitly schedule the interleaving without sleeps.
        use crate::test_support::rotating_token_response;

        let now = SystemTime::now();
        let lifetime = Duration::from_hours(1);
        let headers = http::HeaderMap::new();
        let initial = rotating_token_response("token-0", now);
        let first = rotating_token_response("token-1", now);
        let second = rotating_token_response("token-2", now + lifetime);
        let mut session = test_session();
        session.apply_refresh(&initial, lifetime);
        let key = session.persisted().session_key;
        let store = store_over(VersioningStore::with(session)).await;

        let (mut a, _) = store.external.load(key).await.unwrap().unwrap();
        let (mut b, _) = store.external.load(key).await.unwrap().unwrap();
        assert_eq!(a.refresh_token(), initial.refresh_token());
        assert_eq!(b.refresh_token(), initial.refresh_token());

        store
            .apply_refresh_and_save(&mut a, &first, 0, lifetime, &headers)
            .await
            .unwrap();
        let (mut c, _) = store.external.load(key).await.unwrap().unwrap();
        assert_eq!(c.refresh_token(), first.refresh_token());
        store
            .apply_refresh_and_save(&mut c, &second, 1, lifetime, &headers)
            .await
            .unwrap();
        let (newer, version) = store.external.load(key).await.unwrap().unwrap();
        assert_eq!(newer.refresh_token(), second.refresh_token());
        assert_eq!(version, 2);

        // B must adopt the current session without another write.
        store
            .apply_refresh_and_save(&mut b, &first, 0, lifetime, &headers)
            .await
            .unwrap();
        let (retained, version) = store.external.load(key).await.unwrap().unwrap();
        assert_eq!(version, 2);
        assert_eq!(retained.refresh_token(), second.refresh_token());
        assert_eq!(b.refresh_token(), second.refresh_token());
        assert_eq!(retained.token_expiry(), newer.token_expiry());
        assert_eq!(b.state().refresh_revision, 2);
    }

    /// A refresh-style token response with no `expires_in`, so the new expiry
    /// comes from the `default_lifetime` handed to `apply_refresh`.
    fn refresh_token_response() -> TokenResponse {
        crate::client::grant::core::RawTokenResponse::builder()
            .access_token(crate::core::secrets::SecretString::new(
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
        let session = test_session(); // stored at version 0, no sid
        let mut ext = VersioningStore::with(session.clone());
        // A concurrent writer commits `sid` just before our first CAS (the
        // store advances the version to 1).
        *ext.inject_once.get_mut().unwrap() = Some(|s| {
            s.persisted.state.sid = Some("concurrent".to_owned());
        });
        let store = store_over(ext).await;

        let mut snapshot = session;
        let lifetime = Duration::from_hours(2);
        let cookies = store
            .apply_refresh_and_save(
                &mut snapshot,
                &refresh_token_response(),
                0,
                lifetime,
                &http::HeaderMap::new(),
            )
            .await
            .unwrap();

        // No Set-Cookie: the pointer cookie is unchanged by a refresh.
        assert_eq!(cookies, [] as [http::HeaderValue; 0]);
        // The caller's session was replaced with the committed merge: the
        // concurrent `sid` write survived AND the refresh was applied.
        assert_eq!(snapshot.persisted.state.sid.as_deref(), Some("concurrent"));
        assert!(
            snapshot.state().token_expiry > std::time::SystemTime::now() + Duration::from_mins(90),
            "refresh must extend token_expiry via default_lifetime"
        );
        // The store holds the same merged state, at the post-merge version.
        let (stored, version) = store.external.stored.lock().unwrap().clone().unwrap();
        assert_eq!(stored.persisted.state.sid.as_deref(), Some("concurrent"));
        assert_eq!(version, 2);
    }

    #[tokio::test]
    async fn refresh_save_failure_applies_refresh_in_memory() {
        // On a persist failure the trait contract is "refresh applied in
        // memory, save owed" — the engine serves the request from `snapshot`
        // and retries via `PendingPersist::commit`.
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
                0,
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

    #[rstest::rstest]
    #[case::retry_after_failure(false)]
    #[case::lost_acknowledgement(true)]
    #[tokio::test]
    async fn refresh_retry_adopts_newer_session(#[case] committed: bool) {
        use crate::test_support::rotating_token_response;

        let now = SystemTime::now();
        let lifetime = Duration::from_hours(1);
        let headers = http::HeaderMap::new();
        let first = rotating_token_response("token-1", now);
        let second = rotating_token_response("token-2", now + lifetime);
        let mut pending = test_session();
        let mut store = store_over(VersioningStore::with(pending.clone())).await;
        store.external.always_conflict = !committed;
        *store.external.lose_ack_once.lock().unwrap() = committed;
        let result = store
            .apply_refresh_and_save(&mut pending, &first, 0, lifetime, &headers)
            .await;
        assert_eq!(
            result.unwrap_err().kind(),
            if committed {
                SessionErrorKind::Unavailable
            } else {
                SessionErrorKind::Conflict
            }
        );
        // A committed write whose acknowledgement is lost leaves
        // durable revision 1. A failed call leaves only in-memory tokens.
        store.external.always_conflict = false;
        let key = pending.persisted().session_key;
        let (mut newer, _) = store.external.load(key).await.unwrap().unwrap();
        let revision = newer.state().refresh_revision;
        store
            .apply_refresh_and_save(&mut newer, &second, revision, lifetime, &headers)
            .await
            .unwrap();
        let version = store.external.stored_version();
        store
            .apply_refresh_and_save(&mut pending, &first, 0, lifetime, &headers)
            .await
            .unwrap();
        assert_eq!(pending.refresh_token(), second.refresh_token());
        assert_eq!(pending.state().refresh_revision, revision + 1);
        assert_eq!(store.external.stored_version(), version);
    }

    #[tokio::test]
    async fn refresh_revision_survives_non_rotating_tokens_and_duplicate_retry() {
        let mut snapshot = test_session();
        let store = store_over(VersioningStore::with(snapshot.clone())).await;
        let response = refresh_token_response(); // no replacement refresh token
        let headers = http::HeaderMap::new();
        store
            .apply_refresh_and_save(
                &mut snapshot,
                &response,
                0,
                Duration::from_hours(1),
                &headers,
            )
            .await
            .unwrap();
        assert_eq!(snapshot.state().refresh_revision, 1);
        let expiry = snapshot.token_expiry();
        // Same precondition after a lost acknowledgement: no second write or
        // reapplication, even when token equality cannot distinguish refreshes.
        store
            .apply_refresh_and_save(
                &mut snapshot,
                &response,
                0,
                Duration::from_hours(2),
                &headers,
            )
            .await
            .unwrap();
        assert_eq!(store.external.stored_version(), 1);
        assert_eq!(snapshot.token_expiry(), expiry);
    }

    #[tokio::test]
    async fn refresh_rechecks_revision_after_cas_conflict() {
        let mut snapshot = test_session();
        let mut external = VersioningStore::with(snapshot.clone());
        *external.inject_once.get_mut().unwrap() = Some(|s| {
            s.persisted.state.refresh_revision = 1;
            s.persisted.state.sid = Some("winning-refresh".to_owned());
        });
        let store = store_over(external).await;
        let old_expiry = snapshot.token_expiry();
        store
            .apply_refresh_and_save(
                &mut snapshot,
                &refresh_token_response(),
                0,
                Duration::from_hours(2),
                &http::HeaderMap::new(),
            )
            .await
            .unwrap();
        assert_eq!(store.external.stored_version(), 1);
        assert_eq!(snapshot.state().refresh_revision, 1);
        assert_eq!(snapshot.sid(), Some("winning-refresh"));
        assert_eq!(snapshot.token_expiry(), old_expiry);
    }

    #[tokio::test]
    async fn refresh_revision_never_wraps() {
        let mut snapshot = test_session();
        snapshot.persisted.state.refresh_revision = u64::MAX;
        let store = store_over(VersioningStore::with(snapshot.clone())).await;
        let error = store
            .apply_refresh_and_save(
                &mut snapshot,
                &refresh_token_response(),
                u64::MAX,
                Duration::from_hours(1),
                &http::HeaderMap::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), SessionErrorKind::Store);
        assert_eq!(store.external.stored_version(), 0);
    }

    #[tokio::test]
    async fn deferred_refresh_cannot_resurrect_deleted_session() {
        let mut snapshot = test_session();
        let store = store_over(VersioningStore::with(snapshot.clone())).await;
        store.external.delete(&snapshot).await.unwrap();
        let error = store
            .apply_refresh_and_save(
                &mut snapshot,
                &refresh_token_response(),
                0,
                Duration::from_hours(1),
                &http::HeaderMap::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), SessionErrorKind::Gone);
        assert!(store.external.stored.lock().unwrap().is_none());
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
            .sealer(test_sealer().await)
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
            .into_valid()
            .expect("decodes");
        assert_eq!(recovered, original_key);
    }

    #[tokio::test]
    async fn pointer_cookie_uses_remaining_absolute_lifetime() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();
        let deadline = SystemTime::now() + Duration::from_millis(1_500);

        let headers = store
            .pointer_cookie_headers_with_deadline(session.persisted.session_key, Some(deadline))
            .await
            .unwrap();
        let pointer = headers[0].to_str().unwrap();
        let max_age = pointer
            .split(';')
            .find_map(|attribute| attribute.trim().strip_prefix("Max-Age="))
            .unwrap()
            .parse::<u64>()
            .unwrap();

        assert!(
            (1..=2).contains(&max_age),
            "remaining Max-Age was {max_age}"
        );
    }

    #[tokio::test]
    async fn pointer_cookie_emits_kid_sidecar_when_cipher_has_identity() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .sealer(test_sealer_with_kid("kid-7").await)
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
        use crate::core::crypto::cipher::{AeadDecryptor, MultiKeyCipher, MultiKeyDecryptor};

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
            .sealer(AeadV1Sealer::new(cipher))
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
        assert_eq!(
            store.read_pointer_cookie(&req).await.into_valid(),
            Some(original_key)
        );
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
        type Version = i32;
        type Error = Infallible;

        async fn insert(&self, s: &EnrichedStoreSession, _: SystemTime) -> Result<(), Infallible> {
            *self.0.lock().unwrap() = Some(s.email.clone());
            Ok(())
        }
        async fn load(&self, _: Uuid) -> Result<Option<(EnrichedStoreSession, i32)>, Infallible> {
            Ok(None)
        }
        async fn compare_and_swap(
            &self,
            _: &EnrichedStoreSession,
            _: i32,
            _: SystemTime,
        ) -> Result<SaveOutcome, Infallible> {
            Ok(SaveOutcome::Missing)
        }
        async fn delete(&self, _: &EnrichedStoreSession) -> Result<(), Infallible> {
            Ok(())
        }
    }

    /// A completed login carrying an `email` profile claim.
    fn completed_with_email(email: &str) -> crate::CompletedLogin {
        let token_response = crate::client::grant::core::RawTokenResponse::builder()
            // A fixture token value, not a key — `SecretString::new` is the
            // value wrapper, distinct from the `Secret` key-source layer.
            .access_token(crate::core::secrets::SecretString::new("access-token"))
            .token_type("Bearer")
            .build()
            .into_token_response(None, std::time::SystemTime::now())
            .unwrap();
        let mut claims = crate::client::token::id_token::IdTokenClaims::default();
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
            .sealer(test_sealer().await)
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
            .sealer(test_sealer().await)
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
    async fn session_sealer_returns_the_configured_sealer() {
        // The accessor a convenience layer uses to default the login-state
        // sealer: it must hand back the store's configured sealer (identified
        // here by the kid it stamps on a seal), not a re-wrapped or empty one.
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session))
            .sealer(test_sealer_with_kid("v5").await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();
        let sealed = SessionDriver::session_sealer(&store)
            .seal(b"probe", b"aad")
            .await
            .unwrap();
        assert_eq!(sealed.kid.as_deref(), Some("v5"));
    }

    #[tokio::test]
    async fn termination_clears_pointer_and_kid_sidecar() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .sealer(test_sealer().await)
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .build();

        store.revoke_session(&session).await.unwrap();
        let clears = store.clear_session_cookie_headers();
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

    // ── Cookie metrics emission ──────────────────────────────────────────

    #[cfg(feature = "metrics")]
    use crate::test_support::{counter_value, test_cipher, with_metrics};

    #[cfg(feature = "metrics")]
    fn test_session_and_store() -> (MinimalSession, MinimalExternalStore) {
        let s = test_session();
        (s.clone(), MinimalExternalStore(s))
    }

    /// Counter labels for a pointer-cookie decrypt with the given outcome. The
    /// decrypt counter carries no kid label (see [`CookieSealer::record_decrypt`]).
    #[cfg(feature = "metrics")]
    fn decrypt_labels(outcome: &str) -> [(&str, &str); 2] {
        [("cookie", "__Host-session"), ("outcome", outcome)]
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_pointer_cookie_records_encrypt() {
        let ((), counters) = with_metrics(async {
            let (session, external) = test_session_and_store();
            let store = StoreBackedSessionStore::builder()
                .external(external)
                .sealer(test_sealer().await)
                .cookie_name("session".parse().unwrap())
                .cookie_path("/".parse().unwrap())
                .build();
            store
                .pointer_cookie_headers(session.persisted.session_key)
                .await
                .unwrap();
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.encrypt",
                &[("cookie", "__Host-session"), ("kid", "none")],
            ),
            1
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_pointer_cookie_records_kid_when_cipher_has_identity() {
        let ((), counters) = with_metrics(async {
            let (session, external) = test_session_and_store();
            let store = StoreBackedSessionStore::builder()
                .external(external)
                .sealer(test_sealer_with_kid("v5").await)
                .cookie_name("session".parse().unwrap())
                .cookie_path("/".parse().unwrap())
                .build();
            store
                .pointer_cookie_headers(session.persisted.session_key)
                .await
                .unwrap();
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.encrypt",
                &[("cookie", "__Host-session"), ("kid", "v5")],
            ),
            1
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_read_pointer_cookie_absent_is_silent() {
        let ((), counters) = with_metrics(async {
            let (_, external) = test_session_and_store();
            let store = StoreBackedSessionStore::builder()
                .external(external)
                .sealer(test_sealer().await)
                .cookie_name("session".parse().unwrap())
                .cookie_path("/".parse().unwrap())
                .build();
            store.read_pointer_cookie(&http::HeaderMap::new()).await;
        });
        assert!(
            !counters
                .iter()
                .any(|(name, _, _)| name == "huskarl.session_cookie.decrypt"),
            "absent cookie must not record a decrypt"
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_read_pointer_cookie_bad_encoding() {
        let ((), counters) = with_metrics(async {
            let (_, external) = test_session_and_store();
            let store = StoreBackedSessionStore::builder()
                .external(external)
                .sealer(test_sealer().await)
                .cookie_name("session".parse().unwrap())
                .cookie_path("/".parse().unwrap())
                .build();
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::COOKIE,
                "__Host-session=not!!valid!!base64".parse().unwrap(),
            );
            store.read_pointer_cookie(&headers).await;
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.decrypt",
                &decrypt_labels("bad_encoding"),
            ),
            1
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_read_pointer_cookie_tampered_records_decrypt_failed() {
        let ((), counters) = with_metrics(async {
            let (_, external) = test_session_and_store();
            let store = StoreBackedSessionStore::builder()
                .external(external)
                .sealer(test_sealer().await)
                .cookie_name("session".parse().unwrap())
                .cookie_path("/".parse().unwrap())
                .build();
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::COOKIE,
                "__Host-session=AAAAAAAAAAAA".parse().unwrap(),
            );
            store.read_pointer_cookie(&headers).await;
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.decrypt",
                &decrypt_labels("decrypt_failed"),
            ),
            1
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_read_pointer_cookie_payload_invalid_when_not_16_bytes() {
        let ((), counters) = with_metrics(async {
            let (_, external) = test_session_and_store();
            let store = StoreBackedSessionStore::builder()
                .external(external)
                .sealer(test_sealer().await)
                .cookie_name("session".parse().unwrap())
                .cookie_path("/".parse().unwrap())
                .build();
            // Seal 17 bytes under session_ptr AAD — AEAD passes but the UUID
            // conversion ([u8; 16]) fails, exercising PayloadInvalid.
            let sealed = AeadV1Sealer::new(test_cipher().await)
                .seal(&[0u8; 17], &store.sealer.aad("session_ptr"))
                .await
                .unwrap();
            let encoded = URL_SAFE_NO_PAD.encode(&sealed.bundle);
            let mut headers = http::HeaderMap::new();
            headers.insert(
                http::header::COOKIE,
                format!("__Host-session={encoded}").parse().unwrap(),
            );
            store.read_pointer_cookie(&headers).await;
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.decrypt",
                &decrypt_labels("payload_invalid"),
            ),
            1
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_read_pointer_cookie_success_records_ok() {
        let ((), counters) = with_metrics(async {
            let (session, external) = test_session_and_store();
            let store = StoreBackedSessionStore::builder()
                .external(external)
                .sealer(test_sealer_with_kid("v5").await)
                .cookie_name("session".parse().unwrap())
                .cookie_path("/".parse().unwrap())
                .build();
            let headers_out = store
                .pointer_cookie_headers(session.persisted.session_key)
                .await
                .unwrap();
            // Simulate the browser sending back both the pointer cookie and
            // the kid sidecar.
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
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.decrypt",
                &decrypt_labels("ok"),
            ),
            1
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_name_stamped_via_session_policy_labels_store_counters() {
        let ((), counters) = with_metrics(async {
            let (session, external) = test_session_and_store();
            let mut store = StoreBackedSessionStore::builder()
                .external(external)
                .sealer(test_sealer().await)
                .cookie_name("session".parse().unwrap())
                .cookie_path("/".parse().unwrap())
                .build();
            store
                .apply_session_policy(
                    &SessionPolicy::builder()
                        .secure(true)
                        .metrics_name("tenant-b")
                        .browser_callback_path("/".parse().unwrap())
                        .build(),
                )
                .unwrap();
            store
                .pointer_cookie_headers(session.persisted.session_key)
                .await
                .unwrap();
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session_cookie.encrypt",
                &[
                    ("cookie", "__Host-session"),
                    ("kid", "none"),
                    ("name", "tenant-b"),
                ],
            ),
            1
        );
    }

    // ── Storage metrics emission ─────────────────────────────────────────

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_superseded_delete_records_deleted() {
        let ((), counters) = with_metrics(async {
            let old = test_session();
            let old_key = old.persisted.session_key;
            let external = MapStore::default();
            external.seed(&old);
            let store = StoreBackedSessionStore::builder()
                .external(external)
                .sealer(test_sealer().await)
                .cookie_name("session".parse().unwrap())
                .cookie_path("/".parse().unwrap())
                .build();
            let req = request_cookies(&store.pointer_cookie_headers(old_key).await.unwrap());
            store
                .create(
                    completed_with_email("a@example.com"),
                    Duration::from_hours(1),
                    &req,
                )
                .await
                .unwrap();
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session.superseded_delete",
                &[("outcome", "deleted")],
            ),
            1
        );
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn metrics_liveness_read_failure_records_fail_open() {
        let ((), counters) = with_metrics(async {
            let session = test_session();
            let store = StoreBackedSessionStore::builder()
                .external(MinimalExternalStore(session.clone()))
                .sealer(test_sealer().await)
                .cookie_name("session".parse().unwrap())
                .cookie_path("/".parse().unwrap())
                .build()
                .with_liveness(FailingLiveness, LivenessConfig::default());
            store
                .check_liveness(&session, SystemTime::now(), true, None)
                .await
                .unwrap();
        });
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session.liveness_failure",
                &[("op", "read")],
            ),
            1
        );
    }
}
