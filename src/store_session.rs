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
        SessionPolicy,
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
/// by [`LoadOutcome`] and [`SaveOutcome`]. Reserve [`SessionError`] for backend
/// failures. Every successful write must change [`Self::Version`] and apply
/// the supplied `deadline` as the record's absolute retention deadline.
///
/// ## Errors
///
/// Return [`SessionError`] with a classification appropriate to the specific
/// failure. Use [`SessionErrorKind::Unavailable`] for transient connection or
/// service failures, and [`SessionErrorKind::Store`] for corrupt stored data,
/// schema mismatches, or permanent backend failures. Do not classify every
/// database error as unavailable. Preserve the backend cause with
/// [`SessionError::new`]; the driver and engine propagate the error unchanged.
/// Missing records and version conflicts remain ordinary outcomes, not errors.
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

    /// Persist a newly created session. Called once per login, after
    /// enrichment. Apply `deadline` as the record's absolute TTL; the retention
    /// contract on [`compare_and_swap`](Self::compare_and_swap) applies.
    fn insert(
        &self,
        session: &Self::SessionType,
        deadline: SystemTime,
    ) -> impl Future<Output = Result<(), SessionError>> + MaybeSend;

    /// Load a session by its key, together with the stored
    /// [`Version`](Self::Version). Returns `None` if the key does not exist.
    fn load(
        &self,
        session_key: Uuid,
    ) -> impl Future<Output = Result<LoadOutcome<Self>, SessionError>> + MaybeSend;

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
    ) -> impl Future<Output = Result<SaveOutcome, SessionError>> + MaybeSend;

    /// Delete the session's stored record. Idempotent: a missing record is
    /// `Ok(())`.
    fn delete(
        &self,
        session: &Self::SessionType,
    ) -> impl Future<Output = Result<(), SessionError>> + MaybeSend;
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
/// `build_with_enricher(…)` supplies a custom one. The engine sets the
/// `Secure` attribute and `__Host-` prefix, so this store takes no `secure`
/// setting. Prefer this driver over [`CookieSessionStore`](crate::CookieSessionStore)
/// when sessions are large or need server-side revocation, liveness tracking,
/// or compare-and-swap updates.
///
/// See [Implement an external session store](crate::_docs::how_to::external_store)
/// for a complete backend and builder example, and
/// [Add idle-timeout tracking](crate::_docs::how_to::liveness) for liveness wiring.
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
    #[builder(finish_fn(vis = "", name = build_internal))]
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

impl<E: ExternalSessionStore, S: store_backed_session_store_builder::IsComplete>
    StoreBackedSessionStoreBuilder<E, S>
{
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
    /// [`crate::liveness`] for the fail-open / monotonic contract and
    /// [Add idle-timeout tracking](crate::_docs::how_to::liveness) for an example.
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
    /// from a value captured before the load. Keep external side effects out
    /// of the closure, since it can run again after a conflict.
    ///
    /// Change application fields only. Preserve the session key and the
    /// framework-managed [`SessionState`], including refresh token, expiry,
    /// and revision. This method does not validate those fields after the
    /// closure runs. Use [`PendingPersist::commit`](crate::engine::PendingPersist::commit)
    /// for a pending refresh. No browser cookies are returned by an update.
    /// See [Update application fields](crate::_docs::how_to::external_store#update-application-fields)
    /// for an example.
    ///
    /// # Errors
    ///
    /// [`SessionErrorKind::Gone`] (no session), [`SessionErrorKind::Conflict`]
    /// (retry budget exhausted), or the backend's classified [`SessionError`], propagated unchanged.
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
    /// may run more than once against freshly-loaded state. Preserve the
    /// session key and framework-managed state as required by [`update`](Self::update).
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
            let Some((mut session, version)) = self.external.load(session_key).await? else {
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
                .await?
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
            let Some((mut fresh, version)) = self.external.load(key).await? else {
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
                .await?
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
        self.external.insert(&session, retention_deadline).await?;
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
    ) -> Result<DriverLoad<E::SessionType>, SessionError> {
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
            let Some((current, version)) = self.external.load(key).await? else {
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
                .await?
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
        self.external.delete(session).await?;
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
    /// failures are counted when metrics are enabled and must not fail the login.
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
    ) -> Result<DriverLoad<E::SessionType>, SessionError> {
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
mod tests;
