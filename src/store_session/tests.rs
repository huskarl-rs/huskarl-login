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

    async fn insert(&self, _: &MinimalSession, _: SystemTime) -> Result<(), SessionError> {
        Ok(())
    }

    async fn load(&self, _: Uuid) -> Result<Option<(MinimalSession, i32)>, SessionError> {
        Ok(Some((self.0.clone(), 0)))
    }

    async fn compare_and_swap(
        &self,
        _: &MinimalSession,
        _: i32,
        _: SystemTime,
    ) -> Result<SaveOutcome, SessionError> {
        Ok(SaveOutcome::Committed)
    }

    async fn delete(&self, _: &MinimalSession) -> Result<(), SessionError> {
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
    let store = liveness_store(session.clone(), liveness.clone(), LivenessConfig::default()).await;

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
    let store = liveness_store(session.clone(), liveness.clone(), LivenessConfig::default()).await;

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
    let store = liveness_store(session.clone(), liveness.clone(), LivenessConfig::default()).await;

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
    let store = liveness_store(session.clone(), liveness.clone(), LivenessConfig::default()).await;

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

    async fn insert(&self, s: &MinimalSession, deadline: SystemTime) -> Result<(), SessionError> {
        *self.stored.lock().unwrap() = Some((s.clone(), 0));
        self.deadlines.lock().unwrap().push(deadline);
        Ok(())
    }
    async fn load(&self, _: Uuid) -> Result<Option<(MinimalSession, i32)>, SessionError> {
        Ok(self.stored.lock().unwrap().clone())
    }
    async fn compare_and_swap(
        &self,
        s: &MinimalSession,
        expected: i32,
        deadline: SystemTime,
    ) -> Result<SaveOutcome, SessionError> {
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
                    return Err(SessionError::new(
                        SessionErrorKind::Unavailable,
                        std::io::Error::other("lost commit acknowledgement"),
                    ));
                }
                Ok(SaveOutcome::Committed)
            }
            Some(_) => Ok(SaveOutcome::Conflict),
            None => Ok(SaveOutcome::Missing),
        }
    }
    async fn delete(&self, _: &MinimalSession) -> Result<(), SessionError> {
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
async fn whole_session_save_accepts_serialized_expiry_precision(#[case] stored_roundtripped: bool) {
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

    async fn insert(&self, s: &EnrichedStoreSession, _: SystemTime) -> Result<(), SessionError> {
        *self.0.lock().unwrap() = Some(s.email.clone());
        Ok(())
    }
    async fn load(&self, _: Uuid) -> Result<Option<(EnrichedStoreSession, i32)>, SessionError> {
        Ok(None)
    }
    async fn compare_and_swap(
        &self,
        _: &EnrichedStoreSession,
        _: i32,
        _: SystemTime,
    ) -> Result<SaveOutcome, SessionError> {
        Ok(SaveOutcome::Missing)
    }
    async fn delete(&self, _: &EnrichedStoreSession) -> Result<(), SessionError> {
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
