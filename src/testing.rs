//! Test utilities for integrations built on `huskarl-login`.
//!
//! Enable the `test-support` feature from a dev-dependency. The types in this
//! module are deterministic test doubles, not production storage backends.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

use uuid::Uuid;

use crate::{
    ExternalSessionStore, LoadOutcome, PersistedSession, SaveOutcome, Session,
    core::platform::{MaybeSendSync, SystemTime},
};

/// Invocation counts observed by an [`InMemoryExternalSessionStore`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExternalSessionStoreCalls {
    /// Calls to [`ExternalSessionStore::insert`].
    pub inserts: usize,
    /// Calls to [`ExternalSessionStore::load`].
    pub loads: usize,
    /// Calls to [`ExternalSessionStore::save`].
    pub saves: usize,
    /// Calls to [`ExternalSessionStore::compare_and_swap`].
    pub compare_and_swaps: usize,
    /// Calls to [`ExternalSessionStore::delete`].
    pub deletes: usize,
}

struct StoreState<S> {
    records: HashMap<Uuid, (S, u64)>,
    calls: ExternalSessionStoreCalls,
}

impl<S> Default for StoreState<S> {
    fn default() -> Self {
        Self {
            records: HashMap::new(),
            calls: ExternalSessionStoreCalls::default(),
        }
    }
}

/// Cloneable in-memory [`ExternalSessionStore`] for adapter and integration tests.
///
/// Records are versioned with monotonically increasing `u64` values. Saves are
/// update-only, compare-and-swap observes the supplied version, and deletion is
/// idempotent, matching the production store contract.
#[derive(Clone)]
pub struct InMemoryExternalSessionStore<S> {
    state: Arc<Mutex<StoreState<S>>>,
    fail_inserts: Arc<AtomicBool>,
    fail_deletes: Arc<AtomicBool>,
}

impl<S> Default for InMemoryExternalSessionStore<S> {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(StoreState::default())),
            fail_inserts: Arc::new(AtomicBool::new(false)),
            fail_deletes: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl<S> InMemoryExternalSessionStore<S> {
    fn state(&self) -> MutexGuard<'_, StoreState<S>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Returns whether `session_key` currently identifies a stored record.
    #[must_use]
    pub fn contains(&self, session_key: Uuid) -> bool {
        self.state().records.contains_key(&session_key)
    }

    /// Returns the number of stored session records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state().records.len()
    }

    /// Returns whether the store contains no session records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state().records.is_empty()
    }

    /// Returns a snapshot of calls made through [`ExternalSessionStore`].
    #[must_use]
    pub fn calls(&self) -> ExternalSessionStoreCalls {
        self.state().calls
    }

    /// Configures subsequent inserts to return [`InjectedExternalStoreError`].
    pub fn set_fail_inserts(&self, fail: bool) {
        self.fail_inserts.store(fail, Ordering::Relaxed);
    }

    /// Configures subsequent deletes to return [`InjectedExternalStoreError`].
    pub fn set_fail_deletes(&self, fail: bool) {
        self.fail_deletes.store(fail, Ordering::Relaxed);
    }
}

impl<S: PersistedSession + Clone> InMemoryExternalSessionStore<S> {
    /// Seeds a record directly, bypassing call counting and injected failures.
    pub fn seed(&self, session: &S) {
        self.state()
            .records
            .insert(session.persisted().session_key, (session.clone(), 1));
    }
}

/// Error returned when a configured failure is injected into the test store.
#[derive(Debug)]
pub struct InjectedExternalStoreError;

impl std::fmt::Display for InjectedExternalStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("injected external store failure")
    }
}

impl std::error::Error for InjectedExternalStoreError {}

#[allow(clippy::unused_async_trait_impl)]
impl<S> ExternalSessionStore for InMemoryExternalSessionStore<S>
where
    S: Session + PersistedSession + Clone + MaybeSendSync + 'static,
{
    type SessionType = S;
    type Version = u64;
    type Error = InjectedExternalStoreError;

    async fn insert(&self, session: &S, _: SystemTime) -> Result<(), Self::Error> {
        let mut state = self.state();
        state.calls.inserts += 1;
        if self.fail_inserts.load(Ordering::Relaxed) {
            return Err(InjectedExternalStoreError);
        }
        state
            .records
            .insert(session.persisted().session_key, (session.clone(), 1));
        Ok(())
    }

    async fn load(&self, session_key: Uuid) -> Result<LoadOutcome<Self>, Self::Error> {
        let mut state = self.state();
        state.calls.loads += 1;
        Ok(state.records.get(&session_key).cloned())
    }

    async fn save(&self, session: &S, _: SystemTime) -> Result<SaveOutcome, Self::Error> {
        let mut state = self.state();
        state.calls.saves += 1;
        let Some((stored, version)) = state.records.get_mut(&session.persisted().session_key)
        else {
            return Ok(SaveOutcome::Missing);
        };
        *stored = session.clone();
        *version += 1;
        Ok(SaveOutcome::Committed)
    }

    async fn compare_and_swap(
        &self,
        session: &S,
        expected: u64,
        _: SystemTime,
    ) -> Result<SaveOutcome, Self::Error> {
        let mut state = self.state();
        state.calls.compare_and_swaps += 1;
        let Some((stored, version)) = state.records.get_mut(&session.persisted().session_key)
        else {
            return Ok(SaveOutcome::Missing);
        };
        if *version != expected {
            return Ok(SaveOutcome::Conflict);
        }
        *stored = session.clone();
        *version += 1;
        Ok(SaveOutcome::Committed)
    }

    async fn delete(&self, session: &S) -> Result<(), Self::Error> {
        let mut state = self.state();
        state.calls.deletes += 1;
        if self.fail_deletes.load(Ordering::Relaxed) {
            return Err(InjectedExternalStoreError);
        }
        state.records.remove(&session.persisted().session_key);
        Ok(())
    }
}
