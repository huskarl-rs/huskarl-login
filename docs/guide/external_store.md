# Implementing an external session store

[`StoreBackedSessionStore`](crate::StoreBackedSessionStore) delegates the actual
session data to an [`ExternalSessionStore`](crate::ExternalSessionStore) you
implement over your backend (Redis, SQL, DynamoDB, …). The trait is pure
storage — insert, load, save, compare-and-swap, delete. Session *construction*
from a login is the enricher's job, not the store's.

## The session type

Your session type embeds a [`PersistedSessionState`](crate::PersistedSessionState)
(the framework-managed key, token state, and version) and exposes it via
[`PersistedSession`](crate::PersistedSession). Implement `From<PersistedSessionState>`
if you want the plain `build()` finisher.

## Versioning contract

Each record carries a [`version`](crate::PersistedSessionState):

- [`save`](crate::ExternalSessionStore::save) is last-writer-wins and advances
  the version unconditionally.
- [`compare_and_swap`](crate::ExternalSessionStore::compare_and_swap) writes
  only if the stored version still equals `expected`, advancing it on success
  and returning [`SaveOutcome::Conflict`](crate::SaveOutcome) otherwise. Version
  is compared by **equality only** — a column-based `version + 1` and a
  body-persisted version both work as long as a matched swap ends one higher.

## TTL contract

The record's deadline is stored on the session itself:
[`Session::expire_at`](crate::Session::expire_at) is **frozen at login**
(`created_at` plus the [`SessionLifetime::Bounded`](crate::SessionLifetime)
cap in force at the time), computed by the framework so you never repeat the
configured lifetime in your store. Retain the record until **at least** that
instant. The TTL is garbage collection, not enforcement — the engine checks
the deadline on every load — so deleting early logs a user out while deleting
late only costs storage. Err late:

- `expire_at` is measured on the application's clock, so a backend expiring
  exactly at it by its own clock can already be early — retaining until "at
  least" that instant requires a margin covering the clock skew between the
  two. Rounding up further is free.
- Re-apply the TTL on **every** write — backends like Redis drop a key's TTL
  on a plain overwrite.
- Never use a sliding window: one shorter than the remaining lifetime deletes
  an idle-but-valid record out from under its user.
- On backends whose TTLs are relative (Cassandra, etcd leases), compute
  `expire_at − now` at write time and clamp up to a small positive value
  rather than deleting.

Under a
[delegated](crate::SessionLifetime::DelegatedToAuthorizationServer) lifetime
`expire_at` is `None` — there is no deadline to retain until, so plan your own
garbage collection for abandoned records.

A complete in-memory implementation:

```rust
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Mutex;

use huskarl::core::crypto::cipher::AeadCipher;
use huskarl_login::{
    ExternalSessionStore, PersistedSession, PersistedSessionState, SaveOutcome, Session,
    SessionState, StoreBackedSessionStore,
};
use uuid::Uuid;

#[derive(Clone)]
struct MySession {
    persisted: PersistedSessionState,
}

impl Session for MySession {
    fn state(&self) -> &SessionState { self.persisted.state() }
    fn set_state(&mut self, s: SessionState) { self.persisted.set_state(s); }
}

impl PersistedSession for MySession {
    fn persisted(&self) -> &PersistedSessionState { &self.persisted }
    fn persisted_mut(&mut self) -> &mut PersistedSessionState { &mut self.persisted }
}

impl From<PersistedSessionState> for MySession {
    fn from(persisted: PersistedSessionState) -> Self { Self { persisted } }
}

#[derive(Default)]
struct InMemoryStore {
    rows: Mutex<HashMap<Uuid, (MySession, i32)>>,
}

impl ExternalSessionStore for InMemoryStore {
    type SessionType = MySession;
    type Error = Infallible;

    // A real backend retains each record until at least `session.expire_at()`
    // (see "TTL contract" above); this in-memory demo skips it.
    async fn insert(&self, session: &MySession) -> Result<(), Infallible> {
        let key = session.persisted().session_key;
        self.rows.lock().unwrap().insert(key, (session.clone(), 0));
        Ok(())
    }

    async fn load(&self, session_key: Uuid) -> Result<Option<MySession>, Infallible> {
        Ok(self.rows.lock().unwrap().get(&session_key).map(|(s, version)| {
            // Stamp the stored version onto the loaded session.
            let mut s = s.clone();
            s.persisted_mut().version = *version;
            s
        }))
    }

    async fn save(&self, session: &MySession) -> Result<(), Infallible> {
        let key = session.persisted().session_key;
        let mut rows = self.rows.lock().unwrap();
        let next = rows.get(&key).map_or(0, |(_, v)| v + 1);
        rows.insert(key, (session.clone(), next));
        Ok(())
    }

    async fn compare_and_swap(
        &self,
        session: &MySession,
        expected: i32,
    ) -> Result<SaveOutcome, Infallible> {
        let key = session.persisted().session_key;
        let mut rows = self.rows.lock().unwrap();
        match rows.get(&key) {
            Some((_, v)) if *v == expected => {
                rows.insert(key, (session.clone(), expected + 1));
                Ok(SaveOutcome::Committed)
            }
            _ => Ok(SaveOutcome::Conflict),
        }
    }

    async fn delete(&self, session: &MySession) -> Result<(), Infallible> {
        self.rows.lock().unwrap().remove(&session.persisted().session_key);
        Ok(())
    }
}

// Attach the store. `build()` uses `NoEnrichment` (the `From` impl above);
// use `build_with_enricher` / `build_with_claims` to populate extra fields.
fn attach(cipher: impl AeadCipher + 'static) -> StoreBackedSessionStore<InMemoryStore> {
    StoreBackedSessionStore::builder()
        .external(InMemoryStore::default())
        .cipher(cipher)
        .cookie_name("session".parse().unwrap())
        .cookie_path("/".parse().unwrap())
        .build()
}
```

## Atomic updates outside the login flow

To mutate a stored session safely under concurrency, use
[`update`](crate::StoreBackedSessionStore::update). It loads, applies your
closure, and commits via `compare_and_swap`, retrying on conflict. The closure
may run more than once against freshly-loaded state, so it must be
**replayable** — derive the new state from the session it is given, never from a
value captured beforehand:

```rust
# use huskarl_login::{PersistedSession, SessionError, StoreBackedSessionStore};
# use uuid::Uuid;
# async fn demo<E>(store: StoreBackedSessionStore<E>, key: Uuid) -> Result<(), SessionError>
# where E: huskarl_login::ExternalSessionStore {
let updated = store
    .update(key, |session| {
        session.persisted_mut().state.sub = Some("alice".to_owned());
    })
    .await?;
# let _ = updated;
# Ok(())
# }
```

It errors with [`Gone`](crate::SessionErrorKind) if the key is absent,
[`Conflict`](crate::SessionErrorKind) if the retry budget is exhausted, or
[`Unavailable`](crate::SessionErrorKind) on a store error.

## Idle-timeout tracking

Idle timeout is optional and orthogonal to the data store — attach a
[`LivenessStore`](crate::LivenessStore) with
[`with_liveness`](crate::StoreBackedSessionStore::with_liveness). See the
[liveness explanation](crate::_docs::explanation::liveness).
