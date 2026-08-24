# Implement an external session store

[`StoreBackedSessionStore`](crate::StoreBackedSessionStore) delegates session
data to an [`ExternalSessionStore`](crate::ExternalSessionStore) you
implement over your backend (Redis, SQL, DynamoDB, …). The trait is pure
storage — insert, load, save, compare-and-swap, delete. Session _construction_
from a login is the enricher's job, not the store's.

If you are converting from [`CookieSessionStore`](crate::CookieSessionStore),
audit `cookie_path` before switching. Cookie sessions may use a path that does
not cover the callback. Store-backed sessions may not: the callback needs the
old pointer to revoke the record superseded by re-login, so engine construction
rejects that configuration. The cookie path must also cover any configured
logout route for both drivers.

## The session type

Your session type embeds a [`PersistedSessionState`](crate::PersistedSessionState)
(the framework-managed key and token state) and exposes it via
[`PersistedSession`](crate::PersistedSession). It must be `Clone` —
[`PendingPersist::commit`](crate::engine::PendingPersist::commit) explains why.
Implement `From<PersistedSessionState>` if you want the plain `build()`
finisher.

## Versioning contract

Each record is stored alongside a version — the
[`Version`](crate::ExternalSessionStore::Version) associated type — that the
store owns entirely. It never appears in the session type; it travels through
the trait methods instead:

- [`load`](crate::ExternalSessionStore::load) returns the stored version with
  the session, and the framework hands it back verbatim as `expected`.
- [`save`](crate::ExternalSessionStore::save) is last-writer-wins; every write
  must change the stored version, so an in-flight compare-and-swap cannot
  succeed against overwritten state. It is update-only: if logout already
  deleted the row, return [`SaveOutcome::Missing`](crate::SaveOutcome) instead
  of recreating it.
- [`compare_and_swap`](crate::ExternalSessionStore::compare_and_swap) writes
  only if the stored version still equals `expected`, changing it on success
  and returning [`SaveOutcome::Conflict`](crate::SaveOutcome) on a version
  mismatch or [`SaveOutcome::Missing`](crate::SaveOutcome) if the row is gone.

Version is compared by **equality only**, so any per-write-unique value works:
an integer column you `+ 1` on write, a database row version (e.g. Postgres
`xmin`), an ETag, a fresh UUID per write.

## TTL contract

Every insert, save, and compare-and-swap receives an absolute `deadline` from
the driver. It is the sooner of the effective absolute session cap and the
activity horizon `max(now, token_expiry) + idle_timeout`; the driver also keeps
that idle horizon in lockstep with the [`LivenessConfig`](crate::LivenessConfig)
attached through
[`with_liveness`](crate::StoreBackedSessionStore::with_liveness). Apply the
supplied deadline as the record's absolute TTL on **every** successful write,
erring late:

- The deadline is measured on the application's clock, so a backend expiring
  exactly at it by its own clock can already be early — deleting early logs a
  user out, while a late delete costs storage and stretches the idle bound by
  at most the skew. Add a margin; rounding up is free.
- Re-apply the TTL on **every** write — backends like Redis drop a key's TTL
  on a plain overwrite.
- Never use a sliding window: one shorter than the remaining deadline deletes
  an idle-but-valid record out from under its user.
- On backends whose TTLs are relative (Cassandra, etcd leases), compute
  `deadline − now` at write time and clamp up to a small positive value rather
  than deleting.

The horizon renews with every write: an active session refreshes its tokens
(roughly once per access-token lifetime), each refresh writes the record, and
the deadline moves out. A session nobody uses stops being written, so its
record — refresh token included — expires even under a
[delegated](crate::SessionLifetime::DelegatedToAuthorizationServer) lifetime,
where `expire_at` is `None`.

## Detecting and deleting stale sessions

The framework deletes what it can reach: logout deletes the session, and a new
login that still presents the old pointer cookie deletes the record it names.
Logout clears the browser's pointer cookie independently, even when loading or
deleting the record fails. That logs out the current browser during a store
outage, but a copied pointer remains usable until deletion succeeds or the
record reaches its storage deadline; monitor the logged revocation failures.
Records it cannot reach — the pointer cookie was cleared, or its cookie key
was rotated out without a grace period — are the backend's to reap, and
the stored deadline is the detector: a record past its deadline is one your
lifetime cap or activity bound says must not be served again, so deleting it
is always safe. Deleting it is also what _enforces_ the bound: liveness fails
open, so once the liveness entry is gone, a record that is still stored would
serve — and refresh — an idle-expired session.

- **Backends with native TTLs** (Redis `EXPIREAT`, a DynamoDB TTL attribute):
  set the deadline on every write and the backend reaps for you.
- **Queryable backends** (SQL and friends): persist the deadline as its own
  column on every write and sweep periodically —
  `DELETE FROM sessions WHERE deadline < now()`.
- **Liveness entries** reap the same way: the deadline handed to
  [`touch`](crate::LivenessStore::touch) never falls before the record's, so
  applying it as the entry's TTL is likewise safe.

A complete in-memory implementation:

```rust
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Mutex;

use huskarl_login::core::{
    crypto::{cipher::AeadCipher, seal::AeadV1Sealer},
    platform::SystemTime,
};
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
    rows: Mutex<HashMap<Uuid, (MySession, i32, SystemTime)>>,
}

impl ExternalSessionStore for InMemoryStore {
    type SessionType = MySession;
    type Version = i32;
    type Error = Infallible;

    // A real backend also applies `deadline` as an absolute TTL. This demo
    // stores it so a sweeper could remove expired rows.
    async fn insert(
        &self,
        session: &MySession,
        deadline: SystemTime,
    ) -> Result<(), Infallible> {
        let key = session.persisted().session_key;
        self.rows.lock().unwrap().insert(key, (session.clone(), 0, deadline));
        Ok(())
    }

    async fn load(&self, session_key: Uuid) -> Result<Option<(MySession, i32)>, Infallible> {
        Ok(self.rows.lock().unwrap().get(&session_key)
            .map(|(session, version, _)| (session.clone(), *version)))
    }

    async fn save(
        &self,
        session: &MySession,
        deadline: SystemTime,
    ) -> Result<SaveOutcome, Infallible> {
        let key = session.persisted().session_key;
        let mut rows = self.rows.lock().unwrap();
        let Some((_, version, _)) = rows.get(&key) else {
            return Ok(SaveOutcome::Missing);
        };
        let next = version + 1;
        rows.insert(key, (session.clone(), next, deadline));
        Ok(SaveOutcome::Committed)
    }

    async fn compare_and_swap(
        &self,
        session: &MySession,
        expected: i32,
        deadline: SystemTime,
    ) -> Result<SaveOutcome, Infallible> {
        let key = session.persisted().session_key;
        let mut rows = self.rows.lock().unwrap();
        match rows.get(&key) {
            Some((_, version, _)) if *version == expected => {
                rows.insert(key, (session.clone(), expected + 1, deadline));
                Ok(SaveOutcome::Committed)
            }
            Some(_) => Ok(SaveOutcome::Conflict),
            None => Ok(SaveOutcome::Missing),
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
        .sealer(AeadV1Sealer::new(cipher))
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

Every deployment has an idle bound
([`idle_timeout`](crate::LivenessConfig::idle_timeout), default 30 days); the
TTL contract above enforces it coarsely by reaping records whose horizon has
passed. For precise per-request enforcement, attach a
[`LivenessStore`](crate::LivenessStore) with
[`with_liveness`](crate::StoreBackedSessionStore::with_liveness). See the
[liveness explanation](crate::_docs::explanation::liveness).
