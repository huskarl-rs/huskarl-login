# Implement an external session store

[`StoreBackedSessionStore`](crate::StoreBackedSessionStore) delegates session
data to an [`ExternalSessionStore`](crate::ExternalSessionStore) you
implement over your backend (Redis, SQL, DynamoDB, …). The trait is pure
storage — insert, load, compare-and-swap, delete. Session _construction_
from a login is the enricher's job, not the store's.

If you are converting from [`CookieSessionStore`](crate::CookieSessionStore),
audit `cookie_path` before switching. Cookie sessions may use a path that does
not cover the callback. Store-backed sessions may not: the callback needs the
old pointer to revoke the record superseded by re-login, so engine construction
rejects that configuration. The cookie path must also cover any configured
logout route for both drivers.

## 1. Define the session type

Your session type embeds a [`PersistedSessionState`](crate::PersistedSessionState)
(the framework-managed key and token state) and exposes it via
[`PersistedSession`](crate::PersistedSession). It must be `Clone` —
[`PendingPersist::commit`](crate::engine::PendingPersist::commit) explains why.
Implement `From<PersistedSessionState>` if you want the plain `build()`
finisher.

## 2. Implement atomic version checks

Choose a version value that changes on every write. Return it from `load` and
make `compare_and_swap` check and replace it atomically. Return `Conflict` for
a changed version and `Missing` for a deleted record; never recreate a missing
record during an update. Follow the
[versioning contract](crate::ExternalSessionStore#versioning-contract).

## 3. Apply the supplied storage deadline

Store the supplied `deadline` on every insert and successful compare-and-swap.
Use an absolute backend TTL, or persist a deadline column for a sweeper.
Account for clock skew and rounding as specified by the
[TTL contract](crate::ExternalSessionStore#ttl-contract).

## 4. Reap expired records

The framework deletes what it can reach: logout deletes the session, and a new
login that still presents the old pointer cookie deletes the record it names.
Logout clears the browser's pointer cookie independently, even when loading or
deleting the record fails. That logs out the current browser during a store
outage, but a copied pointer remains usable until deletion succeeds or the
record reaches its storage deadline; monitor revocation failures through the engine diagnostic handler and handled-failure counter (see [metrics](crate::metrics)).
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
  applying it as the entry's TTL is likewise safe. The driver initializes the
  entry at login, after the record insert succeeds, using that same deadline;
  this touch is best-effort so a liveness outage does not fail login.

## 5. Wire the backend into the driver

This in-memory example demonstrates the trait methods and builder. It records
deadlines but does not enforce them; add the expiry handling from step 4 before
using this pattern in a deployment.

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

## Update application fields

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

## Add idle-timeout tracking

Every deployment has an idle bound
([`idle_timeout`](crate::LivenessConfig::idle_timeout), default 30 days); the
[TTL contract](crate::ExternalSessionStore#ttl-contract) enforces it coarsely by reaping records whose horizon has
passed. For precise per-request enforcement, attach a
[`LivenessStore`](crate::LivenessStore) with
[`with_liveness`](crate::StoreBackedSessionStore::with_liveness). See the
[liveness explanation](crate::_docs::explanation::liveness).

## Save a whole session only when replacement is intended

Prefer `StoreBackedSessionStore::update` for application field changes: it
merges your change into the current record. A whole-session save replaces
application fields and can reject stale refresh state with `Conflict`; see
[`SessionDriver::save`](crate::SessionDriver::save) for the checks and costs.

Use [`PendingPersist::commit`](crate::engine::PendingPersist::commit) for a
pending refresh. Preserve refresh fields in application updates and route
writes through the driver so its concurrency checks run.

## Verify the backend

Before connecting a real backend, check these outcomes:

- Two writes with the same expected version: only one commits.
- A write after deletion: returns `Missing` and leaves the record absent.
- A successful overwrite: retains the supplied storage deadline.
- An expired record: is removed by your TTL or cleanup mechanism.

These checks exercise the backend's atomicity and retention behavior; the
in-memory example alone does not establish those properties for your database.
