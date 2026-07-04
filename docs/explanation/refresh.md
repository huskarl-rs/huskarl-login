# Token refresh and refresh-token rotation

[`load_session`](crate::engine::LoginEngine::load_session) refreshes the access
token when it is at or near expiry (within
[`token_refresh_margin`](crate::LoginConfig)). Two aspects of how it does this
have consequences for how you deploy the crate.

## Eager persistence after refresh

A successful refresh is persisted *inside* `load_session`, before it returns —
not deferred to the adapter's post-response
[`PendingPersist::commit`](crate::engine::PendingPersist::commit) call.

The reason is refresh-token rotation. When the authorization server rotates
refresh tokens on each use, a deferred save that never runs — because the
adapter skipped the persist phase, the connection dropped, or the handler
panicked — would strand the rotated token and lock the session out. Persisting
eagerly closes that window.

The persist is *merge-safe*: the engine hands the token response to the
session driver, which applies it as a replayable mutation rather than writing
back the request-scoped snapshot wholesale. For store-backed sessions the
mutation is committed through the same compare-and-swap loop as
[`StoreBackedSessionStore::update`](crate::StoreBackedSessionStore::update),
so an application update committed by a concurrent request between this
request's load and the refresh is merged, never silently overwritten — and the
request continues with the merged session. Cookie sessions keep the plain
write; the browser cookie jar is inherently last-writer-wins.

On success the session is returned as
[`Active`](crate::engine::LoadedSession::Active) with the re-sealed session
cookies in `set_cookies`. If the eager persist *fails*, the session is returned
as [`ActivePending`](crate::engine::LoadedSession::ActivePending), carrying a
[`PendingPersist`](crate::engine::PendingPersist) that pairs the session with
the token response. The post-response
[`commit`](crate::engine::PendingPersist::commit) then acts as the retry,
re-committing the refresh through the same merge-safe path; a commit failure
falls to the adapter's [`PersistFailurePolicy`](crate::PersistFailurePolicy).

## Returned cookies are part of the persist

For cookie sessions the eager persist only *produces* the re-sealed cookies;
the write completes when they reach the browser. Discarding them strands the
rotated refresh token just as surely as a skipped save — the session dies on
its next request. Cookie clears on a
[`Cleared`](crate::engine::LoadedSession::Cleared) result matter the same way:
a dropped clear keeps re-presenting a dead session.

Rust cannot flag a `LoadedSession::Active { session, .. }` pattern that
discards the cookies at compile time, so the engine hands them out wrapped in
[`SetCookies`](crate::SetCookies) — a drop guard that logs an error when a
non-empty value is dropped without being consumed into a response.

## Transient vs conclusive failure

A *transient* refresh failure (a brief authorization-server blip) never tears
the session down — only a conclusive rejection (the AS disowned the refresh
token, e.g. `invalid_grant`) does. What a transient failure changes is whether
the *request* can be served:

- access token **still valid** → the session is retained and served as
  [`Active`](crate::engine::LoadedSession::Active); a later request re-enters
  the refresh window and retries.
- access token **expired** → the session is retained but the request cannot be
  served: [`load_session`](crate::engine::LoginEngine::load_session) yields
  [`RefreshUnavailable`](crate::engine::LoadedSession::RefreshUnavailable), and
  the adapter should respond with a retryable error (e.g. `503` with
  `Retry-After`) — *not* treat the user as anonymous, which would bounce them
  into a login flow against the same unavailable server.

Failing the request instead of deleting the session matters because deletion is
irreversible: an AS outage longer than a token lifetime would otherwise destroy
every idle user's session (and refresh token) even though all of them would
resume by themselves the moment the AS recovers. Refreshes are retried a few
times with exponential backoff and jitter so a short outage doesn't produce a
synchronized thundering herd.

## Concurrent refresh

Two in-flight requests — or two replicas in a distributed deployment — can enter
the refresh window for the same session at once and each exchange the refresh
token independently. The race window is the read → exchange → save-back
sequence; because the save-back is eager (above), it is roughly the
token-exchange round trip plus the store write, and does **not** include the
inner handler's latency.

When the AS rotates refresh tokens, the expected deployment shape is:

- a **shared refresh-token cache** across replicas (implement
  `huskarl::cache::TokenCache` / `RefreshTokenStore` over shared storage) so
  concurrent refreshes converge on the rotated token instead of racing, and
- an AS configured with a **rotation grace period**, so reuse of the
  just-rotated token inside the race window is honored rather than treated as
  token theft (which would revoke the whole token family and log the user out).

Without both, occasional concurrent refreshes lose the race and surface as
teardowns — most visibly with cookie sessions, where the refresh token lives in
the cookie and the last writer wins. See the
[rotation deployment guide](crate::_docs::guide::rotation).
