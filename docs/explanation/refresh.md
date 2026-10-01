# Token refresh and refresh-token rotation

[`load_session`](crate::engine::LoginEngine::load_session) refreshes the access
token when it is at or near expiry (within
[`token_refresh_margin`](crate::LoginConfig)). Without a refresh token, the
session remains active until access-token expiry, subject to its absolute
lifetime and idle-timeout checks. Entering the refresh margin alone does not
end it. Once the access token expires, a session without a refresh token is
cleared. Two aspects of refresh have consequences for how you deploy the crate.

## Eager persistence after refresh

A successful refresh is persisted *inside* `load_session`, before it returns —
not deferred until the handler returns. The adapter calls
[`PendingPersist::commit`](crate::engine::PendingPersist::commit) only when
persistence needs a retry.

The reason is refresh-token rotation. When the authorization server (AS) rotates
refresh tokens on each use, a deferred save that never runs — because the
adapter skipped the persist phase, the connection dropped, or the handler
panicked — would strand the rotated token and lock the session out. Persisting
eagerly closes that window.

The store-backed persist uses compare-and-swap to merge with the latest record.
An unrelated application update survives the refresh. A separate
[`SessionState::refresh_revision`](crate::SessionState::refresh_revision) fences
refresh results: the engine captures it before exchange, and a successful
refresh commit increments it. If it has changed, the driver discards the delayed
response and returns the current stored session without another write. This
also handles providers that do not rotate their refresh token. The revision is
independent of the backend version, which changes on application writes too.

Cookie sessions retain their ordinary write behavior. Their revision cannot
prevent an older `Set-Cookie` response from overwriting a newer browser cookie.

On success the session is returned as
[`Active`](crate::engine::LoadedSession::Active) with the re-sealed session
cookies in `set_cookies`. If the eager persist *fails*, the session is returned
as [`ActivePending`](crate::engine::LoadedSession::ActivePending), carrying a
[`PendingPersist`](crate::engine::PendingPersist) that pairs the session with
the token response and the original expected refresh revision. The
[`commit`](crate::engine::PendingPersist::commit) call after the handler returns,
before sending the response, then acts as the retry,
re-committing the refresh through the same merge-safe path; a commit failure
falls to the adapter's [`PersistFailurePolicy`](crate::PersistFailurePolicy).
The default policy maps a missing record (`Gone`, commonly a concurrent
logout) to `401 Unauthorized` with a `Cookie` challenge; transient backend
unavailability remains `503 Service Unavailable`.

## Returned cookies are part of the persist

For cookie sessions the eager persist only *produces* the re-sealed cookies;
the write completes when they reach the browser. Discarding them strands the
rotated refresh token just as surely as a skipped save — the session dies on
its next request. Cookie clears on a
[`Cleared`](crate::engine::LoadedSession::Cleared) result matter the same way:
a dropped clear keeps re-presenting a dead session.

Rust cannot flag a `LoadedSession::Active { session, .. }` pattern that
discards the cookies at compile time, so the engine hands them out wrapped in
[`SetCookies`](crate::engine::SetCookies) — a drop guard that logs an error when a
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
synchronized thundering herd. A delay the authorization server itself asks for
(`Retry-After`, or a `slow_down` verdict) extends that backoff when it is
longer, but only up to a one-second budget: the retries happen inside a request
the browser is waiting on, so a longer delay ends the attempts and leaves the
outcome to the retained-session paths above.

## Concurrent refresh

Two in-flight requests or replicas can exchange the same refresh token
independently. The engine calls `RefreshGrant::exchange` directly; the
`huskarl::cache::TokenCache` and `RefreshTokenStore` abstractions are not wired
into this path. Implementing one does not coordinate engine refreshes.

The store-backed revision check prevents a delayed result overwriting a
committed refresh, but it does not serialize token-endpoint requests or prevent
provider-side reuse detection. It also cannot guarantee that the first result
committed remains usable if another exchange invalidates it at the provider.
Exchange coordination would require an explicit integration around this path,
shared across replicas, and an appropriate provider policy.

Cookie sessions additionally depend on browser delivery order. Even identical
responses for one input token can be delivered after a later generation has
been installed. A provider grace period may tolerate bounded delays, but cannot
provide a guarantee against arbitrary response delay. Keeping authoritative
refresh state server-side could allow stale cookies to recover, at the cost of
making refresh handling stateful. See the
[rotation deployment guide](crate::_docs::how_to::rotation).

## Revision persistence and upgrades

Older serialized sessions default their refresh revision to zero. Store-backed
whole-session saves load the current record and compare the refresh revision,
refresh token, and expiry. A mismatch returns `Conflict`; a match commits via
CAS. A CAS conflict reloads and repeats all three checks. This prevents publishing
a pending refresh under its old revision as well as overwriting a committed
refresh. Expiry is compared at its serialized whole-second precision and the
stored value is preserved. Pending refreshes must use `PendingPersist::commit`.
Application fields still use last-writer-wins semantics within the same refresh
generation; prefer `StoreBackedSessionStore::update` for application mutations.

Application updates must preserve the refresh fields and revision. Direct writes
through the low-level backend API bypass the driver's checks. Pre-fix binaries
also bypass these checks; this compatibility caveat applies when upgrading from
those binaries, not to every subsequent deployment of compliant writers.

Direct callers of `SessionDriver::apply_refresh_and_save` and adapter tests
using `PendingPersist::new` must now supply the revision observed before the
exchange, including on retries. Do not reconstruct it from the already-refreshed
in-memory session. A lost write acknowledgement can mean the original commit
succeeded: the retry observes the advanced revision and adopts stored state
without applying the response again.
