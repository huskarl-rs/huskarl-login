# Token refresh and refresh-token rotation

[`load_session`](crate::engine::LoginEngine::load_session) refreshes the access
token when it is at or near expiry (within
[`token_refresh_margin`](crate::LoginConfig)). Two aspects of how it does this
have consequences for how you deploy the crate.

## Eager persistence after refresh

A successful refresh is persisted *inside* `load_session`, before it returns —
not deferred to the adapter's post-response
[`persist_session`](crate::engine::LoginEngine::persist_session) call.

The reason is refresh-token rotation. When the authorization server rotates
refresh tokens on each use, a deferred save that never runs — because the
adapter skipped the persist phase, the connection dropped, or the handler
panicked — would strand the rotated token and lock the session out. Persisting
eagerly closes that window.

On success the session is returned as
[`Active`](crate::engine::LoadedSession::Active) with the re-sealed session
cookies in `set_cookies`. If the eager persist *fails*, the session is returned
as [`ActivePending`](crate::engine::LoadedSession::ActivePending) so the
post-response persist — and its
[`PersistFailurePolicy`](crate::PersistFailurePolicy) — acts as the retry.

## Transient vs conclusive failure

A *transient* refresh failure (a brief authorization-server blip) while the
access token is **still valid** does not tear the session down: the session is
retained and a later request re-enters the refresh window and retries. Only a
conclusive rejection (the AS rejected the refresh token, e.g. `invalid_grant`),
or any failure once the access token has actually expired, clears the session.
Refreshes are retried a few times with exponential backoff and jitter so a
short outage doesn't produce a synchronized thundering herd.

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
