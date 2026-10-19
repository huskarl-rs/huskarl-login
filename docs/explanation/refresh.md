# Token refresh and refresh-token rotation

[`load_session`](crate::engine::LoginEngine::load_session) refreshes the access
token when it is at or near expiry. On each load, the proactive threshold is
independently sampled between 75% and 100% of
[`token_refresh_margin`](crate::LoginConfig): 22.5–30 seconds before expiry
with the default margin. This spreads refresh decisions without sleeping in
the request path. Expired tokens are always due; a zero margin disables
proactive refresh. Without a refresh token, the
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
[`SetCookies`](crate::engine::SetCookies) — a drop guard that counts unconsumed,
non-empty cookie updates when the `metrics` feature is enabled.

## Unavailability vs rejection

Only a conclusive rejection tears the session down: an `invalid_grant` verdict,
which is how the AS reports that the refresh token is invalid, expired or revoked
(RFC 6749 §5.2). Every other failure says nothing about the refresh token and
is handled as unavailability. That includes a brief authorization-server blip, a
`5xx` or `429`, a malformed or oversized response, and client misconfiguration
such as `invalid_client`. Such a failure changes whether the *request* can be
served:

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
irreversible: an AS outage or a deployment misconfiguration that outlasts a token
lifetime would otherwise destroy every idle user's session (and refresh token)
even though they could resume once the AS recovers or the configuration is
fixed. Retryable refresh failures are retried a few times with exponential
backoff and jitter so a short outage doesn't produce a synchronized thundering
herd. A delay requested by the authorization server (`Retry-After` or a
`slow_down` verdict) extends that backoff when it is longer, but only up to a
one-second budget: the retries happen inside a request
the browser is waiting on, so a longer delay ends the attempts and leaves the
outcome to the retained-session paths above.

## Concurrent refresh

Initial-threshold jitter can reduce collisions when requests enter the refresh
window, giving a completed refresh time to become visible to later requests.
It does not coordinate exchanges: requests inside the final 75% of the margin
all consider refresh due, including bursts after an idle period. It also cannot
recover a rotated refresh token whose response was lost.

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

A rejection can itself be stale: the losing request's token was rotated by the
winner. A store-backed teardown therefore applies only while the record still
holds the refresh revision the rejected request observed. If a newer refresh
has been committed, the loser keeps the browser cookies and serves that session
while its access token is valid. If that token has already expired, the request
yields [`RefreshUnavailable`](crate::engine::LoadedSession::RefreshUnavailable)
and retains the session for a later refresh.
If the store fails while checking, the request yields
[`RefreshUnavailable`](crate::engine::LoadedSession::RefreshUnavailable) rather
than tearing down on a guess. Cookie sessions have no shared record to check.

### Unknown exchange outcomes

A timeout or `5xx` does not show whether the AS consumed the refresh token. The
engine keeps no durable record of that uncertainty, so a later attempt, whether
an in-request retry or the next request, presents the same token again. Under
strict rotation with reuse detection, this can revoke the session's token
family. That includes credentials another request has already committed, because
the original exchange may still reach the AS after a later one succeeds (see
RFC 9700 §4.14.2). Changing the retry policy does not remove this: skipping a
retry only moves the replay to the next request. Neither expiry of the original
attempt nor token introspection establishes that the original exchange can no
longer be processed.

Cookie sessions additionally depend on browser delivery order. Even identical
responses for one input token can be delivered after a later generation has
been installed. A provider grace period may tolerate bounded delays, but cannot
provide a guarantee against arbitrary response delay. Keeping authoritative
refresh state server-side could allow stale cookies to recover, at the cost of
making refresh handling stateful. See the
[rotation deployment guide](crate::_docs::how_to::rotation).

## Whole-session replacement and refresh

A refresh revision and the backend's write version protect different things.
The backend version detects any concurrent write, including application updates.
The refresh revision identifies which token generation a response belongs to.
This lets a refresh merge into the latest application state while preventing a
delayed token response from replacing a newer generation.

A whole-session save has different semantics: it replaces application fields.
Checking only its refresh revision would allow a failed, still-pending refresh
to be published under the old revision. The driver therefore also compares the
refresh token and expiry, rejecting a mismatch. These checks protect token
state; application fields remain last-writer-wins within a generation.

For mutation procedures and exact contracts, see
[Update application fields](crate::_docs::how_to::external_store#update-application-fields),
[`SessionDriver::save`](crate::SessionDriver::save), and
[`PendingPersist::commit`](crate::engine::PendingPersist::commit).
For older integrations and stored sessions, see the
[migration guide](crate::_docs::how_to::migration).
