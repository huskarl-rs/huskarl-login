# Deploy refresh-token rotation safely

There are two distinct concurrency boundaries: exchanging tokens at the
provider and persisting/delivering the resulting session. The store-backed
refresh revision protects the latter's database write, not the former.

## Check the actual refresh path

`LoginEngine` calls `RefreshGrant::exchange` directly. The client's `TokenCache`
and `RefreshTokenStore` abstractions are **not integrated into this path**;
implementing a shared cache alone does not coordinate login-engine refreshes.
There is currently no built-in refresh coordinator configuration on the engine.

If your provider requires serialized refresh exchanges, deployment needs an
explicit coordination integration covering this path across replicas. Even
with coordination, browser cookie delivery may occur out of order.

## Verify provider behavior

Check how the authorization server handles concurrent reuse of a refresh token:
which responses remain usable, whether reuse revokes a token family, and whether
it offers a grace period. A grace period can tolerate bounded races; it is not
a guarantee against arbitrary request or response delays.

The store-backed revision guard keeps an older result from overwriting a
committed refresh, including during a deferred persistence retry. It does not
stop an independent exchange from invalidating credentials at the provider.

## Cookie-session limitations

Cookie refresh persistence only prepares `Set-Cookie`; delivery completes the
write. An old response can arrive after a newer refresh or logout and replace
browser state. This cannot be prevented by a revision inside a cookie of the
same name, because the browser does not compare revisions.

Stateless deployments must accept this ordering limitation and choose provider
behavior accordingly. An authoritative shared refresh record can support
recovery from stale cookies, but makes refresh handling stateful and requires
an integration beyond the current cookie driver.

## Tuning and rollout

[`token_refresh_margin`](crate::LoginConfig) changes when refresh begins. It
does not fix exchange or response-order races. Eager persistence shortens the
normal store write window, but deferred retries and delayed cookie delivery
can extend it beyond the token-exchange round trip.

Store-backed refresh commits are guarded by their original revision, but
whole-session saves and direct backend writes can bypass that check. Prefer
`StoreBackedSessionStore::update` for application mutations. See the
[refresh explanation](crate::_docs::explanation::refresh).
