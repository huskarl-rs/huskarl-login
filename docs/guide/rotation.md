# Deploying with refresh-token rotation

If your authorization server rotates refresh tokens on each use, a multi-replica
deployment needs two things in place so that concurrent refreshes don't log
users out. The background is in the
[refresh explanation](crate::_docs::explanation::refresh); this is the checklist.

## 1. A shared refresh-token cache

Concurrent requests across replicas can enter the refresh window for the same
session at once. Give them a shared place to converge by implementing
`huskarl::cache::TokenCache` / `RefreshTokenStore` over shared storage (the same
Redis/database you already run). Concurrent refreshes then coordinate through it
instead of each independently spending the refresh token and racing.

## 2. A rotation grace period on the AS

Configure the authorization server with a short **rotation grace period** so
that reuse of a just-rotated refresh token inside the race window is honored
rather than treated as token theft. Without it, the AS sees the second request
replay the old token and revokes the entire token family — logging the user out.

## What happens without them

The race window is small — the engine persists a refresh eagerly, so it is
roughly the token-exchange round trip plus the store write, not the request's
full handler latency. But occasional collisions still occur, and they surface as
session teardowns. This is most visible with
[`CookieSessionStore`](crate::CookieSessionStore), where the refresh token lives
in the browser cookie and the last writer simply wins; a store-backed deployment
with the shared cache above narrows the window further.

## Tuning the window

[`token_refresh_margin`](crate::LoginConfig) controls how early before expiry a
refresh fires. A larger margin refreshes sooner (more headroom against a slow
AS) at the cost of refreshing more often; it does not change the rotation
requirements above.
