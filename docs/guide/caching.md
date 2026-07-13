# Response caching: the adapter's contract

A session cookie that a shared cache stores and later replays to a *different*
user is a session-fixation hole. The engine guards its own responses, but it
cannot guard the inner handler's — so framework adapters carry one
responsibility.

## What the engine already guarantees

The engine marks every response it produces itself — redirects to the
authorization server, error pages, the callback and logout responses —
`Cache-Control: no-store`.

## What the adapter must guarantee

Some session `Set-Cookie` values go out on the **inner handler's** response, whose
caching the engine does not control:

- the re-sealed session cookies on an
  [`Active`](crate::engine::LoadedSession::Active) result after an eager token
  refresh,
- the cookies returned by
  [`PendingPersist::commit`](crate::engine::PendingPersist::commit) /
  [`save_session`](crate::engine::LoginEngine::save_session), and
- the cookie clears on a
  [`Cleared`](crate::engine::LoadedSession::Cleared) result.

Any response carrying these **must not be cacheable by a shared cache**. The
adapter must set `Cache-Control: no-store` (or at minimum `private`) on it. A
simple, safe rule is: whenever you attach engine-provided `Set-Cookie` values to
a response, also set `Cache-Control: no-store`.
