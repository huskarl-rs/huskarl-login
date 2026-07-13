# The session model

Session creation follows one model regardless of where the session is stored.
Three pieces collaborate:

1. **The seed** — framework-managed state the engine prepares on the
   application's behalf after a successful OAuth callback. For cookie sessions
   the seed is [`SessionState`](crate::SessionState); for store-backed sessions
   it is [`PersistedSessionState`](crate::PersistedSessionState), which adds the
   generated session key and an optimistic-concurrency version.
2. **The enricher** — a [`SessionEnricher`](crate::SessionEnricher) turns the
   seed plus the [`CompletedLogin`](crate::CompletedLogin) (validated ID token
   claims and the token response) into the application's session type.
3. **The store** — persists the resulting session.

```text
CompletedLogin ─┐
                ├─▶ SessionEnricher ─▶ session ─▶ store
seed ───────────┘
```

## Two stores

- [`CookieSessionStore`](crate::CookieSessionStore) seals the whole session
  into chunked, AEAD-encrypted browser cookies. There is no server-side
  storage; the cookie *is* the session.
- [`StoreBackedSessionStore`](crate::StoreBackedSessionStore) keeps only an
  encrypted pointer cookie (the session key) in the browser and persists the
  session body through an [`ExternalSessionStore`](crate::ExternalSessionStore)
  (Redis, a database, …).

## Choosing an enricher

The default [`NoEnrichment`](crate::NoEnrichment) converts the seed straight
into the session type via [`From`], and is what the store builders' `build()`
finisher uses. When the session needs ID token claims or I/O to construct,
supply a custom enricher instead — see the
[enrichment guide](crate::_docs::guide::enrichment).

## One driver interface

Both stores implement [`SessionDriver`](crate::SessionDriver), whose mutating
methods (`save`, `touch`, `delete`) return `Vec<HeaderValue>`. Framework
adapters that need a different shape (e.g. Pingora's `&mut ResponseHeader`)
adapt with a small helper that appends the returned headers.

## Who bounds the session lifetime

Every deployment states, via the required
[`SessionLifetime`](crate::SessionLifetime) setting, which party bounds the
session's absolute lifetime. There is deliberately no default: the two
choices have different security properties, so the pick is a policy decision,
not a tuning knob.

### Delegating to the authorization server

[`DelegatedToAuthorizationServer`](crate::SessionLifetime) keeps the session
alive exactly as long as the AS keeps honoring the refresh token, re-verified
on every token refresh (roughly once per access-token lifetime). This is
strongest when the AS binds refresh tokens to its SSO session: the
application session then mirrors the SSO idle and maximum lifetimes, enforced
by the party that owns identity policy. Before choosing it, verify the AS
actually bounds refresh-token lifetime — offline tokens or non-expiring
refresh tokens make the delegated cap meaningless.

What delegation does **not** provide:

- **Re-authentication freshness** — a successful refresh proves the AS still
  honors the token, not that the user recently re-authenticated.
- **Cookie-theft containment** — with
  [`CookieSessionStore`](crate::CookieSessionStore) the refresh token travels
  in the cookie, so a stolen copy refreshes as well as the original; prefer a
  bounded lifetime with that store.
- **Storage bounds** — external-store records and liveness entries get no TTL
  hint, so abandoned sessions are only cleaned up if the user returns — see
  the [external store guide](crate::_docs::guide::external_store).

### Bounding in this crate

[`Bounded`](crate::SessionLifetime::Bounded) tears the session down a fixed
duration after login, regardless of activity or AS policy. The deadline is
frozen into each session at login
([`SessionState::expire_at`](crate::SessionState)); cookie `Max-Age`,
external-store record TTLs, and liveness-entry TTLs all derive from that one
stored value, so the configured lifetime lives in exactly one place.

Freezing makes changing the cap one-directional for existing sessions. The
engine enforces the tighter of the frozen and configured deadlines, so
lowering the cap — the security direction — applies to them immediately.
Raising it cannot extend sessions already issued: their cookies and store
records were stamped with the old deadline and would be discarded under it
regardless of what the engine now accepts. Current users therefore log out
once at the old cap and get the new one on their next login.

Both variants bound the *absolute* lifetime; idle timeout is separate,
configured on the liveness store — see
[liveness](crate::_docs::explanation::liveness).
