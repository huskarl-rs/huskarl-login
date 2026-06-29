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
