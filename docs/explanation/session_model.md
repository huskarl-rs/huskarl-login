# The session model

In this crate, a **session** is the application value made available to an
authenticated request. It contains a framework-managed
[`SessionState`](crate::SessionState) plus
any application fields, such as roles or profile data. Where that value is
stored is an independent choice.

The main terms are:

| Term | Meaning |
|------|---------|
| **Completed login** | Tokens and validated identity claims returned after the Authorization Code flow. |
| **Seed** | Framework-managed state prepared before the application session exists. |
| **Enricher** | Application code that combines the completed login and seed into a session. |
| **Session driver** | The engine-facing persistence abstraction implemented by the two built-in stores. |
| **External store** | A Redis, SQL, or similar backend used only by store-backed sessions. |

Session creation follows the same model regardless of persistence:

1. **The seed** — framework-managed state the engine prepares on the
   application's behalf after a successful OAuth callback. For cookie sessions
   the seed is [`SessionState`](crate::SessionState); for store-backed sessions
   it is [`PersistedSessionState`](crate::PersistedSessionState), which adds the
   generated session key.
2. **The enricher** — a [`SessionEnricher`](crate::SessionEnricher) turns the
   seed plus the [`CompletedLogin`](crate::CompletedLogin) (validated ID token
   claims and the token response) into the application's session type.
3. **The session driver** — persists the resulting session.

```text
CompletedLogin ─┐
                ├─▶ SessionEnricher ─▶ application session ─▶ session driver
seed ───────────┘
```

## Choosing where to store sessions

| Driver | Browser contains | Server contains | Prefer when |
|--------|------------------|-----------------|-------------|
| [`CookieSessionStore`](crate::CookieSessionStore) | The complete AEAD-encrypted session, split into chunks when needed | Nothing | Sessions are small and stateless operation matters more than immediate revocation |
| [`StoreBackedSessionStore`](crate::StoreBackedSessionStore) | An AEAD-encrypted lookup key | The session body in an [`ExternalSessionStore`](crate::ExternalSessionStore) | You need revocation, larger sessions, server-side idle tracking, or atomic updates |

The cookie store is *stateless* only from the server's perspective. The
browser cookie is still authoritative session state, so clearing one browser
cannot revoke a copied cookie. The store-backed driver can revoke all copies
by deleting the referenced record.

For the cookie-path requirements when switching drivers, follow
[Implement an external session store](crate::_docs::how_to::external_store).

## Choosing an enricher

The default [`NoEnrichment`](crate::NoEnrichment) converts the seed straight
into the session type via [`From`], and is what the store builders' `build()`
method uses. When the session needs ID token claims or I/O to construct,
supply a custom enricher instead — see the
[enrichment guide](crate::_docs::how_to::enrichment).

## The engine sees one driver interface

Both built-in stores implement the sealed [`SessionDriver`](crate::SessionDriver)
interface. It lets [`LoginEngine`](crate::engine::LoginEngine) apply the same
login, refresh, and logout state machine to either persistence model. The
engine wraps cookie changes in [`SetCookies`](crate::engine::SetCookies), which
the framework adapter must append to the outgoing response.

Browser-local logout is deliberately separate from server-side deletion:
[`clear_session_cookies`](crate::SessionDriver::clear_session_cookies) builds
cookie clears without store I/O, so the logout response can invalidate the
current browser even while an external store is unavailable.

## Loading classifies the request

[`LoginEngine::load_session`](crate::engine::LoginEngine::load_session) does
not redirect. It validates any presented session, refreshes tokens when
needed, and returns a [`LoadedSession`](crate::engine::LoadedSession) state for
the adapter to handle:

| State | Meaning | Adapter action |
|-------|---------|----------------|
| `Missing` | No session was presented | Serve anonymously or start login, depending on the route |
| `Active` | Authentication is usable and persisted | Serve the application session and deliver any returned cookies |
| `ActivePending` | Authentication is usable, but a refreshed session still needs a persistence retry | Serve the session, then commit the pending persist |
| `Cleared` | A presented session was conclusively invalid | Deliver its cookie clears, then serve anonymously or start login |
| `RefreshUnavailable` | An expired access token could not be refreshed because of a transient failure | Return a retryable error; do not delete the session or treat it as anonymous |

This separation keeps authentication policy in the adapter: the same engine
can protect private routes while still allowing optional authentication on
public routes.

## Lifetime and browser behavior

Absolute lifetime and idle timeout are separate policies. Read
[Session lifetime policy](crate::_docs::explanation::session_lifetime) to
understand delegated and bounded lifetimes, and
[Server-side liveness](crate::_docs::explanation::liveness) for idle tracking.

For cookie delivery, logout races, and browser-state guarantees, see
[Cookie security](crate::_docs::explanation::cookie_security).
