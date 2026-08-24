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

When converting between the drivers, re-check `cookie_path`. A stateless
cookie session may be scoped away from the callback route because the callback
can still set that cookie and there is no old server record to find. A
store-backed session requires its cookie path to cover the callback: re-login
must receive the old pointer so it can revoke the superseded record. Therefore
a path configuration accepted by [`CookieSessionStore`](crate::CookieSessionStore)
can deliberately fail [`LoginEngine`](crate::engine::LoginEngine) construction
after conversion to [`StoreBackedSessionStore`](crate::StoreBackedSessionStore).
Both drivers require the cookie path to cover a configured logout route.

## Choosing an enricher

The default [`NoEnrichment`](crate::NoEnrichment) converts the seed straight
into the session type via [`From`], and is what the store builders' `build()`
finisher uses. When the session needs ID token claims or I/O to construct,
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

### Browser-state invariants

The driver first distinguishes three observations; the engine then owns the
transition exposed to adapters:

| Driver observation | Engine state | Browser effect |
|--------------------|--------------|----------------|
| No session-shaped cookie | `Missing` | None |
| Malformed chunks, bad encoding or seal, invalid payload, or a dangling store pointer | `Cleared { reason: InvalidSession }` | Clear all session cookie slots |
| Valid session | `Active`, `ActivePending`, `Cleared`, or `RefreshUnavailable`, according to lifetime, liveness, and refresh | Deliver every cookie action carried by that state |

Several construction-time and response-time rules keep those transitions
stable:

- Every session-cookie `Path` must cover the browser-facing logout route so
  logout can load the session before clearing it. A store-backed cookie must
  also cover the callback: successful re-login needs the old pointer there to
  revoke the superseded record. Stateless cookie sessions may use a narrower
  path than the callback; they only give up the friendly
  already-authenticated fallback on stale callback navigations.
- A cookie-session save writes its complete used chunk prefix and clears every
  unused configured slot. Therefore two concurrent responses cannot leave a
  ciphertext assembled from different saves, regardless of arrival order.
- Browser clearing is constructed before server-side revocation. A backend
  failure can leave copied store pointers usable, but cannot keep the current
  browser logged in; explicit deletion returns both outcomes together in
  [`TerminateSessionOutcome`](crate::TerminateSessionOutcome).
- Logout is a `POST` whose `Origin` must exactly match the public application
  origin. Cookie `SameSite` policy alone does not stop a sibling same-site
  origin from submitting a request.

A stateless cookie session still has one fundamental browser race: the cookie
jar has no compare-and-set operation, so an older in-flight response arriving
after logout can install its valid session ciphertext again. The crate can
make every multi-chunk save internally coherent, but it cannot revoke that
ciphertext without server state. Use the store-backed driver when logout must
win globally: its update-only save contract cannot recreate a deleted record,
so even a restored pointer remains unauthenticated and is cleared on the next
request.

## Who bounds the session lifetime

Every deployment states, via the required
[`SessionLifetime`](crate::SessionLifetime) setting, which party bounds the
session's absolute lifetime. There is deliberately no default: the two
choices have different security properties, so the pick is a policy decision,
not a tuning knob.

### Delegating to the authorization server

[`DelegatedToAuthorizationServer`](crate::SessionLifetime) keeps the session
alive exactly as long as the authorization server (AS) keeps honoring the
refresh token, re-verified
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
- **Storage bounds from the AS** — the AS's refresh-token lifetime is not
  observable here, so external-store records and liveness entries are bounded
  by the activity horizon instead (default 30 days of inactivity) — see the
  [external store guide](crate::_docs::how_to::external_store).

### Bounding in this crate

[`Bounded`](crate::SessionLifetime::Bounded) tears the session down a fixed
duration after login, regardless of activity or AS policy. The deadline is
frozen into each session at login
([`SessionState::expire_at`](crate::SessionState)); cookie `Max-Age`,
external-store record TTLs, and liveness-entry TTLs all derive from that one
stored value (the latter two additionally capped by the activity horizon —
see the [external store guide](crate::_docs::how_to::external_store)), so the
configured lifetime lives in exactly one place.

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
