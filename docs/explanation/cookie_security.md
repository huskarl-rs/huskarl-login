# Cookie security model

Both stores protect their cookies the same way; only *what* is sealed differs —
the whole session for [`CookieSessionStore`](crate::CookieSessionStore), just
the session key for [`StoreBackedSessionStore`](crate::StoreBackedSessionStore).

## `Secure` and the name prefixes

Cookie security is derived from a single source of truth — the grant's
`redirect_uri` scheme — and stamped onto the store by the engine, so session
cookies and the login-state cookie always share one policy. An `https`
redirect URI yields `Secure` cookies, prefixed `__Host-` for host-wide cookies
(`Path=/`; the browser then guarantees the cookie is host-locked, path-`/`,
and `Secure`) or `__Secure-` for cookies scoped to a narrower path; an `http`
base URL (local development) drops both. The stores therefore take no `secure`
setting of their own.

The prefix is *always* derived — [`CookieName`](crate::CookieName) rejects
names that spell one out (in any casing). An explicit prefix could contradict
the deployment — `__Host-` without `Secure`, or off `Path=/` — and browsers
**silently discard** such a `Set-Cookie`, which surfaces as a mystery login
loop with nothing in any log. Configure the bare name; the wire name gets the
strongest prefix the deployment can honor.

## AEAD associated data

Sealed cookies bind context as AEAD associated data (AAD), so a ciphertext
can't be lifted from one slot and replayed in another:

- session cookies bind the cookie **name** (`session:{name}` /
  `session_ptr:{name}`), and
- the login-state cookie binds the OAuth `state` value
  (`login_state:{state}`), tying it to one in-flight authorization request.

Each seal's AAD carries a distinct purpose prefix, so the domains stay
separate by construction and one AEAD key can safely serve all of them.

## Chunking and the size budget

A cookie session can exceed a single cookie's size limit, so the sealed payload
is split across numbered chunk cookies. On save, slots the new session no longer
occupies are cleared; this is why the persist methods take the original request
headers — to see which stale chunks to drop.

Chunking is bounded by the store's `max_chunks` budget (default 2, ≈ 5.6 KB of
serialized session). A save that would exceed it **fails** rather than writing:
once the total `Cookie` header outgrows a proxy or server's request-header
limit (commonly 8–16 KB), requests are rejected *before* any code that could
clear the cookies runs, locking the client out for the cookies' `Max-Age`.
Failing the save surfaces the oversized payload at login instead. If sessions
routinely need more than one chunk, prefer a
[`StoreBackedSessionStore`](crate::StoreBackedSessionStore).

## Login-state cookie hygiene

Each login start mints one login-state cookie, scoped to the callback path so
it is sent only on callback requests. Abandoned flows expire with the
`login_state_ttl` `Max-Age`, and a **successful callback sweeps every pending
login-state cookie** (not just its own flow's): the session now exists, so
other pending flows are moot, and the sweep keeps flow bursts from piling
toward the browser's per-domain cookie cap — where eviction could hit the
session cookie itself. A callback that arrives after its cookie was swept (a
second tab finishing the race, or a re-navigated stale callback URL) redirects
home when the browser already holds a usable session, instead of failing with
a 400, and performs the same sweep because the pending flows are now moot.

An authorization-server error response (`error=access_denied&state=...`) ends
only the flow it identifies, so the callback clears that flow's login-state
cookie while preserving other tabs' pending flows. The echoed `state` is
untrusted callback input: it is retained only when syntactically valid, and a
clear is emitted only when the derived cookie name is present on the request.

## Browser state and logout

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
win globally: its update-only compare-and-swap contract cannot recreate a deleted record,
so even a restored pointer remains unauthenticated and is cleared on the next
request.

## Cookie encryption-key rotation

Sealing uses one active key; unsealing accepts several. The cipher can carry a
key identity (`kid`), emitted in a sidecar cookie next to the sealed value. On
read the `kid` is a **hint, not a filter**: it picks which key to try first, but
a value that names the wrong (or a forged) key still falls back to trying the
others, so a cookie sealed before a rotation keeps working. Because the sidecar
is client-supplied, a `kid` that reaches a metrics label is normalized — a
forged value collapses to `unknown` rather than inflating label cardinality.
