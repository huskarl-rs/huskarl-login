# Cookie security model

Both stores protect their cookies the same way; only *what* is sealed differs —
the whole session for [`CookieSessionStore`](crate::CookieSessionStore), just
the session key for [`StoreBackedSessionStore`](crate::StoreBackedSessionStore).

## `Secure` and the name prefixes

Cookie security is derived from a single source of truth — the configured
`base_url` scheme — and stamped onto the store by the engine, so session
cookies and the login-state cookie always share one policy. An `https` base URL
yields `Secure` cookies, prefixed `__Host-` for host-wide cookies
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
it rides only on callback requests. Abandoned flows expire with the
`login_state_ttl` `Max-Age`, and a **successful callback sweeps every pending
login-state cookie** (not just its own flow's): the session now exists, so
other pending flows are moot, and the sweep keeps flow bursts from piling
toward the browser's per-domain cookie cap — where eviction could hit the
session cookie itself. A callback that arrives after its cookie was swept (a
second tab finishing the race, or a re-navigated stale callback URL) redirects
home when the browser already holds a usable session, instead of failing with
a 400.

## Key rotation

Sealing uses one active key; unsealing accepts several. The cipher can carry a
key identity (`kid`), emitted in a sidecar cookie next to the sealed value. On
read the `kid` is a **hint, not a filter**: it picks which key to try first, but
a value that names the wrong (or a forged) key still falls back to trying the
others, so a cookie sealed before a rotation keeps working. Because the sidecar
is client-supplied, a `kid` that reaches a metrics label is normalized — a
forged value collapses to `unknown` rather than inflating label cardinality.
