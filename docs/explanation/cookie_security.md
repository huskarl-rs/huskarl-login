# Cookie security model

Both stores protect their cookies the same way; only *what* is sealed differs —
the whole session for [`CookieSessionStore`](crate::CookieSessionStore), just
the session key for [`StoreBackedSessionStore`](crate::StoreBackedSessionStore).

## `Secure` and the `__Host-` prefix

Cookie security is derived from a single source of truth — the configured
`base_url` scheme — and stamped onto the store by the engine, so session
cookies and the login-state cookie always share one policy. An `https` base URL
yields `Secure` cookies with the `__Host-` prefix (the browser then guarantees
the cookie is host-locked, path-`/`, and `Secure`); an `http` base URL (local
development) drops both. The stores therefore take no `secure` setting of their
own.

## AEAD associated data

Sealed cookies bind context as AEAD associated data (AAD), so a ciphertext
can't be lifted from one slot and replayed in another:

- session cookies bind the cookie **name**, and
- the login-state cookie binds the OAuth `state` value, tying it to one
  in-flight authorization request.

## Chunking

A cookie session can exceed a single cookie's size limit, so the sealed payload
is split across numbered chunk cookies. On save, slots the new session no longer
occupies are cleared; this is why the persist methods take the original request
headers — to see which stale chunks to drop.

## Key rotation

Sealing uses one active key; unsealing accepts several. The cipher can carry a
key identity (`kid`), emitted in a sidecar cookie next to the sealed value. On
read the `kid` is a **hint, not a filter**: it picks which key to try first, but
a value that names the wrong (or a forged) key still falls back to trying the
others, so a cookie sealed before a rotation keeps working. Because the sidecar
is client-supplied, a `kid` that reaches a metrics label is normalized — a
forged value collapses to `unknown` rather than inflating label cardinality.
