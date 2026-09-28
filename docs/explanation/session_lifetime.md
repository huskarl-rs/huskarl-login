# Session lifetime policy

Every deployment states, via the required
[`SessionLifetime`](crate::SessionLifetime) setting, which party bounds the
session's absolute lifetime. There is deliberately no default: the two
choices have different security properties, so the pick is a policy decision,
not a tuning knob.

## Delegating to the authorization server

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

## Bounding in this crate

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
