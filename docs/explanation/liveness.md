# Server-side liveness (idle timeout)

Idle timeout is enforced **server-side**, not from a timestamp carried on the
session. A [`StoreBackedSessionStore`](crate::StoreBackedSessionStore) with a
[`LivenessStore`](crate::LivenessStore) attached (via
[`with_liveness`](crate::StoreBackedSessionStore::with_liveness)) keeps a
`last_active` timestamp per session key; on each request the engine reads it,
compares against [`idle_timeout`](crate::LivenessConfig), and tears the session
down on an [`Expired`](crate::LivenessVerdict) verdict.

Cookie sessions, and store-backed sessions without a liveness store, report
[`Untracked`](crate::LivenessVerdict) — idle timeout simply isn't enforced for
them, and only the absolute [`SessionLifetime`](crate::SessionLifetime)
bound applies.

## Fail open

A liveness read failure never expires a session: the verdict degrades to
[`Active`](crate::LivenessVerdict) and idle enforcement falls back to the
absolute session-lifetime bound until the store recovers. An outage of the liveness backend must
not log every user out.

## Hot/cold write split

Reading liveness happens on every request; writing it does not. Activity writes
are:

- **throttled** — coalesced to one write per
  [`touch_min_interval`](crate::LivenessConfig), so steady traffic is a trickle
  of writes rather than one per request, and the throttle is shared across
  replicas because it compares against the persisted `last_active`. Because
  `last_active` advances at most once per interval, the interval must stay
  below `idle_timeout` or continuously-active sessions would idle out; the
  [`LivenessConfig`](crate::LivenessConfig) builder enforces this, and by
  default derives the interval as a quarter of `idle_timeout` (capped at one
  hour);
- **conditional** — skipped entirely when the engine's
  [`ActivityPolicy`](crate::ActivityPolicy) classifies the request as
  non-activity (a cross-site embed, a background poll, …), so those requests
  keep a session readable without keeping it alive;
- **best-effort and monotonic** — a failed write just delays the next advance;
  it never fails the request.

The absolute expiry handed to the store
([`expire_at`](crate::LivenessStore::touch)) is the session's effective
deadline — the tighter of the one frozen at login
([`SessionState::expire_at`](crate::SessionState)) and the live
[`SessionLifetime::Bounded`](crate::SessionLifetime) cap (absent when the
lifetime is delegated to the authorization server) — not a sliding idle TTL.
The liveness entry thus expires exactly when the session can no longer be
valid, which is what keeps fail-open correct.
