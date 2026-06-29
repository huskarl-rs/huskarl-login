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
them, and only [`max_lifetime`](crate::LoginConfig) applies.

## Fail open

A liveness read failure never expires a session: the verdict degrades to
[`Active`](crate::LivenessVerdict) and idle enforcement falls back to
`max_lifetime` until the store recovers. An outage of the liveness backend must
not log every user out.

## Hot/cold write split

Reading liveness happens on every request; writing it does not. Activity writes
are:

- **throttled** — coalesced to one write per
  [`touch_min_interval`](crate::LivenessConfig), so steady traffic is a trickle
  of writes rather than one per request, and the throttle is shared across
  replicas because it compares against the persisted `last_active`;
- **conditional** — skipped entirely when the engine's
  [`ActivityPolicy`](crate::ActivityPolicy) classifies the request as
  non-activity (a cross-site embed, a background poll, …), so those requests
  keep a session readable without keeping it alive;
- **best-effort and monotonic** — a failed write just delays the next advance;
  it never fails the request.

The absolute expiry handed to the store
([`expire_at`](crate::LivenessStore::touch)) is the session's `max_lifetime`
deadline, not a sliding idle TTL — so the liveness entry expires exactly when
the session can no longer be valid, which is what keeps fail-open correct.
