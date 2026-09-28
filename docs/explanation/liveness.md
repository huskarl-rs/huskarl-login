# Server-side liveness (idle timeout)

Idle timeout is enforced **server-side**, not from a timestamp carried on the
session. A [`StoreBackedSessionStore`](crate::StoreBackedSessionStore) with a
[`LivenessStore`](crate::LivenessStore) attached (via
[`with_liveness`](crate::StoreBackedSessionStore::with_liveness)) keeps a
`last_active` timestamp per session key; on each request the engine reads it,
compares against [`idle_timeout`](crate::LivenessConfig), and tears the session
down on an [`Expired`](crate::LivenessVerdict) verdict.

Login initializes `last_active` when the session record is created, so the idle
clock starts at login rather than at the first request after the callback. Like
later activity writes, this initial touch is best-effort: a failure leaves the
record's storage deadline as the fail-open bound.

Every store-backed deployment has a storage idle bound —
[`idle_timeout`](crate::LivenessConfig::idle_timeout) defaults to 30 days
([`DEFAULT_IDLE_TIMEOUT`](crate::DEFAULT_IDLE_TIMEOUT)); there is no unbounded
mode. The default is deliberately long: it changes nothing for deployments
with real idle requirements, while guaranteeing that storage for sessions
nobody uses anymore is eventually reclaimed (see the
[TTL contract](crate::ExternalSessionStore#ttl-contract)).

Cookie sessions, and store-backed sessions without a liveness store, report
[`Untracked`](crate::LivenessVerdict) — there is no `last_active` to judge, so
per-request enforcement doesn't happen for them. Store-backed sessions still
get the coarse form: records whose activity horizon has passed are reaped by
the storage TTL.

## Fail open

A liveness read failure never expires a session: the verdict degrades to
[`Active`](crate::LivenessVerdict) and idle enforcement falls back to the
absolute session-lifetime bound until the store recovers. An outage of the liveness backend must
not log every user out.

## Hot/cold write split

Reading liveness happens on every request. Login contributes one initial write;
subsequent activity writes are:

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

## Entry TTLs and fail-open

The deadline handed to the store ([`touch`](crate::LivenessStore::touch)) is
the record's storage deadline — the sooner of the session's effective absolute
deadline and the activity horizon `max(now, token_expiry) + idle_timeout` —
never a sliding idle TTL. The ordering matters: a missing entry reads as
active, so an entry that expired **before** its record would resurrect an idle
session; an entry that outlives its record is harmless, because the record is
what serves requests. Anchoring the horizon to `token_expiry` rather than
`now` keeps the entry alive across the whole gap to the next possible
record write (a token refresh), which is what preserves that ordering.

One softness is accepted: a token refresh extends the record's deadline, but
the entry keeps the deadline from its last touch until the next one. A session
whose final activity triggered a refresh can therefore fail open — read as
active — for up to one access-token lifetime past its idle timeout. That
window is small against realistic idle timeouts and consistent with fail-open
during a liveness outage.
