# Add idle-timeout tracking

Use this with an existing [`StoreBackedSessionStore`](crate::StoreBackedSessionStore)
when inactivity should expire sessions on a request. Cookie sessions do not
support idle tracking. Without a liveness store, store-backed sessions have only
the coarse retention bound enforced by their record deadlines.

## Implement the activity backend

Implement [`LivenessStore`](crate::LivenessStore) over shared storage keyed by the
session's UUID. It may use the same database as your session backend, but stores
activity separately from the session body:

| Method | Backend operation |
| --- | --- |
| `last_active` | Read the timestamp, returning `None` if absent. |
| `touch` | Atomically retain the later of the existing timestamp and `now`; apply the supplied retention deadline without shortening existing retention. |
| `clear` | Delete the entry; treat an absent entry as success. |

Use a database conditional update, transaction, or script for `touch`; a separate
read followed by an unconditional write can move activity backwards when requests
race. Methods return `MaybeSendBoxFuture`, so wrap async backend calls in
`Box::pin(async move { ... })`.

Apply the supplied absolute `deadline`, allowing for clock skew as described in
the [retention contract](crate::ExternalSessionStore#ttl-contract). `None` means
no TTL. Do not replace it with `now + idle_timeout`: an entry expiring before
its session record can make an idle session appear active again.

Wrap backend errors in [`SessionError`](crate::SessionError). To capture individual
failures, record them in your implementation or a wrapper before returning them;
the driver's optional counter reports only the operation. See
[Observe login failures](crate::_docs::how_to::observability).

## Attach the backend before constructing the engine

This helper takes your existing session driver and liveness implementation:

```rust
use std::time::Duration;
use huskarl_login::{
    ConfigError, ExternalSessionStore, LivenessConfig, LivenessStore,
    StoreBackedSessionStore,
};

fn with_idle_timeout<E: ExternalSessionStore>(
    sessions: StoreBackedSessionStore<E>,
    activity: impl LivenessStore + 'static,
) -> Result<StoreBackedSessionStore<E>, ConfigError> {
    let config = LivenessConfig::builder()
        .idle_timeout(Duration::from_secs(30 * 60))
        .touch_min_interval(Duration::from_secs(60))
        .build()?;
    Ok(sessions.with_liveness(activity, config))
}
```

Pass the returned driver to the engine or adapter builder. The driver uses this
idle timeout when computing session-record retention as well as activity-entry
retention. `touch_min_interval` must be less than `idle_timeout`.

Choose [`LoginConfig::activity_policy`](crate::LoginConfig::activity_policy) for
which requests advance activity. `NavigationsOnly` excludes background polling;
the default `FirstParty` includes same-origin polling and requests without fetch
metadata. Idle checks still run on requests that do not count as activity.

## Verify enforcement and failure behavior

- Log in and confirm an initial activity entry is created.
- Make qualifying requests and confirm timestamps advance at the configured interval.
- Leave the session inactive past the timeout, then request a protected route;
  expect teardown with `IdleTimeout` and browser-cookie clears.
- Send delayed concurrent touches and confirm neither activity nor retention
  moves backwards.
- Fail a liveness read and confirm a valid session remains usable; fail a touch
  and confirm the request still succeeds. Observe the failure counter when enabled.

Idle tracking deliberately fails open on missing entries and backend failures;
it is not a strict inactivity guarantee during an outage. The
[liveness explanation](crate::_docs::explanation::liveness) describes retention
and timing limits, including the effect of token refresh.
