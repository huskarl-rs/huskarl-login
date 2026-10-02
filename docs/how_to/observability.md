# Observe login failures

Use this guide to connect an integration's engine diagnostics and counters to
application monitoring. Axum and Pingora also observe their own request and
response handling; consult your adapter's docs for those hooks.

## Enable counters

Enable the crate's `metrics` feature in the dependency used by your integration:

```toml
huskarl-login = { version = "0.5", features = ["metrics"] }
```

Install a recorder through your application's chosen `metrics` exporter during
startup. Enabling the feature alone does not install one. Give each engine a
stable `.metrics_name("customer-login")` if several engines share a recorder.
Use configuration names, not user or request identifiers.

Start with these observations; the full label schema and counting boundaries
are in the [`metrics`](crate::metrics) reference:

| Counter | Investigate when it increases |
| --- | --- |
| `huskarl.login.complete` with a failure outcome | Callback validation, provider exchange, or session creation failed. |
| `huskarl.login.handled_failure` | The engine consumed an error; inspect its `operation` and your diagnostic handler. |
| `huskarl.session.refresh` with `failed_unavailable` | An expired token could not be refreshed; check provider availability. |
| `huskarl.session.dropped` | An adapter dropped cookie updates or a pending persistence retry. |
| `huskarl.session.liveness_failure` | Idle tracking failed open or could not record/clear activity. |
| `huskarl.session.superseded_delete` with `load_failed` or `delete_failed` | Re-login could not clean up the previous server-side session. |

These populations overlap. A refresh success counts the exchange, not successful
persistence or browser receipt; a dropped-work counter does not detect every
cancelled operation.

## Attach an engine diagnostic handler

The engine returns some errors to the adapter and consumes others while choosing
a response or fallback. `.diagnostics(...)` observes the consumed errors even
without `metrics`. For example, forward operation classifications to a bounded
application queue:

```rust
use std::sync::mpsc::{SyncSender, TrySendError};
use huskarl_login::{ConfigError, LoginConfig, SessionDriver};
use huskarl_login::client::grant::authorization_code::AuthorizationCodeGrant;
use huskarl_login::engine::{DiagnosticOperation, LoginEngine};

fn observed_engine<SD: SessionDriver>(
    config: LoginConfig,
    grant: AuthorizationCodeGrant,
    store: SD,
    events: SyncSender<DiagnosticOperation>,
) -> Result<LoginEngine<SD>, ConfigError> {
    LoginEngine::builder()
        .config(config)
        .grant(grant)
        .session_store(store)
        .metrics_name("customer-login")
        .diagnostics(move |diagnostic| {
            match events.try_send(diagnostic.operation) {
                Ok(()) => {}
                // This example chooses best-effort delivery.
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {}
            }
        })
        .build()
}
```

Create the queue with `std::sync::mpsc::sync_channel` and consume it in your
application's monitoring worker. This example exports only the operation. To
include error classification, inspect or downcast `diagnostic.error` inside the
callback and create an owned, redacted event; the borrowed error cannot escape
the callback. Define how your integration counts queue overflow if losing events
matters.

Handlers run synchronously, may run concurrently, and must not block or panic.
Error sources may contain tokens or untrusted text. This hook is operational
diagnostics, not a durable audit stream.

## Observe errors at their owner

Handle returned `SessionError`s where your adapter calls `load_session`,
`save_session`, or `PendingPersist::commit`. Inspect the independent revocation
result returned by `terminate_session` after preserving its cookie clears.

For individual liveness and superseded-record cleanup errors, instrument your
`LivenessStore` or `ExternalSessionStore` implementation, or wrap it. Those
best-effort driver failures increment counters but do not reach the engine's
diagnostic handler. The library emits no logs itself, and drop guards retain
counts rather than error details.

To verify wiring, inject a store failure and a provider exchange failure in an
integration test. Check the returned error or diagnostic operation at the
appropriate boundary and confirm counters reach the installed recorder. Then
use [Troubleshoot browser login](crate::_docs::how_to::troubleshooting) to relate
those signals to browser symptoms.
