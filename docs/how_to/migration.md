# Adapt an existing integration

Use the sections that apply when updating an older engine integration or session
backend to the API documented here. For Axum and Pingora, also follow the
adapter's migration instructions. These notes describe API and behavior changes;
use the dependency versions selected by your adapter's release.

## Classified session errors

Older external-store implementations declared their own `type Error`. Remove
that associated type, return `SessionError` from each backend method, and map
errors at the I/O or decoding boundary:

- Use `SessionError::new(SessionErrorKind::Unavailable, error)` for transient
  connection or service failures.
- Use `SessionError::new(SessionErrorKind::Store, error)` for corrupt data,
  schema mismatches, or permanent failures.
- Keep missing records and version conflicts as `LoadOutcome` and `SaveOutcome`.

`SessionDriver` is sealed; choose a built-in driver and implement
`ExternalSessionStore` for a custom backend. Adapter tests should use a built-in
driver with a test backend, such as `testing::InMemoryExternalSessionStore`
under the `test-support` feature. Driver loads return `SessionError`.

## Refresh revisions and whole-session saves

Older serialized `SessionState` values without `refresh_revision` deserialize
with revision zero. Retain the field in any custom serialization. Application
updates must preserve the framework-managed state; direct backend writes bypass
the driver's checks.

Direct callers of `SessionDriver::apply_refresh_and_save` and adapter tests using
`PendingPersist::builder` must supply `expected_refresh_revision` from before
the token exchange. Keep that same value on a deferred retry, even when the
in-memory session has changed. A lost write acknowledgement may mean the first
commit succeeded; the retry then adopts stored state rather than applying the
refresh response again.

Whole-session saves compare revision, refresh token, and expiry with stored
state before committing through CAS. Expiry comparison uses serialized
whole-second precision and preserves the stored value. Use `PendingPersist::commit`
for pending refreshes and `StoreBackedSessionStore::update` for application field
changes. A whole-session save can now reject a stale or pending token state with
`SessionErrorKind::Conflict`.

When rolling out these guards for the first time, account for older writers:
binaries without the guards and direct backend writes can still overwrite
protected state. The guarantee holds once all writers follow the contract.
Verify concurrent refresh, application updates, and logout with the
[backend checks](crate::_docs::how_to::external_store#verify-the-backend) and
[rotation checks](crate::_docs::how_to::rotation).

## Optional telemetry and diagnostics

When moving from the always-on telemetry used in 0.4.0 to the opt-in API documented
here, enable `metrics` to retain counters and keep an application recorder
installed. Unnamed series carry `name=""`; update dashboards and label selectors.
Consult the [`metrics`](crate::metrics) catalog for current names and populations.

Replace reliance on library log messages with an engine `.diagnostics(...)`
handler for consumed engine errors. Observe returned errors at adapter call
sites, and instrument the supplied stores for individual best-effort liveness
and superseded-record cleanup failures. Drop guards expose counts, not individual
log events. Decrypt counters have no key-ID label.

Adapter maintainers can forward an optional login dependency's feature with
`huskarl-login?/metrics`; keep adapter diagnostics separate from engine diagnostics
and avoid emitting the engine's counters twice. See
[Observe login failures](crate::_docs::how_to::observability) for wiring and checks.
