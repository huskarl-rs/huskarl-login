//! Server-side session liveness (idle) tracking.
//!
//! Liveness — the "last active" timestamp that backs idle-timeout enforcement —
//! is deliberately split out from session storage. It is the *hot, low-value*
//! write (it advances on every active request), whereas the session is the
//! *cold, high-value* read (tokens, subject), so they have different write
//! frequencies, different consistency needs, and may live in different
//! backends. A [`LivenessStore`] can therefore be pointed at a separate,
//! cheaper backend than the session store.
//!
//! # Server-side only
//!
//! Liveness is tracked **only for store-backed sessions**, because idle
//! enforcement is only meaningful where there is server state to check and
//! delete. A cookie-only session has no server record to expire: a stolen
//! cookie is valid up to its absolute lifetime regardless of any `last_active`
//! it carries, so an idle timeout there only ever constrains the *legitimate*
//! user. There is intentionally no cookie-backed liveness — the [`LivenessStore`]
//! is keyed by the store-backed session's `Uuid` and has no place to attach to
//! a cookie session.
//!
//! # Fail-open
//!
//! Idle timeout is a best-effort tightening on top of the session's absolute
//! `max_lifetime` (computed from `created_at`, carried in the session itself
//! with no external dependency). The absolute cap is the only hard guarantee;
//! idle enforcement degrades gracefully to it whenever liveness is unavailable.
//! A read error or a missing entry is therefore treated as *active*, never as
//! expired — see [`LivenessConfig::verdict`]. A liveness outage (including one
//! during session creation) must never block logins or log users out en masse.
//!
//! # Monotonic, coalescible writes — and where throttling lives
//!
//! `last_active` only ever moves forward, so a [`touch`](LivenessStore::touch)
//! is last-writer-wins under `max` and needs no read-modify-write or
//! compare-and-swap. Concurrent touches of the same session are correct by
//! construction, and an implementation is free to coalesce, reorder, or drop
//! superseded touches provided the latest observed instant eventually becomes
//! durable. This is the easy cousin of refresh-token rotation, which is *not*
//! coalescible — do not reach for that machinery here.
//!
//! Write-rate limiting is **not** the store's job. The store driver throttles
//! for it: it already reads `last_active` to make the idle decision, so it only
//! calls [`touch`](LivenessStore::touch) when that timestamp is older than
//! [`touch_min_interval`](LivenessConfig::touch_min_interval). A
//! [`touch`](LivenessStore::touch) implementation is therefore a plain write —
//! it need not (and should not) debounce. Because the gate uses the *persisted*
//! `last_active`, the throttle is shared across servers (≈one write per interval
//! globally), not one per process.

use huskarl::core::platform::{Duration, MaybeSendBoxFuture, MaybeSendSync, SystemTime};
use uuid::Uuid;

use crate::session::SessionError;

/// Default minimum interval between liveness writes: one hour.
const DEFAULT_TOUCH_MIN_INTERVAL: Duration = Duration::from_secs(3600);

/// A server-side store for session liveness (`last_active`) timestamps.
///
/// Keyed by the store-backed session's `Uuid` (the
/// [`PersistedSessionState::session_key`](crate::PersistedSessionState)). The
/// trait is pure storage: it never emits cookies and never sees HTTP headers,
/// because liveness is a server-side concern only.
///
/// Implementations may back this with the same store as sessions or a separate,
/// cheaper one. See the [module docs](crate::liveness) for the monotonic /
/// fail-open contract that callers rely on.
///
/// This trait is dyn-capable: [`StoreBackedSessionStore`](crate::StoreBackedSessionStore)
/// holds it as `Box<dyn LivenessStore>`, so attaching one via
/// [`with_liveness`](crate::StoreBackedSessionStore::with_liveness) does not
/// change the store's type. Being dyn-erased is also why these methods return
/// the concrete [`SessionError`] rather than an associated `type Error` like
/// [`ExternalSessionStore`](crate::ExternalSessionStore) — an associated type
/// would make the trait object unnameable. Write each method body as
/// `Box::pin(async move { ... })`, and wrap a backend failure with
/// `SessionError::new(SessionErrorKind::Unavailable, err)`.
///
/// Because liveness fails open, an `Err` from any of these methods is
/// **diagnostic only** — it is logged and then treated as an active session
/// (see [`check_liveness`](crate::SessionDriver::check_liveness)). The framework
/// never inspects the [`SessionErrorKind`](crate::SessionErrorKind), so the kind
/// is advisory; `Unavailable` is the honest default.
pub trait LivenessStore: MaybeSendSync {
    /// Returns the last activity instant recorded for `key`, or `None` when no
    /// entry exists.
    ///
    /// `None` is **not** a signal of idle expiry — a fresh session has no entry
    /// until its first touch, and an entry can be lost to eviction or an
    /// outage. Callers treat `None` (and read errors) as active; idle expiry is
    /// driven only by a present, stale value.
    fn last_active(
        &self,
        key: Uuid,
    ) -> MaybeSendBoxFuture<'_, Result<Option<SystemTime>, SessionError>>;

    /// Records activity for `key` at `now`, setting the entry to expire at
    /// `expire_at`.
    ///
    /// A plain write — the store driver already throttles these calls (see the
    /// [module docs](crate::liveness)), so the implementation must **not**
    /// debounce. Last-writer-wins and monotonic: `now` only advances, so a plain
    /// write (or a write to `max(existing, now)`) is correct without
    /// coordination.
    ///
    /// `expire_at` is the session's absolute deadline (`created_at +
    /// max_lifetime`), or `None` when the deployment sets no `max_lifetime`. Set
    /// the entry's TTL to it (e.g. Redis `PEXPIREAT`, an `expires_at` column) so
    /// the entry lives exactly as long as the session can — and **not** on a
    /// sliding idle-length TTL, which would make a missing entry ambiguous and
    /// break fail-open. The framework supplies the value; the store only applies
    /// it.
    fn touch(
        &self,
        key: Uuid,
        now: SystemTime,
        expire_at: Option<SystemTime>,
    ) -> MaybeSendBoxFuture<'_, Result<(), SessionError>>;

    /// Removes the liveness entry for `key`. Called when a session is deleted
    /// (logout, teardown).
    fn clear(&self, key: Uuid) -> MaybeSendBoxFuture<'_, Result<(), SessionError>>;
}

/// Configuration for session liveness tracking.
///
/// Carried alongside the [`LivenessStore`] (not in
/// [`LoginConfig`](crate::LoginConfig)), so that idle behaviour cannot be
/// configured without the server-side mechanism that enforces it.
#[derive(Debug, Clone, bon::Builder)]
#[non_exhaustive]
pub struct LivenessConfig {
    /// Kill the session after this much inactivity. `None` tracks `last_active`
    /// (e.g. for display) without enforcing an idle timeout.
    pub idle_timeout: Option<Duration>,

    /// Minimum interval between liveness writes for an active session.
    ///
    /// The store driver advances `last_active` (one [`touch`](LivenessStore::touch))
    /// only once this much time has passed since the last recorded activity, so
    /// steady traffic costs one write per interval rather than one per request.
    /// Keep it comfortably below [`idle_timeout`](Self::idle_timeout) so skipped
    /// updates never affect idle accuracy. Defaults to one hour.
    #[builder(default = DEFAULT_TOUCH_MIN_INTERVAL)]
    pub touch_min_interval: Duration,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            idle_timeout: None,
            touch_min_interval: DEFAULT_TOUCH_MIN_INTERVAL,
        }
    }
}

/// Outcome of evaluating a session's liveness on a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LivenessVerdict {
    /// No liveness is tracked for this driver (e.g. a cookie session, or a
    /// store-backed session with no [`LivenessStore`] configured). The engine
    /// neither enforces idle timeout nor records activity.
    Untracked,
    /// The session is active. (Recording the activity is a side effect handled
    /// by the driver/store; the engine takes no further action.)
    Active,
    /// The session has been idle longer than
    /// [`idle_timeout`](LivenessConfig::idle_timeout) and should be torn down.
    Expired,
}

impl LivenessConfig {
    /// Decides the [`LivenessVerdict`] for a successfully-read `last_active`
    /// against the current time.
    ///
    /// This is the pure idle decision for the case where the [`LivenessStore`]
    /// read *succeeded*. A read *error* is handled by the caller as fail-open
    /// ([`LivenessVerdict::Active`]) and never reaches here.
    ///
    /// - `None` (no entry yet, or lost) → [`Active`](LivenessVerdict::Active):
    ///   fail-open.
    /// - present but older than `idle_timeout` → [`Expired`](LivenessVerdict::Expired).
    /// - present and within `idle_timeout` (or no timeout) →
    ///   [`Active`](LivenessVerdict::Active).
    ///
    /// A `last_active` in the future (clock skew) is treated as just-now, i.e.
    /// active — never as expired.
    #[must_use]
    pub fn verdict(&self, last_active: Option<SystemTime>, now: SystemTime) -> LivenessVerdict {
        let Some(last_active) = last_active else {
            return LivenessVerdict::Active;
        };
        let idle = now.duration_since(last_active).unwrap_or(Duration::ZERO);
        match self.idle_timeout {
            Some(timeout) if idle > timeout => LivenessVerdict::Expired,
            _ => LivenessVerdict::Active,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_hours(1);
    const DAY: Duration = Duration::from_hours(24);

    fn config(idle_timeout: Option<Duration>) -> LivenessConfig {
        LivenessConfig {
            idle_timeout,
            touch_min_interval: HOUR,
        }
    }

    // ── verdict ───────────────────────────────────────────────────────────

    #[test]
    fn missing_entry_is_fail_open_active() {
        let now = SystemTime::UNIX_EPOCH + DAY;
        assert_eq!(
            config(Some(HOUR)).verdict(None, now),
            LivenessVerdict::Active
        );
    }

    #[test]
    fn recent_activity_is_active() {
        let now = SystemTime::UNIX_EPOCH + DAY;
        let last_active = now - Duration::from_secs(60);
        assert_eq!(
            config(Some(HOUR)).verdict(Some(last_active), now),
            LivenessVerdict::Active
        );
    }

    #[test]
    fn idle_past_timeout_expires() {
        let now = SystemTime::UNIX_EPOCH + DAY;
        let last_active = now - (HOUR + Duration::from_secs(1));
        assert_eq!(
            config(Some(HOUR)).verdict(Some(last_active), now),
            LivenessVerdict::Expired
        );
    }

    #[test]
    fn no_idle_timeout_never_expires() {
        let now = SystemTime::UNIX_EPOCH + DAY;
        assert_eq!(
            config(None).verdict(Some(SystemTime::UNIX_EPOCH), now),
            LivenessVerdict::Active
        );
    }

    #[test]
    fn future_last_active_is_active_not_expired() {
        let now = SystemTime::UNIX_EPOCH + DAY;
        let last_active = now + HOUR; // clock skew into the future
        assert_eq!(
            config(Some(HOUR)).verdict(Some(last_active), now),
            LivenessVerdict::Active
        );
    }

    #[test]
    fn default_touch_min_interval_is_one_hour() {
        assert_eq!(LivenessConfig::default().touch_min_interval, HOUR);
    }
}
