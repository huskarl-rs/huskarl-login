//! Server-side session liveness (idle) tracking.
//!
//! The `last_active` timestamp backing idle-timeout enforcement, tracked only
//! for store-backed sessions and kept separate from session storage. Idle
//! enforcement fails open: a missing entry or read error is treated as active,
//! never expired.

use huskarl::core::platform::{Duration, MaybeSendBoxFuture, MaybeSendSync, SystemTime};
use uuid::Uuid;

use crate::{config::ConfigError, session::SessionError};

/// Default minimum interval between liveness writes: one hour.
const DEFAULT_TOUCH_MIN_INTERVAL: Duration = Duration::from_secs(3600);

/// A server-side store for session liveness (`last_active`) timestamps, keyed
/// by the store-backed session's `Uuid`.
///
/// Liveness fails open, so an `Err` from any method is diagnostic only: it is
/// logged and then treated as an active session. Wrap backend failures with
/// `SessionError::new(SessionErrorKind::Unavailable, err)`.
pub trait LivenessStore: MaybeSendSync {
    /// Returns the last activity instant recorded for `key`, or `None` when no
    /// entry exists. `None` is treated as active, not expired.
    fn last_active(
        &self,
        key: Uuid,
    ) -> MaybeSendBoxFuture<'_, Result<Option<SystemTime>, SessionError>>;

    /// Records activity for `key` at `now`. `expire_at` is the session's
    /// absolute deadline (or `None` if unset); apply it as the entry's TTL, not
    /// a sliding idle TTL. A plain monotonic write; no debounce needed.
    fn touch(
        &self,
        key: Uuid,
        now: SystemTime,
        expire_at: Option<SystemTime>,
    ) -> MaybeSendBoxFuture<'_, Result<(), SessionError>>;

    /// Removes the liveness entry for `key` (called when a session is deleted).
    fn clear(&self, key: Uuid) -> MaybeSendBoxFuture<'_, Result<(), SessionError>>;
}

/// Configuration for session liveness tracking, carried alongside the
/// [`LivenessStore`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LivenessConfig {
    /// Kill the session after this much inactivity. `None` tracks `last_active`
    /// without enforcing an idle timeout.
    pub idle_timeout: Option<Duration>,

    /// Minimum interval between liveness writes for an active session. Must be
    /// less than [`idle_timeout`](Self::idle_timeout): `last_active` advances at
    /// most once per interval, so a longer interval would expire sessions that
    /// were active the whole time. Defaults to one hour, capped at a quarter of
    /// `idle_timeout`.
    pub touch_min_interval: Duration,
}

#[bon::bon]
impl LivenessConfig {
    /// Builds a [`LivenessConfig`], validating the intervals against each other.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidDuration`] if `idle_timeout` is zero, or if
    /// `touch_min_interval` is not less than `idle_timeout`.
    #[builder]
    pub fn new(
        /// Kill the session after this much inactivity. `None` tracks
        /// `last_active` without enforcing an idle timeout.
        idle_timeout: Option<Duration>,
        /// Minimum interval between liveness writes. Must be less than
        /// `idle_timeout`. Defaults to one hour, capped at `idle_timeout / 4`.
        touch_min_interval: Option<Duration>,
    ) -> Result<Self, ConfigError> {
        if idle_timeout == Some(Duration::ZERO) {
            return Err(ConfigError::InvalidDuration {
                field: "idle_timeout",
                reason: "must be greater than zero (use None for no timeout)",
            });
        }
        let touch_min_interval = match (touch_min_interval, idle_timeout) {
            // The hard bound: `last_active` advances at most once per
            // `touch_min_interval`, so an interval reaching `idle_timeout`
            // expires sessions that received requests the whole time.
            (Some(touch), Some(idle)) if touch >= idle => {
                return Err(ConfigError::InvalidDuration {
                    field: "touch_min_interval",
                    reason: "must be less than idle_timeout",
                });
            }
            (Some(touch), _) => touch,
            (None, Some(idle)) => DEFAULT_TOUCH_MIN_INTERVAL.min(idle / 4),
            (None, None) => DEFAULT_TOUCH_MIN_INTERVAL,
        };
        Ok(Self {
            idle_timeout,
            touch_min_interval,
        })
    }
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
    /// No liveness is tracked for this driver (cookie session, or no
    /// [`LivenessStore`] configured).
    Untracked,
    /// The session is active.
    Active,
    /// The session has been idle longer than
    /// [`idle_timeout`](LivenessConfig::idle_timeout) and should be torn down.
    Expired,
}

impl LivenessConfig {
    /// Decides the [`LivenessVerdict`] for a successfully-read `last_active`
    /// against the current time. `None` and future (clock-skewed) values are
    /// treated as active.
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
        LivenessConfig::builder()
            .maybe_idle_timeout(idle_timeout)
            .build()
            .unwrap()
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

    // ── builder validation ────────────────────────────────────────────────

    #[test]
    fn builder_without_idle_timeout_defaults_touch_to_one_hour() {
        let config = LivenessConfig::builder().build().unwrap();
        assert_eq!(config.touch_min_interval, HOUR);
    }

    #[test]
    fn builder_derives_touch_as_quarter_of_idle_timeout() {
        // idle 1h → derived touch 15min, well below the timeout, so a
        // continuously-active session always re-touches before it can expire.
        let config = LivenessConfig::builder().idle_timeout(HOUR).build().unwrap();
        assert_eq!(config.touch_min_interval, HOUR / 4);
    }

    #[test]
    fn builder_derived_touch_is_capped_at_one_hour() {
        // idle 24h → idle/4 would be 6h; the derived default never exceeds
        // the 1h ceiling (more frequent writes are fine, less frequent aren't).
        let config = LivenessConfig::builder().idle_timeout(DAY).build().unwrap();
        assert_eq!(config.touch_min_interval, HOUR);
    }

    #[test]
    fn builder_accepts_explicit_touch_below_idle_timeout() {
        let config = LivenessConfig::builder()
            .idle_timeout(HOUR)
            .touch_min_interval(Duration::from_mins(30))
            .build()
            .unwrap();
        assert_eq!(config.touch_min_interval, Duration::from_mins(30));
    }

    #[test]
    fn builder_rejects_touch_at_or_above_idle_timeout() {
        // The footgun this guards: with touch >= idle, `last_active` cannot
        // advance in time, so continuously-active sessions idle out.
        for touch in [HOUR, HOUR + Duration::from_secs(1)] {
            let err = LivenessConfig::builder()
                .idle_timeout(HOUR)
                .touch_min_interval(touch)
                .build()
                .unwrap_err();
            assert!(
                matches!(
                    err,
                    crate::ConfigError::InvalidDuration {
                        field: "touch_min_interval",
                        ..
                    }
                ),
                "expected reject for touch {touch:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn builder_accepts_any_explicit_touch_without_idle_timeout() {
        // No timeout to violate — a long interval only spaces out writes.
        let config = LivenessConfig::builder()
            .touch_min_interval(DAY)
            .build()
            .unwrap();
        assert_eq!(config.touch_min_interval, DAY);
    }

    #[test]
    fn builder_rejects_zero_idle_timeout() {
        let err = LivenessConfig::builder()
            .idle_timeout(Duration::ZERO)
            .build()
            .unwrap_err();
        assert!(matches!(
            err,
            crate::ConfigError::InvalidDuration {
                field: "idle_timeout",
                ..
            }
        ));
    }
}
