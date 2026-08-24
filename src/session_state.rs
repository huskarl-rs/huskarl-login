//! Application sessions and their framework-managed token and timing state.
//!
//! Every application session embeds a [`SessionState`] and exposes it through
//! [`Session`]. Server-side liveness is stored separately; see
//! [`crate::liveness`].

use serde::{Deserialize, Serialize};

use crate::{
    client::{
        grant::core::TokenResponse,
        token::{IdToken, RefreshToken},
    },
    core::{
        platform::{Duration, SystemTime},
        serde_utils::time::{option_unix_secs, unix_secs},
    },
};

/// A finite fallback for duration additions that exceed [`SystemTime`]'s
/// representable range. This mirrors the access-token expiry policy in
/// `huskarl`: an overflowing deadline remains far in the future without
/// becoming unrepresentable (and therefore unserializable).
const OVERFLOW_TIME_HORIZON: Duration = Duration::from_hours(100 * 365 * 24);

/// Adds a duration to wall-clock time without panicking.
///
/// An unrepresentable result is bounded to a century after `base`; on a
/// pathological platform where even that is unrepresentable, it falls back to
/// `base`.
pub(crate) fn bounded_time_add(base: SystemTime, duration: Duration) -> SystemTime {
    base.checked_add(duration)
        .or_else(|| base.checked_add(OVERFLOW_TIME_HORIZON))
        .unwrap_or(base)
}

/// Framework-managed token and timing fields embedded in every session.
///
/// Applications normally receive this value as the seed passed to a
/// [`SessionEnricher`](crate::SessionEnricher) and preserve it inside their
/// session type. Use [`SessionState::builder`] for tests and custom flows. The
/// raw ID token is deliberately not stored here; see [`Session::id_token`].
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, bon::Builder)]
pub struct SessionState {
    /// Absolute expiry of the access token (from `expires_in`, else the default lifetime).
    #[serde(with = "unix_secs")]
    pub token_expiry: SystemTime,
    /// Refresh token issued alongside the access token, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<RefreshToken>,
    /// Subject identifier from the ID token, for logout revocation lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Session ID from the ID token, for logout revocation lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
    /// When the session was created (initial login).
    #[serde(with = "unix_secs")]
    pub created_at: SystemTime,
    /// Absolute session deadline, **fixed at login**: `created_at` plus the
    /// [`SessionLifetime::Bounded`](crate::SessionLifetime) cap in force when
    /// the session was created; `None` under a delegated lifetime. See
    /// [`Bounded`](crate::SessionLifetime::Bounded) for how changing the cap
    /// affects existing sessions.
    #[serde(with = "option_unix_secs")]
    pub expire_at: Option<SystemTime>,
}

impl SessionState {
    /// Creates a `SessionState` from a completed login. `max_lifetime` is the
    /// [`SessionLifetime::Bounded`](crate::SessionLifetime) cap stamped onto
    /// the session store, freezing [`expire_at`](Self::expire_at) at login.
    pub(crate) fn from_completed(
        completed: &crate::CompletedLogin,
        default_lifetime: Duration,
        max_lifetime: Option<Duration>,
    ) -> Self {
        let now = SystemTime::now();
        let token_response = completed.token_response();
        let token_expiry = token_response
            .access_token()
            .effective_expiry(default_lifetime, Duration::ZERO);
        let sub = completed.subject().map(str::to_string);
        let sid = completed
            .id_token_claims()
            .and_then(|claims| claims.sid.clone());

        Self {
            token_expiry,
            refresh_token: token_response.refresh_token().cloned(),
            sub,
            sid,
            created_at: now,
            expire_at: max_lifetime.map(|max| bounded_time_add(now, max)),
        }
    }

    /// Produces a new `SessionState` with tokens updated from a refresh response,
    /// keeping the existing refresh token unless the response rotates it.
    #[must_use]
    pub fn refreshed(&self, token_response: &TokenResponse, default_lifetime: Duration) -> Self {
        let mut new = self.clone();

        new.token_expiry = token_response
            .access_token()
            .effective_expiry(default_lifetime, Duration::ZERO);

        if let Some(rt) = token_response.refresh_token() {
            new.refresh_token = Some(rt.clone());
        }

        new
    }
}

/// Gives the engine access to an application's session state.
///
/// Implement this trait for a custom application session. Embed the
/// [`SessionState`] supplied by the session enricher, then implement only
/// [`state`](Self::state) and [`set_state`](Self::set_state). The default
/// methods expose its lifecycle fields and apply token refreshes. Override
/// [`id_token`](Self::id_token) or [`apply_refresh`](Self::apply_refresh) only
/// when the custom session stores additional related data.
pub trait Session {
    /// Returns a shared reference to the embedded [`SessionState`].
    fn state(&self) -> &SessionState;

    /// Replaces the embedded [`SessionState`] with a new value.
    fn set_state(&mut self, state: SessionState);

    /// Absolute expiry of the access token.
    fn token_expiry(&self) -> SystemTime {
        self.state().token_expiry
    }

    /// The refresh token, if the authorization server issued one.
    fn refresh_token(&self) -> Option<&RefreshToken> {
        self.state().refresh_token.as_ref()
    }

    /// The ID token, if the session stores one.
    ///
    /// Defaults to `None`: [`SessionState`] does not store the raw `id_token`.
    /// Override on a custom session type to supply it (e.g. for `id_token_hint`).
    fn id_token(&self) -> Option<&IdToken> {
        None
    }

    /// Subject identifier from the ID token, if present.
    fn sub(&self) -> Option<&str> {
        self.state().sub.as_deref()
    }

    /// Session ID from the ID token, if present.
    fn sid(&self) -> Option<&str> {
        self.state().sid.as_deref()
    }

    /// When the session was created (initial login).
    fn created_at(&self) -> SystemTime {
        self.state().created_at
    }

    /// Absolute session deadline fixed at login, if the deployment bounded
    /// it — see [`SessionState::expire_at`]. The engine enforces it alongside
    /// the live config and derives external-store deadlines from it.
    fn expire_at(&self) -> Option<SystemTime> {
        self.state().expire_at
    }

    /// Apply tokens from a refresh response via [`SessionState::refreshed`].
    fn apply_refresh(&mut self, token_response: &TokenResponse, default_lifetime: Duration) {
        let new_state = self.state().refreshed(token_response, default_lifetime);
        self.set_state(new_state);
    }
}

/// Absolute retention deadline for a session record written at `now`.
///
/// Kept crate-private so external stores cannot drift from the driver policy;
/// [`StoreBackedSessionStore`](crate::StoreBackedSessionStore) supplies the
/// resulting deadline to every write.
pub(crate) fn storage_deadline<S: Session + ?Sized>(
    session: &S,
    now: SystemTime,
    idle_timeout: Duration,
) -> SystemTime {
    let horizon = bounded_time_add(session.token_expiry().max(now), idle_timeout);
    session.expire_at().map_or(horizon, |e| e.min(horizon))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    const HOUR: Duration = Duration::from_hours(1);
    const DAY: Duration = Duration::from_hours(24);

    struct S(SessionState);

    impl Session for S {
        fn state(&self) -> &SessionState {
            &self.0
        }
        fn set_state(&mut self, s: SessionState) {
            self.0 = s;
        }
    }

    /// `offset` past the epoch; `now` in the cases below is `at(DAY)`.
    fn at(offset: Duration) -> SystemTime {
        SystemTime::UNIX_EPOCH + offset
    }

    #[rstest]
    #[case::activity_horizon_when_unbounded(at(DAY + HOUR), None, at(DAY * 2 + HOUR))]
    #[case::anchors_at_now_when_token_expired(at(HOUR * 23), None, at(DAY * 2))]
    #[case::expire_at_when_sooner(at(DAY + HOUR), Some(at(DAY + HOUR)), at(DAY + HOUR))]
    #[case::horizon_when_sooner_than_expire_at(
        at(DAY + HOUR),
        Some(at(DAY * 400)),
        at(DAY * 2 + HOUR)
    )]
    fn storage_deadline_cases(
        #[case] token_expiry: SystemTime,
        #[case] expire_at: Option<SystemTime>,
        #[case] expected: SystemTime,
    ) {
        let s = S(SessionState::builder()
            .token_expiry(token_expiry)
            .created_at(SystemTime::UNIX_EPOCH)
            .maybe_expire_at(expire_at)
            .build());
        assert_eq!(storage_deadline(&s, at(DAY), DAY), expected);
    }

    #[test]
    fn oversized_duration_is_bounded_without_panicking() {
        let base = at(DAY);
        assert_eq!(
            bounded_time_add(base, Duration::MAX),
            base + OVERFLOW_TIME_HORIZON
        );
    }

    #[test]
    fn oversized_token_expires_in_is_bounded_without_panicking() {
        let received_at = at(DAY);
        let token_response = crate::client::grant::core::RawTokenResponse::builder()
            .access_token(crate::core::secrets::SecretString::new("access-token"))
            .token_type("Bearer")
            .expires_in(u64::MAX)
            .build()
            .into_token_response(None, received_at)
            .unwrap();
        let completed = crate::CompletedLogin::builder()
            .token_response(token_response)
            .build();

        let state = SessionState::from_completed(&completed, HOUR, None);

        assert_eq!(state.token_expiry, received_at + OVERFLOW_TIME_HORIZON);
    }
}
