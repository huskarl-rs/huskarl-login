//! Metrics observer trait for session cookie operations.
//!
//! [`SessionCookieMetrics`] is a zero-dependency sink that session stores call
//! when they encrypt or decrypt a session cookie. Wire in a Prometheus (or
//! other backend) implementation at construction time via
//! [`CookieSessionStore::with_metrics`] or
//! [`StoreBackedSessionStore::with_metrics`].
//!
//! Absent cookies are always silent — the metric fires only when a
//! session-cookie-shaped value was present in the request.

/// Outcome of a session cookie decryption attempt.
///
/// Passed to [`SessionCookieMetrics::record_decrypt`] to indicate why
/// decryption succeeded or failed. [`as_str`](Self::as_str) returns a
/// `&'static str` suitable for use as a Prometheus label value.
#[non_exhaustive]
pub enum DecryptResult {
    /// The cookie was successfully decrypted and deserialized.
    Ok,
    /// The cookie value was not valid base64url.
    BadEncoding,
    /// The AEAD seal could not be verified (wrong key, tampered payload, etc.).
    DecryptFailed,
    /// The plaintext was authenticated but could not be deserialized.
    PayloadInvalid,
}

impl DecryptResult {
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::BadEncoding => "bad_encoding",
            Self::DecryptFailed => "decrypt_failed",
            Self::PayloadInvalid => "payload_invalid",
        }
    }
}

/// Observer for session cookie encrypt/decrypt events.
///
/// Implement this trait to record metrics to a backend of your choice
/// (Prometheus, `StatsD`, OpenTelemetry, etc.). Session stores accept an optional
/// `Arc<dyn SessionCookieMetrics>` and call the appropriate method on each
/// operation.
///
/// Absent cookies are always silent — [`record_decrypt`](Self::record_decrypt)
/// fires only when a session-cookie-shaped value was actually present in the
/// request.
pub trait SessionCookieMetrics: Send + Sync + 'static {
    /// Record a decryption attempt on the session cookie.
    ///
    /// `cookie_name` is the base session cookie name (e.g. `huskarl_session`).
    /// `kid` is the identity decoded from the kid sidecar cookie, or `None` if
    /// the sidecar was absent or could not be decoded. `result` indicates the
    /// outcome of the attempt.
    fn record_decrypt(&self, cookie_name: &str, kid: Option<&str>, result: &DecryptResult);

    /// Record a completed encryption of the session cookie.
    ///
    /// `cookie_name` is the base session cookie name. `kid` is the key ID
    /// reported by the active sealer (`sealer.key_id()`), or `None` if the
    /// key was constructed without an identity. The `kid` label implicitly
    /// tracks which key is performing live encryption, making key rotation
    /// observable without a separate active-key gauge.
    fn record_encrypt(&self, cookie_name: &str, kid: Option<&str>);
}

// ── Login engine metrics ───────────────────────────────────────────────────────

/// Outcome of a login redirect attempt.
///
/// Passed to [`LoginEngineMetrics::record_login_start`].
#[non_exhaustive]
pub enum LoginStartResult {
    /// The redirect to the authorization server was produced successfully.
    Ok,
    /// Generating the redirect failed (e.g. authorization server unreachable).
    Error,
}

impl LoginStartResult {
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

/// Outcome of processing an OAuth callback (token exchange and session creation).
///
/// Passed to [`LoginEngineMetrics::record_login_complete`].
#[non_exhaustive]
pub enum LoginCompleteResult {
    /// Login completed successfully — a new session was created.
    Ok,
    /// The authorization server returned an error response (e.g. user denied access).
    AsDenied,
    /// The callback request was malformed: missing or invalid `code` or `state`.
    InvalidRequest,
    /// The login-state cookie was absent, corrupted, or could not be authenticated.
    StateInvalid,
    /// The token exchange with the authorization server failed.
    TokenExchangeFailed,
    /// Session creation in the session store failed.
    SessionCreateFailed,
}

impl LoginCompleteResult {
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::AsDenied => "as_denied",
            Self::InvalidRequest => "invalid_request",
            Self::StateInvalid => "state_invalid",
            Self::TokenExchangeFailed => "token_exchange_failed",
            Self::SessionCreateFailed => "session_create_failed",
        }
    }
}

/// OAuth 2.0 / OIDC authorization error codes recognized by
/// [`normalize_as_error`]: RFC 6749 §4.1.2.1 plus the OIDC Core §3.1.2.6
/// additions.
const KNOWN_AS_ERROR_CODES: &[&str] = &[
    // RFC 6749 §4.1.2.1
    "invalid_request",
    "unauthorized_client",
    "access_denied",
    "unsupported_response_type",
    "invalid_scope",
    "server_error",
    "temporarily_unavailable",
    // OIDC Core §3.1.2.6
    "interaction_required",
    "login_required",
    "account_selection_required",
    "consent_required",
    "invalid_request_uri",
    "invalid_request_object",
    "request_not_supported",
    "request_uri_not_supported",
    "registration_not_supported",
];

/// Normalizes an authorization server `error` code to a closed set of values.
///
/// The callback's `error` query parameter is attacker-suppliable — anyone can
/// request `/callback?error=<arbitrary bytes>` — so it must not flow into a
/// metrics label unbounded (label-cardinality explosion). Known RFC 6749 /
/// OIDC Core error codes are returned as their `&'static str` equivalent;
/// anything else maps to `"other"`.
#[must_use]
pub fn normalize_as_error(error: &str) -> &'static str {
    KNOWN_AS_ERROR_CODES
        .iter()
        .find(|code| **code == error)
        .copied()
        .unwrap_or("other")
}

/// Outcome of a token refresh attempt.
///
/// Passed to [`LoginEngineMetrics::record_refresh`].
#[non_exhaustive]
pub enum RefreshResult {
    /// The session had no refresh token — it was cleared.
    NoRefreshToken,
    /// The refresh token was exchanged successfully for new tokens.
    Ok,
    /// The token refresh request failed conclusively — session was cleared.
    Failed,
    /// The refresh failed with a retryable (transient) error while the access
    /// token was still valid — the session was retained and the refresh will
    /// be re-attempted on a later request. A sustained elevated rate here
    /// signals authorization-server trouble *before* users start getting
    /// logged out.
    FailedRetained,
}

impl RefreshResult {
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoRefreshToken => "no_refresh_token",
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::FailedRetained => "failed_retained",
        }
    }
}

/// Outcome of session activity recording for an authenticated request.
///
/// Passed to [`LoginEngineMetrics::record_activity`]. The ratio of
/// [`Touch`](Self::Touch) to [`Skip`](Self::Skip) outcomes is the effective
/// touch rate; use it to tune [`LoginConfig::touch_min_interval`](crate::LoginConfig::touch_min_interval).
#[non_exhaustive]
pub enum ActivityOutcome {
    /// The session's `last_active` timestamp was updated (touch interval elapsed).
    Touch,
    /// Activity was not recorded — the touch interval has not yet elapsed.
    Skip,
}

impl ActivityOutcome {
    /// Returns a `&'static str` suitable for use as a Prometheus label value.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Touch => "touch",
            Self::Skip => "skip",
        }
    }
}

/// Observer for [`LoginEngine`](crate::engine::LoginEngine) events.
///
/// Implement this trait to record login-flow metrics to a backend of your
/// choice. Attach an implementation via
/// [`LoginEngine::with_metrics`](crate::engine::LoginEngine::with_metrics).
pub trait LoginEngineMetrics: Send + Sync + 'static {
    /// Record a login redirect attempt (browser redirected to authorization server).
    fn record_login_start(&self, result: &LoginStartResult);

    /// Record the outcome of processing an OAuth callback.
    ///
    /// `as_error` carries the OAuth 2.0 `error` code from the authorization
    /// server's error response (e.g. `"access_denied"`, `"server_error"`)
    /// when `result` is [`LoginCompleteResult::AsDenied`], and is `None`
    /// for all other outcomes. Useful for distinguishing user-initiated
    /// denials from AS-side errors.
    ///
    /// The value is normalized via [`normalize_as_error`] before reaching
    /// this method: it is always one of the known RFC 6749 / OIDC Core error
    /// codes or the literal `"other"`, never raw attacker-suppliable input —
    /// safe to use directly as a metrics label.
    fn record_login_complete(&self, result: &LoginCompleteResult, as_error: Option<&str>);

    /// Record the outcome of a token refresh attempt.
    ///
    /// Called whenever a session is loaded and the access token is at or near
    /// expiry — whether or not a refresh token is available.
    fn record_refresh(&self, result: &RefreshResult);

    /// Record session activity recording outcome for an authenticated request.
    ///
    /// Called when a valid (non-expiring) session is loaded. The ratio of
    /// [`Touch`](ActivityOutcome::Touch) to [`Skip`](ActivityOutcome::Skip)
    /// outcomes reflects the effective touch rate.
    fn record_activity(&self, outcome: &ActivityOutcome);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_as_error_passes_known_codes_through() {
        for code in KNOWN_AS_ERROR_CODES {
            assert_eq!(normalize_as_error(code), *code);
        }
    }

    #[test]
    fn normalize_as_error_maps_unknown_to_other() {
        for input in [
            "",
            "not_a_real_code",
            "ACCESS_DENIED", // case-sensitive: not the registered code
            "access_denied ",
            "access_denied\n",
            "a]b{c}", // label-syntax metacharacters
        ] {
            assert_eq!(normalize_as_error(input), "other", "input: {input:?}");
        }
    }

    #[test]
    fn normalize_as_error_rejects_oversized_input() {
        let long = "a".repeat(64 * 1024);
        assert_eq!(normalize_as_error(&long), "other");
    }
}
