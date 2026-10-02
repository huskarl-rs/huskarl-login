//! Metrics emitted by this crate through the optional `metrics` facade. Enable the
//! off-by-default `metrics` feature and install a
//! recorder (e.g. `metrics-exporter-prometheus`) to collect them; without one
//! they are no-ops. All are counters, incremented inline on the request path.
//!
//! | Counter | Labels |
//! |---------|--------|
//! | `huskarl.login.start` | `outcome`: `ok`, `error` |
//! | `huskarl.login.complete` | `outcome`: `ok`, `already_authenticated`, `as_denied`, `invalid_request`, `state_invalid`, `token_exchange_failed`, `session_create_failed`; `error`: the normalized AS error code for `as_denied` (RFC 6749 / OIDC Core codes, else `other`), `none` otherwise |
//! | `huskarl.session.refresh` | `outcome`: `ok`, `no_refresh_token`, `failed`, `failed_retained`, `failed_unavailable` |
//! | `huskarl.session.teardown` | `reason`: [`TeardownReason`] values (`max_lifetime`, `idle_timeout`, …); `invalid_reason`: the [`InvalidSessionReason`] value when `reason` is `invalid_session`, `none` otherwise |
//! | `huskarl.session.superseded_delete` | `outcome`: `deleted`, `not_found`, `load_failed`, `delete_failed` |
//! | `huskarl.session.liveness_failure` | `op`: `read` (failed open), `touch`, `clear` |
//! | `huskarl.session_cookie.encrypt` | `cookie`: cookie name; `kid`: active key id, `none` if the key has no identity |
//! | `huskarl.session_cookie.decrypt` | `cookie`: cookie name; `outcome`: `ok`, `bad_encoding`, `decrypt_failed`, `payload_invalid` |
//!
//! Every counter has a `name` label (the empty string when unnamed).
//! When `metrics_name` is set on the [`LoginEngine`] builder, every counter
//! carries a `name` label with that value — it tells engine
//! instances apart when one process runs several (the same label
//! `huskarl.aead.*` uses for cipher instances).
//!
//! # Installation and ownership
//!
//! `metrics` propagates to `huskarl/metrics` and `huskarl-core/metrics`.
//! This engine and its built-in session drivers emit automatically. Supplied
//! HTTP clients and cryptography implementations still need their explicit
//! lower-level metrics decorators. Independently constructed grants keep their
//! own metrics identity; engine naming does not rename shared dependencies.
//! No recorder is installed by this library. Disabled builds allocate no metric
//! labels and make no recorder calls. No library logs are emitted.
//!
//! # Observation boundaries
//!
//! All instruments are counters with unit occurrences, incremented by one.
//! Each row below describes its population and observation point. Outcome
//! values in the schema above are closed; new classifications require a
//! documented schema change rather than copying arbitrary error text.
//!
//! | Counter suffix | Owner and observation |
//! | --- | --- |
//! | `login.start` | Engine, after an attempted authorization redirect finishes; API 401 and cross-site rejection bypass it. `ok` means a response was prepared. |
//! | `login.complete` | Engine, once a callback reaches a classified terminal result, including malformed callbacks and already-authenticated fallback. `ok` means the driver created a session and prepared cookies. |
//! | `session.refresh` | Engine, once per logical refresh, including missing refresh tokens. Internal retries do not recount it. `ok` records exchange success before persistence, which can still fail or be deferred. |
//! | `session.teardown` | Engine load/refresh policy decision to clear a presented session, not successful backend revocation. Explicit logout and termination do not enter this denominator. |
//! | `session.superseded_delete` | Store driver, after a valid old pointer enters replacement cleanup. Missing or invalid pointers bypass it. |
//! | `session.liveness_failure` | Store driver, each failed read/touch/clear, including initial touch and cleanup. It is a failure count, not an operation denominator. |
//! | `session_cookie.encrypt` | Cookie sealer, after sealing a session payload or store pointer successfully (oversized cookie payloads are excluded). Later expiry/header checks can still fail. One seal, independent of cookie chunk count; excludes login-state cookies. |
//! | `session_cookie.decrypt` | Cookie sealer, each classified decoding attempt. Absent cookies bypass it. No client-provided key identifier enters labels. |
//!
//! Additional counters replace previously log-only operational information:
//!
//! | Counter | Labels and observation |
//! | --- | --- |
//! | `huskarl.login.handled_failure` | `operation`: snake-case [`DiagnosticOperation`](crate::engine::DiagnosticOperation) variant. Each error consumed by the engine at that operation, including logout failures and eager-persist fallback. No successful-operation denominator. |
//! | `huskarl.session.refresh_retry` | `outcome`: `scheduled` before retry sleep, or `delay_exceeded` when the requested delay exceeds the in-request budget. Attempts exhausted or conclusively rejected do not enter this counter. |
//! | `huskarl.session.dropped` | `operation`: `set_cookies` or `persist`. One armed guard dropped outside panic unwinding, irrespective of cookie count. Explicit `discard`/`abandon` disarms it. Engine-produced guards retain their engine name; fabricated `PendingPersist::builder` guards are unnamed. |
//!
//! These counters have distinct populations: one request can increment several.
//! Framework adapters own their separate load/persist/revoke and response-write
//! metrics. They must not re-emit these engine counters. Cancellation before a
//! classified result emits no terminal result; earlier observations remain and
//! armed guards can count a drop. No counter proves browser receipt, cookie
//! acceptance, durable audit delivery, or successful upstream response delivery.
//!
//! `PendingPersist::commit` disarms its guard when first polled, before awaiting
//! the store. Cancellation during that await emits no `session.dropped` count
//! and yields no result for an adapter's completed-operation counter. The backend
//! may already have committed. Dropping the commit future before its first poll
//! still drops an armed guard. The dropped-work counter therefore does not count
//! every interrupted or unsuccessful persistence operation.
//!
//! # Cardinality
//!
//! `name` and `cookie` come from bounded local configuration. Names must not be
//! derived from subjects, sessions, URLs, or request values. The encrypt-side
//! `kid` comes from the configured encryptor, which must use a bounded rotation
//! policy over the recorder's retention window. A new key per request is not
//! safe. Cookie names are the configured base names, not chunk or state suffixes.
//! Unknown authorization-server error codes map to `other`. No arbitrary label
//! bag, raw error, subject, token, or decrypt-side `kid` is exposed.
//!
//! # Diagnostic errors
//!
//! The engine's optional `diagnostics` handler receives errors consumed by the
//! engine, independently of the metrics feature. Returned errors remain with
//! the caller. Best-effort liveness and superseded-record failures expose their
//! sources only through instrumentation on the supplied backend; their counters
//! remain available here.
//!
//! See [Observe login failures](crate::_docs::how_to::observability) for recorder
//! setup, diagnostic-handler wiring, and backend instrumentation. Existing
//! integrations should also consult the [migration guide](crate::_docs::how_to::migration).
//!
//! [`TeardownReason`]: crate::engine::TeardownReason
//! [`InvalidSessionReason`]: crate::InvalidSessionReason
//! [`LoginEngine`]: crate::engine::LoginEngine

/// Closed call-site labels only. Disabled builds perform no label allocation
/// or recorder calls. Borrowed values are copied only with metrics enabled.
#[inline]
pub(crate) fn emit_counter<const N: usize>(
    name: &'static str,
    labels: [(&'static str, &str); N],
    metrics_name: Option<&str>,
) {
    #[cfg(feature = "metrics")]
    {
        let labels = labels
            .into_iter()
            .map(|(key, value)| metrics::Label::new(key, value.to_owned()))
            .chain(std::iter::once(metrics::Label::new(
                "name",
                metrics_name.unwrap_or_default().to_owned(),
            )))
            .collect::<Vec<_>>();
        metrics::counter!(name, labels).increment(1);
    }
    #[cfg(not(feature = "metrics"))]
    let _ = (name, labels, metrics_name);
}

/// Outcome of a session cookie decryption attempt; the
/// `huskarl.session_cookie.decrypt` `outcome` label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum DecryptResult {
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
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Outcome of a login redirect attempt; the `huskarl.login.start` `outcome`
/// label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum LoginStartResult {
    /// The redirect to the authorization server was produced successfully.
    Ok,
    /// Generating the redirect failed (e.g. authorization server unreachable).
    Error,
}

impl LoginStartResult {
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Outcome of processing an OAuth callback; the `huskarl.login.complete`
/// `outcome` label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum LoginCompleteResult {
    /// Login completed successfully — a new session was created.
    Ok,
    /// The callback carried no usable login state but the browser already
    /// holds a valid session (e.g. a second tab completing after the first,
    /// or a re-navigated stale callback URL) — redirected home without
    /// re-authenticating.
    AlreadyAuthenticated,
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
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Authorization error codes recognized by [`normalize_as_error`] (RFC 6749 / OIDC Core).
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

/// Normalizes an attacker-suppliable AS `error` code: known codes pass
/// through, anything else maps to `"other"`.
pub(crate) fn normalize_as_error(error: &str) -> &'static str {
    KNOWN_AS_ERROR_CODES
        .iter()
        .find(|code| **code == error)
        .copied()
        .unwrap_or("other")
}

/// Outcome of a token refresh attempt; the `huskarl.session.refresh`
/// `outcome` label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum RefreshResult {
    /// The session had no refresh token — it was cleared.
    NoRefreshToken,
    /// The refresh token was exchanged successfully for new tokens.
    Ok,
    /// The token refresh request failed conclusively — session was cleared.
    Failed,
    /// The refresh failed with a retryable error while the access token was
    /// still valid — the session was retained and keeps being served.
    FailedRetained,
    /// The refresh failed with a retryable error after the access token had
    /// expired — the session was retained for a later retry, but the request
    /// could not be served
    /// ([`LoadedSession::RefreshUnavailable`](crate::engine::LoadedSession::RefreshUnavailable)).
    FailedUnavailable,
}

impl RefreshResult {
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// Outcome of deleting the record a new login superseded; the
/// `huskarl.session.superseded_delete` `outcome` label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum SupersededDeleteResult {
    /// The superseded record was deleted.
    Deleted,
    /// The pointer cookie was valid but no record exists for it.
    NotFound,
    /// Loading the superseded record failed; it may still be stored.
    LoadFailed,
    /// Deleting the superseded record failed; it is still stored.
    DeleteFailed,
}

impl SupersededDeleteResult {
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
}

/// A [`LivenessStore`](crate::LivenessStore) operation that failed
/// (best-effort: the request proceeded); the
/// `huskarl.session.liveness_failure` `op` label.
#[derive(strum::AsRefStr, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum LivenessFailure {
    /// `last_active` could not be read; the session was served as active
    /// (fail open).
    Read,
    /// Recording activity failed; the next advance is delayed.
    Touch,
    /// Removing an entry failed; the stale entry remains until its TTL.
    Clear,
}

impl LivenessFailure {
    pub(crate) fn as_str(&self) -> &'static str {
        self.into()
    }
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
