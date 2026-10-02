use super::*;

// ── error_chain ───────────────────────────────────────────────────────────

#[test]
fn error_chain_formats_single_error() {
    let err = "not-a-number".parse::<i32>().unwrap_err();
    let chain = error_chain(&err);
    assert_ne!(chain, "");
    assert!(chain.contains("invalid digit"), "got: {chain}");
}

// ── Metrics emission ──────────────────────────────────────────────────────

#[cfg(feature = "metrics")]
use crate::test_support::{CapturedCounters, counter_value, with_metrics};

/// True if any counter named `name` was emitted, regardless of labels.
#[cfg(feature = "metrics")]
fn emitted(counters: &CapturedCounters, name: &str) -> bool {
    counters.iter().any(|(n, _, _)| n == name)
}

// ── Login start metrics ───────────────────────────────────────────────────

#[cfg(feature = "metrics")]
#[test]
fn metrics_login_start_ok_on_nav_redirect() {
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let _ = e
            .redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
            .await;
    });
    assert_eq!(
        counter_value(&counters, "huskarl.login.start", &[("outcome", "ok")]),
        1
    );
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_name_labels_engine_counters() {
    let ((), counters) = with_metrics(async {
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(test_grant(FailingHttp::new(false).0).await)
            .session_store(MockSessionStore::empty())
            .sealer(test_sealer().await)
            .metrics_name("tenant-a")
            .build()
            .unwrap();
        let _ = e
            .redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.start",
            &[("outcome", "ok"), ("name", "tenant-a")],
        ),
        1
    );
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_no_login_start_on_api_401() {
    // XHR/API 401s don't redirect to the AS — no login start is recorded.
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let _ = e
            .redirect_to_login(&api_headers(), &"/api".parse().unwrap())
            .await;
    });
    assert!(!emitted(&counters, "huskarl.login.start"));
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_login_start_error_when_grant_start_fails() {
    // PAR-required grant + failing HTTP double: start() must perform HTTP and
    // therefore fails.
    let ((), counters) = with_metrics(async {
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(par_failing_grant().await)
            .session_store(MockSessionStore::empty())
            .sealer(test_sealer().await)
            .build()
            .unwrap();
        let _ = e
            .redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
            .await;
    });
    assert_eq!(
        counter_value(&counters, "huskarl.login.start", &[("outcome", "error")]),
        1
    );
}

// ── Login complete metrics ────────────────────────────────────────────────

/// Counter labels for a login completion with the given outcome and
/// normalized AS error code.
#[cfg(feature = "metrics")]
fn complete_labels<'a>(outcome: &'a str, error: &'a str) -> [(&'a str, &'a str); 2] {
    [("outcome", outcome), ("error", error)]
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_callback_invalid_request_on_missing_params() {
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let uri = "/callback".parse().unwrap();
        e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("invalid_request", "none"),
        ),
        1
    );
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_callback_as_denied_carries_error_code() {
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let uri = "/callback?error=access_denied".parse().unwrap();
        e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("as_denied", "access_denied"),
        ),
        1
    );
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_callback_as_denied_normalizes_unknown_error_code() {
    // The `error` parameter is attacker-suppliable; anything outside the
    // registered RFC 6749 / OIDC codes must reach the metrics sink as
    // "other" so it can't blow up label cardinality.
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let uri = "/callback?error=attacker_chosen_garbage_12345"
            .parse()
            .unwrap();
        e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("as_denied", "other"),
        ),
        1
    );
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_callback_already_authenticated_on_stale_callback_with_session() {
    // A stale callback rescued by an existing session must not be counted as
    // an invalid request (nor as a fresh login).
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::with_session(valid_session())).await;
        let uri = "/callback?code=authcode&state=mystate".parse().unwrap();
        e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("already_authenticated", "none"),
        ),
        1
    );
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_callback_invalid_request_on_missing_state_cookie() {
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let uri = "/callback?code=authcode&state=mystate".parse().unwrap();
        e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("invalid_request", "none"),
        ),
        1
    );
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_callback_state_invalid_on_tampered_bundle() {
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let state = "teststate";
        let fake = URL_SAFE_NO_PAD.encode(b"not an AEAD bundle");
        let h = headers_with_login_cookie(state, &fake);
        let uri = format!("/callback?code=authcode&state={state}")
            .parse()
            .unwrap();
        e.try_handle_login_route(&Method::GET, &h, &uri).await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("state_invalid", "none"),
        ),
        1
    );
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_callback_ok_on_successful_login() {
    let ((), counters) = with_metrics(async {
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(test_grant(TokenHttp).await)
            .session_store(MockSessionStore::empty())
            .sealer(test_sealer().await)
            .build()
            .unwrap();
        let state = "valid_state";
        let sealed = seal_login_cookie(state, "https://app.example.com/").await;
        let h = headers_with_login_cookie(state, &sealed);
        let uri = format!("/callback?code=authcode&state={state}")
            .parse()
            .unwrap();
        e.try_handle_login_route(&Method::GET, &h, &uri).await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("ok", "none"),
        ),
        1
    );
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_callback_token_exchange_failed_when_grant_complete_fails() {
    // The default engine's HTTP double fails every token request — verify
    // token_exchange_failed is recorded.
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let state = "valid_state";
        let sealed = seal_login_cookie(state, "https://app.example.com/").await;
        let h = headers_with_login_cookie(state, &sealed);
        let uri = format!("/callback?code=authcode&state={state}")
            .parse()
            .unwrap();
        e.try_handle_login_route(&Method::GET, &h, &uri).await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("token_exchange_failed", "none"),
        ),
        1
    );
}

// ── Refresh metrics ───────────────────────────────────────────────────────

#[cfg(feature = "metrics")]
#[test]
fn metrics_refresh_no_refresh_token_when_none_available() {
    let ((), counters) = with_metrics(async {
        let session = session_with(
            SystemTime::now() - Duration::from_mins(1),
            None,
            SystemTime::now(),
        );
        let e = engine(MockSessionStore::with_session(session)).await;
        let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh",
            &[("outcome", "no_refresh_token")],
        ),
        1
    );
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.teardown",
            &[("invalid_reason", "none"), ("reason", "no_refresh_token")],
        ),
        1
    );
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_refresh_failed_when_grant_refresh_fails() {
    let ((), counters) = with_metrics(async {
        use crate::core::secrets::SecretString;
        let session = session_with(
            SystemTime::now() - Duration::from_mins(1),
            Some(RefreshToken::new(SecretString::new("test_refresh"), None)),
            SystemTime::now(),
        );
        let e = engine(MockSessionStore::with_session(session)).await;
        let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    });
    // The engine's HTTP double fails non-retryably — a conclusive rejection.
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh",
            &[("outcome", "failed")],
        ),
        1
    );
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.teardown",
            &[("invalid_reason", "none"), ("reason", "refresh_rejected")],
        ),
        1
    );
}

// ── Teardown metrics ──────────────────────────────────────────────────────

#[cfg(feature = "metrics")]
#[test]
fn metrics_teardown_on_idle_timeout() {
    let ((), counters) = with_metrics(async {
        let store =
            MockSessionStore::with_session_and_verdict(valid_session(), LivenessVerdict::Expired);
        let e = engine(store).await;
        let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.teardown",
            &[("invalid_reason", "none"), ("reason", "idle_timeout")],
        ),
        1
    );
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_invalid_session_teardown_preserves_driver_reason() {
    let expected = [
        (
            crate::InvalidSessionReason::IncompleteChunks,
            "incomplete_chunks",
        ),
        (crate::InvalidSessionReason::BadEncoding, "bad_encoding"),
        (
            crate::InvalidSessionReason::DecryptionFailed,
            "decryption_failed",
        ),
        (
            crate::InvalidSessionReason::InvalidPayload,
            "invalid_payload",
        ),
        (
            crate::InvalidSessionReason::SessionNotFound,
            "session_not_found",
        ),
    ];
    let ((), counters) = with_metrics(async {
        for &(reason, _) in &expected {
            let e = engine(MockSessionStore::with_invalid_load(reason)).await;
            let _ = e.load_session(&HeaderMap::new()).await.unwrap();
        }
    });

    for (_, invalid_reason) in expected {
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session.teardown",
                &[
                    ("invalid_reason", invalid_reason),
                    ("reason", "invalid_session"),
                ],
            ),
            1
        );
    }
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_refresh_failed_retained_on_transient_failure_with_valid_token() {
    let ((), counters) = with_metrics(async {
        let session = refreshable_session(SystemTime::now() + Duration::from_secs(15));
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(test_grant(FailingHttp::new(true).0).await)
            .session_store(MockSessionStore::with_session_and_verdict(
                session,
                LivenessVerdict::Active,
            ))
            .sealer(test_sealer().await)
            .build()
            .unwrap();
        let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    });
    // The transient-retention path retains the session as-is — the refresh
    // outcome is recorded, and no teardown is.
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh",
            &[("outcome", "failed_retained")],
        ),
        1
    );
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh_retry",
            &[("outcome", "scheduled")]
        ),
        u64::from(super::super::REFRESH_MAX_ATTEMPTS - 1)
    );
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.handled_failure",
            &[("operation", "refresh")]
        ),
        1
    );
    assert!(!emitted(&counters, "huskarl.session.teardown"));
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_refresh_failed_unavailable_on_transient_failure_with_expired_token() {
    // Transient failure past expiry: the session is retained (no teardown
    // metric) but the request can't be served — a distinct refresh outcome so
    // dashboards can tell "AS down, users seeing 503s" from both teardowns
    // and the still-serving retained case.
    let ((), counters) = with_metrics(async {
        let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(test_grant(FailingHttp::new(true).0).await)
            .session_store(MockSessionStore::with_session(session))
            .sealer(test_sealer().await)
            .build()
            .unwrap();
        let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh",
            &[("outcome", "failed_unavailable")],
        ),
        1
    );
    assert!(!emitted(&counters, "huskarl.session.teardown"));
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_refresh_ok_on_successful_refresh() {
    let ((), counters) = with_metrics(async {
        let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(test_grant(TokenHttp).await)
            .session_store(MockSessionStore::with_session(session))
            .sealer(test_sealer().await)
            .build()
            .unwrap();
        // Consume via expect_active: a successful refresh returns owed cookies,
        // and dropping them unconsumed would (correctly) trip the SetCookies guard.
        let _ = expect_active(e.load_session(&HeaderMap::new()).await.unwrap());
    });
    assert_eq!(
        counter_value(&counters, "huskarl.session.refresh", &[("outcome", "ok")]),
        1
    );
}

#[test]
fn diagnostics_preserve_consumed_errors_independently_of_metrics() {
    use super::super::DiagnosticOperation;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = seen.clone();
    let ((), counters) = crate::test_support::with_metrics(async {
        let engine = LoginEngine::builder()
            .config(default_config())
            .grant(par_failing_grant().await)
            .session_store(MockSessionStore::empty())
            .sealer(test_sealer().await)
            .metrics_name("diagnostics")
            .diagnostics(move |event| {
                sink.lock()
                    .unwrap()
                    .push((event.operation, event.error.to_string()));
            })
            .build()
            .unwrap();
        let response = engine
            .redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
            .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    });
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, DiagnosticOperation::Start);
    assert!(!seen[0].1.is_empty());
    #[cfg(feature = "metrics")]
    assert_eq!(
        crate::test_support::counter_value(
            &counters,
            "huskarl.login.handled_failure",
            &[("name", "diagnostics"), ("operation", "start")]
        ),
        1
    );
    #[cfg(not(feature = "metrics"))]
    assert!(counters.is_empty());
}

#[rstest]
#[case(false)]
#[case(true)]
fn diagnostics_allow_downcasting_consumed_session_errors(#[case] automatic_teardown: bool) {
    use super::super::DiagnosticOperation;
    let operation = if automatic_teardown {
        DiagnosticOperation::Revoke
    } else {
        DiagnosticOperation::LogoutRevoke
    };
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let ((), counters) = crate::test_support::with_metrics(async {
        let engine = LoginEngine::builder()
            .config(config_with_logout())
            .grant(test_grant(FailingHttp::new(false).0).await)
            .session_store(
                MockSessionStore::with_session_failing_revoke(valid_session()).with_verdict(
                    if automatic_teardown {
                        LivenessVerdict::Expired
                    } else {
                        LivenessVerdict::Untracked
                    },
                ),
            )
            .sealer(test_sealer().await)
            .diagnostics(move |event| {
                let error = event.error.downcast_ref::<SessionError>().unwrap();
                assert!(event.error.source().unwrap().is::<StoreRevocationError>());
                sink.lock().unwrap().push((event.operation, error.kind()));
            })
            .build()
            .unwrap();
        if automatic_teardown {
            let loaded = engine.load_session(&HeaderMap::new()).await.unwrap();
            let (reason, clears) = expect_cleared(loaded);
            assert_eq!(reason, TeardownReason::IdleTimeout);
            assert_eq!(
                clears,
                vec![HeaderValue::from_static("mock-session=; Max-Age=0")]
            );
        } else {
            let response = engine
                .try_handle_login_route(
                    &Method::POST,
                    &logout_headers(),
                    &"/logout".parse().unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert!(response.headers().iter().any(|(name, value)| {
                *name == http::header::SET_COOKIE && value == "mock-session=; Max-Age=0"
            }));
        }
        assert!(engine.session_store.revoke_called());
    });
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(operation, SessionErrorKind::Unavailable)]
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        crate::test_support::counter_value(
            &counters,
            "huskarl.login.handled_failure",
            &[("operation", operation.as_ref())]
        ),
        1
    );
    #[cfg(not(feature = "metrics"))]
    assert!(counters.is_empty());
}

#[test]
fn diagnostics_report_eager_persist_failure_once_before_deferred_recovery() {
    use super::super::DiagnosticOperation;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let ((), counters) = crate::test_support::with_metrics(async {
        let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
        let mut engine = LoginEngine::builder()
            .config(default_config())
            .grant(test_grant(TokenHttp).await)
            .session_store(MockSessionStore::with_session_failing_save(session))
            .sealer(test_sealer().await)
            .diagnostics(move |event| {
                let error = event.error.downcast_ref::<SessionError>().unwrap();
                assert!(event.error.source().unwrap().is::<StoreSaveError>());
                sink.lock().unwrap().push((event.operation, error.kind()));
            })
            .build()
            .unwrap();
        let loaded = engine.load_session(&HeaderMap::new()).await.unwrap();
        let pending = expect_pending(loaded);
        assert_eq!(seen.lock().unwrap().len(), 1);
        engine.session_store.fail_save = false;
        let cookies = pending.commit(&engine, &HeaderMap::new()).await.unwrap();
        assert_eq!(
            cookies.into_headers(),
            vec![HeaderValue::from_static(MOCK_SAVE_COOKIE)]
        );
    });
    assert_eq!(
        *seen.lock().unwrap(),
        vec![(
            DiagnosticOperation::EagerPersist,
            SessionErrorKind::Unavailable
        )]
    );
    #[cfg(feature = "metrics")]
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.handled_failure",
            &[("operation", "eager_persist")]
        ),
        1
    );
    #[cfg(not(feature = "metrics"))]
    assert!(counters.is_empty());
}

#[test]
fn diagnostics_preserve_original_logout_load_error() {
    use super::super::DiagnosticOperation;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let ((), counters) = crate::test_support::with_metrics(async {
        let engine = LoginEngine::builder()
            .config(config_with_logout())
            .grant(test_grant(FailingHttp::new(false).0).await)
            .session_store(ErrorSessionStore)
            .sealer(test_sealer().await)
            .diagnostics(move |event| {
                let error = event.error.downcast_ref::<SessionError>().unwrap();
                assert_eq!(error.kind(), SessionErrorKind::Unavailable);
                assert!(
                    std::error::Error::source(error)
                        .unwrap()
                        .is::<StoreLoadError>()
                );
                sink.lock().unwrap().push(event.operation);
            })
            .build()
            .unwrap();
        let response = engine
            .try_handle_login_route(
                &Method::POST,
                &logout_headers(),
                &"/logout".parse().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(response.headers().iter().any(|(name, value)| {
            *name == http::header::SET_COOKIE && value == "mock-session=; Max-Age=0"
        }));
    });
    assert_eq!(*seen.lock().unwrap(), vec![DiagnosticOperation::LogoutLoad]);
    #[cfg(feature = "metrics")]
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.handled_failure",
            &[("operation", "logout_load")]
        ),
        1
    );
    #[cfg(not(feature = "metrics"))]
    assert!(counters.is_empty());
}

#[test]
fn dropped_work_is_named_and_explicit_disposal_is_silent() {
    let ((), counters) = crate::test_support::with_metrics(async {
        let mut engine = engine(MockSessionStore::empty()).await;
        engine.metrics_name = Some("guard-owner".into());
        let cookies = || vec![HeaderValue::from_static("session=secret")];
        drop(engine.set_cookies(cookies()));
        engine.set_cookies(cookies()).discard();
        let _ = engine.set_cookies(cookies()).into_headers();
        drop(engine.set_cookies(Vec::new()));
        let pending = || {
            PendingPersist::builder()
                .session(())
                .token_response(token_response_fixture())
                .expected_refresh_revision(0)
                .build()
                .with_metrics_name(engine.metrics_name.as_ref())
        };
        drop(pending());
        pending().abandon();
    });
    #[cfg(feature = "metrics")]
    {
        for operation in ["set_cookies", "persist"] {
            assert_eq!(
                crate::test_support::counter_value(
                    &counters,
                    "huskarl.session.dropped",
                    &[("name", "guard-owner"), ("operation", operation)]
                ),
                1
            );
        }
        assert_eq!(counters.len(), 2);
    }
    #[cfg(not(feature = "metrics"))]
    assert!(counters.is_empty());
}

#[cfg(not(feature = "metrics"))]
#[test]
fn disabled_metrics_emit_nothing_for_login_and_cookie_operations() {
    let ((), counters) = crate::test_support::with_metrics(async {
        let engine = engine(MockSessionStore::empty()).await;
        let _ = engine
            .redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
            .await;
        let _ = engine
            .try_handle_login_route(
                &Method::GET,
                &HeaderMap::new(),
                &"/callback?error=untrusted".parse().unwrap(),
            )
            .await;
        let sealer = crate::cookie::CookieSealer::builder()
            .sealer(Arc::new(test_sealer().await))
            .cookie_name("session".parse().unwrap())
            .cookie_path("/".parse().unwrap())
            .max_age(Duration::from_secs(60))
            .build();
        sealer.record_encrypt(Some("configured-key"));
        sealer.record_decrypt(&crate::metrics::DecryptResult::DecryptFailed);
    });
    assert!(counters.is_empty());
}

#[cfg(feature = "metrics")]
#[test]
fn metrics_retry_delay_cap_counts_once_without_scheduling() {
    let ((), counters) = with_metrics(async {
        let session = refreshable_session(SystemTime::now() - Duration::from_secs(60));
        let (engine, _) =
            engine_with_refresh_advice(RetryAdvice::retry_after(Duration::from_secs(60)), session)
                .await;
        let _ = engine.load_session(&HeaderMap::new()).await.unwrap();
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh_retry",
            &[("outcome", "delay_exceeded")]
        ),
        1
    );
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh_retry",
            &[("outcome", "scheduled")]
        ),
        0
    );
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh",
            &[("outcome", "failed_unavailable")]
        ),
        1
    );
}
