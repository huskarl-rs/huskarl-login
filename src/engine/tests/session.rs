use super::*;

#[tokio::test]
async fn load_session_empty_store_returns_missing() {
    let e = engine(MockSessionStore::empty()).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(matches!(loaded, LoadedSession::Missing));
}

#[tokio::test]
async fn invalid_browser_session_is_classified_and_cleared() {
    let e = engine(MockSessionStore::with_invalid_load(
        crate::InvalidSessionReason::BadEncoding,
    ))
    .await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, clears) = expect_cleared(loaded);

    assert_eq!(reason, TeardownReason::InvalidSession);
    assert_eq!(
        clears,
        vec![HeaderValue::from_static("mock-session=; Max-Age=0")]
    );
}

#[tokio::test]
async fn restored_store_pointer_after_logout_is_unauthenticated_and_cleared() {
    let mut store = StoreBackedSessionStore::builder()
        .external(RevocableExternalStore::<PersistedSessionState>::default())
        .sealer(test_sealer().await)
        .cookie_name("session".parse().unwrap())
        .cookie_path("/".parse().unwrap())
        .build();
    // Match the policy the HTTPS engine will stamp so the captured cookie has
    // the same name and attributes as the subsequent clear.
    store
        .apply_session_policy(&test_session_policy(None))
        .unwrap();

    let completed = CompletedLogin::builder()
        .token_response(token_response_fixture())
        .build();
    let (session, set_cookies) = store
        .create(completed, Duration::from_hours(1), &HeaderMap::new())
        .await
        .unwrap();
    let request_headers = request_cookies(&set_cookies);
    assert!(
        request_headers.contains_key(http::header::COOKIE),
        "pointer cookie was created"
    );

    // Logout revokes the server record. The browser then restores its old
    // pointer, as can happen through history/session restoration.
    store.revoke(&session).await.unwrap();

    let engine = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(store)
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    let loaded = engine.load_session(&request_headers).await.unwrap();
    let (reason, clears) = match loaded {
        LoadedSession::Cleared { reason, clears } => (reason, clears.into_headers()),
        _ => panic!("a dangling restored pointer must be cleared"),
    };

    assert_eq!(reason, TeardownReason::InvalidSession);
    assert!(clears.iter().any(|header| {
        header.to_str().is_ok_and(|value| {
            value.starts_with("__Host-session=; ") && value.contains("Max-Age=0")
        })
    }));
    assert!(clears.iter().any(|header| {
        header.to_str().is_ok_and(|value| {
            value.starts_with("__Host-session.kid=; ") && value.contains("Max-Age=0")
        })
    }));
}

#[tokio::test]
async fn untracked_verdict_yields_active() {
    // The default driver verdict is `Untracked` (no liveness tracking), so the
    // engine returns `Active` with nothing owed post-response.
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (_session, set_cookies) = expect_active(loaded);
    assert_eq!(set_cookies, [] as [HeaderValue; 0]);
}

#[tokio::test]
async fn active_verdict_yields_active() {
    // The driver reports the session is active (a throttled touch), so the
    // engine returns `Active` and the store sees no write during load.
    let store =
        MockSessionStore::with_session_and_verdict(valid_session(), LivenessVerdict::Active);
    let e = engine(store).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (_session, set_cookies) = expect_active(loaded);
    assert_eq!(set_cookies, [] as [HeaderValue; 0]);
    assert!(!e.session_store.save_called());
}

#[tokio::test]
async fn max_lifetime_expired_clears_session() {
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() - Duration::from_secs(7201),
    );
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(1)))
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::with_session(session), config).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::MaxLifetime);
    assert!(e.session_store.revoke_called());
}

#[tokio::test]
async fn frozen_expire_at_is_enforced_over_a_raised_lifetime() {
    // The session was created under a 1h cap (expire_at frozen at login) and
    // that hour has passed. The config has since been raised to 24h — but the
    // session's cookies and store records were stamped with the old deadline,
    // so the engine honors the frozen (tighter) one and tears down.
    let created_at = SystemTime::now() - Duration::from_secs(7200);
    let mut session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        created_at,
    );
    session.state.expire_at = Some(created_at + Duration::from_hours(1));
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(24)))
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::with_session(session), config).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::MaxLifetime);
}

#[tokio::test]
async fn lowered_lifetime_applies_to_sessions_with_a_longer_frozen_deadline() {
    // Tightening is the security direction: the live config wins over a
    // frozen deadline that would keep the session alive for another day.
    let created_at = SystemTime::now() - Duration::from_secs(7200);
    let mut session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        created_at,
    );
    session.state.expire_at = Some(created_at + Duration::from_hours(48));
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(1)))
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::with_session(session), config).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::MaxLifetime);
}

#[tokio::test]
async fn frozen_expire_at_is_enforced_under_a_delegated_config() {
    // Switching the config to delegated does not resurrect sessions created
    // under a bounded lifetime — their frozen deadline still applies.
    let created_at = SystemTime::now() - Duration::from_secs(7200);
    let mut session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        created_at,
    );
    session.state.expire_at = Some(created_at + Duration::from_hours(1));
    let e = engine(MockSessionStore::with_session(session)).await; // delegated config
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::MaxLifetime);
}

#[tokio::test]
async fn idle_timeout_expired_clears_session() {
    // The driver's liveness check returns `Expired`; the engine tears the
    // session down with an `IdleTimeout` reason.
    let store =
        MockSessionStore::with_session_and_verdict(valid_session(), LivenessVerdict::Expired);
    let e = engine(store).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::IdleTimeout);
    assert!(e.session_store.revoke_called());
}

#[tokio::test]
async fn activity_policy_first_party_excludes_cross_site_fetch() {
    // Default config is `ActivityPolicy::FirstParty`. A cross-site, non-navigation
    // request must reach the store as a non-activity check.
    let store =
        MockSessionStore::with_session_and_verdict(valid_session(), LivenessVerdict::Active);
    let e = engine(store).await;
    let h = headers(&[("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "cors")]);
    let _ = e.load_session(&h).await.unwrap();
    assert_eq!(e.session_store.last_record_activity(), Some(false));
}

#[tokio::test]
async fn activity_policy_first_party_counts_cross_site_navigation() {
    // A genuine inbound link click is cross-site *and* a navigation — it counts.
    let store =
        MockSessionStore::with_session_and_verdict(valid_session(), LivenessVerdict::Active);
    let e = engine(store).await;
    let h = headers(&[
        ("sec-fetch-site", "cross-site"),
        ("sec-fetch-mode", "navigate"),
    ]);
    let _ = e.load_session(&h).await.unwrap();
    assert_eq!(e.session_store.last_record_activity(), Some(true));
}

#[tokio::test]
async fn activity_policy_first_party_counts_same_origin_fetch() {
    let store =
        MockSessionStore::with_session_and_verdict(valid_session(), LivenessVerdict::Active);
    let e = engine(store).await;
    let h = headers(&[
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "cors"),
    ]);
    let _ = e.load_session(&h).await.unwrap();
    assert_eq!(e.session_store.last_record_activity(), Some(true));
}

#[tokio::test]
async fn activity_policy_navigations_only_excludes_same_origin_fetch() {
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .activity_policy(ActivityPolicy::NavigationsOnly)
        .build()
        .unwrap();
    let store =
        MockSessionStore::with_session_and_verdict(valid_session(), LivenessVerdict::Active);
    let e = engine_with_config(store, config).await;
    let h = headers(&[
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "cors"),
    ]);
    let _ = e.load_session(&h).await.unwrap();
    assert_eq!(e.session_store.last_record_activity(), Some(false));
}

#[tokio::test]
async fn load_session_store_error_bubbles_up() {
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(ErrorSessionStore)
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    let err = e
        .load_session(&HeaderMap::new())
        .await
        .expect_err("opaque store load failure must surface as an error");
    // An opaque backing-store failure is classified `Unavailable` — the more
    // often transient kind — so callers treat it as retryable rather than a
    // hard 4xx/permanent fault.
    assert_eq!(err.kind(), SessionErrorKind::Unavailable);
    assert!(err.is_retryable());
}

// ── Clock-skew handling ───────────────────────────────────────────────────

#[tokio::test]
async fn small_future_skew_is_tolerated() {
    // created_at 10s in the future — within MAX_CLOCK_SKEW.
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() + Duration::from_secs(10),
    );
    let e = engine(MockSessionStore::with_session(session)).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(loaded.session().is_some());
    assert!(!e.session_store.revoke_called());
}

#[tokio::test]
async fn future_created_at_clears_session() {
    // created_at 1 hour in the future — well past MAX_CLOCK_SKEW.
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() + Duration::from_hours(1),
    );
    let store = MockSessionStore::with_session(session);
    let e = engine(store).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::ClockSkew);
    assert!(e.session_store.revoke_called());
}

#[tokio::test]
async fn skew_just_under_limit_is_tolerated() {
    // created_at 4m55s in the future — just inside MAX_CLOCK_SKEW (5min), so
    // the session is served, not torn down. Together with
    // `skew_just_over_limit_clears_session` this brackets the threshold to a
    // few seconds, where `small_future_skew_is_tolerated` (10s) only proves
    // it is somewhere above 10s.
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() + Duration::from_secs(4 * 60 + 55),
    );
    let e = engine(MockSessionStore::with_session(session)).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    expect_active(loaded);
    assert!(!e.session_store.revoke_called());
}

#[tokio::test]
async fn skew_just_over_limit_clears_session() {
    // created_at 5m10s in the future — just past MAX_CLOCK_SKEW (5min), so
    // the session is treated as clock-skew corrupted and cleared.
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() + Duration::from_secs(5 * 60 + 10),
    );
    let e = engine(MockSessionStore::with_session(session)).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::ClockSkew);
    assert!(e.session_store.revoke_called());
}
