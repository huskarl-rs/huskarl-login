use super::*;

#[tokio::test]
async fn valid_token_within_refresh_margin_without_refresh_token_stays_active() {
    // A short-lived token starts inside the default 30-second refresh margin.
    let now = SystemTime::now();
    let expiry = now + Duration::from_secs(20);
    let session = session_with(expiry, None, now);
    let (e, calls) = engine_with_failing_refresh(false, session).await;

    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (session, set_cookies) = expect_active(loaded);

    assert_eq!(session.token_expiry(), expiry);
    assert!(session.refresh_token().is_none());
    assert_eq!(set_cookies, [] as [HeaderValue; 0]);
    assert!(!e.session_store.revoke_called());
    assert!(!e.session_store.save_called());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn token_expired_no_refresh_token_clears_session() {
    let session = session_with(
        SystemTime::now() - Duration::from_mins(1),
        None,
        SystemTime::now(),
    );
    let store = MockSessionStore::with_session(session);
    let e = engine(store).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::NoRefreshToken);
    assert!(e.session_store.revoke_called());
}

#[tokio::test]
async fn token_expired_refresh_fails_clears_session() {
    use crate::core::secrets::SecretString;
    let session = session_with(
        SystemTime::now() - Duration::from_mins(1),
        Some(RefreshToken::new(SecretString::new("test_refresh"), None)),
        SystemTime::now(),
    );
    let store = MockSessionStore::with_session(session);
    let e = engine(store).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    // The engine's HTTP double fails non-retryably — a conclusive rejection.
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::RefreshRejected);
    assert!(e.session_store.revoke_called());
}

#[tokio::test]
async fn refresh_retries_when_error_is_retryable() {
    // Token expired a minute ago — the refresh outcome is decisive.
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let (e, calls) = engine_with_failing_refresh(true, session).await;
    let _ = e.load_session(&HeaderMap::new()).await;
    // Initial call + REFRESH_MAX_ATTEMPTS - 1 retries == REFRESH_MAX_ATTEMPTS total.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        super::super::REFRESH_MAX_ATTEMPTS
    );
}

#[tokio::test]
async fn refresh_does_not_retry_when_server_asks_for_a_long_delay() {
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    // A `Retry-After` past the in-request budget: waiting it out would hold the
    // browser's request, so the attempt stops and the session survives for the
    // next request to retry.
    let advice = RetryAdvice::retry_after(Duration::from_mins(1));
    let (e, calls) = engine_with_refresh_advice(advice, session).await;
    let loaded = e.load_session(&HeaderMap::new()).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(loaded, Ok(LoadedSession::RefreshUnavailable)));
}

#[tokio::test]
async fn refresh_does_not_retry_when_error_is_non_retryable() {
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let (e, calls) = engine_with_failing_refresh(false, session).await;
    let _ = e.load_session(&HeaderMap::new()).await;
    // Non-retryable AS rejection (e.g. invalid_grant) must short-circuit at
    // the first attempt — retrying would just amplify load.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn refresh_success_persists_eagerly() {
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::with_session(session))
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    // The refreshed session was saved inside load_session — `Active`, with
    // nothing left for the post-response persist phase.
    let (session, set_cookies) = expect_active(loaded);
    assert!(e.session_store.save_called());
    // The refresh response carried expires_in=3600 — expiry moved well past now.
    assert!(session.token_expiry() > SystemTime::now() + Duration::from_mins(30));
    // The eager save's Set-Cookie headers come back on the loaded result.
    assert_eq!(
        set_cookies,
        vec![HeaderValue::from_static(MOCK_SAVE_COOKIE)]
    );
}

#[tokio::test]
async fn refresh_success_with_failing_save_defers_persistence() {
    // The refresh succeeded but the eager save didn't — the session (holding
    // the rotated refresh token) must survive with `Save` persistence so the
    // adapter's post-response persist acts as the retry.
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::with_session_failing_save(session))
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let pending = expect_pending(loaded);
    // The refresh itself was applied — only persistence is outstanding.
    assert!(pending.session().token_expiry() > SystemTime::now() + Duration::from_mins(30));
    // Not committed in this test — defuse the drop guard.
    pending.abandon();
}

#[tokio::test]
async fn refresh_save_gone_clears_instead_of_deferring_or_serving() {
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::with_session_gone_on_save(session))
        .sealer(test_sealer().await)
        .build()
        .unwrap();

    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, clears) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::InvalidSession);
    assert_eq!(
        clears,
        vec![HeaderValue::from_static("mock-session=; Max-Age=0")]
    );
}

#[tokio::test]
async fn commit_retries_the_deferred_refresh_save() {
    // The `PendingPersist` carries the refresh response so the post-response
    // commit can re-apply it (through the merge-safe path) once the store
    // recovers.
    let mut session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    session.state.refresh_revision = 7;
    let mut e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::with_session_failing_save(session))
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let mut pending = expect_pending(loaded);
    assert_eq!(pending.expected_refresh_revision, 7);
    Arc::make_mut(&mut pending.session).state.refresh_revision = 8;
    // A serving handle taken during the request survives the commit.
    let session = pending.session_arc();

    // The store recovers; the owed persist now succeeds.
    e.session_store.fail_save = false;
    let set_cookies = pending.commit(&e, &HeaderMap::new()).await.unwrap();
    assert!(e.session_store.save_called());
    assert_eq!(
        *e.session_store.refresh_revisions.lock().unwrap(),
        vec![7, 7]
    );
    assert_eq!(
        set_cookies.into_headers(),
        vec![HeaderValue::from_static(MOCK_SAVE_COOKIE)]
    );
    // The applied refresh keeps the session's tokens fresh.
    assert!(session.token_expiry() > SystemTime::now() + Duration::from_mins(30));
}

// ── Transient refresh failure inside the early-refresh window ─────────────

#[tokio::test]
async fn transient_refresh_failure_with_valid_token_retains_session() {
    // Token expires 15s from now — inside the 30s refresh margin but still
    // valid. A transient refresh failure must not log the user out.
    let session = refreshable_session(SystemTime::now() + Duration::from_secs(15));
    let (e, calls) = engine_with_failing_refresh(true, session).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    // The default driver verdict is `Untracked`, so the retained session comes
    // back `Active` with nothing owed.
    let (_session, set_cookies) = expect_active(loaded);
    assert_eq!(set_cookies, [] as [HeaderValue; 0]);
    assert!(!e.session_store.revoke_called());
    // The full retry budget was spent before falling back to retention.
    assert_eq!(
        calls.load(Ordering::SeqCst),
        super::super::REFRESH_MAX_ATTEMPTS
    );
}

#[tokio::test]
async fn non_retryable_refresh_failure_clears_session_even_with_valid_token() {
    // The AS conclusively rejected the refresh token (e.g. invalid_grant —
    // possibly reuse-detection revocation). Retention would serve a session
    // the AS just disowned; tear it down even though the token has 15s left.
    let session = refreshable_session(SystemTime::now() + Duration::from_secs(15));
    let (e, _) = engine_with_failing_refresh(false, session).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::RefreshRejected);
    assert!(e.session_store.revoke_called());
}

#[tokio::test]
async fn transient_refresh_failure_with_expired_token_retains_session_unavailable() {
    // Past actual expiry there is no valid token to serve THIS request — but
    // a transient AS failure can't refute the session either. The session and
    // its cookies must survive for a later retry (the outcome is
    // `RefreshUnavailable`, not a teardown): deleting here would permanently
    // destroy sessions that recover by themselves when the AS does.
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let (e, _) = engine_with_failing_refresh(true, session).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(
        matches!(loaded, LoadedSession::RefreshUnavailable),
        "expected RefreshUnavailable, got {}",
        variant_name(&loaded)
    );
    assert!(
        !e.session_store.revoke_called(),
        "a transient failure must not delete the session"
    );
}

#[tokio::test]
async fn refresh_unavailable_session_recovers_when_the_as_does() {
    // The companion to the retention test: the same session, presented again
    // once the AS answers, refreshes and resumes without a fresh login.
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let (e, _) = engine_with_failing_refresh(true, session).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(matches!(loaded, LoadedSession::RefreshUnavailable));

    // Same (retained) session against a recovered AS.
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::with_session(session))
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (recovered, _) = expect_active(loaded);
    assert!(recovered.token_expiry() > SystemTime::now() + Duration::from_mins(30));
}
