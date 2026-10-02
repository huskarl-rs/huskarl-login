use super::*;

// ── Logout handler ────────────────────────────────────────────────────────

#[tokio::test]
async fn logout_without_session_redirects_to_base_url() {
    let e = engine_with_config(MockSessionStore::empty(), config_with_logout()).await;
    let uri = "/logout".parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::POST, &logout_headers(), &uri)
        .await
        .expect("logout handled");
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let hdrs = r.headers();
    let loc = hdrs
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap());
    assert_eq!(loc, Some("https://app.example.com/"));
}

#[tokio::test]
async fn logout_with_session_revokes_session() {
    let e = engine_with_config(
        MockSessionStore::with_session(valid_session()),
        config_with_logout(),
    )
    .await;
    let uri = "/logout".parse().unwrap();
    let _ = e
        .try_handle_login_route(&Method::POST, &logout_headers(), &uri)
        .await;
    assert!(e.session_store.revoke_called());
}

#[tokio::test]
async fn logout_load_failure_still_clears_browser_session() {
    let e = LoginEngine::builder()
        .config(config_with_logout())
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(ErrorSessionStore)
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    let uri = "/logout".parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::POST, &logout_headers(), &uri)
        .await
        .expect("logout handled");

    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(has_mock_session_clear(&r));
}

#[tokio::test]
async fn logout_revocation_failure_still_clears_browser_session() {
    let e = engine_with_config(
        MockSessionStore::with_session_failing_revoke(valid_session()),
        config_with_logout(),
    )
    .await;
    let uri = "/logout".parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::POST, &logout_headers(), &uri)
        .await
        .expect("logout handled");

    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(e.session_store.revoke_called());
    assert!(has_mock_session_clear(&r));
}

#[tokio::test]
async fn explicit_termination_preserves_browser_clears_when_revocation_fails() {
    let e = engine(MockSessionStore::with_session_failing_revoke(
        valid_session(),
    ))
    .await;
    let session = valid_session();

    let outcome = e.terminate_session(&session, &HeaderMap::new()).await;
    let (clears, revocation) = outcome.into_parts();
    assert!(revocation.is_err());
    assert_eq!(
        clears.into_headers(),
        vec![HeaderValue::from_static("mock-session=; Max-Age=0")]
    );
}

fn has_mock_session_clear(response: &super::super::LoginResponse) -> bool {
    response.headers().iter().any(|(name, value)| {
        *name == http::header::SET_COOKIE && value == "mock-session=; Max-Age=0"
    })
}

#[tokio::test]
async fn logout_redirects_to_configured_post_logout_uri() {
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .logout(
            LogoutConfig::builder()
                .path("/logout")
                .post_logout_redirect_uri("https://app.example.com/signed-out")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::empty(), config).await;
    let uri = "/logout".parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::POST, &logout_headers(), &uri)
        .await
        .expect("logout handled");
    let hdrs = r.headers();
    let loc = hdrs
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap());
    assert_eq!(loc, Some("https://app.example.com/signed-out"));
}

#[tokio::test]
async fn logout_end_session_url_includes_client_id_without_id_token() {
    // The stock case: built-in sessions store no id_token, so the end-session
    // URL must still identify the RP via client_id — otherwise the OP drops
    // post_logout_redirect_uri (OIDC RP-Initiated Logout 1.0 §2).
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .logout(
            LogoutConfig::builder()
                .path("/logout")
                .end_session_endpoint("https://auth.example.com/logout".parse().unwrap())
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::with_session(valid_session()), config).await;
    let uri = "/logout".parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::POST, &logout_headers(), &uri)
        .await
        .expect("logout handled");
    let loc = r
        .headers()
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap().to_owned())
        .expect("location header");
    // test_grant uses client_id = "client".
    assert!(loc.contains("client_id=client"), "got: {loc}");
    assert!(loc.contains("post_logout_redirect_uri="), "got: {loc}");
    assert!(!loc.contains("id_token_hint="), "got: {loc}");
}

#[tokio::test]
async fn post_logout_redirect_uri_is_sent_exactly_not_normalized() {
    // OIDC RP-Initiated Logout 1.0 §3 requires the OP to match
    // post_logout_redirect_uri against the registered value byte-for-byte.
    // An authority-only URL must NOT gain a trailing slash on the way to the
    // wire (parsing through http::Uri would add one), or the OP drops it.
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .logout(
            LogoutConfig::builder()
                .path("/logout")
                .end_session_endpoint("https://auth.example.com/logout".parse().unwrap())
                .post_logout_redirect_uri("https://app.example.com")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::empty(), config).await;
    let uri = "/logout".parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::POST, &logout_headers(), &uri)
        .await
        .expect("logout handled");
    let loc = r
        .headers()
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap().to_owned())
        .expect("location header");
    // The exact bytes survive: encoded "https://app.example.com" with no
    // trailing %2F. The normalized (buggy) form would end in "...com%2F".
    assert!(
        loc.ends_with("post_logout_redirect_uri=https%3A%2F%2Fapp.example.com"),
        "got: {loc}"
    );
    assert!(!loc.contains("app.example.com%2F"), "got: {loc}");
}

#[tokio::test]
async fn logout_rejects_cross_site_request_without_deleting_session() {
    // A forged cross-site POST (e.g. an auto-submitting form on an attacker's
    // page) must not log the user out: 403, no redirect, session left intact.
    let e = engine_with_config(
        MockSessionStore::with_session(valid_session()),
        config_with_logout(),
    )
    .await;
    let uri = "/logout".parse().unwrap();
    let h = headers(&[("sec-fetch-site", "cross-site")]);
    let r = e
        .try_handle_login_route(&Method::POST, &h, &uri)
        .await
        .expect("logout handled");
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(
        !r.headers()
            .iter()
            .any(|(n, _)| *n == http::header::LOCATION),
        "cross-site logout must not redirect"
    );
    assert!(!e.session_store.revoke_called());
}

#[tokio::test]
async fn logout_allows_same_origin_request() {
    let e = engine_with_config(
        MockSessionStore::with_session(valid_session()),
        config_with_logout(),
    )
    .await;
    let uri = "/logout".parse().unwrap();
    let h = headers(&[
        ("sec-fetch-site", "same-origin"),
        ("origin", "https://app.example.com"),
    ]);
    let r = e
        .try_handle_login_route(&Method::POST, &h, &uri)
        .await
        .expect("logout handled");
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(e.session_store.revoke_called());
}

#[tokio::test]
async fn logout_rejects_same_site_sibling_origin() {
    let e = engine_with_config(
        MockSessionStore::with_session(valid_session()),
        config_with_logout(),
    )
    .await;
    let uri = "/logout".parse().unwrap();
    let h = headers(&[
        ("sec-fetch-site", "same-site"),
        ("origin", "https://evil.example.com"),
    ]);
    let r = e
        .try_handle_login_route(&Method::POST, &h, &uri)
        .await
        .expect("logout handled");
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(!e.session_store.revoke_called());
}

#[tokio::test]
async fn logout_rejects_missing_origin() {
    let e = engine_with_config(
        MockSessionStore::with_session(valid_session()),
        config_with_logout(),
    )
    .await;
    let uri = "/logout".parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::POST, &HeaderMap::new(), &uri)
        .await
        .expect("logout handled");
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(!e.session_store.revoke_called());
}
