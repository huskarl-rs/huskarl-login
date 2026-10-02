use super::*;

// ── Server-side login-state TTL ───────────────────────────────────────────

#[tokio::test]
async fn callback_expired_login_state_returns_400_and_clears_cookie() {
    let e = engine(MockSessionStore::empty()).await;
    let state = "expiredstate";
    // Default login_state_ttl is 10 minutes; this flow started 11 minutes ago.
    let created_at = SystemTime::now() - Duration::from_mins(11);
    let value = seal_login_cookie_at(state, "https://app.example.com/a", created_at).await;
    let h = headers_with_login_cookie(state, &value);
    let uri = format!("/callback?code=abc&state={state}").parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::GET, &h, &uri)
        .await
        .expect("callback handled");
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let cleared = r.headers().iter().any(|(n, v)| {
        *n == http::header::SET_COOKIE && {
            let s = v.to_str().unwrap();
            s.starts_with(&format!("{}=;", login_cookie_name(state))) && s.contains("Max-Age=0")
        }
    });
    assert!(cleared, "expired flow's cookie must be cleared");
}

#[tokio::test]
async fn callback_far_future_login_state_returns_400_and_clears_cookie() {
    // A sealed `created_at` implausibly far ahead of the clock (beyond the 5m
    // skew tolerance) means a backwards clock jump, not a fresh flow. Without
    // the far-future guard `elapsed_since` clamps to zero and the flow would
    // never expire; it must be rejected and the cookie cleared, symmetric with
    // the session teardown path.
    let e = engine(MockSessionStore::empty()).await;
    let state = "futurestate";
    let created_at = SystemTime::now() + Duration::from_mins(10);
    let value = seal_login_cookie_at(state, "https://app.example.com/a", created_at).await;
    let h = headers_with_login_cookie(state, &value);
    let uri = format!("/callback?code=abc&state={state}").parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::GET, &h, &uri)
        .await
        .expect("callback handled");
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let cleared = r.headers().iter().any(|(n, v)| {
        *n == http::header::SET_COOKIE && {
            let s = v.to_str().unwrap();
            s.starts_with(&format!("{}=;", login_cookie_name(state))) && s.contains("Max-Age=0")
        }
    });
    assert!(cleared, "far-future flow's cookie must be cleared");
}

#[tokio::test]
async fn callback_pre_created_at_format_treated_as_expired() {
    // A cookie sealed before the created_at field existed deserializes with
    // the epoch default and is uniformly rejected as expired — the documented
    // re-login behavior for wire-format changes.
    #[derive(serde::Serialize)]
    struct OldLoginStateCookie<'a> {
        original_url: &'a str,
        pending_state: &'a PendingState,
    }
    let state = "oldformat";
    let pending_state = test_pending_state(state);
    let payload = crate::cookie::encode_payload(&OldLoginStateCookie {
        original_url: "https://app.example.com/a",
        pending_state: &pending_state,
    })
    .unwrap();
    let sealer = AeadV1Sealer::new(test_cipher().await);
    let output = sealer.seal(&payload, state.as_bytes()).await.unwrap();
    let value = URL_SAFE_NO_PAD.encode(&output.bundle);

    let e = engine(MockSessionStore::empty()).await;
    let h = headers_with_login_cookie(state, &value);
    let uri = format!("/callback?code=abc&state={state}").parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::GET, &h, &uri)
        .await
        .expect("callback handled");
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

// ── Callback handler ──────────────────────────────────────────────────────

async fn callback_status(path_and_query: &str, request_headers: &HeaderMap) -> StatusCode {
    let e = engine(MockSessionStore::empty()).await;
    let uri = path_and_query.parse().unwrap();
    e.try_handle_login_route(&Method::GET, request_headers, &uri)
        .await
        .expect("callback handled")
        .status()
}

#[tokio::test]
async fn callback_no_params_returns_400() {
    assert_eq!(
        callback_status("/callback", &HeaderMap::new()).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn callback_missing_code_returns_400() {
    assert_eq!(
        callback_status("/callback?state=abc", &HeaderMap::new()).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn callback_missing_state_returns_400() {
    assert_eq!(
        callback_status("/callback?code=authcode", &HeaderMap::new()).await,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn callback_as_error_returns_403() {
    assert_eq!(
        callback_status("/callback?error=access_denied", &HeaderMap::new()).await,
        StatusCode::FORBIDDEN,
    );
}

#[tokio::test]
async fn callback_as_error_with_description_returns_403() {
    assert_eq!(
        callback_status(
            "/callback?error=access_denied&error_description=User+denied+access",
            &HeaderMap::new(),
        )
        .await,
        StatusCode::FORBIDDEN,
    );
}

#[tokio::test]
async fn callback_as_error_clears_only_the_failed_flows_cookie() {
    let e = engine(MockSessionStore::empty()).await;
    let state = "denied_state";
    let sealed = seal_login_cookie(state, "https://app.example.com/page").await;
    let failed_name = login_cookie_name(state);
    let other_name = login_cookie_name("other");
    let cookie_header = format!("{failed_name}={sealed}; {other_name}=other-flow");
    let h = headers(&[("cookie", &cookie_header)]);
    let uri = format!("/callback?error=access_denied&state={state}")
        .parse()
        .unwrap();

    let response = e
        .try_handle_login_route(&Method::GET, &h, &uri)
        .await
        .expect("callback handled");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(cookie_is_cleared(&response, &failed_name));
    assert!(!cookie_is_cleared(&response, &other_name));
}

#[tokio::test]
async fn callback_as_error_without_matching_cookie_sets_no_cookie() {
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/callback?error=access_denied&state=unknown_state"
        .parse()
        .unwrap();

    let response = e
        .try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
        .await
        .expect("callback handled");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !response
            .headers()
            .iter()
            .any(|(name, _)| *name == http::header::SET_COOKIE)
    );
}

#[tokio::test]
async fn callback_no_state_cookie_returns_400() {
    let status = callback_status("/callback?code=authcode&state=mystate", &HeaderMap::new()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn callback_malformed_base64_cookie_returns_400() {
    let state = "teststate";
    let h = headers_with_login_cookie(state, "not-valid!!!base64");
    assert_eq!(
        callback_status(&format!("/callback?code=authcode&state={state}"), &h).await,
        StatusCode::BAD_REQUEST,
    );
}

#[tokio::test]
async fn callback_tampered_aead_bundle_returns_400() {
    let state = "teststate";
    let fake = URL_SAFE_NO_PAD.encode(b"this is not an AEAD ciphertext bundle");
    let h = headers_with_login_cookie(state, &fake);
    assert_eq!(
        callback_status(&format!("/callback?code=authcode&state={state}"), &h).await,
        StatusCode::BAD_REQUEST,
    );
}

#[tokio::test]
async fn callback_mismatched_state_aad_returns_400() {
    // Seal with AAD "right_state", present under state "wrong_state" — AEAD auth fails.
    let sealed = seal_login_cookie("right_state", "https://app.example.com/page").await;
    let wrong = "wrong_state";
    let h = headers_with_login_cookie(wrong, &sealed);
    assert_eq!(
        callback_status(&format!("/callback?code=authcode&state={wrong}"), &h).await,
        StatusCode::BAD_REQUEST,
    );
}

#[tokio::test]
async fn callback_valid_cookie_exchange_fails_returns_502() {
    let state = "valid_state";
    let sealed = seal_login_cookie(state, "https://app.example.com/page").await;
    let h = headers_with_login_cookie(state, &sealed);
    assert_eq!(
        callback_status(&format!("/callback?code=authcode&state={state}"), &h).await,
        StatusCode::BAD_GATEWAY,
    );
}

#[tokio::test]
async fn callback_success_redirects_to_original_url() {
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::empty())
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    let state = "valid_state";
    let sealed = seal_login_cookie(state, "https://app.example.com/page").await;
    let h = headers_with_login_cookie(state, &sealed);
    let uri = format!("/callback?code=authcode&state={state}")
        .parse()
        .unwrap();
    let r = e
        .try_handle_login_route(&Method::GET, &h, &uri)
        .await
        .expect("callback handled");
    assert_eq!(r.status(), StatusCode::FOUND);
    let hdrs = r.headers();
    let loc = hdrs
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap());
    assert_eq!(loc, Some("https://app.example.com/page"));
    // The login-state cookie is cleared on the way out.
    let login_cookie_cleared = r.headers().iter().any(|(n, v)| {
        *n == http::header::SET_COOKIE
            && v.to_str().unwrap().contains("huskarl_login_")
            && v.to_str().unwrap().contains("Max-Age=0")
    });
    assert!(login_cookie_cleared, "login-state cookie must be cleared");
}

#[tokio::test]
async fn callback_success_sweeps_all_pending_login_state_cookies() {
    // Abandoned flows (other tabs, retried logins) leave login-state cookies
    // behind; a completed login makes them all moot, so the success response
    // clears every one — bounding jar growth toward the browser's per-domain
    // cookie cap.
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::empty())
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    let state = "valid_state";
    let sealed = seal_login_cookie(state, "https://app.example.com/page").await;
    let name = |s: &str| {
        crate::cookie::login_state_cookie_name(
            s,
            true,
            "/callback",
            crate::cookie::DEFAULT_LOGIN_COOKIE_PREFIX,
        )
    };
    let cookie_header = format!(
        "{}={sealed}; unrelated=keep; {}=stale1; {}=stale2",
        name(state),
        name("stale_a"),
        name("stale_b"),
    );
    let h = headers(&[("cookie", &cookie_header)]);
    let uri = format!("/callback?code=authcode&state={state}")
        .parse()
        .unwrap();
    let r = e
        .try_handle_login_route(&Method::GET, &h, &uri)
        .await
        .expect("callback handled");
    assert_eq!(r.status(), StatusCode::FOUND);
    for s in [state, "stale_a", "stale_b"] {
        let n = name(s);
        let cleared = r.headers().iter().any(|(hn, v)| {
            *hn == http::header::SET_COOKIE
                && v.to_str().unwrap().starts_with(&format!("{n}=;"))
                && v.to_str().unwrap().contains("Max-Age=0")
        });
        assert!(cleared, "expected clear for pending flow cookie {n}");
    }
    // Cookies outside the login-state namespace are untouched.
    let unrelated_touched = r.headers().iter().any(|(hn, v)| {
        *hn == http::header::SET_COOKIE && v.to_str().unwrap().starts_with("unrelated=")
    });
    assert!(!unrelated_touched, "unrelated cookies must not be swept");
}

#[tokio::test]
async fn callback_without_state_cookie_but_with_session_redirects_home() {
    // The success sweep (or a re-navigated stale callback URL) can produce a
    // code+state callback with no matching login-state cookie. With a usable
    // session already present, the user is sent home instead of shown a 400.
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let uri = "/callback?code=authcode&state=mystate".parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
        .await
        .expect("callback handled");
    assert_eq!(r.status(), StatusCode::FOUND);
    let hdrs = r.headers();
    let loc = hdrs
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap());
    assert_eq!(loc, Some("https://app.example.com/"));
}

#[tokio::test]
async fn callback_already_authenticated_sweeps_login_state_cookies() {
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let first_name = login_cookie_name("stale_a");
    let second_name = login_cookie_name("stale_b");
    let cookie_header = format!("{first_name}=stale1; unrelated=keep; {second_name}=stale2");
    let h = headers(&[("cookie", &cookie_header)]);
    let uri = "/callback?code=authcode&state=mystate".parse().unwrap();

    let response = e
        .try_handle_login_route(&Method::GET, &h, &uri)
        .await
        .expect("callback handled");

    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(cookie_is_cleared(&response, &first_name));
    assert!(cookie_is_cleared(&response, &second_name));
    assert!(!response.headers().iter().any(|(name, value)| {
        *name == http::header::SET_COOKIE && value.to_str().unwrap().starts_with("unrelated=")
    }));
}

fn cookie_is_cleared(response: &super::super::LoginResponse, cookie_name: &str) -> bool {
    response.headers().iter().any(|(name, value)| {
        *name == http::header::SET_COOKIE
            && value
                .to_str()
                .is_ok_and(|value| value.starts_with(&format!("{cookie_name}=;")))
            && value
                .to_str()
                .is_ok_and(|value| value.contains("Max-Age=0"))
    })
}

#[tokio::test]
async fn callback_without_state_cookie_and_expired_session_returns_400() {
    // An expired session can't vouch for the user — the fallback must not
    // rescue it; the 400 (and a fresh login) is correct.
    let session = session_with(
        SystemTime::now() - Duration::from_mins(5),
        None,
        SystemTime::now() - Duration::from_hours(1),
    );
    let e = engine(MockSessionStore::with_session(session)).await;
    let uri = "/callback?code=authcode&state=mystate".parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
        .await
        .expect("callback handled");
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}
