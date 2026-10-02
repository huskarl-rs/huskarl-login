use super::*;

// ── is_navigation_request ─────────────────────────────────────────────────

#[rstest]
#[case::xhr(&[("x-requested-with", "XMLHttpRequest")], false)]
#[case::xhr_case_insensitive(&[("x-requested-with", "xmlhttprequest")], false)]
#[case::sec_fetch_mode_navigate(&[("sec-fetch-mode", "navigate")], true)]
#[case::sec_fetch_mode_cors(&[("sec-fetch-mode", "cors")], false)]
#[case::sec_fetch_mode_no_cors(&[("sec-fetch-mode", "no-cors")], false)]
#[case::sec_fetch_dest_document(&[("sec-fetch-dest", "document")], true)]
#[case::sec_fetch_dest_empty(&[("sec-fetch-dest", "empty")], false)]
#[case::sec_fetch_dest_image(&[("sec-fetch-dest", "image")], false)]
#[case::accept_text_html(&[("accept", "text/html,application/xhtml+xml,*/*;q=0.8")], true)]
#[case::accept_xhtml_only(&[("accept", "application/xhtml+xml")], true)]
#[case::accept_json(&[("accept", "application/json")], false)]
#[case::no_relevant_headers(&[], false)]
// Sec-Fetch-User is an affirmative navigation signal when Mode/Dest are absent
// (e.g. stripped by an intermediary), rescuing the navigation before Accept.
#[case::sec_fetch_user_activated(&[("sec-fetch-user", "?1")], true)]
#[case::sec_fetch_user_rescues_over_accept_json(
    &[("sec-fetch-user", "?1"), ("accept", "application/json")],
    true
)]
// Precedence: an explicit XHR/CORS signal wins over a navigation-looking one.
#[case::xhr_overrides_sec_fetch_navigate(
    &[("x-requested-with", "XMLHttpRequest"), ("sec-fetch-mode", "navigate")],
    false
)]
#[case::sec_fetch_mode_overrides_accept(&[("sec-fetch-mode", "cors"), ("accept", "text/html")], false)]
// Mode/Dest take precedence over Sec-Fetch-User: a non-navigation Mode wins.
#[case::sec_fetch_mode_overrides_user(&[("sec-fetch-mode", "cors"), ("sec-fetch-user", "?1")], false)]
// Frame loads send `mode=navigate` too — only `dest=document` is a real
// top-level navigation.
#[case::navigate_into_document(
    &[("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "document")],
    true
)]
#[case::navigate_into_iframe(
    &[("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "iframe")],
    false
)]
#[case::navigate_into_embed(
    &[("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "embed")],
    false
)]
// Speculative loads are never navigations, whatever the fetch metadata says.
#[case::sec_purpose_prefetch(
    &[("sec-fetch-mode", "navigate"), ("sec-fetch-dest", "document"), ("sec-purpose", "prefetch")],
    false
)]
#[case::sec_purpose_prerender(
    &[
        ("sec-fetch-mode", "navigate"),
        ("sec-fetch-dest", "document"),
        ("sec-purpose", "prefetch;prerender")
    ],
    false
)]
#[case::legacy_purpose_prefetch(
    &[("purpose", "prefetch"), ("accept", "text/html")],
    false
)]
#[case::purpose_other_value_ignored(&[("purpose", "preview"), ("sec-fetch-mode", "navigate")], true)]
fn is_navigation_request_cases(#[case] pairs: &[(&str, &str)], #[case] expected: bool) {
    assert_eq!(is_navigation_request(&headers(pairs)), expected);
}

// ── is_cross_site_request ─────────────────────────────────────────────────

#[rstest]
#[case::cross_site(&[("sec-fetch-site", "cross-site")], true)]
#[case::same_origin(&[("sec-fetch-site", "same-origin")], false)]
#[case::same_site(&[("sec-fetch-site", "same-site")], false)]
// "none" means user-initiated (typed URL, bookmark) — not a forgery.
#[case::none_user_initiated(&[("sec-fetch-site", "none")], false)]
#[case::absent(&[], false)]
fn is_cross_site_request_cases(#[case] pairs: &[(&str, &str)], #[case] expected: bool) {
    assert_eq!(is_cross_site_request(&headers(pairs)), expected);
}

// ── Routing ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn callback_path_is_handled() {
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/callback".parse().unwrap();
    let resp = e
        .try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
        .await
        .expect("reserved /callback path must be claimed, not fall through");
    // No code/state on the callback → 400, rather than a silent pass-through.
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn logout_path_is_handled_when_configured() {
    let e = engine_with_config(MockSessionStore::empty(), config_with_logout()).await;
    let uri = "/logout".parse().unwrap();
    let resp = e
        .try_handle_login_route(&Method::POST, &logout_headers(), &uri)
        .await
        .expect("configured /logout path must be claimed, not fall through");
    // No session present is not an error for logout: it still redirects
    // (303: logout is a POST, See Other pins the follow-up to GET).
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn callback_rejects_non_get_methods() {
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/callback".parse().unwrap();
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::HEAD] {
        let resp = e
            .try_handle_login_route(&method, &HeaderMap::new(), &uri)
            .await
            .expect("reserved path must not fall through");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{method}");
        let hdrs = resp.headers();
        let allow = hdrs
            .iter()
            .find(|(n, _)| *n == http::header::ALLOW)
            .map(|(_, v)| v.to_str().unwrap());
        assert_eq!(allow, Some("GET"), "{method}");
    }
}

#[tokio::test]
async fn logout_accepts_post() {
    let e = engine_with_config(MockSessionStore::empty(), config_with_logout()).await;
    let uri = "/logout".parse().unwrap();
    let resp = e
        .try_handle_login_route(&Method::POST, &logout_headers(), &uri)
        .await
        .expect("logout handles POST");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn logout_rejects_other_methods() {
    // GET is rejected too: logout is POST-only so it can't be triggered by a
    // link, an `<img>`, or a prefetch.
    let e = engine_with_config(MockSessionStore::empty(), config_with_logout()).await;
    let uri = "/logout".parse().unwrap();
    for method in [Method::GET, Method::PUT, Method::DELETE, Method::HEAD] {
        let resp = e
            .try_handle_login_route(&method, &HeaderMap::new(), &uri)
            .await
            .expect("reserved path must not fall through");
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{method}");
        let hdrs = resp.headers();
        let allow = hdrs
            .iter()
            .find(|(n, _)| *n == http::header::ALLOW)
            .map(|(_, v)| v.to_str().unwrap());
        assert_eq!(allow, Some("POST"), "{method}");
    }
}

#[tokio::test]
async fn logout_path_returns_none_when_unconfigured() {
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/logout".parse().unwrap();
    let resp = e
        .try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
        .await;
    assert!(resp.is_none());
}

#[test]
fn cors_preflight_is_detected() {
    let h = headers(&[("access-control-request-method", "POST")]);
    assert!(is_cors_preflight(&Method::OPTIONS, &h));
}

#[test]
fn options_without_acr_header_is_not_preflight() {
    assert!(!is_cors_preflight(&Method::OPTIONS, &api_headers()));
}
