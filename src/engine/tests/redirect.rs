use super::*;

// ── Session management ────────────────────────────────────────────────────

#[tokio::test]
async fn redirect_to_login_navigation_returns_302() {
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/protected".parse().unwrap();
    let r = e.redirect_to_login(&nav_headers(), &uri).await;
    assert_eq!(r.status(), StatusCode::FOUND);
    let hdrs = r.headers();
    let loc = hdrs
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap())
        .expect("Location header");
    assert!(
        loc.starts_with("https://auth.example.com/authorize?"),
        "{loc}"
    );
    assert!(loc.contains("client_id=client"), "{loc}");
}

#[tokio::test]
async fn redirect_to_login_navigation_sets_login_state_cookie() {
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/protected".parse().unwrap();
    let r = e.redirect_to_login(&nav_headers(), &uri).await;
    let has_login_cookie = r.headers().iter().any(|(n, v)| {
        *n == http::header::SET_COOKIE && v.to_str().unwrap().contains("huskarl_login_")
    });
    assert!(has_login_cookie);
}

#[tokio::test]
async fn redirect_to_login_navigation_is_no_store() {
    // The redirect carries a session-bearing login-state cookie, so the
    // boundary materializes `Cache-Control: no-store` for every redirect.
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/protected".parse().unwrap();
    let r = e.redirect_to_login(&nav_headers(), &uri).await;
    let hdrs = r.headers();
    let cache = hdrs
        .iter()
        .find(|(n, _)| *n == http::header::CACHE_CONTROL)
        .map(|(_, v)| v.to_str().unwrap());
    assert_eq!(cache, Some("no-store"));
}

#[tokio::test]
async fn redirect_to_login_api_returns_401() {
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/api/data".parse().unwrap();
    let r = e.redirect_to_login(&api_headers(), &uri).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // RFC 9110: every 401 carries a WWW-Authenticate challenge.
    let challenge = r
        .headers()
        .iter()
        .find(|(n, _)| *n == http::header::WWW_AUTHENTICATE)
        .map(|(_, v)| v.to_str().unwrap().to_owned());
    assert_eq!(challenge.as_deref(), Some("Cookie"));
}

#[tokio::test]
async fn login_state_cookie_uses_configured_ttl() {
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .login_state_ttl(Duration::from_mins(30))
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::empty(), config).await;
    let uri = "/protected".parse().unwrap();
    let r = e.redirect_to_login(&nav_headers(), &uri).await;
    let hdrs = r.headers();
    let cookie = hdrs
        .iter()
        .find(|(n, v)| {
            *n == http::header::SET_COOKIE && v.to_str().unwrap().contains("huskarl_login_")
        })
        .expect("login-state cookie");
    assert!(cookie.1.to_str().unwrap().contains("Max-Age=1800"));
}
