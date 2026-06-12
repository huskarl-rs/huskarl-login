use std::{
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, SystemTime},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use huskarl::{
    core::{
        Error, ErrorKind,
        client_auth::NoAuth,
        crypto::cipher::{AeadSealer as _, AeadV1Cipher},
        http::{HttpClient, HttpResponse, Idempotency},
        platform::MaybeSendBoxFuture,
        secrets::{Secret, SecretBytes, SecretOutput},
    },
    grant::authorization_code::{AuthorizationCodeGrant, PendingState},
    token::RefreshToken,
};
use huskarl_crypto_native::aead::{AesGcmKey, AesGcmKeyType};

use super::{
    LoginEngine, SessionPersistence, error_chain, is_cors_preflight, is_cross_site_request,
    is_navigation_request,
};
use crate::{
    CompletedLogin, LoginConfig, Session, SessionDriver, SessionError, SessionState,
    metrics::{
        ActivityOutcome, LoginCompleteResult, LoginEngineMetrics, LoginStartResult, RefreshResult,
    },
    session::sealed::Sealed,
};

// ── TestSecret / cipher ───────────────────────────────────────────────────

#[derive(Clone)]
struct TestSecret(SecretBytes);

impl Secret for TestSecret {
    type Output = SecretBytes;
    fn get_secret_value(&self) -> MaybeSendBoxFuture<'_, Result<SecretOutput<SecretBytes>, Error>> {
        let out = SecretOutput {
            value: self.0.clone(),
            identity: None,
        };
        Box::pin(async move { Ok(out) })
    }
}

async fn test_cipher() -> AesGcmKey {
    AesGcmKey::from_secret(
        AesGcmKeyType::Aes256,
        TestSecret(SecretBytes::new(vec![0u8; 32])),
        |_| None,
    )
    .await
    .unwrap()
}

// ── HTTP doubles ──────────────────────────────────────────────────────────

#[derive(Debug)]
struct FlakyError;

impl std::fmt::Display for FlakyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("flaky transport error")
    }
}

impl std::error::Error for FlakyError {}

/// Fails every request with a transport error of the given retryability,
/// counting calls. One refresh attempt makes exactly one token-endpoint
/// request (`NoAuth` needs no HTTP and no `DPoP` is configured), so the call
/// count equals the attempt count.
struct FailingHttp {
    calls: Arc<AtomicU32>,
    retryable: bool,
}

impl FailingHttp {
    fn new(retryable: bool) -> (Self, Arc<AtomicU32>) {
        let calls = Arc::new(AtomicU32::new(0));
        (
            Self {
                calls: Arc::clone(&calls),
                retryable,
            },
            calls,
        )
    }
}

impl HttpClient for FailingHttp {
    fn execute(
        &self,
        _: http::Request<Bytes>,
        _: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let retryable = self.retryable;
        Box::pin(async move { Err(Error::new(ErrorKind::Transport { retryable }, FlakyError)) })
    }
}

/// Answers every request with a minimal valid token response, exercising the
/// success paths (token exchange on callback, token refresh).
struct TokenHttp;

impl HttpClient for TokenHttp {
    fn execute(
        &self,
        _: http::Request<Bytes>,
        _: Idempotency,
    ) -> MaybeSendBoxFuture<'_, Result<HttpResponse, Error>> {
        Box::pin(async {
            let mut headers = HeaderMap::new();
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            Ok(HttpResponse {
                status: StatusCode::OK,
                headers,
                body: Bytes::from_static(
                    br#"{"access_token":"at","token_type":"Bearer","expires_in":3600}"#,
                ),
            })
        })
    }
}

// ── Grant fixtures ────────────────────────────────────────────────────────

/// A real `AuthorizationCodeGrant` over the given HTTP double. `start()` uses
/// direct delivery (no PAR) and performs no HTTP, so the double only sees
/// token-endpoint requests.
async fn test_grant(http_client: impl HttpClient + 'static) -> AuthorizationCodeGrant {
    AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(http_client)
        .client_auth(NoAuth)
        .token_endpoint("https://auth.example.com/token")
        .unwrap()
        .authorization_endpoint("https://auth.example.com/authorize")
        .unwrap()
        .redirect_uri("https://app.example.com/callback")
        .build()
        .await
        .unwrap()
}

/// A grant that must deliver its authorization request via PAR, so `start()`
/// performs HTTP and fails against the failing double.
async fn par_failing_grant() -> AuthorizationCodeGrant {
    AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(FailingHttp::new(false).0)
        .client_auth(NoAuth)
        .token_endpoint("https://auth.example.com/token")
        .unwrap()
        .authorization_endpoint("https://auth.example.com/authorize")
        .unwrap()
        .pushed_authorization_request_endpoint("https://auth.example.com/par")
        .unwrap()
        .require_pushed_authorization_requests(true)
        .redirect_uri("https://app.example.com/callback")
        .build()
        .await
        .unwrap()
}

// ── MockSession ───────────────────────────────────────────────────────────

struct MockSession {
    state: crate::SessionState,
}

impl Session for MockSession {
    fn state(&self) -> &crate::SessionState {
        &self.state
    }
    fn set_state(&mut self, s: crate::SessionState) {
        self.state = s;
    }
}

fn session_with(
    token_expiry: SystemTime,
    refresh_token: Option<RefreshToken>,
    created_at: SystemTime,
    last_active: SystemTime,
) -> MockSession {
    MockSession {
        state: crate::SessionState::builder()
            .token_expiry(token_expiry)
            .maybe_refresh_token(refresh_token)
            .created_at(created_at)
            .last_active(last_active)
            .build(),
    }
}

fn valid_session() -> MockSession {
    session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now(),
        SystemTime::now(),
    )
}

// ── MockSessionStore ──────────────────────────────────────────────────────

struct MockSessionStore {
    session: Mutex<Option<MockSession>>,
    save_called: Mutex<bool>,
    touch_called: Mutex<bool>,
    delete_called: Mutex<bool>,
}

impl MockSessionStore {
    fn with_session(s: MockSession) -> Self {
        Self {
            session: Mutex::new(Some(s)),
            save_called: Mutex::new(false),
            touch_called: Mutex::new(false),
            delete_called: Mutex::new(false),
        }
    }
    fn empty() -> Self {
        Self {
            session: Mutex::new(None),
            save_called: Mutex::new(false),
            touch_called: Mutex::new(false),
            delete_called: Mutex::new(false),
        }
    }
    fn save_called(&self) -> bool {
        *self.save_called.lock().unwrap()
    }
    fn touch_called(&self) -> bool {
        *self.touch_called.lock().unwrap()
    }
    fn delete_called(&self) -> bool {
        *self.delete_called.lock().unwrap()
    }
}

impl Sealed for MockSessionStore {}

impl SessionDriver for MockSessionStore {
    type SessionType = MockSession;
    type LoadError = Infallible;

    async fn create(
        &self,
        completed: CompletedLogin,
        default_lifetime: Duration,
        _: &HeaderMap,
    ) -> Result<(MockSession, Vec<HeaderValue>), SessionError> {
        Ok((
            MockSession {
                state: SessionState::from_completed(&completed, default_lifetime),
            },
            vec![],
        ))
    }
    async fn load(&self, _: &HeaderMap) -> Result<Option<MockSession>, Infallible> {
        Ok(self.session.lock().unwrap().take())
    }
    async fn save(&self, _: &MockSession, _: &HeaderMap) -> Result<Vec<HeaderValue>, SessionError> {
        *self.save_called.lock().unwrap() = true;
        Ok(vec![])
    }
    async fn touch(
        &self,
        _: &MockSession,
        _: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        *self.touch_called.lock().unwrap() = true;
        Ok(vec![])
    }
    async fn delete(
        &self,
        _: &MockSession,
        _: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        *self.delete_called.lock().unwrap() = true;
        Ok(vec![])
    }
}

// ── ErrorSessionStore — load always fails ─────────────────────────────────

#[derive(Debug)]
struct StoreLoadError;
impl std::fmt::Display for StoreLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("store load error")
    }
}
impl std::error::Error for StoreLoadError {}

struct ErrorSessionStore;
impl Sealed for ErrorSessionStore {}
impl SessionDriver for ErrorSessionStore {
    type SessionType = MockSession;
    type LoadError = StoreLoadError;

    async fn create(
        &self,
        _: CompletedLogin,
        _: Duration,
        _: &HeaderMap,
    ) -> Result<(MockSession, Vec<HeaderValue>), SessionError> {
        unimplemented!()
    }
    async fn load(&self, _: &HeaderMap) -> Result<Option<MockSession>, StoreLoadError> {
        Err(StoreLoadError)
    }
    async fn save(&self, _: &MockSession, _: &HeaderMap) -> Result<Vec<HeaderValue>, SessionError> {
        unimplemented!()
    }
    async fn touch(
        &self,
        _: &MockSession,
        _: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        unimplemented!()
    }
    async fn delete(
        &self,
        _: &MockSession,
        _: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        unimplemented!()
    }
}

// ── Engine / config helpers ───────────────────────────────────────────────

fn default_config() -> LoginConfig {
    LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .build()
        .unwrap()
}

fn config_with_logout() -> LoginConfig {
    LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .logout_path("/logout".to_owned())
        .build()
        .unwrap()
}

async fn engine(store: MockSessionStore) -> LoginEngine<MockSessionStore> {
    engine_with_config(store, default_config()).await
}

async fn engine_with_config(
    store: MockSessionStore,
    config: LoginConfig,
) -> LoginEngine<MockSessionStore> {
    LoginEngine::builder()
        .config(config)
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(store)
        .cipher(test_cipher().await)
        .build()
}

// ── Header / URI helpers ──────────────────────────────────────────────────

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn nav_headers() -> HeaderMap {
    headers(&[("sec-fetch-mode", "navigate")])
}

fn api_headers() -> HeaderMap {
    headers(&[("accept", "application/json")])
}

// ── Login-state cookie helper ─────────────────────────────────────────────

async fn seal_login_cookie(state: &str, original_url: &str) -> String {
    let sealer = AeadV1Cipher::new(test_cipher().await);
    let cookie = super::LoginStateCookie {
        original_url: original_url.to_owned(),
        pending_state: PendingState {
            redirect_uri: "https://app.example.com/callback".to_owned(),
            pkce_verifier: None,
            state: state.to_owned(),
            nonce: "test_nonce".to_owned(),
            dpop_jkt: None,
        },
    };
    let payload = crate::cookie::encode_payload(&cookie).unwrap();
    let bundle = sealer.seal(&payload, state.as_bytes()).await.unwrap();
    URL_SAFE_NO_PAD.encode(&bundle)
}

fn headers_with_login_cookie(state: &str, value: &str) -> HeaderMap {
    let name = crate::cookie::login_state_cookie_name(
        state,
        true,
        "/callback",
        crate::cookie::DEFAULT_LOGIN_COOKIE_PREFIX,
    );
    headers(&[("cookie", &format!("{name}={value}"))])
}

// ── is_navigation_request ─────────────────────────────────────────────────

#[test]
fn xhr_header_returns_false() {
    assert!(!is_navigation_request(&headers(&[(
        "x-requested-with",
        "XMLHttpRequest"
    )])));
}

#[test]
fn xhr_header_is_case_insensitive() {
    assert!(!is_navigation_request(&headers(&[(
        "x-requested-with",
        "xmlhttprequest"
    )])));
}

#[test]
fn sec_fetch_mode_navigate_returns_true() {
    assert!(is_navigation_request(&headers(&[(
        "sec-fetch-mode",
        "navigate"
    )])));
}

#[test]
fn sec_fetch_mode_cors_returns_false() {
    assert!(!is_navigation_request(&headers(&[(
        "sec-fetch-mode",
        "cors"
    )])));
}

#[test]
fn sec_fetch_mode_no_cors_returns_false() {
    assert!(!is_navigation_request(&headers(&[(
        "sec-fetch-mode",
        "no-cors"
    )])));
}

#[test]
fn sec_fetch_dest_document_returns_true() {
    assert!(is_navigation_request(&headers(&[(
        "sec-fetch-dest",
        "document"
    )])));
}

#[test]
fn sec_fetch_dest_empty_returns_false() {
    assert!(!is_navigation_request(&headers(&[(
        "sec-fetch-dest",
        "empty"
    )])));
}

#[test]
fn sec_fetch_dest_image_returns_false() {
    assert!(!is_navigation_request(&headers(&[(
        "sec-fetch-dest",
        "image"
    )])));
}

#[test]
fn accept_text_html_returns_true() {
    assert!(is_navigation_request(&headers(&[(
        "accept",
        "text/html,application/xhtml+xml,*/*;q=0.8"
    )])));
}

#[test]
fn accept_xhtml_only_returns_true() {
    assert!(is_navigation_request(&headers(&[(
        "accept",
        "application/xhtml+xml"
    )])));
}

#[test]
fn accept_json_returns_false() {
    assert!(!is_navigation_request(&headers(&[(
        "accept",
        "application/json"
    )])));
}

#[test]
fn no_relevant_headers_returns_false() {
    assert!(!is_navigation_request(&HeaderMap::new()));
}

#[test]
fn xhr_overrides_sec_fetch_navigate() {
    let h = headers(&[
        ("x-requested-with", "XMLHttpRequest"),
        ("sec-fetch-mode", "navigate"),
    ]);
    assert!(!is_navigation_request(&h));
}

#[test]
fn sec_fetch_mode_overrides_accept() {
    let h = headers(&[("sec-fetch-mode", "cors"), ("accept", "text/html")]);
    assert!(!is_navigation_request(&h));
}

// ── is_cross_site_request ─────────────────────────────────────────────────

#[test]
fn sec_fetch_site_cross_site_is_cross_site() {
    assert!(is_cross_site_request(&headers(&[(
        "sec-fetch-site",
        "cross-site"
    )])));
}

#[test]
fn sec_fetch_site_same_origin_is_not_cross_site() {
    assert!(!is_cross_site_request(&headers(&[(
        "sec-fetch-site",
        "same-origin"
    )])));
}

#[test]
fn sec_fetch_site_same_site_is_not_cross_site() {
    assert!(!is_cross_site_request(&headers(&[(
        "sec-fetch-site",
        "same-site"
    )])));
}

#[test]
fn sec_fetch_site_none_is_not_cross_site() {
    // "none" means user-initiated (typed URL, bookmark) — not a forgery.
    assert!(!is_cross_site_request(&headers(&[(
        "sec-fetch-site",
        "none"
    )])));
}

#[test]
fn absent_sec_fetch_site_is_not_cross_site() {
    assert!(!is_cross_site_request(&HeaderMap::new()));
}

// ── error_chain ───────────────────────────────────────────────────────────

#[test]
fn error_chain_formats_single_error() {
    let err = "not-a-number".parse::<i32>().unwrap_err();
    let chain = error_chain(&err);
    assert!(!chain.is_empty());
    assert!(chain.contains("invalid digit"), "got: {chain}");
}

// ── Routing ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn callback_path_is_handled() {
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/callback".parse().unwrap();
    let resp = e
        .try_handle_login_route("/callback", &Method::GET, &HeaderMap::new(), &uri)
        .await;
    assert!(resp.is_some());
}

#[tokio::test]
async fn logout_path_is_handled_when_configured() {
    let e = engine_with_config(MockSessionStore::empty(), config_with_logout()).await;
    let uri = "/logout".parse().unwrap();
    let resp = e
        .try_handle_login_route("/logout", &Method::GET, &HeaderMap::new(), &uri)
        .await;
    assert!(resp.is_some());
}

#[tokio::test]
async fn logout_path_returns_none_when_unconfigured() {
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/logout".parse().unwrap();
    let resp = e
        .try_handle_login_route("/logout", &Method::GET, &HeaderMap::new(), &uri)
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

// ── Session management ────────────────────────────────────────────────────

#[tokio::test]
async fn redirect_to_login_navigation_returns_302() {
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/protected".parse().unwrap();
    let r = e.redirect_to_login(&nav_headers(), &uri).await;
    assert_eq!(r.status, StatusCode::FOUND);
    let loc = r
        .headers
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
    let has_login_cookie = r.headers.iter().any(|(n, v)| {
        *n == http::header::SET_COOKIE && v.to_str().unwrap().contains("huskarl_login_")
    });
    assert!(has_login_cookie);
}

#[tokio::test]
async fn redirect_to_login_api_returns_401() {
    let e = engine(MockSessionStore::empty()).await;
    let uri = "/api/data".parse().unwrap();
    let r = e.redirect_to_login(&api_headers(), &uri).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn load_session_empty_store_returns_none() {
    let e = engine(MockSessionStore::empty()).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(loaded.session.is_none());
    assert!(loaded.clear_cookies.is_empty());
}

#[tokio::test]
async fn load_session_valid_returns_skip_when_recently_active() {
    // last_active is "now" — well within the default 1h touch_min_interval.
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (_session, persistence) = loaded.session.expect("session present");
    assert!(matches!(persistence, SessionPersistence::Skip));
    assert!(loaded.clear_cookies.is_empty());
}

#[tokio::test]
async fn load_session_valid_returns_touch_when_interval_elapsed() {
    // last_active is 2h ago — past the default 1h touch_min_interval.
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() - Duration::from_hours(2),
        SystemTime::now() - Duration::from_hours(2),
    );
    let e = engine(MockSessionStore::with_session(session)).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (_session, persistence) = loaded.session.expect("session present");
    assert!(matches!(persistence, SessionPersistence::Touch));
    assert!(loaded.clear_cookies.is_empty());
}

#[tokio::test]
async fn touch_min_interval_skips_recent_activity() {
    // last_active is "now" — well within a 60s touch_min_interval.
    let config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .touch_min_interval(Duration::from_mins(1))
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::with_session(valid_session()), config).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (_, persistence) = loaded.session.expect("session present");
    assert!(matches!(persistence, SessionPersistence::Skip));
}

#[tokio::test]
async fn touch_min_interval_touches_after_interval_elapsed() {
    // last_active is 120s ago — exceeds a 60s touch_min_interval.
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() - Duration::from_mins(2),
        SystemTime::now() - Duration::from_mins(2),
    );
    let config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .touch_min_interval(Duration::from_mins(1))
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::with_session(session), config).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (_, persistence) = loaded.session.expect("session present");
    assert!(matches!(persistence, SessionPersistence::Touch));
}

#[tokio::test]
async fn persist_skip_calls_neither_save_nor_touch() {
    let config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .touch_min_interval(Duration::from_mins(1))
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::with_session(valid_session()), config).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (session, persistence) = loaded.session.expect("session present");
    assert!(matches!(persistence, SessionPersistence::Skip));
    let headers = e
        .persist_session(&session, persistence, &api_headers())
        .await
        .unwrap();
    assert!(headers.is_empty());
    assert!(!e.session_store().save_called());
    assert!(!e.session_store().touch_called());
}

#[tokio::test]
async fn login_state_cookie_uses_configured_ttl() {
    let config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .login_state_ttl(Duration::from_mins(30))
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::empty(), config).await;
    let uri = "/protected".parse().unwrap();
    let r = e.redirect_to_login(&nav_headers(), &uri).await;
    let cookie = r
        .headers
        .iter()
        .find(|(n, v)| {
            *n == http::header::SET_COOKIE && v.to_str().unwrap().contains("huskarl_login_")
        })
        .expect("login-state cookie");
    assert!(cookie.1.to_str().unwrap().contains("Max-Age=1800"));
}

#[tokio::test]
async fn max_lifetime_expired_clears_session() {
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() - Duration::from_secs(7201),
        SystemTime::now(),
    );
    let config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .max_lifetime(Duration::from_hours(1))
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::with_session(session), config).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(loaded.session.is_none());
    assert!(e.session_store().delete_called());
}

#[tokio::test]
async fn idle_timeout_expired_clears_session() {
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now(),
        SystemTime::now() - Duration::from_secs(1801),
    );
    let config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .idle_timeout(Duration::from_mins(15))
        .build()
        .unwrap();
    let store = MockSessionStore::with_session(session);
    let e = engine_with_config(store, config).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(loaded.session.is_none());
    assert!(e.session_store().delete_called());
}

#[tokio::test]
async fn token_expired_no_refresh_token_clears_session() {
    let session = session_with(
        SystemTime::now() - Duration::from_mins(1),
        None,
        SystemTime::now(),
        SystemTime::now(),
    );
    let store = MockSessionStore::with_session(session);
    let e = engine(store).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(loaded.session.is_none());
    assert!(e.session_store().delete_called());
}

#[tokio::test]
async fn token_expired_refresh_fails_clears_session() {
    use huskarl::core::secrets::SecretString;
    let session = session_with(
        SystemTime::now() - Duration::from_mins(1),
        Some(RefreshToken::new(SecretString::new("test_refresh"), None)),
        SystemTime::now(),
        SystemTime::now(),
    );
    let store = MockSessionStore::with_session(session);
    let e = engine(store).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(loaded.session.is_none());
    assert!(e.session_store().delete_called());
}

// ── Refresh retry ─────────────────────────────────────────────────────────

/// A session whose access token expires at `token_expiry` and that holds a
/// refresh token — i.e. one that enters the refresh path on load whenever
/// `token_expiry` is within the refresh margin.
fn refreshable_session(token_expiry: SystemTime) -> MockSession {
    use huskarl::core::secrets::SecretString;
    session_with(
        token_expiry,
        Some(RefreshToken::new(SecretString::new("test_refresh"), None)),
        SystemTime::now(),
        SystemTime::now(),
    )
}

/// Engine whose grant fails every token request with the given retryability,
/// returning the HTTP call counter alongside.
async fn engine_with_failing_refresh(
    retryable: bool,
    session: MockSession,
) -> (LoginEngine<MockSessionStore>, Arc<AtomicU32>) {
    let (http, calls) = FailingHttp::new(retryable);
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(http).await)
        .session_store(MockSessionStore::with_session(session))
        .cipher(test_cipher().await)
        .build();
    (e, calls)
}

#[tokio::test]
async fn refresh_retries_when_error_is_retryable() {
    // Token expired a minute ago — the refresh outcome is decisive.
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let (e, calls) = engine_with_failing_refresh(true, session).await;
    let _ = e.load_session(&HeaderMap::new()).await;
    // Initial call + REFRESH_MAX_ATTEMPTS - 1 retries == REFRESH_MAX_ATTEMPTS total.
    assert_eq!(calls.load(Ordering::SeqCst), super::REFRESH_MAX_ATTEMPTS);
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
async fn refresh_success_returns_save_persistence() {
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::with_session(session))
        .cipher(test_cipher().await)
        .build();
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (session, persistence) = loaded.session.expect("session refreshed");
    assert_eq!(persistence, SessionPersistence::Save);
    // The refresh response carried expires_in=3600 — expiry moved well past now.
    assert!(session.token_expiry() > SystemTime::now() + Duration::from_mins(30));
    assert!(loaded.clear_cookies.is_empty());
}

// ── Transient refresh failure inside the early-refresh window ─────────────

#[tokio::test]
async fn transient_refresh_failure_with_valid_token_retains_session() {
    // Token expires 15s from now — inside the 30s refresh margin but still
    // valid. A transient refresh failure must not log the user out.
    let session = refreshable_session(SystemTime::now() + Duration::from_secs(15));
    let (e, calls) = engine_with_failing_refresh(true, session).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (_, persistence) = loaded.session.expect("session retained");
    // last_active is fresh, so the throttled activity update skips.
    assert_eq!(persistence, SessionPersistence::Skip);
    assert!(loaded.clear_cookies.is_empty());
    assert!(!e.session_store().delete_called());
    // The full retry budget was spent before falling back to retention.
    assert_eq!(calls.load(Ordering::SeqCst), super::REFRESH_MAX_ATTEMPTS);
}

#[tokio::test]
async fn non_retryable_refresh_failure_clears_session_even_with_valid_token() {
    // The AS conclusively rejected the refresh token (e.g. invalid_grant —
    // possibly reuse-detection revocation). Retention would serve a session
    // the AS just disowned; tear it down even though the token has 15s left.
    let session = refreshable_session(SystemTime::now() + Duration::from_secs(15));
    let (e, _) = engine_with_failing_refresh(false, session).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(loaded.session.is_none());
    assert!(e.session_store().delete_called());
}

#[tokio::test]
async fn transient_refresh_failure_with_expired_token_clears_session() {
    // Past actual expiry there is no valid token to keep serving — transient
    // or not, the session is torn down.
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let (e, _) = engine_with_failing_refresh(true, session).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(loaded.session.is_none());
    assert!(e.session_store().delete_called());
}

#[tokio::test]
async fn load_session_store_error_bubbles_up() {
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(ErrorSessionStore)
        .cipher(test_cipher().await)
        .build();
    let err = e.load_session(&HeaderMap::new()).await;
    assert!(err.is_err());
}

// ── persist_session ───────────────────────────────────────────────────────

#[tokio::test]
async fn persist_save_calls_store_save() {
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (session, _) = loaded.session.expect("session present");
    e.persist_session(&session, SessionPersistence::Save, &api_headers())
        .await
        .unwrap();
    assert!(e.session_store().save_called());
    assert!(!e.session_store().touch_called());
}

#[tokio::test]
async fn persist_touch_calls_store_touch() {
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (session, _) = loaded.session.expect("session present");
    e.persist_session(&session, SessionPersistence::Touch, &api_headers())
        .await
        .unwrap();
    assert!(e.session_store().touch_called());
    assert!(!e.session_store().save_called());
}

// ── Callback handler ──────────────────────────────────────────────────────

async fn callback_status(path_and_query: &str, request_headers: &HeaderMap) -> StatusCode {
    let e = engine(MockSessionStore::empty()).await;
    let uri = path_and_query.parse().unwrap();
    e.try_handle_login_route("/callback", &Method::GET, request_headers, &uri)
        .await
        .expect("callback handled")
        .status
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
        .cipher(test_cipher().await)
        .build();
    let state = "valid_state";
    let sealed = seal_login_cookie(state, "https://app.example.com/page").await;
    let h = headers_with_login_cookie(state, &sealed);
    let uri = format!("/callback?code=authcode&state={state}")
        .parse()
        .unwrap();
    let r = e
        .try_handle_login_route("/callback", &Method::GET, &h, &uri)
        .await
        .expect("callback handled");
    assert_eq!(r.status, StatusCode::FOUND);
    let loc = r
        .headers
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap());
    assert_eq!(loc, Some("https://app.example.com/page"));
    // The login-state cookie is cleared on the way out.
    let login_cookie_cleared = r.headers.iter().any(|(n, v)| {
        *n == http::header::SET_COOKIE
            && v.to_str().unwrap().contains("huskarl_login_")
            && v.to_str().unwrap().contains("Max-Age=0")
    });
    assert!(login_cookie_cleared, "login-state cookie must be cleared");
}

// ── Logout handler ────────────────────────────────────────────────────────

#[tokio::test]
async fn logout_without_session_redirects_to_base_url() {
    let e = engine_with_config(MockSessionStore::empty(), config_with_logout()).await;
    let uri = "/logout".parse().unwrap();
    let r = e
        .try_handle_login_route("/logout", &Method::GET, &HeaderMap::new(), &uri)
        .await
        .expect("logout handled");
    assert_eq!(r.status, StatusCode::FOUND);
    let loc = r
        .headers
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap());
    assert_eq!(loc, Some("https://app.example.com/"));
}

#[tokio::test]
async fn logout_with_session_deletes_session() {
    let e = engine_with_config(
        MockSessionStore::with_session(valid_session()),
        config_with_logout(),
    )
    .await;
    let uri = "/logout".parse().unwrap();
    let _ = e
        .try_handle_login_route("/logout", &Method::GET, &HeaderMap::new(), &uri)
        .await;
    assert!(e.session_store().delete_called());
}

#[tokio::test]
async fn logout_redirects_to_configured_post_logout_uri() {
    let config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .base_url("https://app.example.com".parse().unwrap())
        .logout_path("/logout".to_owned())
        .post_logout_redirect_uri("https://app.example.com/signed-out".to_owned())
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::empty(), config).await;
    let uri = "/logout".parse().unwrap();
    let r = e
        .try_handle_login_route("/logout", &Method::GET, &HeaderMap::new(), &uri)
        .await
        .expect("logout handled");
    let loc = r
        .headers
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap());
    assert_eq!(loc, Some("https://app.example.com/signed-out"));
}

#[tokio::test]
async fn logout_rejects_cross_site_request_without_deleting_session() {
    // A forged cross-site navigation (e.g. a link on an attacker's page) must
    // not log the user out: 403, no redirect, session left intact.
    let e = engine_with_config(
        MockSessionStore::with_session(valid_session()),
        config_with_logout(),
    )
    .await;
    let uri = "/logout".parse().unwrap();
    let h = headers(&[("sec-fetch-site", "cross-site")]);
    let r = e
        .try_handle_login_route("/logout", &Method::GET, &h, &uri)
        .await
        .expect("logout handled");
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert!(
        !r.headers.iter().any(|(n, _)| *n == http::header::LOCATION),
        "cross-site logout must not redirect"
    );
    assert!(!e.session_store().delete_called());
}

#[tokio::test]
async fn logout_allows_same_origin_request() {
    let e = engine_with_config(
        MockSessionStore::with_session(valid_session()),
        config_with_logout(),
    )
    .await;
    let uri = "/logout".parse().unwrap();
    let h = headers(&[("sec-fetch-site", "same-origin")]);
    let r = e
        .try_handle_login_route("/logout", &Method::GET, &h, &uri)
        .await
        .expect("logout handled");
    assert_eq!(r.status, StatusCode::FOUND);
    assert!(e.session_store().delete_called());
}

// ── Clock-skew handling ───────────────────────────────────────────────────

#[tokio::test]
async fn small_future_skew_is_tolerated() {
    // last_active 10s in the future — within MAX_CLOCK_SKEW.
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now(),
        SystemTime::now() + Duration::from_secs(10),
    );
    let e = engine(MockSessionStore::with_session(session)).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(loaded.session.is_some());
    assert!(!e.session_store().delete_called());
}

#[tokio::test]
async fn future_created_at_clears_session() {
    // created_at 1 hour in the future — well past MAX_CLOCK_SKEW.
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() + Duration::from_hours(1),
        SystemTime::now(),
    );
    let store = MockSessionStore::with_session(session);
    let e = engine(store).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(loaded.session.is_none());
    assert!(e.session_store().delete_called());
}

#[tokio::test]
async fn future_last_active_clears_session() {
    // last_active 1 hour in the future — well past MAX_CLOCK_SKEW.
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now(),
        SystemTime::now() + Duration::from_hours(1),
    );
    let store = MockSessionStore::with_session(session);
    let e = engine(store).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(loaded.session.is_none());
    assert!(e.session_store().delete_called());
}

// ── Metrics test infrastructure ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum MetricCall {
    LoginStart {
        result: &'static str,
    },
    LoginComplete {
        result: &'static str,
        as_error: Option<String>,
    },
    Refresh {
        result: &'static str,
    },
    Activity {
        outcome: &'static str,
    },
}

#[derive(Default)]
struct TestEngineMetrics {
    calls: Mutex<Vec<MetricCall>>,
}

impl TestEngineMetrics {
    fn calls(&self) -> Vec<MetricCall> {
        self.calls.lock().unwrap().clone()
    }
}

impl LoginEngineMetrics for TestEngineMetrics {
    fn record_login_start(&self, r: &LoginStartResult) {
        self.calls
            .lock()
            .unwrap()
            .push(MetricCall::LoginStart { result: r.as_str() });
    }
    fn record_login_complete(&self, r: &LoginCompleteResult, as_error: Option<&str>) {
        self.calls.lock().unwrap().push(MetricCall::LoginComplete {
            result: r.as_str(),
            as_error: as_error.map(str::to_owned),
        });
    }
    fn record_refresh(&self, r: &RefreshResult) {
        self.calls
            .lock()
            .unwrap()
            .push(MetricCall::Refresh { result: r.as_str() });
    }
    fn record_activity(&self, o: &ActivityOutcome) {
        self.calls.lock().unwrap().push(MetricCall::Activity {
            outcome: o.as_str(),
        });
    }
}

async fn engine_with_metrics(
    store: MockSessionStore,
) -> (LoginEngine<MockSessionStore>, Arc<TestEngineMetrics>) {
    let m = Arc::new(TestEngineMetrics::default());
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(store)
        .cipher(test_cipher().await)
        .metrics(Arc::clone(&m) as Arc<dyn LoginEngineMetrics>)
        .build();
    (e, m)
}

// ── Login start metrics ───────────────────────────────────────────────────

#[tokio::test]
async fn metrics_login_start_ok_on_nav_redirect() {
    let (e, m) = engine_with_metrics(MockSessionStore::empty()).await;
    e.redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
        .await;
    assert_eq!(m.calls(), vec![MetricCall::LoginStart { result: "ok" }]);
}

#[tokio::test]
async fn metrics_no_login_start_on_api_401() {
    // XHR/API 401s don't redirect to the AS — no login start is recorded.
    let (e, m) = engine_with_metrics(MockSessionStore::empty()).await;
    e.redirect_to_login(&api_headers(), &"/api".parse().unwrap())
        .await;
    assert!(m.calls().is_empty());
}

#[tokio::test]
async fn metrics_login_start_error_when_grant_start_fails() {
    // PAR-required grant + failing HTTP double: start() must perform HTTP and
    // therefore fails.
    let m = Arc::new(TestEngineMetrics::default());
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(par_failing_grant().await)
        .session_store(MockSessionStore::empty())
        .cipher(test_cipher().await)
        .metrics(Arc::clone(&m) as Arc<dyn LoginEngineMetrics>)
        .build();
    e.redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
        .await;
    assert_eq!(m.calls(), vec![MetricCall::LoginStart { result: "error" }]);
}

// ── Login complete metrics ────────────────────────────────────────────────

#[tokio::test]
async fn metrics_callback_invalid_request_on_missing_params() {
    let (e, m) = engine_with_metrics(MockSessionStore::empty()).await;
    let uri = "/callback".parse().unwrap();
    e.try_handle_login_route("/callback", &Method::GET, &HeaderMap::new(), &uri)
        .await;
    assert_eq!(
        m.calls(),
        vec![MetricCall::LoginComplete {
            result: "invalid_request",
            as_error: None
        }]
    );
}

#[tokio::test]
async fn metrics_callback_as_denied_carries_error_code() {
    let (e, m) = engine_with_metrics(MockSessionStore::empty()).await;
    let uri = "/callback?error=access_denied".parse().unwrap();
    e.try_handle_login_route("/callback", &Method::GET, &HeaderMap::new(), &uri)
        .await;
    assert_eq!(
        m.calls(),
        vec![MetricCall::LoginComplete {
            result: "as_denied",
            as_error: Some("access_denied".to_owned()),
        }]
    );
}

#[tokio::test]
async fn metrics_callback_as_denied_normalizes_unknown_error_code() {
    // The `error` parameter is attacker-suppliable; anything outside the
    // registered RFC 6749 / OIDC codes must reach the metrics sink as
    // "other" so it can't blow up label cardinality.
    let (e, m) = engine_with_metrics(MockSessionStore::empty()).await;
    let uri = "/callback?error=attacker_chosen_garbage_12345"
        .parse()
        .unwrap();
    e.try_handle_login_route("/callback", &Method::GET, &HeaderMap::new(), &uri)
        .await;
    assert_eq!(
        m.calls(),
        vec![MetricCall::LoginComplete {
            result: "as_denied",
            as_error: Some("other".to_owned()),
        }]
    );
}

#[tokio::test]
async fn metrics_callback_invalid_request_on_missing_state_cookie() {
    let (e, m) = engine_with_metrics(MockSessionStore::empty()).await;
    let uri = "/callback?code=authcode&state=mystate".parse().unwrap();
    e.try_handle_login_route("/callback", &Method::GET, &HeaderMap::new(), &uri)
        .await;
    assert_eq!(
        m.calls(),
        vec![MetricCall::LoginComplete {
            result: "invalid_request",
            as_error: None
        }]
    );
}

#[tokio::test]
async fn metrics_callback_state_invalid_on_tampered_bundle() {
    let (e, m) = engine_with_metrics(MockSessionStore::empty()).await;
    let state = "teststate";
    let fake = URL_SAFE_NO_PAD.encode(b"not an AEAD bundle");
    let h = headers_with_login_cookie(state, &fake);
    let uri = format!("/callback?code=authcode&state={state}")
        .parse()
        .unwrap();
    e.try_handle_login_route("/callback", &Method::GET, &h, &uri)
        .await;
    assert_eq!(
        m.calls(),
        vec![MetricCall::LoginComplete {
            result: "state_invalid",
            as_error: None
        }]
    );
}

#[tokio::test]
async fn metrics_callback_ok_on_successful_login() {
    let m = Arc::new(TestEngineMetrics::default());
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::empty())
        .cipher(test_cipher().await)
        .metrics(Arc::clone(&m) as Arc<dyn LoginEngineMetrics>)
        .build();
    let state = "valid_state";
    let sealed = seal_login_cookie(state, "https://app.example.com/").await;
    let h = headers_with_login_cookie(state, &sealed);
    let uri = format!("/callback?code=authcode&state={state}")
        .parse()
        .unwrap();
    e.try_handle_login_route("/callback", &Method::GET, &h, &uri)
        .await;
    assert_eq!(
        m.calls(),
        vec![MetricCall::LoginComplete {
            result: "ok",
            as_error: None
        }]
    );
}

#[tokio::test]
async fn metrics_callback_token_exchange_failed_when_grant_complete_fails() {
    // The default engine's HTTP double fails every token request — verify
    // token_exchange_failed is recorded.
    let (e, m) = engine_with_metrics(MockSessionStore::empty()).await;
    let state = "valid_state";
    let sealed = seal_login_cookie(state, "https://app.example.com/").await;
    let h = headers_with_login_cookie(state, &sealed);
    let uri = format!("/callback?code=authcode&state={state}")
        .parse()
        .unwrap();
    e.try_handle_login_route("/callback", &Method::GET, &h, &uri)
        .await;
    assert_eq!(
        m.calls(),
        vec![MetricCall::LoginComplete {
            result: "token_exchange_failed",
            as_error: None
        }]
    );
}

// ── Refresh metrics ───────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_refresh_no_refresh_token_when_none_available() {
    let session = session_with(
        SystemTime::now() - Duration::from_mins(1),
        None,
        SystemTime::now(),
        SystemTime::now(),
    );
    let (e, m) = engine_with_metrics(MockSessionStore::with_session(session)).await;
    e.load_session(&HeaderMap::new()).await.unwrap();
    assert_eq!(
        m.calls(),
        vec![MetricCall::Refresh {
            result: "no_refresh_token"
        }]
    );
}

#[tokio::test]
async fn metrics_refresh_failed_when_grant_refresh_fails() {
    use huskarl::core::secrets::SecretString;
    let session = session_with(
        SystemTime::now() - Duration::from_mins(1),
        Some(RefreshToken::new(SecretString::new("test_refresh"), None)),
        SystemTime::now(),
        SystemTime::now(),
    );
    let (e, m) = engine_with_metrics(MockSessionStore::with_session(session)).await;
    e.load_session(&HeaderMap::new()).await.unwrap();
    assert_eq!(m.calls(), vec![MetricCall::Refresh { result: "failed" }]);
}

#[tokio::test]
async fn metrics_refresh_failed_retained_on_transient_failure_with_valid_token() {
    let m = Arc::new(TestEngineMetrics::default());
    let session = refreshable_session(SystemTime::now() + Duration::from_secs(15));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(FailingHttp::new(true).0).await)
        .session_store(MockSessionStore::with_session(session))
        .cipher(test_cipher().await)
        .metrics(Arc::clone(&m) as Arc<dyn LoginEngineMetrics>)
        .build();
    e.load_session(&HeaderMap::new()).await.unwrap();
    // The retained session goes through the normal activity path, so a
    // (throttled) activity outcome follows the refresh outcome.
    assert_eq!(
        m.calls(),
        vec![
            MetricCall::Refresh {
                result: "failed_retained"
            },
            MetricCall::Activity { outcome: "skip" },
        ]
    );
}

#[tokio::test]
async fn metrics_refresh_ok_on_successful_refresh() {
    let m = Arc::new(TestEngineMetrics::default());
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::with_session(session))
        .cipher(test_cipher().await)
        .metrics(Arc::clone(&m) as Arc<dyn LoginEngineMetrics>)
        .build();
    e.load_session(&HeaderMap::new()).await.unwrap();
    assert_eq!(m.calls(), vec![MetricCall::Refresh { result: "ok" }]);
}

// ── Activity metrics ──────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_activity_skip_when_recently_active() {
    let (e, m) = engine_with_metrics(MockSessionStore::with_session(valid_session())).await;
    e.load_session(&HeaderMap::new()).await.unwrap();
    assert_eq!(m.calls(), vec![MetricCall::Activity { outcome: "skip" }]);
}

#[tokio::test]
async fn metrics_activity_touch_when_interval_elapsed() {
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() - Duration::from_hours(2),
        SystemTime::now() - Duration::from_hours(2),
    );
    let (e, m) = engine_with_metrics(MockSessionStore::with_session(session)).await;
    e.load_session(&HeaderMap::new()).await.unwrap();
    assert_eq!(m.calls(), vec![MetricCall::Activity { outcome: "touch" }]);
}
