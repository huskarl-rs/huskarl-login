use std::{
    convert::Infallible,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use huskarl::{
    core::{
        BoxedError,
        crypto::cipher::{AeadSealer, AeadV1Sealer, BoxedAeadCipher},
        http::{HttpClient, HttpResponse},
        secrets::{Secret, SecretBytes, SecretOutput},
    },
    grant::{
        authorization_code::{PendingState, StartOutput},
        core::TokenResponse,
    },
    token::RefreshToken,
};
use huskarl_crypto_native::aead::{AesGcmKey, AesGcmKeyType};

use super::{
    LoginEngine, SessionPersistence, error_chain, is_cors_preflight, is_navigation_request,
};
use crate::{
    LoginConfig, LoginGrant, Session, SessionDriver, SessionError, grant::CompletedLogin,
    session::sealed::Sealed,
};

// ── TestSecret / cipher ───────────────────────────────────────────────────

#[derive(Clone)]
struct TestSecret(SecretBytes);

impl Secret for TestSecret {
    type Output = SecretBytes;
    type Error = Infallible;
    async fn get_secret_value(&self) -> Result<SecretOutput<SecretBytes>, Infallible> {
        Ok(SecretOutput {
            value: self.0.clone(),
            identity: None,
        })
    }
}

async fn test_cipher() -> BoxedAeadCipher {
    let key = AesGcmKey::from_secret(
        AesGcmKeyType::Aes256,
        TestSecret(SecretBytes::new(vec![0u8; 32])),
        |_| None,
    )
    .await
    .unwrap();
    BoxedAeadCipher::new(key)
}

// ── MockHttpClient ────────────────────────────────────────────────────────

struct MockHttpResponse;

impl HttpResponse for MockHttpResponse {
    type Error = Infallible;
    fn status(&self) -> StatusCode {
        unimplemented!()
    }
    fn headers(&self) -> HeaderMap {
        unimplemented!()
    }
    async fn body(self) -> Result<Bytes, Infallible> {
        unimplemented!()
    }
}

struct MockHttpClient;

impl HttpClient for MockHttpClient {
    type Response = MockHttpResponse;
    type Error = Infallible;
    type ResponseError = Infallible;
    async fn execute(&self, _: http::Request<Bytes>) -> Result<MockHttpResponse, Infallible> {
        unimplemented!()
    }
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
        _: CompletedLogin,
        _: Duration,
        _: &HeaderMap,
    ) -> Result<(MockSession, Vec<HeaderValue>), SessionError> {
        unimplemented!()
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

// ── MockGrant ─────────────────────────────────────────────────────────────

struct MockGrant {
    authorization_url: &'static str,
}

impl LoginGrant for MockGrant {
    async fn start(&self, _: &impl HttpClient, _: Vec<String>) -> Result<StartOutput, BoxedError> {
        Ok(StartOutput {
            authorization_url: self.authorization_url.parse().unwrap(),
            expires_in: None,
            pending_state: PendingState {
                redirect_uri: "https://app.example.com/callback".to_owned(),
                pkce_verifier: None,
                state: "mock_state".to_owned(),
                nonce: "mock_nonce".to_owned(),
                dpop_jkt: None,
            },
        })
    }

    async fn complete(
        &self,
        _: &impl HttpClient,
        _: &PendingState,
        _: String,
        _: String,
        _: Option<String>,
    ) -> Result<CompletedLogin, BoxedError> {
        Err(BoxedError::from_err("\0".parse::<http::Uri>().unwrap_err()))
    }

    // Note: constructing a successful TokenResponse requires huskarl's
    // pub(crate) RawTokenResponse::into_token_response, so only the failure
    // path is testable here. The success path (Continue { Save }) is covered
    // indirectly by the persist_session test with Save persistence.
    async fn refresh(
        &self,
        _: &impl HttpClient,
        _: &RefreshToken,
    ) -> Result<TokenResponse, BoxedError> {
        Err(BoxedError::from_err("\0".parse::<http::Uri>().unwrap_err()))
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

async fn engine(
    store: MockSessionStore,
) -> LoginEngine<MockGrant, MockSessionStore, MockHttpClient> {
    engine_with_config(store, default_config()).await
}

async fn engine_with_config(
    store: MockSessionStore,
    config: LoginConfig,
) -> LoginEngine<MockGrant, MockSessionStore, MockHttpClient> {
    LoginEngine::builder()
        .config(config)
        .grant(MockGrant {
            authorization_url: "https://auth.example.com/authorize",
        })
        .session_store(store)
        .cipher(test_cipher().await)
        .http_client(MockHttpClient)
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
    let cipher = test_cipher().await;
    let sealer = AeadV1Sealer::new(cipher);
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
    let name = crate::cookie::login_state_cookie_name(state, true, "/callback");
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
        .map(|(_, v)| v.to_str().unwrap());
    assert_eq!(loc, Some("https://auth.example.com/authorize"));
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
async fn load_session_valid_returns_session_with_touch() {
    let e = engine(MockSessionStore::with_session(valid_session())).await;
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

#[derive(Debug)]
struct FlakyError {
    retryable: bool,
}

impl std::fmt::Display for FlakyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("flaky transport error")
    }
}

impl std::error::Error for FlakyError {}

impl huskarl::core::Error for FlakyError {
    fn is_retryable(&self) -> bool {
        self.retryable
    }
}

struct RetryGrant {
    refresh_calls: std::sync::atomic::AtomicU32,
    /// Number of leading attempts that should fail. The next attempt succeeds
    /// if a `token_response` is available, otherwise it keeps failing.
    fail_first_n: u32,
    retryable: bool,
}

impl RetryGrant {
    fn refresh_count(&self) -> u32 {
        self.refresh_calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl LoginGrant for RetryGrant {
    async fn start(&self, _: &impl HttpClient, _: Vec<String>) -> Result<StartOutput, BoxedError> {
        unimplemented!()
    }

    async fn complete(
        &self,
        _: &impl HttpClient,
        _: &PendingState,
        _: String,
        _: String,
        _: Option<String>,
    ) -> Result<CompletedLogin, BoxedError> {
        unimplemented!()
    }

    async fn refresh(
        &self,
        _: &impl HttpClient,
        _: &RefreshToken,
    ) -> Result<TokenResponse, BoxedError> {
        let attempt = self
            .refresh_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        if attempt <= self.fail_first_n {
            return Err(BoxedError::from_err(FlakyError {
                retryable: self.retryable,
            }));
        }
        // We never actually succeed in these tests — constructing a successful
        // TokenResponse requires huskarl-internal APIs. We assert call counts,
        // not the post-refresh Continue path.
        Err(BoxedError::from_err(FlakyError {
            retryable: self.retryable,
        }))
    }
}

async fn engine_with_retry_grant(
    grant: RetryGrant,
) -> LoginEngine<RetryGrant, MockSessionStore, MockHttpClient> {
    use huskarl::core::secrets::SecretString;
    let session = session_with(
        SystemTime::now() - Duration::from_mins(1),
        Some(RefreshToken::new(SecretString::new("test_refresh"), None)),
        SystemTime::now(),
        SystemTime::now(),
    );
    LoginEngine::builder()
        .config(default_config())
        .grant(grant)
        .session_store(MockSessionStore::with_session(session))
        .cipher(test_cipher().await)
        .http_client(MockHttpClient)
        .build()
}

#[tokio::test]
async fn refresh_retries_when_error_is_retryable() {
    let grant = RetryGrant {
        refresh_calls: std::sync::atomic::AtomicU32::new(0),
        fail_first_n: u32::MAX,
        retryable: true,
    };
    let e = engine_with_retry_grant(grant).await;
    let _ = e.load_session(&HeaderMap::new()).await;
    // Initial call + REFRESH_MAX_ATTEMPTS - 1 retries == REFRESH_MAX_ATTEMPTS total.
    assert_eq!(e.grant.refresh_count(), super::REFRESH_MAX_ATTEMPTS);
}

#[tokio::test]
async fn refresh_does_not_retry_when_error_is_non_retryable() {
    let grant = RetryGrant {
        refresh_calls: std::sync::atomic::AtomicU32::new(0),
        fail_first_n: u32::MAX,
        retryable: false,
    };
    let e = engine_with_retry_grant(grant).await;
    let _ = e.load_session(&HeaderMap::new()).await;
    // Non-retryable AS rejection (e.g. invalid_grant) must short-circuit at
    // the first attempt — retrying would just amplify load.
    assert_eq!(e.grant.refresh_count(), 1);
}

#[tokio::test]
async fn load_session_store_error_bubbles_up() {
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(MockGrant {
            authorization_url: "https://auth.example.com/authorize",
        })
        .session_store(ErrorSessionStore)
        .cipher(test_cipher().await)
        .http_client(MockHttpClient)
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
