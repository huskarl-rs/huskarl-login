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
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use huskarl::{
    core::{
        Error, ErrorKind,
        client_auth::NoAuth,
        crypto::{
            KeyMatchStrength,
            cipher::{
                AeadCipher, AeadDecryptor, AeadEncryptor, AeadOutput, AeadSealer as _,
                AeadV1Cipher, CipherMatch, DecryptError,
            },
        },
        http::{HttpClient, HttpResponse, Idempotency},
        platform::MaybeSendBoxFuture,
    },
    grant::authorization_code::{AuthorizationCodeGrant, PendingState},
    token::RefreshToken,
};
use rstest::rstest;
use snafu::Snafu;

use super::{
    LoadedSession, LoginEngine, TeardownReason, error_chain, is_cors_preflight,
    is_cross_site_request, is_navigation_request,
};
use crate::{
    ActivityPolicy, CompletedLogin, LivenessVerdict, LoginConfig, LogoutConfig, Session,
    SessionDriver, SessionError, SessionErrorKind, SessionLifetime, SessionState,
    metrics::{LoginCompleteResult, LoginEngineMetrics, LoginStartResult, RefreshResult},
    session::sealed::Sealed,
    test_support::{header_map as headers, test_cipher},
};

// ── HTTP doubles ──────────────────────────────────────────────────────────

#[derive(Debug, Snafu)]
#[snafu(display("flaky transport error"))]
struct FlakyError;

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
        .token_endpoint("https://auth.example.com/token".parse().unwrap())
        .authorization_endpoint("https://auth.example.com/authorize".parse().unwrap())
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
        .token_endpoint("https://auth.example.com/token".parse().unwrap())
        .authorization_endpoint("https://auth.example.com/authorize".parse().unwrap())
        .pushed_authorization_request_endpoint("https://auth.example.com/par".parse().unwrap())
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
) -> MockSession {
    MockSession {
        state: crate::SessionState::builder()
            .token_expiry(token_expiry)
            .maybe_refresh_token(refresh_token)
            .created_at(created_at)
            .build(),
    }
}

fn valid_session() -> MockSession {
    session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now(),
    )
}

// ── LoadedSession assertion helpers ───────────────────────────────────────

/// A short tag for failure messages in the `expect_*` helpers below.
fn variant_name(loaded: &LoadedSession<MockSession>) -> &'static str {
    match loaded {
        LoadedSession::Missing => "Missing",
        LoadedSession::RefreshUnavailable => "RefreshUnavailable",
        LoadedSession::Cleared { .. } => "Cleared",
        LoadedSession::Active { .. } => "Active",
        LoadedSession::ActivePending { .. } => "ActivePending",
    }
}

/// Unwraps [`LoadedSession::Active`] into the session and its cookies.
fn expect_active(loaded: LoadedSession<MockSession>) -> (MockSession, Vec<HeaderValue>) {
    match loaded {
        LoadedSession::Active {
            session,
            set_cookies,
        } => (session, set_cookies),
        other => unreachable!("expected Active, got {}", variant_name(&other)),
    }
}

/// Unwraps [`LoadedSession::ActivePending`] into the session and the refresh
/// response owed to [`LoginEngine::persist_session`].
fn expect_pending(
    loaded: LoadedSession<MockSession>,
) -> (MockSession, Box<huskarl::grant::core::TokenResponse>) {
    match loaded {
        LoadedSession::ActivePending {
            session,
            token_response,
        } => (session, token_response),
        other => unreachable!("expected ActivePending, got {}", variant_name(&other)),
    }
}

/// Unwraps [`LoadedSession::Cleared`] into the teardown reason and clears.
fn expect_cleared(loaded: LoadedSession<MockSession>) -> (TeardownReason, Vec<HeaderValue>) {
    match loaded {
        LoadedSession::Cleared { reason, clears } => (reason, clears),
        other => unreachable!("expected Cleared, got {}", variant_name(&other)),
    }
}

// ── MockSessionStore ──────────────────────────────────────────────────────

/// A do-nothing AEAD cipher so [`MockSessionStore`] can satisfy
/// [`SessionDriver::session_aead_cipher`] without async key construction in its
/// sync constructors. The engine under test is always built with an explicit
/// `.cipher(...)`, so this is never actually invoked to seal or unseal.
#[derive(Debug)]
struct NoopCipher;

impl AeadEncryptor for NoopCipher {
    fn enc_algorithm(&self) -> std::borrow::Cow<'_, str> {
        std::borrow::Cow::Borrowed("noop")
    }
    fn key_id(&self) -> Option<std::borrow::Cow<'_, str>> {
        None
    }
    fn encrypt<'a>(
        &'a self,
        _plaintext: &'a [u8],
        _aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<AeadOutput, Error>> {
        Box::pin(async {
            Ok(AeadOutput {
                nonce: Vec::new(),
                ciphertext: Vec::new(),
                tag: Vec::new(),
            })
        })
    }
}

impl AeadDecryptor for NoopCipher {
    fn cipher_match(&self, _m: &CipherMatch<'_>) -> Option<KeyMatchStrength> {
        None
    }
    fn decrypt<'a>(
        &'a self,
        _cipher_match: Option<&'a CipherMatch<'a>>,
        _nonce: &'a [u8],
        _ciphertext: &'a [u8],
        _tag: &'a [u8],
        _aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

struct MockSessionStore {
    session: Mutex<Option<MockSession>>,
    save_called: Mutex<bool>,
    delete_called: Mutex<bool>,
    fail_save: bool,
    /// Liveness verdict returned by [`SessionDriver::check_liveness`], so a
    /// test can drive the engine's verdict-mapping without re-implementing the
    /// idle/throttle logic (which is tested elsewhere).
    verdict: LivenessVerdict,
    /// Records the `record_activity` flag the engine passes to
    /// [`SessionDriver::check_liveness`], so a test can assert the
    /// [`ActivityPolicy`](crate::ActivityPolicy) classification reaches the
    /// store.
    last_record_activity: Mutex<Option<bool>>,
    /// Records the values the engine stamps via
    /// [`SessionDriver::apply_session_policy`], so a test can assert the
    /// deployment policy (secure flag, lifetime bound) reaches the store.
    applied_policy: Mutex<Option<(bool, Option<Duration>)>>,
}

/// The `Set-Cookie` value [`MockSessionStore::save`] returns, so tests can
/// assert that save's cookies propagate to the response.
const MOCK_SAVE_COOKIE: &str = "mock-save=1";

impl MockSessionStore {
    fn with_session(s: MockSession) -> Self {
        Self {
            session: Mutex::new(Some(s)),
            save_called: Mutex::new(false),
            delete_called: Mutex::new(false),
            fail_save: false,
            verdict: LivenessVerdict::Untracked,
            last_record_activity: Mutex::new(None),
            applied_policy: Mutex::new(None),
        }
    }
    fn with_session_failing_save(s: MockSession) -> Self {
        Self {
            fail_save: true,
            ..Self::with_session(s)
        }
    }
    /// [`with_session`](Self::with_session) plus a fixed liveness verdict.
    fn with_session_and_verdict(s: MockSession, v: LivenessVerdict) -> Self {
        Self::with_session(s).with_verdict(v)
    }
    fn with_verdict(mut self, v: LivenessVerdict) -> Self {
        self.verdict = v;
        self
    }
    fn empty() -> Self {
        Self {
            session: Mutex::new(None),
            save_called: Mutex::new(false),
            delete_called: Mutex::new(false),
            fail_save: false,
            verdict: LivenessVerdict::Untracked,
            last_record_activity: Mutex::new(None),
            applied_policy: Mutex::new(None),
        }
    }
    fn last_record_activity(&self) -> Option<bool> {
        *self.last_record_activity.lock().unwrap()
    }
    fn save_called(&self) -> bool {
        *self.save_called.lock().unwrap()
    }
    fn delete_called(&self) -> bool {
        *self.delete_called.lock().unwrap()
    }
    fn applied_policy(&self) -> Option<(bool, Option<Duration>)> {
        *self.applied_policy.lock().unwrap()
    }
}

impl Sealed for MockSessionStore {}

// Test stub: the async method signatures are mandated by the trait; the
// bodies are synchronous.
#[allow(clippy::unused_async_trait_impl)]
impl SessionDriver for MockSessionStore {
    type SessionType = MockSession;
    type LoadError = Infallible;

    fn apply_session_policy(&mut self, secure: bool, max_lifetime: Option<Duration>) {
        *self.applied_policy.lock().unwrap() = Some((secure, max_lifetime));
    }

    fn session_aead_cipher(&self) -> Arc<dyn AeadCipher> {
        Arc::new(NoopCipher)
    }

    async fn create(
        &self,
        completed: CompletedLogin,
        default_lifetime: Duration,
        _: &HeaderMap,
    ) -> Result<(MockSession, Vec<HeaderValue>), SessionError> {
        // Honor the stamped policy like the real stores: freeze `expire_at`
        // from the max_lifetime the engine applied at construction.
        let max_lifetime = self.applied_policy().and_then(|(_, max)| max);
        Ok((
            MockSession {
                state: SessionState::from_completed(&completed, default_lifetime, max_lifetime),
            },
            vec![],
        ))
    }
    async fn load(&self, _: &HeaderMap) -> Result<Option<MockSession>, Infallible> {
        Ok(self.session.lock().unwrap().take())
    }
    async fn save(&self, _: &MockSession, _: &HeaderMap) -> Result<Vec<HeaderValue>, SessionError> {
        if self.fail_save {
            return Err(SessionError::new(
                SessionErrorKind::Unavailable,
                StoreSaveError,
            ));
        }
        *self.save_called.lock().unwrap() = true;
        Ok(vec![HeaderValue::from_static(MOCK_SAVE_COOKIE)])
    }
    async fn check_liveness(
        &self,
        _: &MockSession,
        _: SystemTime,
        record_activity: bool,
        _: Option<SystemTime>,
    ) -> Result<LivenessVerdict, SessionError> {
        *self.last_record_activity.lock().unwrap() = Some(record_activity);
        Ok(self.verdict)
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

/// Error returned by [`MockSessionStore::save`] when constructed via
/// [`MockSessionStore::with_session_failing_save`].
#[derive(Debug, Snafu)]
#[snafu(display("store save error"))]
struct StoreSaveError;

// ── ErrorSessionStore — load always fails ─────────────────────────────────

#[derive(Debug, Snafu)]
#[snafu(display("store load error"))]
struct StoreLoadError;

struct ErrorSessionStore;
impl Sealed for ErrorSessionStore {}
// Test stub: the async method signatures are mandated by the trait; the
// bodies are synchronous (mostly `unimplemented!()` for unexercised paths).
#[allow(clippy::unused_async_trait_impl)]
impl SessionDriver for ErrorSessionStore {
    type SessionType = MockSession;
    type LoadError = StoreLoadError;

    fn apply_session_policy(&mut self, _secure: bool, _max_lifetime: Option<Duration>) {}

    fn session_aead_cipher(&self) -> Arc<dyn AeadCipher> {
        unimplemented!()
    }

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
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .base_url("https://app.example.com".parse().unwrap())
        .build()
        .unwrap()
}

fn config_with_logout() -> LoginConfig {
    LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .base_url("https://app.example.com".parse().unwrap())
        .logout(LogoutConfig::builder().path("/logout").build().unwrap())
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

#[tokio::test]
async fn engine_stamps_store_secure_from_https_base_url() {
    // default_config uses an https base_url, so the engine must stamp the
    // store with the secure policy at construction.
    let e = engine(MockSessionStore::empty()).await;
    assert_eq!(e.session_store.applied_policy(), Some((true, None)));
}

#[tokio::test]
async fn engine_stamps_store_insecure_from_http_base_url() {
    let http_config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .base_url("http://localhost:6188".parse().unwrap())
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::empty(), http_config).await;
    assert_eq!(e.session_store.applied_policy(), Some((false, None)));
}

#[tokio::test]
async fn engine_stamps_store_with_bounded_session_lifetime() {
    // A Bounded lifetime reaches the driver so cookie Max-Age (and any
    // store-side deadlines) can be clamped to the session cap.
    let config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(8)))
        .base_url("https://app.example.com".parse().unwrap())
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::empty(), config).await;
    assert_eq!(
        e.session_store.applied_policy(),
        Some((true, Some(Duration::from_hours(8))))
    );
}

// ── Header / URI helpers ──────────────────────────────────────────────────

fn nav_headers() -> HeaderMap {
    headers(&[("sec-fetch-mode", "navigate")])
}

fn api_headers() -> HeaderMap {
    headers(&[("accept", "application/json")])
}

// ── Login-state cookie helper ─────────────────────────────────────────────

async fn seal_login_cookie(state: &str, original_url: &str) -> String {
    seal_login_cookie_at(state, original_url, SystemTime::now()).await
}

async fn seal_login_cookie_at(state: &str, original_url: &str, created_at: SystemTime) -> String {
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
        created_at,
    };
    let payload = crate::cookie::encode_payload(&cookie).unwrap();
    let bundle = sealer
        .seal(&payload, &super::login_state_aad(state))
        .await
        .unwrap();
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
        .try_handle_login_route(&Method::POST, &HeaderMap::new(), &uri)
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
        .try_handle_login_route(&Method::POST, &HeaderMap::new(), &uri)
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
async fn load_session_empty_store_returns_missing() {
    let e = engine(MockSessionStore::empty()).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    assert!(matches!(loaded, LoadedSession::Missing));
}

#[tokio::test]
async fn untracked_verdict_yields_active() {
    // The default driver verdict is `Untracked` (no liveness tracking), so the
    // engine returns `Active` with nothing owed post-response.
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (_session, set_cookies) = expect_active(loaded);
    assert!(set_cookies.is_empty());
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
    assert!(set_cookies.is_empty());
    assert!(!e.session_store.save_called());
}

#[tokio::test]
async fn login_state_cookie_uses_configured_ttl() {
    let config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .base_url("https://app.example.com".parse().unwrap())
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

fn login_cookie_name(state: &str) -> String {
    crate::cookie::login_state_cookie_name(
        state,
        true,
        "/callback",
        crate::cookie::DEFAULT_LOGIN_COOKIE_PREFIX,
    )
}

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
    let pending_state = PendingState {
        redirect_uri: "https://app.example.com/callback".to_owned(),
        pkce_verifier: None,
        state: state.to_owned(),
        nonce: "test_nonce".to_owned(),
        dpop_jkt: None,
    };
    let payload = crate::cookie::encode_payload(&OldLoginStateCookie {
        original_url: "https://app.example.com/a",
        pending_state: &pending_state,
    })
    .unwrap();
    let sealer = AeadV1Cipher::new(test_cipher().await);
    let bundle = sealer.seal(&payload, state.as_bytes()).await.unwrap();
    let value = URL_SAFE_NO_PAD.encode(&bundle);

    let e = engine(MockSessionStore::empty()).await;
    let h = headers_with_login_cookie(state, &value);
    let uri = format!("/callback?code=abc&state={state}").parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::GET, &h, &uri)
        .await
        .expect("callback handled");
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn max_lifetime_expired_clears_session() {
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() - Duration::from_secs(7201),
    );
    let config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(1)))
        .base_url("https://app.example.com".parse().unwrap())
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::with_session(session), config).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::MaxLifetime);
    assert!(e.session_store.delete_called());
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
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(24)))
        .base_url("https://app.example.com".parse().unwrap())
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
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(1)))
        .base_url("https://app.example.com".parse().unwrap())
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
    assert!(e.session_store.delete_called());
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
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .base_url("https://app.example.com".parse().unwrap())
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
    assert!(e.session_store.delete_called());
}

#[tokio::test]
async fn token_expired_refresh_fails_clears_session() {
    use huskarl::core::secrets::SecretString;
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
    assert!(e.session_store.delete_called());
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
async fn refresh_success_persists_eagerly() {
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::with_session(session))
        .cipher(test_cipher().await)
        .build();
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    // The refreshed session was saved inside load_session — `Active`, with
    // nothing left for the post-response persist phase.
    let (session, set_cookies) = expect_active(loaded);
    assert!(e.session_store.save_called());
    // The refresh response carried expires_in=3600 — expiry moved well past now.
    assert!(session.token_expiry() > SystemTime::now() + Duration::from_mins(30));
    // The eager save's Set-Cookie headers ride back on the loaded result.
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
        .cipher(test_cipher().await)
        .build();
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (session, _token_response) = expect_pending(loaded);
    // The refresh itself was applied — only persistence is outstanding.
    assert!(session.token_expiry() > SystemTime::now() + Duration::from_mins(30));
}

#[tokio::test]
async fn persist_session_retries_the_deferred_refresh_save() {
    // ActivePending carries the refresh response so the post-response persist
    // can re-commit it (through the merge-safe path) once the store recovers.
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let mut e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(TokenHttp).await)
        .session_store(MockSessionStore::with_session_failing_save(session))
        .cipher(test_cipher().await)
        .build();
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (mut session, token_response) = expect_pending(loaded);

    // The store recovers; the owed persist now succeeds.
    e.session_store.fail_save = false;
    let set_cookies = e
        .persist_session(&mut session, &token_response, &HeaderMap::new())
        .await
        .unwrap();
    assert!(e.session_store.save_called());
    assert_eq!(
        set_cookies,
        vec![HeaderValue::from_static(MOCK_SAVE_COOKIE)]
    );
    // The re-applied refresh keeps the session's tokens fresh.
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
    assert!(set_cookies.is_empty());
    assert!(!e.session_store.delete_called());
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
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::RefreshRejected);
    assert!(e.session_store.delete_called());
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
        !e.session_store.delete_called(),
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
        .cipher(test_cipher().await)
        .build();
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (recovered, _) = expect_active(loaded);
    assert!(recovered.token_expiry() > SystemTime::now() + Duration::from_mins(30));
}

#[tokio::test]
async fn load_session_store_error_bubbles_up() {
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(ErrorSessionStore)
        .cipher(test_cipher().await)
        .build();
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

// ── persist_session ───────────────────────────────────────────────────────

#[tokio::test]
async fn persist_save_calls_store_save() {
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (mut session, _) = expect_active(loaded);
    e.persist_session(&mut session, &token_response_fixture(), &api_headers())
        .await
        .unwrap();
    assert!(e.session_store.save_called());
}

/// A minimal refresh-style token response for driving `persist_session`.
fn token_response_fixture() -> huskarl::grant::core::TokenResponse {
    use huskarl::core::secrets::SecretString;
    huskarl::grant::core::RawTokenResponse::builder()
        .access_token(SecretString::new("refreshed-access-token"))
        .token_type("Bearer")
        .build()
        .into_token_response(None, SystemTime::now())
        .unwrap()
}

// ── DefaultPersistFailurePolicy ───────────────────────────────────────────

#[test]
fn default_persist_failure_policy_maps_kinds_and_is_no_store() {
    use super::PersistFailurePolicy as _;
    use crate::DefaultPersistFailurePolicy;
    let policy = DefaultPersistFailurePolicy;
    for (kind, expected) in [
        (SessionErrorKind::Conflict, StatusCode::CONFLICT),
        (SessionErrorKind::Crypto, StatusCode::INTERNAL_SERVER_ERROR),
        (
            SessionErrorKind::Encoding,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (SessionErrorKind::Store, StatusCode::INTERNAL_SERVER_ERROR),
        (
            SessionErrorKind::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (SessionErrorKind::Gone, StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let err = SessionError::from(kind);
        let resp = policy
            .handle(&err)
            .expect("default policy replaces the response");
        assert_eq!(resp.status(), expected, "kind {kind:?}");
        // Session-adjacent responses are never cacheable.
        let no_store = resp
            .headers()
            .iter()
            .any(|(n, v)| *n == http::header::CACHE_CONTROL && v.as_bytes() == b"no-store");
        assert!(no_store, "persist-failure response must be no-store");
    }
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
        .cipher(test_cipher().await)
        .build();
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

// ── Logout handler ────────────────────────────────────────────────────────

#[tokio::test]
async fn logout_without_session_redirects_to_base_url() {
    let e = engine_with_config(MockSessionStore::empty(), config_with_logout()).await;
    let uri = "/logout".parse().unwrap();
    let r = e
        .try_handle_login_route(&Method::POST, &HeaderMap::new(), &uri)
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
async fn logout_with_session_deletes_session() {
    let e = engine_with_config(
        MockSessionStore::with_session(valid_session()),
        config_with_logout(),
    )
    .await;
    let uri = "/logout".parse().unwrap();
    let _ = e
        .try_handle_login_route(&Method::POST, &HeaderMap::new(), &uri)
        .await;
    assert!(e.session_store.delete_called());
}

#[tokio::test]
async fn logout_redirects_to_configured_post_logout_uri() {
    let config = LoginConfig::builder()
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .base_url("https://app.example.com".parse().unwrap())
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
        .try_handle_login_route(&Method::POST, &HeaderMap::new(), &uri)
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
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .base_url("https://app.example.com".parse().unwrap())
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
        .try_handle_login_route(&Method::POST, &HeaderMap::new(), &uri)
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
        .callback_path("/callback".to_owned())
        .scopes(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .base_url("https://app.example.com".parse().unwrap())
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
        .try_handle_login_route(&Method::POST, &HeaderMap::new(), &uri)
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
    assert!(!e.session_store.delete_called());
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
        .try_handle_login_route(&Method::POST, &h, &uri)
        .await
        .expect("logout handled");
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert!(e.session_store.delete_called());
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
    assert!(!e.session_store.delete_called());
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
    assert!(e.session_store.delete_called());
}

#[tokio::test]
async fn skew_just_under_limit_is_tolerated() {
    // created_at 55s in the future — just inside MAX_CLOCK_SKEW (60s), so the
    // session is served, not torn down. Together with
    // `skew_just_over_limit_clears_session` this brackets the threshold to a
    // few seconds, where `small_future_skew_is_tolerated` (10s) only proves
    // it is somewhere above 10s.
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() + Duration::from_secs(55),
    );
    let e = engine(MockSessionStore::with_session(session)).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    expect_active(loaded);
    assert!(!e.session_store.delete_called());
}

#[tokio::test]
async fn skew_just_over_limit_clears_session() {
    // created_at 70s in the future — just past MAX_CLOCK_SKEW (60s), so the
    // session is treated as clock-skew corrupted and cleared.
    let session = session_with(
        SystemTime::now() + Duration::from_hours(1),
        None,
        SystemTime::now() + Duration::from_secs(70),
    );
    let e = engine(MockSessionStore::with_session(session)).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (reason, _) = expect_cleared(loaded);
    assert_eq!(reason, TeardownReason::ClockSkew);
    assert!(e.session_store.delete_called());
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
    Teardown {
        reason: &'static str,
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
    fn record_teardown(&self, r: &TeardownReason) {
        self.calls
            .lock()
            .unwrap()
            .push(MetricCall::Teardown { reason: r.as_str() });
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
    let _ = e
        .redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
        .await;
    assert_eq!(m.calls(), vec![MetricCall::LoginStart { result: "ok" }]);
}

#[tokio::test]
async fn metrics_no_login_start_on_api_401() {
    // XHR/API 401s don't redirect to the AS — no login start is recorded.
    let (e, m) = engine_with_metrics(MockSessionStore::empty()).await;
    let _ = e
        .redirect_to_login(&api_headers(), &"/api".parse().unwrap())
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
    let _ = e
        .redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
        .await;
    assert_eq!(m.calls(), vec![MetricCall::LoginStart { result: "error" }]);
}

// ── Login complete metrics ────────────────────────────────────────────────

#[tokio::test]
async fn metrics_callback_invalid_request_on_missing_params() {
    let (e, m) = engine_with_metrics(MockSessionStore::empty()).await;
    let uri = "/callback".parse().unwrap();
    e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
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
    e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
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
    e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
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
async fn metrics_callback_already_authenticated_on_stale_callback_with_session() {
    // A stale callback rescued by an existing session must not be counted as
    // an invalid request (nor as a fresh login).
    let (e, m) = engine_with_metrics(MockSessionStore::with_session(valid_session())).await;
    let uri = "/callback?code=authcode&state=mystate".parse().unwrap();
    e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
        .await;
    assert_eq!(
        m.calls(),
        vec![MetricCall::LoginComplete {
            result: "already_authenticated",
            as_error: None
        }]
    );
}

#[tokio::test]
async fn metrics_callback_invalid_request_on_missing_state_cookie() {
    let (e, m) = engine_with_metrics(MockSessionStore::empty()).await;
    let uri = "/callback?code=authcode&state=mystate".parse().unwrap();
    e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
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
    e.try_handle_login_route(&Method::GET, &h, &uri).await;
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
    e.try_handle_login_route(&Method::GET, &h, &uri).await;
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
    e.try_handle_login_route(&Method::GET, &h, &uri).await;
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
    );
    let (e, m) = engine_with_metrics(MockSessionStore::with_session(session)).await;
    let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    assert_eq!(
        m.calls(),
        vec![
            MetricCall::Refresh {
                result: "no_refresh_token"
            },
            MetricCall::Teardown {
                reason: "no_refresh_token"
            },
        ]
    );
}

#[tokio::test]
async fn metrics_refresh_failed_when_grant_refresh_fails() {
    use huskarl::core::secrets::SecretString;
    let session = session_with(
        SystemTime::now() - Duration::from_mins(1),
        Some(RefreshToken::new(SecretString::new("test_refresh"), None)),
        SystemTime::now(),
    );
    let (e, m) = engine_with_metrics(MockSessionStore::with_session(session)).await;
    let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    // The engine's HTTP double fails non-retryably — a conclusive rejection.
    assert_eq!(
        m.calls(),
        vec![
            MetricCall::Refresh { result: "failed" },
            MetricCall::Teardown {
                reason: "refresh_rejected"
            },
        ]
    );
}

// ── Teardown metrics ──────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_teardown_on_idle_timeout() {
    let m = Arc::new(TestEngineMetrics::default());
    let store =
        MockSessionStore::with_session_and_verdict(valid_session(), LivenessVerdict::Expired);
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(store)
        .cipher(test_cipher().await)
        .metrics(Arc::clone(&m) as Arc<dyn LoginEngineMetrics>)
        .build();
    let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    assert_eq!(
        m.calls(),
        vec![MetricCall::Teardown {
            reason: "idle_timeout"
        }]
    );
}

#[tokio::test]
async fn metrics_refresh_failed_retained_on_transient_failure_with_valid_token() {
    let m = Arc::new(TestEngineMetrics::default());
    let session = refreshable_session(SystemTime::now() + Duration::from_secs(15));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(FailingHttp::new(true).0).await)
        .session_store(MockSessionStore::with_session_and_verdict(
            session,
            LivenessVerdict::Active,
        ))
        .cipher(test_cipher().await)
        .metrics(Arc::clone(&m) as Arc<dyn LoginEngineMetrics>)
        .build();
    let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    // The transient-retention path retains the session as-is without
    // re-evaluating liveness, so only the refresh outcome is recorded — no
    // activity metric, even though the driver would have reported `Active`.
    assert_eq!(
        m.calls(),
        vec![MetricCall::Refresh {
            result: "failed_retained"
        }]
    );
}

#[tokio::test]
async fn metrics_refresh_failed_unavailable_on_transient_failure_with_expired_token() {
    // Transient failure past expiry: the session is retained (no teardown
    // metric) but the request can't be served — a distinct refresh outcome so
    // dashboards can tell "AS down, users seeing 503s" from both teardowns
    // and the still-serving retained case.
    let m = Arc::new(TestEngineMetrics::default());
    let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(FailingHttp::new(true).0).await)
        .session_store(MockSessionStore::with_session(session))
        .cipher(test_cipher().await)
        .metrics(Arc::clone(&m) as Arc<dyn LoginEngineMetrics>)
        .build();
    let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    assert_eq!(
        m.calls(),
        vec![MetricCall::Refresh {
            result: "failed_unavailable"
        }]
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
    let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    assert_eq!(m.calls(), vec![MetricCall::Refresh { result: "ok" }]);
}
