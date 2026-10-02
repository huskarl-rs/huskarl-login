//! Shared fixtures for the engine unit tests.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, SystemTime},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use rstest::rstest;
use snafu::Snafu;

use super::{
    LoadedSession, LoginEngine, PendingPersist, TeardownReason, error_chain, is_cors_preflight,
    is_cross_site_request, is_navigation_request,
};
use crate::{
    ActivityPolicy, CompletedLogin, LivenessVerdict, LoginConfig, LogoutConfig,
    PersistedSessionState, Session, SessionDriver, SessionError, SessionErrorKind, SessionLifetime,
    SessionState, StoreBackedSessionStore,
    client::{
        grant::authorization_code::{AuthorizationCodeGrant, PendingState},
        token::RefreshToken,
    },
    core::{
        Error, RetryAdvice,
        client_auth::NoAuth,
        crypto::{
            cipher::DecryptError,
            seal::{AeadSealer, AeadSealerUnsealer, AeadUnsealer, AeadV1Sealer, SealOutput},
        },
        http::{HttpClient, HttpResponse, Idempotency},
        platform::MaybeSendBoxFuture,
    },
    session::sealed::Sealed,
    test_support::{
        RevocableExternalStore, header_map as headers, request_cookies, test_cipher, test_sealer,
        test_session_policy,
    },
};

// ── HTTP doubles ──────────────────────────────────────────────────────────

#[derive(Debug, Snafu)]
#[snafu(display("flaky transport error"))]
struct FlakyError;

/// Fails every request with a transport error carrying the given retry
/// advice, counting calls. One refresh attempt makes exactly one token-endpoint
/// request (`NoAuth` needs no HTTP and no `DPoP` is configured), so the call
/// count equals the attempt count.
struct FailingHttp {
    calls: Arc<AtomicU32>,
    advice: RetryAdvice,
}

impl FailingHttp {
    fn new(retryable: bool) -> (Self, Arc<AtomicU32>) {
        Self::with_advice(RetryAdvice::retry_if(retryable))
    }

    fn with_advice(advice: RetryAdvice) -> (Self, Arc<AtomicU32>) {
        let calls = Arc::new(AtomicU32::new(0));
        (
            Self {
                calls: Arc::clone(&calls),
                advice,
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
        let advice = self.advice;
        Box::pin(async move { Err(Error::new(advice, FlakyError)) })
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

#[derive(Clone)]
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

/// Unwraps [`LoadedSession::Active`] into the session and its cookies
/// (consumed out of the [`SetCookies`] guard).
fn expect_active(loaded: LoadedSession<MockSession>) -> (MockSession, Vec<HeaderValue>) {
    match loaded {
        LoadedSession::Active {
            session,
            set_cookies,
        } => (session, set_cookies.into_headers()),
        other => unreachable!("expected Active, got {}", variant_name(&other)),
    }
}

/// Unwraps [`LoadedSession::ActivePending`] into the owed persist.
fn expect_pending(loaded: LoadedSession<MockSession>) -> PendingPersist<MockSession> {
    match loaded {
        LoadedSession::ActivePending { pending } => pending,
        other => unreachable!("expected ActivePending, got {}", variant_name(&other)),
    }
}

/// Unwraps [`LoadedSession::Cleared`] into the teardown reason and clears
/// (consumed out of the [`SetCookies`] guard).
fn expect_cleared(loaded: LoadedSession<MockSession>) -> (TeardownReason, Vec<HeaderValue>) {
    match loaded {
        LoadedSession::Cleared { reason, clears } => (reason, clears.into_headers()),
        other => unreachable!("expected Cleared, got {}", variant_name(&other)),
    }
}

// ── MockSessionStore ──────────────────────────────────────────────────────

/// A do-nothing sealer so [`MockSessionStore`] can satisfy
/// [`SessionDriver::session_sealer`] without async key construction in its
/// sync constructors. The engine under test is always built with an explicit
/// `.sealer(...)`, so this is never actually invoked to seal or unseal.
#[derive(Debug)]
struct NoopSealer;

impl AeadSealer for NoopSealer {
    fn seal<'a>(
        &'a self,
        _plaintext: &'a [u8],
        _aad: &'a [u8],
    ) -> MaybeSendBoxFuture<'a, Result<SealOutput, Error>> {
        Box::pin(async {
            Ok(SealOutput {
                bundle: Vec::new(),
                kid: None,
            })
        })
    }
}

impl AeadUnsealer for NoopSealer {
    fn unseal<'a>(
        &'a self,
        _bundle: &'a [u8],
        _aad: &'a [u8],
        _kid: Option<&'a str>,
    ) -> MaybeSendBoxFuture<'a, Result<Vec<u8>, DecryptError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

#[allow(clippy::struct_excessive_bools)] // Independent failure controls for test scenarios.
struct MockSessionStore {
    session: Mutex<Option<MockSession>>,
    save_called: Mutex<bool>,
    refresh_revisions: Mutex<Vec<u64>>,
    revoke_called: Mutex<bool>,
    fail_save: bool,
    suspend_save: bool,
    gone_on_save: bool,
    fail_revoke: bool,
    invalid_load: Option<crate::InvalidSessionReason>,
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
    /// The sealer returned from [`SessionDriver::session_sealer`]. `None`
    /// falls back to [`NoopSealer`]; a test that exercises the engine's
    /// default-login-state-sealer path sets a real sealer here.
    store_cipher: Option<Arc<dyn AeadSealerUnsealer>>,
}

/// The `Set-Cookie` value [`MockSessionStore::save`] returns, so tests can
/// assert that save's cookies propagate to the response.
const MOCK_SAVE_COOKIE: &str = "mock-save=1";

impl MockSessionStore {
    fn with_session(s: MockSession) -> Self {
        Self {
            session: Mutex::new(Some(s)),
            save_called: Mutex::new(false),
            refresh_revisions: Mutex::new(Vec::new()),
            revoke_called: Mutex::new(false),
            fail_save: false,
            suspend_save: false,
            gone_on_save: false,
            fail_revoke: false,
            invalid_load: None,
            verdict: LivenessVerdict::Untracked,
            last_record_activity: Mutex::new(None),
            applied_policy: Mutex::new(None),
            store_cipher: None,
        }
    }
    fn with_session_failing_save(s: MockSession) -> Self {
        Self {
            fail_save: true,
            ..Self::with_session(s)
        }
    }
    fn with_session_gone_on_save(s: MockSession) -> Self {
        Self {
            gone_on_save: true,
            ..Self::with_session(s)
        }
    }
    fn with_session_failing_revoke(s: MockSession) -> Self {
        Self {
            fail_revoke: true,
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
            refresh_revisions: Mutex::new(Vec::new()),
            revoke_called: Mutex::new(false),
            fail_save: false,
            suspend_save: false,
            gone_on_save: false,
            fail_revoke: false,
            invalid_load: None,
            verdict: LivenessVerdict::Untracked,
            last_record_activity: Mutex::new(None),
            applied_policy: Mutex::new(None),
            store_cipher: None,
        }
    }
    fn with_invalid_load(reason: crate::InvalidSessionReason) -> Self {
        Self {
            invalid_load: Some(reason),
            ..Self::empty()
        }
    }
    /// Sets the sealer [`SessionDriver::session_sealer`] returns, so a test can
    /// exercise the engine defaulting the login-state sealer to the store's.
    fn with_cipher(mut self, sealer: Arc<dyn AeadSealerUnsealer>) -> Self {
        self.store_cipher = Some(sealer);
        self
    }
    fn last_record_activity(&self) -> Option<bool> {
        *self.last_record_activity.lock().unwrap()
    }
    fn save_called(&self) -> bool {
        *self.save_called.lock().unwrap()
    }
    fn revoke_called(&self) -> bool {
        *self.revoke_called.lock().unwrap()
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

    fn apply_session_policy(
        &mut self,
        policy: &crate::SessionPolicy,
    ) -> Result<(), crate::ConfigError> {
        *self.applied_policy.lock().unwrap() = Some((policy.secure(), policy.max_lifetime()));
        Ok(())
    }

    fn session_sealer(&self) -> Arc<dyn AeadSealerUnsealer> {
        self.store_cipher
            .clone()
            .unwrap_or_else(|| Arc::new(NoopSealer))
    }

    fn clear_session_cookies(&self, _: &HeaderMap) -> Vec<HeaderValue> {
        vec![HeaderValue::from_static("mock-session=; Max-Age=0")]
    }

    fn strip_session_credentials(&self, _headers: &mut HeaderMap) {}

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
    async fn load(&self, _: &HeaderMap) -> Result<crate::DriverLoad<MockSession>, SessionError> {
        if let Some(reason) = self.invalid_load {
            return Ok(crate::DriverLoad::Invalid(reason));
        }
        Ok(self
            .session
            .lock()
            .unwrap()
            .take()
            .map_or(crate::DriverLoad::Absent, crate::DriverLoad::Valid))
    }
    async fn apply_refresh_and_save(
        &self,
        session: &mut MockSession,
        response: &crate::client::grant::core::TokenResponse,
        expected_refresh_revision: u64,
        lifetime: Duration,
        headers: &HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.refresh_revisions
            .lock()
            .unwrap()
            .push(expected_refresh_revision);
        session.apply_refresh(response, lifetime);
        self.save(session, headers).await
    }

    async fn save(&self, _: &MockSession, _: &HeaderMap) -> Result<Vec<HeaderValue>, SessionError> {
        if self.fail_save {
            return Err(SessionError::new(
                SessionErrorKind::Unavailable,
                StoreSaveError,
            ));
        }
        if self.gone_on_save {
            return Err(SessionError::new(SessionErrorKind::Gone, StoreSaveError));
        }
        *self.save_called.lock().unwrap() = true;
        if self.suspend_save {
            std::future::pending::<()>().await;
        }
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
    async fn revoke(&self, _: &MockSession) -> Result<(), SessionError> {
        *self.revoke_called.lock().unwrap() = true;
        if self.fail_revoke {
            return Err(SessionError::new(
                SessionErrorKind::Unavailable,
                StoreRevocationError,
            ));
        }
        Ok(())
    }
}

/// Error returned by [`MockSessionStore::save`] when constructed via
/// [`MockSessionStore::with_session_failing_save`].
#[derive(Debug, Snafu)]
#[snafu(display("store save error"))]
struct StoreSaveError;

#[derive(Debug, Snafu)]
#[snafu(display("store revocation error"))]
struct StoreRevocationError;

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

    fn apply_session_policy(
        &mut self,
        _policy: &crate::SessionPolicy,
    ) -> Result<(), crate::ConfigError> {
        Ok(())
    }

    fn session_sealer(&self) -> Arc<dyn AeadSealerUnsealer> {
        unimplemented!()
    }

    fn clear_session_cookies(&self, _: &HeaderMap) -> Vec<HeaderValue> {
        vec![HeaderValue::from_static("mock-session=; Max-Age=0")]
    }

    fn strip_session_credentials(&self, _headers: &mut HeaderMap) {}

    async fn create(
        &self,
        _: CompletedLogin,
        _: Duration,
        _: &HeaderMap,
    ) -> Result<(MockSession, Vec<HeaderValue>), SessionError> {
        unimplemented!()
    }
    async fn load(&self, _: &HeaderMap) -> Result<crate::DriverLoad<MockSession>, SessionError> {
        Err(SessionError::new(
            SessionErrorKind::Unavailable,
            StoreLoadError,
        ))
    }
    async fn save(&self, _: &MockSession, _: &HeaderMap) -> Result<Vec<HeaderValue>, SessionError> {
        unimplemented!()
    }
    async fn revoke(&self, _: &MockSession) -> Result<(), SessionError> {
        unimplemented!()
    }
}

// ── Engine / config helpers ───────────────────────────────────────────────

fn default_config() -> LoginConfig {
    LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .build()
        .unwrap()
}

fn config_with_logout() -> LoginConfig {
    LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
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
        .sealer(test_sealer().await)
        .build()
        .unwrap()
}

// ── Header / URI helpers ──────────────────────────────────────────────────

fn nav_headers() -> HeaderMap {
    headers(&[("sec-fetch-mode", "navigate")])
}

fn api_headers() -> HeaderMap {
    headers(&[("accept", "application/json")])
}

fn logout_headers() -> HeaderMap {
    headers(&[("origin", "https://app.example.com")])
}

// ── Login-state cookie helper ─────────────────────────────────────────────

async fn seal_login_cookie(state: &str, original_url: &str) -> String {
    seal_login_cookie_at(state, original_url, SystemTime::now()).await
}

/// Builds a [`PendingState`] for tests. It is `#[non_exhaustive]` upstream, so
/// it can't be struct-literal'd from this crate — round-trip through serde.
fn test_pending_state(state: &str) -> PendingState {
    serde_json::from_value(serde_json::json!({
        "redirect_uri": "https://app.example.com/callback",
        "pkce_verifier": null,
        "state": state,
        "nonce": "test_nonce",
        "dpop_jkt": null,
    }))
    .unwrap()
}

async fn seal_login_cookie_at(state: &str, original_url: &str, created_at: SystemTime) -> String {
    let sealer = AeadV1Sealer::new(test_cipher().await);
    let cookie = super::LoginStateCookie {
        original_url: original_url.to_owned(),
        pending_state: test_pending_state(state),
        created_at,
    };
    let payload = crate::cookie::encode_payload(&cookie).unwrap();
    let output = sealer
        .seal(&payload, &super::login_state_aad(state))
        .await
        .unwrap();
    URL_SAFE_NO_PAD.encode(&output.bundle)
}

fn headers_with_login_cookie(state: &str, value: &str) -> HeaderMap {
    let name = login_cookie_name(state);
    headers(&[("cookie", &format!("{name}={value}"))])
}

fn login_cookie_name(state: &str) -> String {
    crate::cookie::login_state_cookie_name(
        state,
        true,
        "/callback",
        crate::cookie::DEFAULT_LOGIN_COOKIE_PREFIX,
    )
}

// ── Refresh retry ─────────────────────────────────────────────────────────

/// A session whose access token expires at `token_expiry` and that holds a
/// refresh token — i.e. one that enters the refresh path on load whenever
/// `token_expiry` is within the refresh margin.
fn refreshable_session(token_expiry: SystemTime) -> MockSession {
    use crate::core::secrets::SecretString;
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
    engine_with_refresh_advice(RetryAdvice::retry_if(retryable), session).await
}

/// As [`engine_with_failing_refresh`], with the failure's retry advice given
/// in full (so a server-supplied delay can be exercised).
async fn engine_with_refresh_advice(
    advice: RetryAdvice,
    session: MockSession,
) -> (LoginEngine<MockSessionStore>, Arc<AtomicU32>) {
    let (http, calls) = FailingHttp::with_advice(advice);
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(http).await)
        .session_store(MockSessionStore::with_session(session))
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    (e, calls)
}

/// A minimal refresh-style token response for driving
/// [`PendingPersist::commit`].
fn token_response_fixture() -> crate::client::grant::core::TokenResponse {
    use crate::core::secrets::SecretString;
    crate::client::grant::core::RawTokenResponse::builder()
        .access_token(SecretString::new("refreshed-access-token"))
        .token_type("Bearer")
        .build()
        .into_token_response(None, SystemTime::now())
        .unwrap()
}

mod callback;
mod construction;
mod logout;
mod persist;
mod redirect;
mod refresh;
mod routing;
mod session;
mod telemetry;
