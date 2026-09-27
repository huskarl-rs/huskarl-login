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

struct MockSessionStore {
    session: Mutex<Option<MockSession>>,
    save_called: Mutex<bool>,
    refresh_revisions: Mutex<Vec<u64>>,
    revoke_called: Mutex<bool>,
    fail_save: bool,
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
    type LoadError = Infallible;

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
    async fn load(&self, _: &HeaderMap) -> Result<crate::DriverLoad<MockSession>, Infallible> {
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
    type LoadError = StoreLoadError;

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
    async fn load(&self, _: &HeaderMap) -> Result<crate::DriverLoad<MockSession>, StoreLoadError> {
        Err(StoreLoadError)
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

#[tokio::test]
async fn engine_reconstructs_base_url_from_grant_redirect_uri() {
    // The origin is not configured on LoginConfig; the engine takes it from the
    // grant's redirect_uri (https://app.example.com). Reconstructing the
    // post-login redirect proves it used that origin.
    let e = engine(MockSessionStore::empty()).await;
    let uri: http::Uri = "/dashboard".parse().unwrap();
    assert_eq!(
        crate::url::original_url(&e.base_url, e.config.strip_prefix.as_ref(), &uri).as_deref(),
        Some("https://app.example.com/dashboard"),
    );
}

#[tokio::test]
async fn engine_stamps_store_secure_from_https_base_url() {
    // default_config uses an https base_url, so the engine must stamp the
    // store with the secure policy at construction.
    let e = engine(MockSessionStore::empty()).await;
    assert_eq!(e.session_store.applied_policy(), Some((true, None)));
}

#[tokio::test]
async fn engine_stamps_store_insecure_from_http_redirect_uri() {
    // `secure` comes from the grant's redirect_uri scheme; an http redirect_uri
    // must stamp the store insecure.
    let http_grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(FailingHttp::new(false).0)
        .client_auth(NoAuth)
        .token_endpoint("https://auth.example.com/token".parse().unwrap())
        .authorization_endpoint("https://auth.example.com/authorize".parse().unwrap())
        .redirect_uri("http://app.example.com/callback")
        .build()
        .await
        .unwrap();
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(http_grant)
        .session_store(MockSessionStore::empty())
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    assert_eq!(e.session_store.applied_policy(), Some((false, None)));
}

#[tokio::test]
async fn engine_stamps_store_with_bounded_session_lifetime() {
    // A Bounded lifetime reaches the driver so cookie Max-Age (and any
    // store-side deadlines) can be clamped to the session cap.
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(8)))
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::empty(), config).await;
    assert_eq!(
        e.session_store.applied_policy(),
        Some((true, Some(Duration::from_hours(8))))
    );
}

#[tokio::test]
async fn engine_recomputes_browser_paths_after_config_mutation() {
    let mut config = LoginConfig::builder()
        .callback_path("/app/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .logout(LogoutConfig::builder().path("/app/logout").build().unwrap())
        .build()
        .unwrap();
    // Simulate an adapter adjusting the public route configuration after the
    // builder ran. The stale derived value still says `/app/logout`.
    config.logout.as_mut().unwrap().path = "/logout".parse().unwrap();
    assert_eq!(
        config
            .browser_logout_path
            .as_ref()
            .map(crate::RoutePath::as_str),
        Some("/app/logout")
    );

    let store = StoreBackedSessionStore::builder()
        .external(RevocableExternalStore::<PersistedSessionState>::default())
        .sealer(test_sealer().await)
        .cookie_name("session".parse().unwrap())
        .cookie_path("/app".parse().unwrap())
        .build();
    let result = LoginEngine::builder()
        .config(config)
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(store)
        .build();

    let Err(error) = result else {
        panic!("the recomputed logout path must fail cookie-scope validation");
    };
    assert!(matches!(
        error,
        crate::ConfigError::InvalidSessionCookiePath {
            route: "logout",
            ..
        }
    ));
}

#[tokio::test]
async fn engine_revalidates_durations_after_config_mutation() {
    let mut config = default_config();
    config.login_state_ttl = Duration::ZERO;

    let result = LoginEngine::builder()
        .config(config)
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(MockSessionStore::empty())
        .sealer(test_sealer().await)
        .build();

    let Err(error) = result else {
        panic!("mutated duration must be revalidated at the engine boundary");
    };
    assert!(matches!(
        error,
        crate::ConfigError::InvalidDuration {
            field: "login_state_ttl",
            ..
        }
    ));
}

#[tokio::test]
async fn engine_revalidates_logout_redirect_after_config_mutation() {
    let mut config = config_with_logout();
    config.logout.as_mut().unwrap().post_logout_redirect_uri = Some("/signed-out".to_owned());

    let result = LoginEngine::builder()
        .config(config)
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(MockSessionStore::empty())
        .sealer(test_sealer().await)
        .build();

    let Err(error) = result else {
        panic!("mutated logout redirect must be revalidated at the engine boundary");
    };
    assert!(matches!(
        error,
        crate::ConfigError::InvalidPostLogoutRedirectUri { .. }
    ));
}

#[tokio::test]
async fn engine_defaults_login_state_cipher_to_store_cipher() {
    // Omitting `.sealer()` must default the login-state seal to the store's own
    // AEAD cipher — the two seals are AAD-domain-separated, so sharing one key
    // is safe. Moving this defaulting into the builder means every adapter gets
    // it (and its safety argument) for free instead of reimplementing it. Build
    // the engine WITHOUT a cipher over a store whose `session_aead_cipher()` is
    // the shared test key, then confirm the login-state cookie it seals unseals
    // under that same key.
    let store = MockSessionStore::empty().with_cipher(Arc::new(test_sealer().await));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(store)
        .build()
        .unwrap();

    let uri = "/dashboard".parse().unwrap();
    let r = e.redirect_to_login(&nav_headers(), &uri).await;
    let hdrs = r.headers();

    // The `state` the engine minted is carried in the authorize redirect; it
    // is the AAD the login-state cookie was sealed under.
    let location = hdrs
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap())
        .expect("Location header");
    let state = location
        .split_once("state=")
        .and_then(|(_, rest)| rest.split('&').next())
        .expect("state param");

    // The login-state cookie value the engine emitted.
    let cookie_value = hdrs
        .iter()
        .filter(|(n, _)| *n == http::header::SET_COOKIE)
        .find_map(|(_, v)| {
            let s = v.to_str().ok()?;
            s.contains("huskarl_login_").then(|| {
                s.split_once('=')
                    .unwrap()
                    .1
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned()
            })
        })
        .expect("login-state cookie");

    // Independently rebuild a sealer over the same fixed test key and unseal:
    // success proves the engine sealed with the store's cipher (the default),
    // not some unrelated key.
    let bundle = URL_SAFE_NO_PAD.decode(&cookie_value).unwrap();
    let sealer = AeadV1Sealer::new(test_cipher().await);
    let plaintext = sealer
        .unseal(&bundle, &super::login_state_aad(state), None)
        .await
        .expect("login-state cookie unseals under the store cipher");
    let decoded = crate::cookie::decode_payload::<super::LoginStateCookie>(&plaintext).unwrap();
    assert!(
        decoded.original_url.contains("dashboard"),
        "unsealed original_url should round-trip the request path, got {}",
        decoded.original_url
    );
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
    assert!(set_cookies.is_empty());
    assert!(!e.session_store.revoke_called());
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

// ── PendingPersist::commit ────────────────────────────────────────────────

#[tokio::test]
async fn commit_calls_store_save() {
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (session, _) = expect_active(loaded);
    // The public constructor: what adapter tests use to fabricate the
    // deferred-persist path without arranging a failing store.
    let pending = PendingPersist::new(session, token_response_fixture(), 0);
    let set_cookies = pending.commit(&e, &api_headers()).await.unwrap();
    assert!(e.session_store.save_called());
    assert!(!set_cookies.into_headers().is_empty());
}

#[test]
fn pending_persist_drop_guard_detects_a_dropped_persist() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let probe = Arc::new(AtomicUsize::new(0));
    let dropped = PendingPersist::new(valid_session(), token_response_fixture(), 0)
        .with_drop_probe(Arc::clone(&probe));
    drop(dropped);
    assert_eq!(
        probe.load(Ordering::Relaxed),
        1,
        "a dropped owed persist must be detected"
    );
}

#[tokio::test]
async fn pending_persist_drop_guard_stays_silent_for_defused_guards() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let probe = Arc::new(AtomicUsize::new(0));

    // `commit` defuses the guard (consuming the returned cookies keeps the
    // `SetCookies` guard quiet too — this test is about the persist guard).
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let committed = PendingPersist::new(valid_session(), token_response_fixture(), 0)
        .with_drop_probe(Arc::clone(&probe));
    let _cookies = committed
        .commit(&e, &api_headers())
        .await
        .unwrap()
        .into_headers();

    // So does `abandon`, the explicit non-commit verb.
    let abandoned = PendingPersist::new(valid_session(), token_response_fixture(), 0)
        .with_drop_probe(Arc::clone(&probe));
    abandoned.abandon();

    // An armed guard dropped by panic unwinding stays silent too: the owed
    // persist is collateral of the panic, not a separate bug to report.
    let unwind_probe = Arc::clone(&probe);
    let result = std::panic::catch_unwind(move || {
        let _armed = PendingPersist::new(valid_session(), token_response_fixture(), 0)
            .with_drop_probe(unwind_probe);
        panic!("handler panic");
    });
    assert!(result.is_err());

    assert_eq!(probe.load(Ordering::Relaxed), 0);
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
        (SessionErrorKind::Gone, StatusCode::UNAUTHORIZED),
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
        let response_headers = resp.headers();
        let challenge = response_headers
            .iter()
            .find(|(name, _)| *name == http::header::WWW_AUTHENTICATE)
            .map(|(_, value)| value.as_bytes());
        assert_eq!(
            challenge,
            (kind == SessionErrorKind::Gone).then_some(b"Cookie".as_slice()),
            "only a gone session should request re-authentication"
        );
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

fn cookie_is_cleared(response: &super::LoginResponse, cookie_name: &str) -> bool {
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

fn has_mock_session_clear(response: &super::LoginResponse) -> bool {
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

// ── Metrics emission ──────────────────────────────────────────────────────

use crate::test_support::{CapturedCounters, counter_value, with_metrics};

/// True if any counter named `name` was emitted, regardless of labels.
fn emitted(counters: &CapturedCounters, name: &str) -> bool {
    counters.iter().any(|(n, _, _)| n == name)
}

// ── Login start metrics ───────────────────────────────────────────────────

#[test]
fn metrics_login_start_ok_on_nav_redirect() {
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let _ = e
            .redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
            .await;
    });
    assert_eq!(
        counter_value(&counters, "huskarl.login.start", &[("outcome", "ok")]),
        1
    );
}

#[test]
fn metrics_name_labels_engine_counters() {
    let ((), counters) = with_metrics(async {
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(test_grant(FailingHttp::new(false).0).await)
            .session_store(MockSessionStore::empty())
            .sealer(test_sealer().await)
            .metrics_name("tenant-a")
            .build()
            .unwrap();
        let _ = e
            .redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.start",
            &[("outcome", "ok"), ("name", "tenant-a")],
        ),
        1
    );
}

#[test]
fn metrics_no_login_start_on_api_401() {
    // XHR/API 401s don't redirect to the AS — no login start is recorded.
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let _ = e
            .redirect_to_login(&api_headers(), &"/api".parse().unwrap())
            .await;
    });
    assert!(!emitted(&counters, "huskarl.login.start"));
}

#[test]
fn metrics_login_start_error_when_grant_start_fails() {
    // PAR-required grant + failing HTTP double: start() must perform HTTP and
    // therefore fails.
    let ((), counters) = with_metrics(async {
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(par_failing_grant().await)
            .session_store(MockSessionStore::empty())
            .sealer(test_sealer().await)
            .build()
            .unwrap();
        let _ = e
            .redirect_to_login(&nav_headers(), &"/protected".parse().unwrap())
            .await;
    });
    assert_eq!(
        counter_value(&counters, "huskarl.login.start", &[("outcome", "error")]),
        1
    );
}

// ── Login complete metrics ────────────────────────────────────────────────

/// Counter labels for a login completion with the given outcome and
/// normalized AS error code.
fn complete_labels<'a>(outcome: &'a str, error: &'a str) -> [(&'a str, &'a str); 2] {
    [("outcome", outcome), ("error", error)]
}

#[test]
fn metrics_callback_invalid_request_on_missing_params() {
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let uri = "/callback".parse().unwrap();
        e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("invalid_request", "none"),
        ),
        1
    );
}

#[test]
fn metrics_callback_as_denied_carries_error_code() {
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let uri = "/callback?error=access_denied".parse().unwrap();
        e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("as_denied", "access_denied"),
        ),
        1
    );
}

#[test]
fn metrics_callback_as_denied_normalizes_unknown_error_code() {
    // The `error` parameter is attacker-suppliable; anything outside the
    // registered RFC 6749 / OIDC codes must reach the metrics sink as
    // "other" so it can't blow up label cardinality.
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let uri = "/callback?error=attacker_chosen_garbage_12345"
            .parse()
            .unwrap();
        e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("as_denied", "other"),
        ),
        1
    );
}

#[test]
fn metrics_callback_already_authenticated_on_stale_callback_with_session() {
    // A stale callback rescued by an existing session must not be counted as
    // an invalid request (nor as a fresh login).
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::with_session(valid_session())).await;
        let uri = "/callback?code=authcode&state=mystate".parse().unwrap();
        e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("already_authenticated", "none"),
        ),
        1
    );
}

#[test]
fn metrics_callback_invalid_request_on_missing_state_cookie() {
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let uri = "/callback?code=authcode&state=mystate".parse().unwrap();
        e.try_handle_login_route(&Method::GET, &HeaderMap::new(), &uri)
            .await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("invalid_request", "none"),
        ),
        1
    );
}

#[test]
fn metrics_callback_state_invalid_on_tampered_bundle() {
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let state = "teststate";
        let fake = URL_SAFE_NO_PAD.encode(b"not an AEAD bundle");
        let h = headers_with_login_cookie(state, &fake);
        let uri = format!("/callback?code=authcode&state={state}")
            .parse()
            .unwrap();
        e.try_handle_login_route(&Method::GET, &h, &uri).await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("state_invalid", "none"),
        ),
        1
    );
}

#[test]
fn metrics_callback_ok_on_successful_login() {
    let ((), counters) = with_metrics(async {
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(test_grant(TokenHttp).await)
            .session_store(MockSessionStore::empty())
            .sealer(test_sealer().await)
            .build()
            .unwrap();
        let state = "valid_state";
        let sealed = seal_login_cookie(state, "https://app.example.com/").await;
        let h = headers_with_login_cookie(state, &sealed);
        let uri = format!("/callback?code=authcode&state={state}")
            .parse()
            .unwrap();
        e.try_handle_login_route(&Method::GET, &h, &uri).await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("ok", "none"),
        ),
        1
    );
}

#[test]
fn metrics_callback_token_exchange_failed_when_grant_complete_fails() {
    // The default engine's HTTP double fails every token request — verify
    // token_exchange_failed is recorded.
    let ((), counters) = with_metrics(async {
        let e = engine(MockSessionStore::empty()).await;
        let state = "valid_state";
        let sealed = seal_login_cookie(state, "https://app.example.com/").await;
        let h = headers_with_login_cookie(state, &sealed);
        let uri = format!("/callback?code=authcode&state={state}")
            .parse()
            .unwrap();
        e.try_handle_login_route(&Method::GET, &h, &uri).await;
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.login.complete",
            &complete_labels("token_exchange_failed", "none"),
        ),
        1
    );
}

// ── Refresh metrics ───────────────────────────────────────────────────────

#[test]
fn metrics_refresh_no_refresh_token_when_none_available() {
    let ((), counters) = with_metrics(async {
        let session = session_with(
            SystemTime::now() - Duration::from_mins(1),
            None,
            SystemTime::now(),
        );
        let e = engine(MockSessionStore::with_session(session)).await;
        let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh",
            &[("outcome", "no_refresh_token")],
        ),
        1
    );
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.teardown",
            &[("invalid_reason", "none"), ("reason", "no_refresh_token")],
        ),
        1
    );
}

#[test]
fn metrics_refresh_failed_when_grant_refresh_fails() {
    let ((), counters) = with_metrics(async {
        use crate::core::secrets::SecretString;
        let session = session_with(
            SystemTime::now() - Duration::from_mins(1),
            Some(RefreshToken::new(SecretString::new("test_refresh"), None)),
            SystemTime::now(),
        );
        let e = engine(MockSessionStore::with_session(session)).await;
        let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    });
    // The engine's HTTP double fails non-retryably — a conclusive rejection.
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh",
            &[("outcome", "failed")],
        ),
        1
    );
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.teardown",
            &[("invalid_reason", "none"), ("reason", "refresh_rejected")],
        ),
        1
    );
}

// ── Teardown metrics ──────────────────────────────────────────────────────

#[test]
fn metrics_teardown_on_idle_timeout() {
    let ((), counters) = with_metrics(async {
        let store =
            MockSessionStore::with_session_and_verdict(valid_session(), LivenessVerdict::Expired);
        let e = engine(store).await;
        let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.teardown",
            &[("invalid_reason", "none"), ("reason", "idle_timeout")],
        ),
        1
    );
}

#[test]
fn metrics_invalid_session_teardown_preserves_driver_reason() {
    let expected = [
        (
            crate::InvalidSessionReason::IncompleteChunks,
            "incomplete_chunks",
        ),
        (crate::InvalidSessionReason::BadEncoding, "bad_encoding"),
        (
            crate::InvalidSessionReason::DecryptionFailed,
            "decryption_failed",
        ),
        (
            crate::InvalidSessionReason::InvalidPayload,
            "invalid_payload",
        ),
        (
            crate::InvalidSessionReason::SessionNotFound,
            "session_not_found",
        ),
    ];
    let ((), counters) = with_metrics(async {
        for &(reason, _) in &expected {
            let e = engine(MockSessionStore::with_invalid_load(reason)).await;
            let _ = e.load_session(&HeaderMap::new()).await.unwrap();
        }
    });

    for (_, invalid_reason) in expected {
        assert_eq!(
            counter_value(
                &counters,
                "huskarl.session.teardown",
                &[
                    ("invalid_reason", invalid_reason),
                    ("reason", "invalid_session"),
                ],
            ),
            1
        );
    }
}

#[test]
fn metrics_refresh_failed_retained_on_transient_failure_with_valid_token() {
    let ((), counters) = with_metrics(async {
        let session = refreshable_session(SystemTime::now() + Duration::from_secs(15));
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(test_grant(FailingHttp::new(true).0).await)
            .session_store(MockSessionStore::with_session_and_verdict(
                session,
                LivenessVerdict::Active,
            ))
            .sealer(test_sealer().await)
            .build()
            .unwrap();
        let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    });
    // The transient-retention path retains the session as-is — the refresh
    // outcome is recorded, and no teardown is.
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh",
            &[("outcome", "failed_retained")],
        ),
        1
    );
    assert!(!emitted(&counters, "huskarl.session.teardown"));
}

#[test]
fn metrics_refresh_failed_unavailable_on_transient_failure_with_expired_token() {
    // Transient failure past expiry: the session is retained (no teardown
    // metric) but the request can't be served — a distinct refresh outcome so
    // dashboards can tell "AS down, users seeing 503s" from both teardowns
    // and the still-serving retained case.
    let ((), counters) = with_metrics(async {
        let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(test_grant(FailingHttp::new(true).0).await)
            .session_store(MockSessionStore::with_session(session))
            .sealer(test_sealer().await)
            .build()
            .unwrap();
        let _ = e.load_session(&HeaderMap::new()).await.unwrap();
    });
    assert_eq!(
        counter_value(
            &counters,
            "huskarl.session.refresh",
            &[("outcome", "failed_unavailable")],
        ),
        1
    );
    assert!(!emitted(&counters, "huskarl.session.teardown"));
}

#[test]
fn metrics_refresh_ok_on_successful_refresh() {
    let ((), counters) = with_metrics(async {
        let session = refreshable_session(SystemTime::now() - Duration::from_mins(1));
        let e = LoginEngine::builder()
            .config(default_config())
            .grant(test_grant(TokenHttp).await)
            .session_store(MockSessionStore::with_session(session))
            .sealer(test_sealer().await)
            .build()
            .unwrap();
        // Consume via expect_active: a successful refresh returns owed cookies,
        // and dropping them unconsumed would (correctly) trip the SetCookies guard.
        let _ = expect_active(e.load_session(&HeaderMap::new()).await.unwrap());
    });
    assert_eq!(
        counter_value(&counters, "huskarl.session.refresh", &[("outcome", "ok")]),
        1
    );
}

// ── SetCookies drop guard ─────────────────────────────────────────────────

#[test]
fn set_cookies_drop_guard_fires_when_cookies_are_discarded() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::SetCookies;

    let probe = Arc::new(AtomicUsize::new(0));

    // The bug the guard exists for: matching `Active { session, .. }` takes
    // the session and drops the re-sealed cookies on the floor. Rust cannot
    // flag the `..` pattern at compile time, so the guard detects the drop
    // at runtime.
    // The `..` residue of a partially-moved local drops when the local's
    // scope ends, hence the inner block.
    let session = {
        let loaded = LoadedSession::Active {
            session: valid_session(),
            set_cookies: SetCookies::new(vec![HeaderValue::from_static("a=b")])
                .with_drop_probe(Arc::clone(&probe)),
        };
        match loaded {
            LoadedSession::Active { session, .. } => session,
            _ => unreachable!(),
        }
    };
    assert_eq!(
        probe.load(Ordering::Relaxed),
        1,
        "discarded cookies must be detected"
    );
    drop(session);
}

#[test]
fn set_cookies_drop_guard_stays_silent_for_consumed_and_empty_guards() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::SetCookies;

    let probe = Arc::new(AtomicUsize::new(0));

    // Consuming into headers defuses the guard.
    let consumed =
        SetCookies::new(vec![HeaderValue::from_static("a=b")]).with_drop_probe(Arc::clone(&probe));
    assert_eq!(consumed.len(), 1);
    assert_eq!(
        consumed.into_headers(),
        vec![HeaderValue::from_static("a=b")]
    );

    // So does consuming by iteration (the `extend(set_cookies)` shape).
    let iterated =
        SetCookies::new(vec![HeaderValue::from_static("c=d")]).with_drop_probe(Arc::clone(&probe));
    let mut sink: Vec<HeaderValue> = vec![];
    sink.extend(iterated);
    assert_eq!(sink.len(), 1);

    // So does the explicit non-delivery verb, for the path where the
    // response is already gone.
    let undeliverable =
        SetCookies::new(vec![HeaderValue::from_static("e=f")]).with_drop_probe(Arc::clone(&probe));
    undeliverable.discard();

    // The steady state — nothing owed — drops silently.
    let empty = SetCookies::default().with_drop_probe(Arc::clone(&probe));
    assert!(empty.is_empty());
    drop(empty);

    // A non-empty guard dropped by panic unwinding stays silent too: the
    // cookies are collateral of the panic, not a separate bug to report.
    let unwind_probe = Arc::clone(&probe);
    let result = std::panic::catch_unwind(move || {
        let _guarded =
            SetCookies::new(vec![HeaderValue::from_static("e=f")]).with_drop_probe(unwind_probe);
        panic!("handler panic");
    });
    assert!(result.is_err());

    assert_eq!(probe.load(Ordering::Relaxed), 0);
}
