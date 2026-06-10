//! External-store-backed session storage.
//!
//! [`StoreBackedSessionStore`] keeps an encrypted pointer cookie in the browser
//! and delegates actual session data to an [`ExternalSessionStore`] (Redis, a
//! database, etc.). The external store receives [`PersistedSessionState`] on
//! creation and returns its own `Session` type, which may enrich the persisted
//! state with domain-specific fields.

use std::{borrow::Cow, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderValue;
use huskarl::core::crypto::cipher::{
    AeadEncryptor, AeadSealer, AeadUnsealer, AeadV1Sealer, AeadV1Unsealer, BoxedAeadCipher,
    CipherMatch,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    cookie::{
        DEFAULT_COOKIE_MAX_AGE, cookie_attrs, encode_kid, get_cookie, get_kid_cookie,
        kid_cookie_name,
    },
    metrics::{DecryptResult, SessionCookieMetrics},
    session::{SessionDriver, SessionError, to_session_err},
    session_state::{Session, SessionState},
};

/// Trait for external session data stores (Redis, database, etc.).
///
/// This is the only trait users need to implement to use store-backed sessions.
/// The cookie mechanics (pointer cookie encryption, session key generation) are
/// handled by [`StoreBackedSessionStore`].
///
/// The associated [`Session`](Self::SessionType) type is what the middleware works
/// with after login. For the simplest case, use [`PersistedSessionState`]
/// directly. For enriched sessions (e.g. with user profile data), define a
/// custom type that implements [`Session`] and [`PersistedSession`], embedding
/// a `PersistedSessionState`.
pub trait ExternalSessionStore: Send + Sync {
    /// The session type returned by this store.
    ///
    /// Must implement [`Session`] so the middleware can inspect token expiry,
    /// refresh tokens, etc., and [`PersistedSession`] so the framework can
    /// reach the embedded [`PersistedSessionState`] (session key plus any
    /// future framework-managed fields).
    type SessionType: Session + PersistedSession + Send + Sync + 'static;

    /// The error type returned by store operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Create a new session from framework-prepared state.
    ///
    /// Called after a successful OAuth callback. The store should persist the
    /// session and return its (possibly enriched) session type.
    ///
    /// `completed` is provided so the store can read ID token claims (e.g.
    /// `email`, `name`, non-standard `extra` fields) when denormalizing into
    /// a user record. Standard `sub`/`sid` are already extracted into
    /// `persisted.state` and don't need to be re-parsed.
    fn create(
        &self,
        persisted: PersistedSessionState,
        completed: &crate::grant::CompletedLogin,
    ) -> impl Future<Output = Result<Self::SessionType, Self::Error>> + Send;

    /// Load a session by its key. Returns `None` if the key does not exist.
    ///
    /// The key is a `UUIDv7` — passed by value because `Uuid` is `Copy` and
    /// 16 bytes. Implementations that key records by string form should call
    /// `session_key.to_string()` (or `as_simple()` for a hyphen-free form).
    fn load(
        &self,
        session_key: Uuid,
    ) -> impl Future<Output = Result<Option<Self::SessionType>, Self::Error>> + Send;

    /// Save a session. Called when the session has been mutated (e.g. after a
    /// token refresh).
    fn save(
        &self,
        session: &Self::SessionType,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Extend the TTL of a session without rewriting data.
    ///
    /// Called on every authenticated request that doesn't trigger a full save.
    /// Implementations may choose to no-op or throttle this.
    fn touch(
        &self,
        session: &Self::SessionType,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Delete a session.
    fn delete(
        &self,
        session: &Self::SessionType,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Framework-managed session state carried by every store-backed session.
///
/// Contains the session key, session state, and any future framework-managed
/// fields (e.g. step-up auth timestamp, MFA assertions, revocation versions).
/// Built by the framework and passed to [`ExternalSessionStore::create`] after
/// a successful login.
///
/// The struct is `#[non_exhaustive]` so new framework-managed fields can be
/// added in a minor release without breaking store implementations.
///
/// For simple stores that don't need to enrich sessions, use
/// `PersistedSessionState` directly as your [`ExternalSessionStore::SessionType`]
/// type. For enriched sessions, embed this in your custom type and implement
/// [`PersistedSession`] (and [`Session`]) by forwarding to the embedded value.
#[non_exhaustive]
#[derive(Clone, Serialize, Deserialize, bon::Builder)]
pub struct PersistedSessionState {
    /// The random session key used as the primary lookup key in the external
    /// store. A time-ordered `UUIDv7`.
    pub session_key: Uuid,
    /// Shared token and timing state. See [`SessionState`] for the field set.
    pub state: SessionState,
}

impl Session for PersistedSessionState {
    fn state(&self) -> &SessionState {
        &self.state
    }
    fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }
}

/// Trait implemented by every store-backed session type, exposing the
/// embedded [`PersistedSessionState`] to the framework.
///
/// `PersistedSessionState` carries the session key plus any framework-managed
/// fields. Requiring this trait on `ExternalSessionStore::SessionType` lets the
/// framework rely on those fields being present without store implementations
/// having to opt in per-capability.
///
/// The default implementation on `PersistedSessionState` itself is trivial;
/// enriched session types implement this by forwarding to their embedded
/// `PersistedSessionState` field.
pub trait PersistedSession {
    /// Returns a shared reference to the embedded [`PersistedSessionState`].
    fn persisted(&self) -> &PersistedSessionState;

    /// Returns a mutable reference to the embedded [`PersistedSessionState`].
    fn persisted_mut(&mut self) -> &mut PersistedSessionState;
}

impl PersistedSession for PersistedSessionState {
    fn persisted(&self) -> &PersistedSessionState {
        self
    }
    fn persisted_mut(&mut self) -> &mut PersistedSessionState {
        self
    }
}

/// Generates a time-ordered session key using UUID v7.
fn generate_session_key() -> Uuid {
    Uuid::now_v7()
}

/// A session store that keeps an encrypted pointer cookie in the browser and
/// stores session data in an external [`ExternalSessionStore`].
///
/// The pointer cookie contains the encrypted session key (a random string).
/// The actual session data is stored via the external store, which receives
/// [`PersistedSessionState`] on creation and returns its own session type.
pub struct StoreBackedSessionStore<E> {
    external: E,
    sealer: AeadV1Sealer<BoxedAeadCipher>,
    unsealer: AeadV1Unsealer<BoxedAeadCipher>,
    cookie_name: String,
    secure: bool,
    cookie_path: String,
    max_age: Duration,
    metrics: Option<Arc<dyn SessionCookieMetrics>>,
}

#[bon::bon]
impl<E: ExternalSessionStore> StoreBackedSessionStore<E> {
    /// Creates a new store-backed session store.
    #[builder]
    pub fn new(
        external: E,
        cipher: BoxedAeadCipher,
        #[builder(into)] cookie_name: String,
        secure: bool,
        #[builder(into)] cookie_path: String,
        /// Defaults to 400 days. If `max_lifetime` is configured in `LoginConfig`,
        /// pass it here so the browser discards the cookie when the session can
        /// no longer be valid.
        #[builder(default = DEFAULT_COOKIE_MAX_AGE)]
        max_age: Duration,
        /// Optional metrics observer for encrypt/decrypt events.
        metrics: Option<Arc<dyn SessionCookieMetrics>>,
    ) -> Self {
        Self {
            external,
            sealer: AeadV1Sealer::new(cipher.clone()),
            unsealer: AeadV1Unsealer::new(cipher),
            cookie_name,
            secure,
            cookie_path,
            max_age,
            metrics,
        }
    }

    /// Returns the active sealer's key ID, if the key has an identity.
    ///
    /// Delegates to [`AeadEncryptor::key_id`]. Once reload support is added to
    /// `AeadCipher`, this will reflect the key that will be used for the
    /// **next** seal operation — suitable for updating an active-key gauge from
    /// a reload callback.
    pub fn key_id(&self) -> Option<Cow<'_, str>> {
        self.sealer.key_id()
    }

    fn base_cookie_attrs(&self) -> String {
        cookie_attrs(self.secure, &self.cookie_path)
    }

    fn cookie_attrs(&self) -> String {
        format!(
            "{}; Max-Age={}",
            self.base_cookie_attrs(),
            self.max_age.as_secs()
        )
    }

    /// Encrypt the pointer cookie and emit it alongside the kid sidecar.
    ///
    /// The plaintext is the UUID's 16 raw bytes — not the 36-byte hyphenated
    /// string form. This is the same compact representation Postgres uses
    /// for its `uuid` type, and saves ~27 bytes off the wire on every
    /// authenticated request once AEAD overhead and base64 expansion are
    /// accounted for.
    ///
    /// The kid sidecar is set when the sealer reports an active identity, and
    /// emitted as a `Max-Age=0` clear otherwise. The sidecar lets the unsealer
    /// skip trial-decrypt when multiple keys are configured; absence (or any
    /// corruption) degrades gracefully to trial-decrypt.
    async fn pointer_cookie_headers(
        &self,
        session_key: Uuid,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        let bundle = self
            .sealer
            .seal(session_key.as_bytes(), b"session_ptr")
            .await
            .map_err(to_session_err)?;
        // See cookie_session.rs for the rationale on reading `key_id()` from
        // the same sealer that just sealed the bundle: stable for single-key
        // ciphers; if multi-key sealers land, switch to `AeadCipherSelector`.
        let kid = self.sealer.key_id();
        if let Some(m) = &self.metrics {
            m.record_encrypt(&self.cookie_name, kid.as_deref());
        }
        let cookie_value = URL_SAFE_NO_PAD.encode(&bundle);
        let attrs = self.cookie_attrs();
        let pointer =
            HeaderValue::from_str(&format!("{}={cookie_value}; {attrs}", self.cookie_name))
                .map_err(to_session_err)?;
        let kid_header = self.build_kid_header(kid.as_deref())?;
        Ok(vec![pointer, kid_header])
    }

    /// Builds the `Set-Cookie` for the kid sidecar (or a `Max-Age=0` clear
    /// when no identity is available — see [`Self::pointer_cookie_headers`]).
    fn build_kid_header(&self, kid: Option<&str>) -> Result<HeaderValue, SessionError> {
        let name = kid_cookie_name(&self.cookie_name);
        let value = match kid {
            Some(k) => format!("{name}={}; {}", encode_kid(k), self.cookie_attrs()),
            None => format!("{name}=; {}; Max-Age=0", self.base_cookie_attrs()),
        };
        HeaderValue::from_str(&value).map_err(to_session_err)
    }

    /// Read and decrypt the pointer cookie to get the session key.
    async fn read_pointer_cookie(&self, headers: &http::HeaderMap) -> Option<Uuid> {
        let encoded = get_cookie(headers, &self.cookie_name)?;

        // A pointer-cookie-shaped value is present — record the outcome.
        let kid = get_kid_cookie(headers, &self.cookie_name);

        let Ok(bundle) = URL_SAFE_NO_PAD.decode(encoded) else {
            self.record_decrypt(kid.as_deref(), &DecryptResult::BadEncoding);
            return None;
        };
        let cipher_match = kid
            .as_deref()
            .map(|k| CipherMatch::builder().kid(k).build());
        let Ok(plaintext) = self
            .unsealer
            .unseal(cipher_match.as_ref(), &bundle, b"session_ptr")
            .await
        else {
            self.record_decrypt(kid.as_deref(), &DecryptResult::DecryptFailed);
            return None;
        };
        // Must be exactly 16 bytes (UUID); anything else is a corrupted cookie.
        if let Ok(bytes) = <[u8; 16]>::try_from(plaintext) {
            self.record_decrypt(kid.as_deref(), &DecryptResult::Ok);
            Some(Uuid::from_bytes(bytes))
        } else {
            self.record_decrypt(kid.as_deref(), &DecryptResult::PayloadInvalid);
            None
        }
    }

    fn record_decrypt(&self, kid: Option<&str>, result: &DecryptResult) {
        if let Some(m) = &self.metrics {
            m.record_decrypt(&self.cookie_name, kid, result);
        }
    }
}

// -- Internal methods --

impl<E: ExternalSessionStore> StoreBackedSessionStore<E> {
    pub(crate) async fn create_session(
        &self,
        completed: &crate::grant::CompletedLogin,
        default_lifetime: std::time::Duration,
    ) -> Result<(E::SessionType, Vec<HeaderValue>), SessionError> {
        let persisted = PersistedSessionState {
            session_key: generate_session_key(),
            state: SessionState::from_completed(completed, default_lifetime),
        };

        let session = self
            .external
            .create(persisted, completed)
            .await
            .map_err(to_session_err)?;
        let cookies = self
            .pointer_cookie_headers(session.persisted().session_key)
            .await?;
        Ok((session, cookies))
    }

    pub(crate) async fn load_session(
        &self,
        headers: &http::HeaderMap,
    ) -> Result<Option<E::SessionType>, E::Error> {
        let Some(session_key) = self.read_pointer_cookie(headers).await else {
            return Ok(None);
        };

        self.external.load(session_key).await
    }

    pub(crate) async fn save_session(
        &self,
        session: &E::SessionType,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.external.save(session).await.map_err(to_session_err)?;
        // The pointer cookie's value (the session_key) doesn't change after
        // creation, so subsequent saves don't reissue it. The initial cookie
        // is emitted by `create_session`.
        Ok(vec![])
    }

    pub(crate) async fn touch_session(
        &self,
        session: &E::SessionType,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.external.touch(session).await.map_err(to_session_err)?;
        Ok(vec![])
    }

    pub(crate) async fn delete_session(
        &self,
        session: &E::SessionType,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.external
            .delete(session)
            .await
            .map_err(to_session_err)?;
        // Clear the pointer cookie and the kid sidecar.
        let clear_attrs = format!("{}; Max-Age=0", self.base_cookie_attrs());
        let mut headers = Vec::new();
        if let Ok(v) = HeaderValue::from_str(&format!("{}=; {clear_attrs}", self.cookie_name)) {
            headers.push(v);
        }
        let kid_name = kid_cookie_name(&self.cookie_name);
        if let Ok(v) = HeaderValue::from_str(&format!("{kid_name}=; {clear_attrs}")) {
            headers.push(v);
        }
        Ok(headers)
    }
}

impl<E: ExternalSessionStore> crate::session::sealed::Sealed for StoreBackedSessionStore<E> {}

impl<E: ExternalSessionStore> SessionDriver for StoreBackedSessionStore<E> {
    type SessionType = E::SessionType;
    type LoadError = E::Error;

    async fn create(
        &self,
        completed: crate::grant::CompletedLogin,
        default_lifetime: std::time::Duration,
        _headers: &http::HeaderMap,
    ) -> Result<(E::SessionType, Vec<HeaderValue>), SessionError> {
        self.create_session(&completed, default_lifetime).await
    }

    async fn load(&self, headers: &http::HeaderMap) -> Result<Option<E::SessionType>, E::Error> {
        self.load_session(headers).await
    }

    async fn save(
        &self,
        session: &E::SessionType,
        _headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.save_session(session).await
    }

    async fn touch(
        &self,
        session: &E::SessionType,
        _headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.touch_session(session).await
    }

    async fn delete(
        &self,
        session: &E::SessionType,
        _headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.delete_session(session).await
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use huskarl::core::{
        crypto::cipher::BoxedAeadCipher,
        secrets::{Secret, SecretBytes, SecretOutput},
    };
    use huskarl_crypto_native::aead::{AesGcmKey, AesGcmKeyType};

    use super::*;
    use crate::session_state::{Session, SessionState};

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

    #[derive(Clone)]
    struct MinimalSession {
        persisted: PersistedSessionState,
    }

    impl Session for MinimalSession {
        fn state(&self) -> &SessionState {
            self.persisted.state()
        }
        fn set_state(&mut self, s: SessionState) {
            self.persisted.set_state(s);
        }
    }

    impl PersistedSession for MinimalSession {
        fn persisted(&self) -> &PersistedSessionState {
            &self.persisted
        }
        fn persisted_mut(&mut self) -> &mut PersistedSessionState {
            &mut self.persisted
        }
    }

    struct MinimalExternalStore(MinimalSession);

    impl ExternalSessionStore for MinimalExternalStore {
        type SessionType = MinimalSession;
        type Error = Infallible;

        async fn create(
            &self,
            _: PersistedSessionState,
            _: &crate::grant::CompletedLogin,
        ) -> Result<MinimalSession, Infallible> {
            Ok(self.0.clone())
        }

        async fn load(&self, _: Uuid) -> Result<Option<MinimalSession>, Infallible> {
            Ok(Some(self.0.clone()))
        }

        async fn save(&self, _: &MinimalSession) -> Result<(), Infallible> {
            Ok(())
        }

        async fn touch(&self, _: &MinimalSession) -> Result<(), Infallible> {
            Ok(())
        }

        async fn delete(&self, _: &MinimalSession) -> Result<(), Infallible> {
            Ok(())
        }
    }

    fn test_session() -> MinimalSession {
        let now = std::time::SystemTime::now();
        MinimalSession {
            persisted: PersistedSessionState {
                session_key: Uuid::now_v7(),
                state: SessionState::builder()
                    .token_expiry(now + std::time::Duration::from_hours(1))
                    .created_at(now)
                    .last_active(now)
                    .build(),
            },
        }
    }

    #[tokio::test]
    async fn touch_returns_no_cookies() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher().await)
            .cookie_name("session")
            .secure(true)
            .cookie_path("/")
            .build();

        let headers = store.touch_session(&session).await.unwrap();

        assert!(
            headers.is_empty(),
            "touch should not re-emit the pointer cookie"
        );
    }

    #[tokio::test]
    async fn pointer_cookie_roundtrips_uuid() {
        let session = test_session();
        let original_key = session.persisted.session_key;
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher().await)
            .cookie_name("session")
            .secure(true)
            .cookie_path("/")
            .build();

        // Seal a pointer cookie, then read it back through the request-side path.
        let headers_out = store.pointer_cookie_headers(original_key).await.unwrap();
        // The pointer cookie is the one whose value is non-empty (the kid
        // sidecar is a Max-Age=0 clear for the no-identity test cipher).
        let pointer = headers_out
            .iter()
            .find(|h| {
                let s = h.to_str().unwrap();
                let value_part = s.split(';').next().unwrap();
                let (name, value) = value_part.split_once('=').unwrap();
                name.trim() == "session" && !value.is_empty()
            })
            .expect("pointer cookie present");
        let cookie_value = pointer
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .split_once('=')
            .unwrap()
            .1;
        let mut req_headers = http::HeaderMap::new();
        req_headers.insert(
            http::header::COOKIE,
            format!("session={cookie_value}").parse().unwrap(),
        );

        let recovered = store
            .read_pointer_cookie(&req_headers)
            .await
            .expect("decodes");
        assert_eq!(recovered, original_key);
    }

    async fn test_cipher_with_kid(kid: &str) -> BoxedAeadCipher {
        let kid_owned = kid.to_owned();
        let key = AesGcmKey::from_secret(
            AesGcmKeyType::Aes256,
            TestSecret(SecretBytes::new(vec![0u8; 32])),
            move |_| Some(kid_owned.clone()),
        )
        .await
        .unwrap();
        BoxedAeadCipher::new(key)
    }

    #[tokio::test]
    async fn pointer_cookie_emits_kid_sidecar_when_cipher_has_identity() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher_with_kid("kid-7").await)
            .cookie_name("session")
            .secure(true)
            .cookie_path("/")
            .build();

        let headers_out = store
            .pointer_cookie_headers(session.persisted.session_key)
            .await
            .unwrap();
        let expected_value = URL_SAFE_NO_PAD.encode("kid-7".as_bytes());
        let sidecar_set = headers_out.iter().any(|h| {
            let s = h.to_str().unwrap();
            s.starts_with(&format!("session.kid={expected_value};"))
        });
        assert!(
            sidecar_set,
            "expected kid sidecar set to base64url(identity)"
        );
    }

    #[tokio::test]
    async fn delete_clears_pointer_and_kid_sidecar() {
        let session = test_session();
        let store = StoreBackedSessionStore::builder()
            .external(MinimalExternalStore(session.clone()))
            .cipher(test_cipher().await)
            .cookie_name("session")
            .secure(true)
            .cookie_path("/")
            .build();

        let clears = store.delete_session(&session).await.unwrap();
        let bare = clears.iter().any(|h| {
            let s = h.to_str().unwrap();
            s.starts_with("session=;") && s.contains("Max-Age=0")
        });
        let kid = clears.iter().any(|h| {
            let s = h.to_str().unwrap();
            s.starts_with("session.kid=;") && s.contains("Max-Age=0")
        });
        assert!(bare, "expected pointer cookie clear");
        assert!(kid, "expected kid sidecar clear");
    }

    // ── SessionCookieMetrics ──────────────────────────────────────────────

    use std::sync::{Arc, Mutex};

    use crate::metrics::{DecryptResult, SessionCookieMetrics};

    #[derive(Default)]
    struct RecordingMetrics {
        encrypts: Mutex<Vec<Option<String>>>,
        decrypts: Mutex<Vec<(Option<String>, &'static str)>>,
    }

    impl SessionCookieMetrics for RecordingMetrics {
        fn record_decrypt(&self, _: &str, kid: Option<&str>, result: &DecryptResult) {
            self.decrypts
                .lock()
                .unwrap()
                .push((kid.map(str::to_owned), result.as_str()));
        }
        fn record_encrypt(&self, _: &str, kid: Option<&str>) {
            self.encrypts.lock().unwrap().push(kid.map(str::to_owned));
        }
    }

    impl RecordingMetrics {
        fn encrypts(&self) -> Vec<Option<String>> {
            self.encrypts.lock().unwrap().clone()
        }
        fn decrypts(&self) -> Vec<(Option<String>, &'static str)> {
            self.decrypts.lock().unwrap().clone()
        }
    }

    fn test_session_and_store() -> (MinimalSession, MinimalExternalStore) {
        let s = test_session();
        (s.clone(), MinimalExternalStore(s))
    }

    #[tokio::test]
    async fn metrics_pointer_cookie_records_encrypt() {
        let (session, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher().await)
            .cookie_name("session")
            .secure(true)
            .cookie_path("/")
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        store
            .pointer_cookie_headers(session.persisted.session_key)
            .await
            .unwrap();
        assert_eq!(m.encrypts(), vec![None]);
    }

    #[tokio::test]
    async fn metrics_pointer_cookie_records_kid_when_cipher_has_identity() {
        let (session, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("session")
            .secure(true)
            .cookie_path("/")
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        store
            .pointer_cookie_headers(session.persisted.session_key)
            .await
            .unwrap();
        assert_eq!(m.encrypts(), vec![Some("v5".to_owned())]);
    }

    #[tokio::test]
    async fn metrics_read_pointer_cookie_absent_is_silent() {
        let (_, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher().await)
            .cookie_name("session")
            .secure(true)
            .cookie_path("/")
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        store.read_pointer_cookie(&http::HeaderMap::new()).await;
        assert!(m.decrypts().is_empty());
    }

    #[tokio::test]
    async fn metrics_read_pointer_cookie_bad_encoding() {
        let (_, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher().await)
            .cookie_name("session")
            .secure(true)
            .cookie_path("/")
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "session=not!!valid!!base64".parse().unwrap(),
        );
        store.read_pointer_cookie(&headers).await;
        assert_eq!(m.decrypts(), vec![(None, "bad_encoding")]);
    }

    #[tokio::test]
    async fn metrics_read_pointer_cookie_tampered_records_decrypt_failed() {
        let (_, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher().await)
            .cookie_name("session")
            .secure(true)
            .cookie_path("/")
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "session=AAAAAAAAAAAA".parse().unwrap(),
        );
        store.read_pointer_cookie(&headers).await;
        assert_eq!(m.decrypts(), vec![(None, "decrypt_failed")]);
    }

    #[tokio::test]
    async fn metrics_read_pointer_cookie_payload_invalid_when_not_16_bytes() {
        let (_, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher().await)
            .cookie_name("session")
            .secure(true)
            .cookie_path("/")
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        // Seal 17 bytes under session_ptr AAD — AEAD passes but the UUID
        // conversion ([u8; 16]) fails, exercising PayloadInvalid.
        let bundle = AeadV1Sealer::new(test_cipher().await)
            .seal(&[0u8; 17], b"session_ptr")
            .await
            .unwrap();
        let encoded = URL_SAFE_NO_PAD.encode(&bundle);
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            format!("session={encoded}").parse().unwrap(),
        );
        store.read_pointer_cookie(&headers).await;
        assert_eq!(m.decrypts(), vec![(None, "payload_invalid")]);
    }

    #[tokio::test]
    async fn metrics_read_pointer_cookie_success_records_ok_with_kid() {
        let (session, external) = test_session_and_store();
        let m = Arc::new(RecordingMetrics::default());
        let store = StoreBackedSessionStore::builder()
            .external(external)
            .cipher(test_cipher_with_kid("v5").await)
            .cookie_name("session")
            .secure(true)
            .cookie_path("/")
            .metrics(Arc::clone(&m) as Arc<dyn SessionCookieMetrics>)
            .build();
        let headers_out = store
            .pointer_cookie_headers(session.persisted.session_key)
            .await
            .unwrap();
        // Simulate the browser sending back both the pointer cookie and the kid sidecar.
        let pairs: String = headers_out
            .iter()
            .filter_map(|h| {
                let s = h.to_str().ok()?;
                let pair = s.split(';').next()?;
                let (_, v) = pair.split_once('=')?;
                (!v.is_empty()).then(|| pair.to_owned())
            })
            .collect::<Vec<_>>()
            .join("; ");
        let mut req = http::HeaderMap::new();
        if !pairs.is_empty() {
            req.insert(http::header::COOKIE, pairs.parse().unwrap());
        }
        store.read_pointer_cookie(&req).await;
        assert_eq!(m.decrypts(), vec![(Some("v5".to_owned()), "ok")]);
    }
}
