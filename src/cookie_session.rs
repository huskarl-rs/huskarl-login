//! Cookie-based session storage.
//!
//! [`CookieSessionStore`] encrypts the entire session into chunked browser
//! cookies using AEAD, so no server-side session store is needed. Large
//! payloads are automatically split across multiple cookies (`.0`, `.1`, ...)
//! to stay within browser size limits.

use std::marker::PhantomData;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::HeaderValue;
use huskarl::core::crypto::cipher::{
    AeadSealer, AeadUnsealer, AeadV1Sealer, AeadV1Unsealer, BoxedAeadCipher,
};
use serde::{Deserialize, Serialize};

use crate::{
    cookie::{cookie_attrs, decode_payload, encode_payload},
    grant::CompletedLogin,
    session::{SessionDriver, SessionError, to_session_err},
    session_state::{Session, SessionState},
};

const CHUNK_SIZE: usize = 3800;

/// Trait for cookie session payload types.
///
/// Implement this to store only the fields your application needs in the
/// browser cookie, rather than the full [`SessionState`].
///
/// The type must also implement [`Session`] so the middleware can enforce
/// session policies (lifetime, idle timeout, token refresh).
///
/// # Storing user info from the ID token
///
/// The default [`CookieSession`] does not carry the raw `id_token` JWT or any
/// of its claims (beyond `sub` and `sid` which are needed for logout). To
/// expose user info in handlers, define a custom type that captures just the
/// fields you use:
///
/// ```ignore
/// #[derive(Serialize, Deserialize)]
/// struct MySession {
///     state: SessionState,
///     email: Option<String>,
///     name: Option<String>,
/// }
///
/// impl CookieData for MySession {
///     type Error = std::convert::Infallible;
///     fn from_login(state: SessionState, completed: &CompletedLogin) -> Result<Self, Self::Error> {
///         let claims = completed.id_token_claims();
///         Ok(Self {
///             state,
///             email: claims.and_then(|c| c.email.clone()),
///             name: claims.and_then(|c| c.name.clone()),
///         })
///     }
/// }
/// ```
///
/// For non-standard claims, use `claims.extra.get("name").and_then(|v| v.as_str())`.
///
/// # Storing the `id_token` for RP-initiated logout
///
/// If your `IdP` supports RP-initiated logout and you want clean logout UX
/// (no OP confirmation page), store the `id_token` in your custom type and
/// override [`Session::id_token`]:
///
/// ```ignore
/// impl Session for MySession {
///     fn id_token(&self) -> Option<&IdToken> { self.id_token.as_ref() }
///     // ...other methods
/// }
/// ```
///
/// # Updating custom fields on token refresh
///
/// If any of your custom fields come from a refresh response, override
/// [`Session::apply_refresh`] to update them alongside the [`SessionState`]:
///
/// ```ignore
/// fn apply_refresh(&mut self, token_response: &TokenResponse) {
///     let new_state = self.state().refreshed(token_response);
///     self.set_state(new_state);
///     // update your own fields from token_response here
/// }
/// ```
pub trait CookieData:
    Session + Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static
{
    /// Error type returned by [`from_login`](Self::from_login).
    type Error: std::error::Error + Send + Sync + 'static;

    /// Build a cookie session payload from the framework-prepared `SessionState`
    /// and the completed login.
    ///
    /// `state` already carries the standard token/timing fields (including
    /// `sub`/`sid` extracted from the ID token). Embed it in the returned
    /// type and add any additional fields read from `completed.id_token_claims()`
    /// or `completed.token_response()`.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the implementation can't construct a session
    /// from the available data (e.g. a required claim is missing).
    fn from_login(state: SessionState, completed: &CompletedLogin) -> Result<Self, Self::Error>;
}

/// A session that stores token state encrypted in browser cookies.
///
/// This is the default session type used with [`CookieSessionStore`]. It is a
/// transparent newtype over [`SessionState`], so existing encrypted cookies
/// deserialize correctly.
///
/// For a smaller cookie, define a custom type implementing [`CookieData`] and
/// use `CookieSessionStore<MyType>`.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
pub struct CookieSession(SessionState);

impl Session for CookieSession {
    fn state(&self) -> &SessionState {
        &self.0
    }
    fn set_state(&mut self, state: SessionState) {
        self.0 = state;
    }
}

impl CookieData for CookieSession {
    type Error = std::convert::Infallible;

    fn from_login(state: SessionState, _completed: &CompletedLogin) -> Result<Self, Self::Error> {
        Ok(CookieSession(state))
    }
}

/// A built-in session store that encrypts session data into chunked cookies.
///
/// Large payloads are automatically split across multiple cookies (`.0`, `.1`,
/// etc.) to stay within browser cookie size limits. Decryption failure is
/// treated as "no session" rather than an error.
///
/// The type parameter `C` controls what is stored in the cookie. The default
/// is [`CookieSession`], which stores the full [`SessionState`]. For a smaller
/// cookie, supply a custom type that implements [`CookieData`].
///
/// # Cookie format
///
/// - Cookie name: `{name}.0`, `{name}.1`, etc.
/// - Chunk value: raw base64 of the sealed payload, split across chunks
/// - Attributes: `HttpOnly; SameSite=Lax; Path={path}` plus optional `Secure`
///
/// On read, chunks are concatenated by walking `{name}.0`, `{name}.1`, … until
/// an index is missing. Truncation or stale leftover chunks just produce a
/// payload the AEAD layer can't authenticate, which surfaces as "no session"
/// and triggers a fresh login.
pub struct CookieSessionStore<C = CookieSession> {
    sealer: AeadV1Sealer<BoxedAeadCipher>,
    unsealer: AeadV1Unsealer<BoxedAeadCipher>,
    cookie_name: String,
    secure: bool,
    cookie_path: String,
    _phantom: PhantomData<C>,
}

impl<C> CookieSessionStore<C> {
    /// Creates a new cookie session store.
    ///
    /// - `cipher` -- AEAD cipher for encrypting/decrypting session data
    /// - `cookie_name` -- base name for the session cookies (e.g. `"huskarl_session"`)
    /// - `secure` -- whether to set the `Secure` cookie attribute
    /// - `cookie_path` -- the `Path` cookie attribute (e.g. `"/"`)
    pub fn new(
        cipher: BoxedAeadCipher,
        cookie_name: impl Into<String>,
        secure: bool,
        cookie_path: impl Into<String>,
    ) -> Self {
        Self {
            sealer: AeadV1Sealer::new(cipher.clone()),
            unsealer: AeadV1Unsealer::new(cipher),
            cookie_name: cookie_name.into(),
            secure,
            cookie_path: cookie_path.into(),
            _phantom: PhantomData,
        }
    }

    fn cookie_attrs(&self) -> String {
        cookie_attrs(self.secure, &self.cookie_path)
    }
}

// -- Internal methods --

impl<C: CookieData> CookieSessionStore<C> {
    pub(crate) async fn load_session(&self, headers: &http::HeaderMap) -> Option<C> {
        let chunks = self.collect_session_chunks(headers);
        let raw_encoded = reassemble_chunks(&chunks)?;
        let bundle = URL_SAFE_NO_PAD.decode(&raw_encoded).ok()?;
        let plaintext = self.unsealer.unseal(None, &bundle, b"session").await.ok()?;
        decode_payload(&plaintext).ok()
    }

    /// Scans request `Cookie` headers for `{cookie_name}.N` pairs, returning a
    /// map of chunk index to value. Unrelated cookies are ignored.
    fn collect_session_chunks(
        &self,
        headers: &http::HeaderMap,
    ) -> std::collections::HashMap<usize, String> {
        let mut chunks = std::collections::HashMap::new();
        for value in headers.get_all(http::header::COOKIE) {
            let Ok(s) = value.to_str() else { continue };
            for pair in s.split(';') {
                if let Some((index, val)) = self.parse_chunk_pair(pair) {
                    chunks.insert(index, val);
                }
            }
        }
        chunks
    }

    /// Parses a single `name=value` cookie pair as a chunk if `name` matches
    /// `{cookie_name}.N` for some non-negative integer `N`. The full
    /// `(index, value)` form is what `load_session` needs to reassemble.
    fn parse_chunk_pair(&self, pair: &str) -> Option<(usize, String)> {
        let (k, v) = pair.trim().split_once('=')?;
        Some((self.parse_chunk_index(k)?, v.trim().to_owned()))
    }

    /// Parses just the chunk index from a cookie name. Used by the clear-path,
    /// which needs to know which `{name}.N` slots the browser currently has
    /// but doesn't care about their values.
    fn parse_chunk_index(&self, name: &str) -> Option<usize> {
        let suffix = name.trim().strip_prefix(&self.cookie_name)?;
        suffix.strip_prefix('.')?.parse::<usize>().ok()
    }

    /// Invokes `f` once with each `{cookie_name}.N` index the browser sent on
    /// this request. The callback shape avoids materializing a `Vec<usize>`
    /// when the only reason for enumerating is to emit one `Set-Cookie` per
    /// match — and we only ever enumerate on a save/touch/delete path that's
    /// already emitting cookies, so this is the one walk per write.
    fn for_each_request_chunk_index(&self, headers: &http::HeaderMap, mut f: impl FnMut(usize)) {
        for value in headers.get_all(http::header::COOKIE) {
            let Ok(s) = value.to_str() else { continue };
            for pair in s.split(';') {
                let Some((name, _)) = pair.trim().split_once('=') else {
                    continue;
                };
                if let Some(idx) = self.parse_chunk_index(name) {
                    f(idx);
                }
            }
        }
    }

    pub(crate) async fn save_session(
        &self,
        session: &C,
        request_headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        let payload = encode_payload(session)?;
        let bundle = self
            .sealer
            .seal(&payload, b"session")
            .await
            .map_err(to_session_err)?;
        let cookie_value = URL_SAFE_NO_PAD.encode(&bundle);
        let chunks = split_into_chunks(&cookie_value);
        let num_chunks = chunks.len();

        let attrs = self.cookie_attrs();
        let mut headers = Vec::with_capacity(num_chunks + 1);
        for (i, chunk) in chunks.iter().enumerate() {
            headers.push(self.build_chunk_header(i, chunk, &attrs)?);
        }
        self.append_clears_for_leftover_chunks(&mut headers, num_chunks, request_headers, &attrs);
        // Clear the old base name in case it was left over from a previous version.
        if let Ok(v) = HeaderValue::from_str(&format!("{}=; {attrs}; Max-Age=0", self.cookie_name))
        {
            headers.push(v);
        }
        Ok(headers)
    }

    /// Builds the `Set-Cookie` header for chunk `i`. All chunks carry the raw
    /// base64 payload — chunk count is implied by the presence of `{name}.0`,
    /// `{name}.1`, … in the request and inferred by the reader.
    fn build_chunk_header(
        &self,
        i: usize,
        chunk: &str,
        attrs: &str,
    ) -> Result<HeaderValue, SessionError> {
        HeaderValue::from_str(&format!("{}.{i}={chunk}; {attrs}", self.cookie_name))
            .map_err(to_session_err)
    }

    /// Appends `Max-Age=0` clears for every chunk slot the browser sent that
    /// the current save is not going to overwrite (indices `>= num_chunks`).
    /// Reads the request rather than walking a fixed range, so there is no
    /// chunk-count cap to grow over time and no orphaned slots after a shrink.
    fn append_clears_for_leftover_chunks(
        &self,
        headers: &mut Vec<HeaderValue>,
        num_chunks: usize,
        request_headers: &http::HeaderMap,
        attrs: &str,
    ) {
        let cookie_name = &self.cookie_name;
        self.for_each_request_chunk_index(request_headers, |idx| {
            if idx >= num_chunks
                && let Ok(v) =
                    HeaderValue::from_str(&format!("{cookie_name}.{idx}=; {attrs}; Max-Age=0"))
            {
                headers.push(v);
            }
        });
    }

    pub(crate) fn delete_headers(&self, request_headers: &http::HeaderMap) -> Vec<HeaderValue> {
        let attrs = self.cookie_attrs();
        let cookie_name = &self.cookie_name;
        let mut headers = Vec::new();
        // Clear the bare base name (legacy single-cookie format).
        if let Ok(v) = HeaderValue::from_str(&format!("{cookie_name}=; {attrs}; Max-Age=0")) {
            headers.push(v);
        }
        // Clear every chunk slot the browser currently has — we don't have
        // a fixed cap to sweep, but we don't need one: the request tells us
        // exactly which slots exist.
        self.for_each_request_chunk_index(request_headers, |idx| {
            if let Ok(v) =
                HeaderValue::from_str(&format!("{cookie_name}.{idx}=; {attrs}; Max-Age=0"))
            {
                headers.push(v);
            }
        });
        headers
    }
}

impl<C: CookieData> crate::session::sealed::Sealed for CookieSessionStore<C> {}

impl<C: CookieData> SessionDriver for CookieSessionStore<C> {
    type SessionType = C;
    type LoadError = std::convert::Infallible;

    async fn create(
        &self,
        completed: CompletedLogin,
        default_lifetime: std::time::Duration,
        headers: &http::HeaderMap,
    ) -> Result<(C, Vec<HeaderValue>), SessionError> {
        let state = SessionState::from_completed(&completed, default_lifetime);
        let session = C::from_login(state, &completed).map_err(to_session_err)?;
        let cookies = self.save_session(&session, headers).await?;
        Ok((session, cookies))
    }

    async fn load(&self, headers: &http::HeaderMap) -> Result<Option<C>, std::convert::Infallible> {
        Ok(self.load_session(headers).await)
    }

    async fn save(
        &self,
        session: &C,
        headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.save_session(session, headers).await
    }

    /// Re-emits the chunked session cookies so that the updated `last_active`
    /// timestamp reaches the browser. Cookie sessions have no server-side TTL,
    /// so a touch is implemented as a full re-save.
    ///
    /// This means every `Touch` pays the cost of an AEAD seal + emitting the
    /// session-cookie chunks on the response. Pair with a non-zero
    /// [`touch_min_interval`](crate::LoginConfig::touch_min_interval) (e.g. a
    /// fraction of [`idle_timeout`](crate::LoginConfig::idle_timeout)) so this
    /// only fires periodically instead of on every authenticated request.
    async fn touch(
        &self,
        session: &C,
        headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        self.save_session(session, headers).await
    }

    async fn delete(
        &self,
        _session: &C,
        headers: &http::HeaderMap,
    ) -> Result<Vec<HeaderValue>, SessionError> {
        Ok(self.delete_headers(headers))
    }
}

/// Splits the encoded session string into [`CHUNK_SIZE`]-byte slices. The
/// input is URL-safe base64 (ASCII), so byte chunks are valid UTF-8.
fn split_into_chunks(cookie_value: &str) -> Vec<&str> {
    cookie_value
        .as_bytes()
        .chunks(CHUNK_SIZE)
        .map(|c| std::str::from_utf8(c).expect("base64 output is ASCII"))
        .collect()
}

/// Reassembles the chunked session payload by concatenating `{name}.0`,
/// `{name}.1`, … until a gap is found. Returns `None` if chunk 0 is absent.
/// Truncation, gaps, and stale leftover chunks all produce a payload the AEAD
/// layer can't authenticate — caller treats that as "no session" and the user
/// re-logs in.
///
/// The loop is bounded by the size of the request (the chunk map only contains
/// what the browser actually sent), which is in turn bounded by the HTTP layer's
/// request-size limit.
fn reassemble_chunks(chunks: &std::collections::HashMap<usize, String>) -> Option<String> {
    let first = chunks.get(&0)?;
    let mut raw_encoded = String::with_capacity(chunks.len() * CHUNK_SIZE);
    raw_encoded.push_str(first);
    let mut i = 1;
    while let Some(chunk) = chunks.get(&i) {
        raw_encoded.push_str(chunk);
        i += 1;
    }
    Some(raw_encoded)
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        time::{Duration, SystemTime},
    };

    use http::HeaderMap;
    use huskarl::core::secrets::{Secret, SecretBytes, SecretOutput};
    use huskarl_crypto_native::aead::{AesGcmKey, AesGcmKeyType};

    use super::*;
    use crate::session_state::SessionState;

    // ── Cipher / fixtures ─────────────────────────────────────────────────

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

    fn test_state() -> SessionState {
        let now = SystemTime::now();
        SessionState::builder()
            .token_expiry(now + Duration::from_hours(1))
            .created_at(now)
            .last_active(now)
            .build()
    }

    async fn test_store() -> CookieSessionStore<CookieSession> {
        CookieSessionStore::new(test_cipher().await, "huskarl_session", true, "/")
    }

    /// Builds a `Cookie:` header from the `Set-Cookie` values a save produced,
    /// stripping cookie attributes so it looks like an actual request cookie
    /// header sent by the browser.
    fn request_cookies_from_set_cookies(set_cookies: &[HeaderValue]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let mut pairs = Vec::new();
        for v in set_cookies {
            let s = v.to_str().unwrap();
            // Skip Max-Age=0 clears (empty value).
            let pair = s.split(';').next().unwrap();
            let (_name, value) = pair.split_once('=').unwrap();
            if !value.is_empty() {
                pairs.push(pair.to_owned());
            }
        }
        if !pairs.is_empty() {
            headers.insert(http::header::COOKIE, pairs.join("; ").parse().unwrap());
        }
        headers
    }

    /// A request `Cookie:` header carrying chunk slots `.0` through `.{n-1}`.
    /// Used to exercise the clear-leftover-chunks path on save without going
    /// through a real round-trip.
    fn request_with_chunk_slots(n: usize) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if n > 0 {
            let pairs: Vec<String> = (0..n).map(|i| format!("huskarl_session.{i}=x")).collect();
            headers.insert(http::header::COOKIE, pairs.join("; ").parse().unwrap());
        }
        headers
    }

    // ── Cookie attribute tests ────────────────────────────────────────────

    #[tokio::test]
    async fn save_emits_chunk_zero_with_raw_base64_value() {
        let store = test_store().await;
        let session = CookieSession(test_state());
        let cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();

        let chunk0 = cookies[0].to_str().unwrap();
        assert!(chunk0.starts_with("huskarl_session.0="), "got: {chunk0}");
        let value = chunk0.split('=').nth(1).unwrap().split(';').next().unwrap();
        // URL-safe base64 has no ':' — chunk 0 is now raw payload, no prefix.
        assert!(
            !value.contains(':'),
            "chunk 0 must not carry a delimiter prefix: {value}"
        );
        assert!(!value.is_empty(), "chunk 0 must carry payload data");
    }

    #[tokio::test]
    async fn save_sets_security_attributes() {
        let store = test_store().await;
        let session = CookieSession(test_state());
        let cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let chunk0 = cookies[0].to_str().unwrap();
        assert!(chunk0.contains("HttpOnly"));
        assert!(chunk0.contains("SameSite=Lax"));
        assert!(chunk0.contains("Secure"));
        assert!(chunk0.contains("Path=/"));
    }

    #[tokio::test]
    async fn save_emits_no_chunk_clears_when_request_has_none() {
        // Without any request-side chunks to clear, the save emits only the
        // new chunk cookies plus the bare-name legacy clear.
        let store = test_store().await;
        let session = CookieSession(test_state());
        let cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let bare_clear = cookies
            .iter()
            .filter(|c| {
                let s = c.to_str().unwrap();
                s.starts_with("huskarl_session=;") && s.contains("Max-Age=0")
            })
            .count();
        assert_eq!(bare_clear, 1, "expected exactly the legacy bare-name clear");
        let chunk_clears = cookies
            .iter()
            .filter(|c| {
                let s = c.to_str().unwrap();
                s.contains("huskarl_session.") && s.contains("Max-Age=0")
            })
            .count();
        assert_eq!(
            chunk_clears, 0,
            "no chunk slots to clear without prior chunks"
        );
    }

    #[tokio::test]
    async fn save_clears_only_request_chunks_above_new_count() {
        // Browser sent chunks .0 through .4 from a prior larger session.
        // New save fits in a single chunk → must emit clears for slots .1-.4,
        // and NOT clear slot .0 (it's about to be overwritten with new data).
        let store = test_store().await;
        let session = CookieSession(test_state());
        let req = request_with_chunk_slots(5);
        let cookies = store.save_session(&session, &req).await.unwrap();

        for stale in 1..5 {
            let cleared = cookies.iter().any(|c| {
                let s = c.to_str().unwrap();
                s.starts_with(&format!("huskarl_session.{stale}=;")) && s.contains("Max-Age=0")
            });
            assert!(cleared, "expected clear for stale slot .{stale}");
        }
        // Slot .0 is being overwritten with data, not cleared.
        let zero_clear = cookies.iter().any(|c| {
            let s = c.to_str().unwrap();
            s.starts_with("huskarl_session.0=;") && s.contains("Max-Age=0")
        });
        assert!(
            !zero_clear,
            "slot .0 must not be cleared — it's overwritten with new data",
        );
    }

    // ── Save / load roundtrip ─────────────────────────────────────────────

    /// Sanity-check that the CBOR payload is meaningfully smaller than the
    /// equivalent JSON payload. Cookies are sent on every authenticated
    /// request, so this directly affects bandwidth.
    #[test]
    fn cbor_payload_is_smaller_than_json() {
        let state = test_state();
        let session = CookieSession(state);

        let json = serde_json::to_vec(&session).unwrap();
        let mut cbor = Vec::new();
        ciborium::into_writer(&session, &mut cbor).unwrap();

        assert!(
            cbor.len() < json.len(),
            "CBOR ({}) should be smaller than JSON ({})",
            cbor.len(),
            json.len()
        );
        // Allow some slack but flag if savings drop below ~15%.
        assert!(
            cbor.len() * 100 / json.len() <= 85,
            "expected CBOR <=85% of JSON size, got {}% ({} / {})",
            cbor.len() * 100 / json.len(),
            cbor.len(),
            json.len()
        );
    }

    #[tokio::test]
    async fn save_then_load_roundtrips_state() {
        let store = test_store().await;
        let original_state = test_state();
        let session = CookieSession(original_state.clone());

        let set_cookies = store
            .save_session(&session, &HeaderMap::new())
            .await
            .unwrap();
        let req_headers = request_cookies_from_set_cookies(&set_cookies);
        let loaded = store
            .load_session(&req_headers)
            .await
            .expect("session loads");

        // SessionState serializes timestamps as unix seconds, so compare at
        // second precision.
        let secs = |t: SystemTime| t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        assert_eq!(
            secs(loaded.state().token_expiry),
            secs(original_state.token_expiry)
        );
        assert_eq!(
            secs(loaded.state().created_at),
            secs(original_state.created_at)
        );
        assert_eq!(
            secs(loaded.state().last_active),
            secs(original_state.last_active)
        );
    }

    #[tokio::test]
    async fn load_returns_none_when_no_cookies() {
        let store = test_store().await;
        assert!(store.load_session(&HeaderMap::new()).await.is_none());
    }

    #[tokio::test]
    async fn load_returns_none_for_unrelated_cookies() {
        let store = test_store().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "other=value; another=42".parse().unwrap(),
        );
        assert!(store.load_session(&headers).await.is_none());
    }

    #[tokio::test]
    async fn load_returns_none_when_continuation_chunk_missing() {
        // Gap between chunks 0 and 2: reassembly stops at chunk 1's gap,
        // producing only chunk 0's data, which then fails AEAD authentication.
        let store = test_store().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "huskarl_session.0=AAAA; huskarl_session.2=BBBB"
                .parse()
                .unwrap(),
        );
        assert!(store.load_session(&headers).await.is_none());
    }

    #[tokio::test]
    async fn load_returns_none_when_decryption_fails() {
        let store = test_store().await;
        let mut headers = HeaderMap::new();
        // Valid base64 but won't decrypt under the test cipher.
        headers.insert(
            http::header::COOKIE,
            "huskarl_session.0=AAAAAAAAAAAA".parse().unwrap(),
        );
        assert!(store.load_session(&headers).await.is_none());
    }

    // ── delete ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn delete_emits_clears_for_every_chunk_slot_the_request_sent() {
        let store = test_store().await;
        let req = request_with_chunk_slots(5);
        let clears = store.delete_headers(&req);
        // Bare name + 5 chunk slots (.0 through .4).
        assert_eq!(clears.len(), 6);
        for c in &clears {
            assert!(c.to_str().unwrap().contains("Max-Age=0"));
        }
        for i in 0..5 {
            let found = clears.iter().any(|c| {
                let s = c.to_str().unwrap();
                s.starts_with(&format!("huskarl_session.{i}=;"))
            });
            assert!(found, "expected clear for slot .{i}");
        }
    }

    #[tokio::test]
    async fn delete_emits_only_legacy_clear_when_request_has_no_chunks() {
        // Edge case: a logout with no session cookies present still emits the
        // bare-name clear (defense against legacy single-cookie format) but
        // doesn't sweep any speculative chunk slots.
        let store = test_store().await;
        let clears = store.delete_headers(&HeaderMap::new());
        assert_eq!(clears.len(), 1);
        let s = clears[0].to_str().unwrap();
        assert!(s.starts_with("huskarl_session=;"), "got: {s}");
        assert!(s.contains("Max-Age=0"));
    }

    // ── parse_chunk_pair ──────────────────────────────────────────────────

    #[tokio::test]
    async fn parse_chunk_pair_matches_indexed_cookie() {
        let store = test_store().await;
        assert_eq!(
            store.parse_chunk_pair("huskarl_session.3=abc"),
            Some((3, "abc".to_owned()))
        );
    }

    #[tokio::test]
    async fn parse_chunk_pair_rejects_unrelated_cookie() {
        let store = test_store().await;
        assert_eq!(store.parse_chunk_pair("other=value"), None);
    }

    #[tokio::test]
    async fn parse_chunk_pair_rejects_base_name_without_index() {
        let store = test_store().await;
        // "huskarl_session=foo" — missing `.N` suffix.
        assert_eq!(store.parse_chunk_pair("huskarl_session=foo"), None);
    }

    #[tokio::test]
    async fn parse_chunk_pair_rejects_non_numeric_suffix() {
        let store = test_store().await;
        assert_eq!(store.parse_chunk_pair("huskarl_session.abc=foo"), None);
    }

    #[tokio::test]
    async fn parse_chunk_pair_accepts_any_index_within_usize() {
        // No artificial cap: the natural bound is "fits in the request" because
        // the chunk map and the reassembler walk top out at what the browser
        // could send. Indices are usize, so an attacker-crafted huge index
        // still parses; the reassembler stops at the first gap regardless.
        let store = test_store().await;
        assert_eq!(
            store.parse_chunk_pair("huskarl_session.42=foo"),
            Some((42, "foo".to_owned()))
        );
        assert_eq!(
            store.parse_chunk_pair("huskarl_session.1000000=foo"),
            Some((1_000_000, "foo".to_owned()))
        );
    }

    // ── reassemble_chunks ─────────────────────────────────────────────────

    #[test]
    fn reassemble_returns_none_when_chunk_zero_missing() {
        let mut chunks = std::collections::HashMap::new();
        chunks.insert(1, "c1".to_owned());
        assert!(reassemble_chunks(&chunks).is_none());
    }

    #[test]
    fn reassemble_concatenates_contiguous_chunks() {
        let mut chunks = std::collections::HashMap::new();
        chunks.insert(0, "c0".to_owned());
        chunks.insert(1, "c1".to_owned());
        chunks.insert(2, "c2".to_owned());
        assert_eq!(reassemble_chunks(&chunks).as_deref(), Some("c0c1c2"));
    }

    #[test]
    fn reassemble_stops_at_first_gap() {
        // Chunks 0, 1 present; 2 missing; 3 present. The reader stops at 2,
        // dropping the orphan chunk 3 (likely a stale leftover from an older
        // larger session). AEAD on the truncated payload will then fail.
        let mut chunks = std::collections::HashMap::new();
        chunks.insert(0, "c0".to_owned());
        chunks.insert(1, "c1".to_owned());
        chunks.insert(3, "stale".to_owned());
        assert_eq!(reassemble_chunks(&chunks).as_deref(), Some("c0c1"));
    }

    #[test]
    fn reassemble_handles_many_chunks() {
        let mut chunks = std::collections::HashMap::new();
        for i in 0..64 {
            chunks.insert(i, format!("c{i}"));
        }
        let out = reassemble_chunks(&chunks).expect("contiguous chunks reassemble");
        assert!(out.starts_with("c0"));
        assert!(out.ends_with("c63"));
    }
}
