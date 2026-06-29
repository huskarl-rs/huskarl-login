//! Cookie helpers for the login layer: reading cookies ([`get_cookie`]), the
//! validated [`CookieName`] newtype, login-state and session cookie naming
//! with the right security prefix (`__Host-`/`__Secure-`/none), and CBOR
//! encoding for the payloads sealed into the session and login-state cookies.

use std::{borrow::Cow, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderValue, header};
use huskarl::core::crypto::{
    KeyMatchStrength,
    cipher::{AeadCipher, AeadEncryptor as _, AeadUnsealer, AeadV1Cipher, CipherMatch},
};
use serde::{Serialize, de::DeserializeOwned};
use snafu::Snafu;

use crate::{
    config::RoutePath,
    metrics::{DecryptResult, SessionCookieMetrics},
    session::{SessionError, SessionErrorKind},
};

/// The v1 bundle cipher (over a type-erased AEAD cipher) used to seal cookies.
pub(crate) type SessionCipher = AeadV1Cipher<Arc<dyn AeadCipher>>;

/// Default `Max-Age` for session cookies (400 days, the browser ceiling).
pub(crate) const DEFAULT_COOKIE_MAX_AGE: Duration = Duration::from_hours(9600);

/// Encodes a cookie payload as CBOR (before AEAD-sealing and base64-encoding).
pub(crate) fn encode_payload<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut bytes = Vec::with_capacity(128);
    ciborium::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

/// Decodes a CBOR cookie payload written by [`encode_payload`].
pub(crate) fn decode_payload<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, ciborium::de::Error<std::io::Error>> {
    ciborium::from_reader(bytes)
}

pub(crate) const DEFAULT_LOGIN_COOKIE_PREFIX: &str = "huskarl_login";

/// Maximum accepted length of an OAuth `state` value (256 bytes).
pub(crate) const MAX_OAUTH_STATE_LEN: usize = 256;

/// Returns `true` if `state` is safe to splice into a cookie name: non-empty,
/// within the maximum length, and only base64url chars (`A-Za-z0-9-_`).
#[must_use]
pub fn is_valid_oauth_state(state: &str) -> bool {
    !state.is_empty()
        && state.len() <= MAX_OAUTH_STATE_LEN
        && state
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Returns the security-prefixed login-state cookie name for OAuth `state`,
/// which must satisfy [`is_valid_oauth_state`] (debug-asserted).
#[must_use]
pub fn login_state_cookie_name(state: &str, secure: bool, path: &str, prefix: &str) -> String {
    debug_assert!(
        is_valid_oauth_state(state),
        "login_state_cookie_name called with state that is not URL-safe base64url"
    );
    format!(
        "{}{state}",
        login_state_cookie_name_prefix(secure, path, prefix)
    )
}

/// Returns the name prefix shared by every login-state cookie under the given
/// security settings: `{security_prefix}{prefix}_`.
pub(crate) fn login_state_cookie_name_prefix(secure: bool, path: &str, prefix: &str) -> String {
    let security_prefix = if secure {
        if path == "/" { "__Host-" } else { "__Secure-" }
    } else {
        ""
    };
    format!("{security_prefix}{prefix}_")
}

/// Returns the session cookie base name, prepending `__Host-` when `secure`
/// and `path` is `"/"`. Names already prefixed are left untouched.
pub(crate) fn session_cookie_name(name: &str, secure: bool, path: &str) -> String {
    if secure && path == "/" && !name.starts_with("__Host-") && !name.starts_with("__Secure-") {
        format!("__Host-{name}")
    } else {
        name.to_owned()
    }
}

/// Error returned when a configured session cookie name is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[snafu(display("invalid cookie name {name:?}: {reason}"))]
pub struct InvalidCookieName {
    /// The offending name.
    pub name: String,
    /// Why the name was rejected.
    pub reason: &'static str,
}

/// A validated session cookie base name: non-empty and restricted to
/// `[A-Za-z0-9_-]`. Cookie-name counterpart to [`RoutePath`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieName(String);

impl CookieName {
    /// Validates `name` (non-empty, `[A-Za-z0-9_-]`) and wraps it. `.` is
    /// excluded as it separates the chunk/kid-sidecar namespace.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCookieName`] if `name` is empty or has a disallowed char.
    pub fn new(name: impl Into<String>) -> Result<Self, InvalidCookieName> {
        let name = name.into();
        if name.is_empty() {
            return Err(InvalidCookieName {
                name,
                reason: "must not be empty",
            });
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(InvalidCookieName {
                name,
                reason: "must contain only ASCII letters, digits, '_', or '-'",
            });
        }
        Ok(Self(name))
    }

    /// The validated name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CookieName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for CookieName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// `TryFrom`, not `From`: validation is fallible. Mirrors [`CookieName::new`]
// for `?`/`try_into()` callers.
impl TryFrom<String> for CookieName {
    type Error = InvalidCookieName;
    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl TryFrom<&str> for CookieName {
    type Error = InvalidCookieName;
    fn try_from(name: &str) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

// Enables `"session".parse::<CookieName>()` and inference at call sites that
// expect a `CookieName` (e.g. the `cookie_name` builder setters).
impl std::str::FromStr for CookieName {
    type Err = InvalidCookieName;
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::new(name)
    }
}

/// Returns `"HttpOnly; SameSite=Lax; Path={path}"`, appending `; Secure` when
/// `secure` is `true`.
#[must_use]
pub fn cookie_attrs(secure: bool, path: &str) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("HttpOnly; SameSite=Lax; Path={path}{secure}")
}

/// Shared cookie-sealing machinery behind both built-in session stores: AEAD
/// seal, security-prefixed naming, kid sidecar, and encrypt/decrypt metrics.
pub(crate) struct CookieSealer {
    /// The v1-bundle cipher used to seal/unseal cookie values.
    pub(crate) cipher: SessionCipher,
    /// The raw cipher behind [`cipher`](Self::cipher), handed back unwrapped by
    /// [`SessionDriver::session_aead_cipher`](crate::SessionDriver::session_aead_cipher).
    pub(crate) aead: Arc<dyn AeadCipher>,
    /// The configured cookie name, before any security prefix is applied.
    raw_cookie_name: CookieName,
    /// The security-prefixed cookie name actually emitted on the wire.
    pub(crate) cookie_name: String,
    /// Whether the deployment is HTTPS (drives `Secure` and the name prefix).
    pub(crate) secure: bool,
    cookie_path: RoutePath,
    max_age: Duration,
    metrics: Option<Arc<dyn SessionCookieMetrics>>,
}

impl CookieSealer {
    /// Wraps `cipher` in the v1 bundle format and derives a secure-by-default
    /// cookie name; `secure` is re-stamped later via
    /// [`apply_secure`](Self::apply_secure).
    pub(crate) fn new(
        cipher: Arc<dyn AeadCipher>,
        cookie_name: CookieName,
        cookie_path: RoutePath,
        max_age: Duration,
        metrics: Option<Arc<dyn SessionCookieMetrics>>,
    ) -> Self {
        let secure = true;
        let raw_cookie_name = cookie_name;
        let cookie_name =
            session_cookie_name(raw_cookie_name.as_str(), secure, cookie_path.as_str());
        Self {
            aead: cipher.clone(),
            cipher: AeadV1Cipher::new(cipher),
            raw_cookie_name,
            cookie_name,
            secure,
            cookie_path,
            max_age,
            metrics,
        }
    }

    /// The active key's identity, if it has one.
    pub(crate) fn key_id(&self) -> Option<Cow<'_, str>> {
        self.cipher.key_id()
    }

    /// AEAD associated data `"{purpose}:{cookie_name}"` for the given `purpose`
    /// (`"session"` / `"session_ptr"`), binding the value to this cookie. Seal
    /// and open must use the same value.
    pub(crate) fn aad(&self, purpose: &str) -> Vec<u8> {
        format!("{purpose}:{}", self.cookie_name).into_bytes()
    }

    /// Re-derives `cookie_name` for the deployment's real `secure` flag.
    pub(crate) fn apply_secure(&mut self, secure: bool) {
        self.secure = secure;
        self.cookie_name = session_cookie_name(
            self.raw_cookie_name.as_str(),
            secure,
            self.cookie_path.as_str(),
        );
    }

    /// Cookie attributes without `Max-Age` (clears append their own).
    pub(crate) fn base_cookie_attrs(&self) -> String {
        cookie_attrs(self.secure, self.cookie_path.as_str())
    }

    /// Full cookie attributes including this store's configured `Max-Age`.
    pub(crate) fn cookie_attrs(&self) -> String {
        format!(
            "{}; Max-Age={}",
            self.base_cookie_attrs(),
            self.max_age.as_secs()
        )
    }

    /// Builds the `Set-Cookie` for the kid sidecar: the base64url-encoded
    /// identity when `kid` is `Some`, otherwise a `Max-Age=0` clear.
    pub(crate) fn build_kid_header(&self, kid: Option<&str>) -> Result<HeaderValue, SessionError> {
        let name = kid_cookie_name(&self.cookie_name);
        let value = match kid {
            Some(k) => format!("{name}={}; {}", encode_kid(k), self.cookie_attrs()),
            None => format!("{name}=; {}; Max-Age=0", self.base_cookie_attrs()),
        };
        HeaderValue::from_str(&value).map_err(|e| SessionError::new(SessionErrorKind::Store, e))
    }

    /// Records an encrypt event (active key id) if metrics are configured.
    pub(crate) fn record_encrypt(&self, kid: Option<&str>) {
        if let Some(m) = &self.metrics {
            m.record_encrypt(&self.cookie_name, kid);
        }
    }

    /// Records a decrypt outcome if metrics are configured, bounding the
    /// client-supplied kid label via [`normalize_kid_label`].
    pub(crate) fn record_decrypt(&self, kid: Option<&str>, result: &DecryptResult) {
        let label = normalize_kid_label(&*self.aead, &self.cookie_name, kid);
        if let Some(m) = &self.metrics {
            m.record_decrypt(&self.cookie_name, label, result);
        }
    }
}

/// Suffix forming the kid sidecar cookie name. The sidecar carries the active
/// key's base64url identity as a decrypt hint; it is not security-bearing
/// (tampering or absence just degrades to trial-decrypt).
pub(crate) const KID_COOKIE_SUFFIX: &str = ".kid";

/// Unseals `bundle`, treating the kid sidecar's `cipher_match` as a hint, not
/// a filter: if unsealing under the hint fails, retry once across all keys.
/// A stale or tampered hint must not lock out an otherwise-authentic session.
pub(crate) async fn unseal_with_kid_fallback(
    unsealer: &impl AeadUnsealer,
    cipher_match: Option<&CipherMatch<'_>>,
    bundle: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    if let Some(m) = cipher_match
        && let Ok(plaintext) = unsealer.unseal(Some(m), bundle, aad).await
    {
        return Some(plaintext);
    }
    unsealer.unseal(None, bundle, aad).await.ok()
}

/// Returns the sidecar cookie name for the given session cookie base name.
#[must_use]
pub(crate) fn kid_cookie_name(base_name: &str) -> String {
    format!("{base_name}{KID_COOKIE_SUFFIX}")
}

/// Reads the kid sidecar cookie for `base_name` and returns the decoded
/// identity, or `None` if it is missing, not base64url, or not UTF-8.
pub(crate) fn get_kid_cookie(headers: &http::HeaderMap, base_name: &str) -> Option<String> {
    let name = kid_cookie_name(base_name);
    let encoded = get_cookie(headers, &name)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    String::from_utf8(bytes).ok()
}

/// Returns the base64url encoding of `identity`, the kid sidecar cookie value
/// (identities may contain chars outside the cookie-value charset).
#[must_use]
pub(crate) fn encode_kid(identity: &str) -> String {
    URL_SAFE_NO_PAD.encode(identity.as_bytes())
}

/// Normalizes a client-supplied sidecar kid into a bounded metrics label:
/// kept only on an exact [`KeyMatchStrength::ByKeyId`] match, else `"unknown"`
/// to cap label cardinality. Unmatched kids are logged at debug.
pub(crate) fn normalize_kid_label<'a>(
    cipher: &dyn AeadCipher,
    cookie_name: &str,
    kid: Option<&'a str>,
) -> Option<&'a str> {
    let k = kid?;
    let m = CipherMatch::builder().kid(k).build();
    if matches!(cipher.cipher_match(&m), Some(KeyMatchStrength::ByKeyId)) {
        Some(k)
    } else {
        log::debug!("session cookie {cookie_name}: sidecar kid {k:?} matches no configured key");
        Some("unknown")
    }
}

/// Returns the first value of cookie `name` from the request headers, trimmed.
/// The value is not unquoted or percent-decoded.
pub fn get_cookie<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    for value in headers.get_all(header::COOKIE) {
        let Ok(s) = value.to_str() else { continue };
        for pair in s.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=')
                && k.trim() == name
            {
                return Some(v.trim());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_cookie_present() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::COOKIE, "foo=bar".parse().unwrap());
        assert_eq!(get_cookie(&headers, "foo"), Some("bar"));
    }

    #[test]
    fn get_cookie_missing() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::COOKIE, "foo=bar".parse().unwrap());
        assert_eq!(get_cookie(&headers, "baz"), None);
    }

    #[test]
    fn get_cookie_multiple_pairs() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::COOKIE, "a=1; b=2; c=3".parse().unwrap());
        assert_eq!(get_cookie(&headers, "a"), Some("1"));
        assert_eq!(get_cookie(&headers, "b"), Some("2"));
        assert_eq!(get_cookie(&headers, "c"), Some("3"));
    }

    #[test]
    fn get_cookie_whitespace_trimmed() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::COOKIE, " foo = bar ".parse().unwrap());
        assert_eq!(get_cookie(&headers, "foo"), Some("bar"));
    }

    #[test]
    fn get_cookie_empty_headers() {
        let headers = http::HeaderMap::new();
        assert_eq!(get_cookie(&headers, "foo"), None);
    }

    #[test]
    fn get_cookie_multiple_cookie_headers() {
        let mut headers = http::HeaderMap::new();
        headers.append(header::COOKIE, "a=1".parse().unwrap());
        headers.append(header::COOKIE, "b=2".parse().unwrap());
        assert_eq!(get_cookie(&headers, "a"), Some("1"));
        assert_eq!(get_cookie(&headers, "b"), Some("2"));
    }

    #[test]
    fn get_cookie_value_with_equals() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::COOKIE, "token=abc=def".parse().unwrap());
        // split_once on '=' means value is "abc=def"
        assert_eq!(get_cookie(&headers, "token"), Some("abc=def"));
    }

    // -- login_state_cookie_name tests --

    #[test]
    fn cookie_name_secure_root_uses_host_prefix() {
        let name = login_state_cookie_name("abc123", true, "/", DEFAULT_LOGIN_COOKIE_PREFIX);
        assert!(name.starts_with("__Host-"));
    }

    #[test]
    fn cookie_name_secure_subpath_uses_secure_prefix() {
        let name = login_state_cookie_name("abc123", true, "/app", DEFAULT_LOGIN_COOKIE_PREFIX);
        assert!(name.starts_with("__Secure-"));
    }

    #[test]
    fn cookie_name_insecure_no_prefix() {
        let name = login_state_cookie_name("abc123", false, "/", DEFAULT_LOGIN_COOKIE_PREFIX);
        assert!(!name.starts_with("__"));
    }

    #[test]
    fn cookie_name_is_prefix_plus_state() {
        for (secure, path) in [(true, "/"), (true, "/app"), (false, "/")] {
            let name = login_state_cookie_name("abc123", secure, path, DEFAULT_LOGIN_COOKIE_PREFIX);
            let prefix = login_state_cookie_name_prefix(secure, path, DEFAULT_LOGIN_COOKIE_PREFIX);
            assert_eq!(name, format!("{prefix}abc123"));
        }
    }

    #[test]
    fn cookie_name_contains_state() {
        let name = login_state_cookie_name("mystate", true, "/", DEFAULT_LOGIN_COOKIE_PREFIX);
        assert!(name.contains("mystate"));
    }

    // -- is_valid_oauth_state tests --

    #[test]
    fn state_accepts_alphanumeric_and_url_safe_chars() {
        assert!(is_valid_oauth_state("abc123"));
        assert!(is_valid_oauth_state("AbC-_xyz"));
    }

    #[test]
    fn state_rejects_empty() {
        assert!(!is_valid_oauth_state(""));
    }

    #[test]
    fn state_rejects_overly_long() {
        let long = "a".repeat(MAX_OAUTH_STATE_LEN + 1);
        assert!(!is_valid_oauth_state(&long));
    }

    #[test]
    fn state_rejects_separators_and_specials() {
        for s in [
            "abc;def", "abc=def", "abc def", "abc\nxyz", "abc/def", "abc+def", "abc.def",
        ] {
            assert!(!is_valid_oauth_state(s), "expected reject: {s:?}");
        }
    }

    #[test]
    fn state_rejects_non_ascii() {
        assert!(!is_valid_oauth_state("café"));
    }

    // -- session_cookie_name tests --

    #[test]
    fn session_cookie_name_prefixes_secure_root() {
        assert_eq!(session_cookie_name("sess", true, "/"), "__Host-sess");
    }

    #[test]
    fn session_cookie_name_skips_insecure() {
        assert_eq!(session_cookie_name("sess", false, "/"), "sess");
    }

    #[test]
    fn session_cookie_name_skips_subpath() {
        assert_eq!(session_cookie_name("sess", true, "/app"), "sess");
    }

    #[test]
    fn session_cookie_name_keeps_existing_prefix() {
        assert_eq!(session_cookie_name("__Host-sess", true, "/"), "__Host-sess");
        assert_eq!(
            session_cookie_name("__Secure-sess", true, "/"),
            "__Secure-sess"
        );
    }

    // -- CookieName tests --

    #[test]
    fn cookie_name_new_accepts_and_rejects() {
        assert_eq!(
            CookieName::new("huskarl_session").unwrap().as_str(),
            "huskarl_session"
        );
        assert_eq!(
            CookieName::new("__Host-sess").unwrap().as_str(),
            "__Host-sess"
        );
        assert_eq!(CookieName::new("").unwrap_err().reason, "must not be empty");
        // Separators that would corrupt/inject into Set-Cookie.
        assert!(CookieName::new("bad;name").is_err());
        assert!(CookieName::new("a=b").is_err());
        assert!(CookieName::new("has space").is_err());
        // `.` is reserved for the chunk/kid sidecar namespace.
        assert!(CookieName::new("base.kid").is_err());
    }

    #[test]
    fn cookie_name_try_from() {
        assert!(CookieName::try_from("ok_name").is_ok());
        assert!(CookieName::try_from("bad;x".to_owned()).is_err());
        let n: CookieName = "scoped".try_into().unwrap();
        assert_eq!(n.as_str(), "scoped");
    }

    // -- kid sidecar tests --

    #[test]
    fn kid_cookie_name_suffixes_base() {
        assert_eq!(kid_cookie_name("huskarl_session"), "huskarl_session.kid");
    }

    #[test]
    fn get_kid_cookie_decodes_present_value() {
        let mut headers = http::HeaderMap::new();
        let encoded = encode_kid("arn:aws:kms:us-east-1:111:key/abc");
        headers.insert(
            header::COOKIE,
            format!("huskarl_session.kid={encoded}").parse().unwrap(),
        );
        assert_eq!(
            get_kid_cookie(&headers, "huskarl_session").as_deref(),
            Some("arn:aws:kms:us-east-1:111:key/abc")
        );
    }

    #[test]
    fn get_kid_cookie_absent_returns_none() {
        let headers = http::HeaderMap::new();
        assert_eq!(get_kid_cookie(&headers, "huskarl_session"), None);
    }

    #[test]
    fn get_kid_cookie_invalid_base64_returns_none() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "huskarl_session.kid=!!!notbase64!!!".parse().unwrap(),
        );
        assert_eq!(get_kid_cookie(&headers, "huskarl_session"), None);
    }

    #[test]
    fn get_kid_cookie_invalid_utf8_returns_none() {
        let mut headers = http::HeaderMap::new();
        // base64url of [0xff, 0xfe, 0xfd] — valid base64 but not valid UTF-8.
        let bad = URL_SAFE_NO_PAD.encode([0xff_u8, 0xfe, 0xfd]);
        headers.insert(
            header::COOKIE,
            format!("huskarl_session.kid={bad}").parse().unwrap(),
        );
        assert_eq!(get_kid_cookie(&headers, "huskarl_session"), None);
    }
}
