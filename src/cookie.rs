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
    metrics::DecryptResult,
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

/// Returns the name of every login-state cookie on the request: cookies whose
/// name is `{prefix}{state}` with a suffix satisfying [`is_valid_oauth_state`]
/// (so each returned name is safe to splice into a `Set-Cookie` clear).
/// Duplicates are returned once.
pub(crate) fn login_state_cookie_names(headers: &http::HeaderMap, prefix: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for value in headers.get_all(header::COOKIE) {
        let Ok(s) = value.to_str() else { continue };
        for pair in s.split(';') {
            let Some((name, _)) = pair.trim().split_once('=') else {
                continue;
            };
            let name = name.trim();
            let Some(state) = name.strip_prefix(prefix) else {
                continue;
            };
            if is_valid_oauth_state(state) && !names.iter().any(|n| n == name) {
                names.push(name.to_owned());
            }
        }
    }
    names
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

/// The cookie security prefix derived from the deployment: `__Host-` when
/// `secure` and the cookie is host-wide (`path == "/"`), `__Secure-` when
/// `secure` on a narrower path, none otherwise. The crate owns prefixing
/// entirely — [`CookieName`] rejects explicitly prefixed names, so a
/// configured name can never contradict the deployment and produce a
/// `Set-Cookie` the browser silently drops.
fn security_prefix(secure: bool, path: &str) -> &'static str {
    if !secure {
        ""
    } else if path == "/" {
        "__Host-"
    } else {
        "__Secure-"
    }
}

/// Returns the name prefix shared by every login-state cookie under the given
/// security settings: `{security_prefix}{prefix}_`.
pub(crate) fn login_state_cookie_name_prefix(secure: bool, path: &str, prefix: &str) -> String {
    format!("{}{prefix}_", security_prefix(secure, path))
}

/// Returns the session cookie name with the derived [`security_prefix`]
/// prepended.
pub(crate) fn session_cookie_name(name: &str, secure: bool, path: &str) -> String {
    format!("{}{name}", security_prefix(secure, path))
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

/// A validated session cookie base name: non-empty, restricted to
/// `[A-Za-z0-9_-]`, and without a `__Host-`/`__Secure-` prefix (the store
/// derives the right prefix from the deployment). Cookie-name counterpart to
/// [`RoutePath`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CookieName(String);

impl CookieName {
    /// Validates `name` (non-empty, `[A-Za-z0-9_-]`) and wraps it. `.` is
    /// excluded as it separates the chunk/kid-sidecar namespace.
    ///
    /// A `__Host-`/`__Secure-` prefix (any casing — browsers match prefixes
    /// case-insensitively) is rejected: the store derives the strongest valid
    /// prefix from the deployment's `base_url` scheme and cookie path. An
    /// explicit prefix could contradict them (`__Host-` without `Secure` or
    /// off `Path=/`), and browsers *silently discard* such a `Set-Cookie` —
    /// an undebuggable login loop. Configure the bare name instead.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidCookieName`] if `name` is empty, has a disallowed
    /// char, or carries a security prefix.
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
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("__host-") || lower.starts_with("__secure-") {
            return Err(InvalidCookieName {
                name,
                reason: "must not start with `__Host-` or `__Secure-`; the security prefix is \
                         derived from the deployment (base_url scheme and cookie path) — \
                         configure the bare name",
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
    /// Instance `name` label for emitted counters; stamped by
    /// [`SessionDriver::apply_session_policy`](crate::SessionDriver::apply_session_policy).
    pub(crate) metrics_name: Option<String>,
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
            metrics_name: None,
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

    /// Clamps the cookie `Max-Age` to `limit` (the deployment's
    /// `SessionLifetime::Bounded` cap), so the browser discards the cookie
    /// once the session can no longer be valid. Only ever lowers the
    /// configured value; a
    /// shorter configured `max_age` is kept. `Max-Age` counts from each
    /// `Set-Cookie` write, so this is a hygiene bound — expiry enforcement
    /// stays server-side, from `created_at`.
    pub(crate) fn clamp_max_age(&mut self, limit: Duration) {
        self.max_age = self.max_age.min(limit);
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
        HeaderValue::from_str(&value).map_err(|e| SessionError::new(SessionErrorKind::Encoding, e))
    }

    /// Records an encrypt event (active key id).
    pub(crate) fn record_encrypt(&self, kid: Option<&str>) {
        crate::metrics::emit_counter(
            "huskarl.session_cookie.encrypt",
            vec![
                metrics::Label::new("cookie", self.cookie_name.clone()),
                metrics::Label::new("kid", kid.map_or_else(|| "none".to_owned(), str::to_owned)),
            ],
            self.metrics_name.as_deref(),
        );
    }

    /// Records a decrypt outcome, bounding the client-supplied kid label via
    /// [`normalize_kid_label`].
    pub(crate) fn record_decrypt(&self, kid: Option<&str>, result: &DecryptResult) {
        let label = normalize_kid_label(&*self.aead, &self.cookie_name, kid);
        crate::metrics::emit_counter(
            "huskarl.session_cookie.decrypt",
            vec![
                metrics::Label::new("cookie", self.cookie_name.clone()),
                metrics::Label::new(
                    "kid",
                    label.map_or_else(|| "none".to_owned(), str::to_owned),
                ),
                metrics::Label::new("outcome", result.as_str()),
            ],
            self.metrics_name.as_deref(),
        );
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

    // -- login_state_cookie_names tests --

    #[test]
    fn login_state_names_finds_all_matching_cookies() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "__Host-huskarl_login_aaa=1; other=x; __Host-huskarl_login_bbb=2"
                .parse()
                .unwrap(),
        );
        let names = login_state_cookie_names(&headers, "__Host-huskarl_login_");
        assert_eq!(
            names,
            vec!["__Host-huskarl_login_aaa", "__Host-huskarl_login_bbb"]
        );
    }

    #[test]
    fn login_state_names_spans_multiple_cookie_headers_and_dedups() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            header::COOKIE,
            "__Host-huskarl_login_aaa=1".parse().unwrap(),
        );
        headers.append(
            header::COOKIE,
            "__Host-huskarl_login_aaa=dup; __Host-huskarl_login_bbb=2"
                .parse()
                .unwrap(),
        );
        let names = login_state_cookie_names(&headers, "__Host-huskarl_login_");
        assert_eq!(
            names,
            vec!["__Host-huskarl_login_aaa", "__Host-huskarl_login_bbb"]
        );
    }

    #[test]
    fn login_state_names_skips_invalid_state_suffixes() {
        // Suffixes outside the state charset (or empty) are not login-state
        // cookies this crate minted — never splice them into a Set-Cookie.
        let mut headers = http::HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "__Host-huskarl_login_=empty; __Host-huskarl_login_a.b=dot; \
             __Host-huskarl_login_ok-1=x"
                .parse()
                .unwrap(),
        );
        let names = login_state_cookie_names(&headers, "__Host-huskarl_login_");
        assert_eq!(names, vec!["__Host-huskarl_login_ok-1"]);
    }

    #[test]
    fn login_state_names_empty_without_matches() {
        let mut headers = http::HeaderMap::new();
        headers.insert(header::COOKIE, "session=abc; foo=bar".parse().unwrap());
        assert!(login_state_cookie_names(&headers, "__Host-huskarl_login_").is_empty());
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
    fn session_cookie_name_secure_subpath_uses_secure_prefix() {
        // A sub-path scope can't satisfy `__Host-` (which demands `Path=/`),
        // but `__Secure-` is valid and matches the login-state cookies.
        assert_eq!(session_cookie_name("sess", true, "/app"), "__Secure-sess");
    }

    #[test]
    fn session_cookie_name_insecure_subpath_stays_bare() {
        assert_eq!(session_cookie_name("sess", false, "/app"), "sess");
    }

    // -- CookieName tests --

    #[test]
    fn cookie_name_new_accepts_and_rejects() {
        assert_eq!(
            CookieName::new("huskarl_session").unwrap().as_str(),
            "huskarl_session"
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
    fn cookie_name_rejects_explicit_security_prefixes() {
        // The prefix is derived from the deployment; an explicit one could
        // contradict it (`__Host-` on http or off `Path=/`) and browsers drop
        // such Set-Cookies silently. Browsers match prefixes
        // case-insensitively, so validation must too.
        for name in [
            "__Host-sess",
            "__Secure-sess",
            "__host-sess",
            "__HOST-sess",
            "__SeCuRe-sess",
        ] {
            let err = CookieName::new(name).unwrap_err();
            assert!(
                err.reason.contains("derived from the deployment"),
                "expected prefix rejection for {name:?}, got: {}",
                err.reason
            );
        }
        // Similar-looking names that carry no browser prefix semantics pass.
        assert!(CookieName::new("__internal").is_ok());
        assert!(CookieName::new("_Host-ish").is_ok());
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
