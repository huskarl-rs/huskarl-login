//! Shared fixtures for the crate's unit tests.
//!
//! Hoisted here so the per-module `#[cfg(test)]` blocks don't each reinvent
//! the AEAD cipher doubles and header builders. Compiled only under `cfg(test)`
//! and reachable as `crate::test_support::*`.

use http::{HeaderMap, HeaderName, HeaderValue};
use huskarl_crypto_native::aead::AesGcmKey;

pub(crate) use crate::testing::InMemoryExternalSessionStore as RevocableExternalStore;
use crate::{
    SessionPolicy,
    core::{
        Error,
        crypto::seal::AeadV1Sealer,
        jwk::OctBytes,
        platform::MaybeSendBoxFuture,
        secrets::{Secret, SecretBytes, SecretOutput},
    },
};

/// A successful rotation response with a controlled token and issuance time.
pub(crate) fn rotating_token_response(
    token: &str,
    issued_at: std::time::SystemTime,
) -> crate::client::grant::core::TokenResponse {
    use crate::core::secrets::SecretString;

    crate::client::grant::core::RawTokenResponse::builder()
        .access_token(SecretString::new("rotated-access-token"))
        .refresh_token(SecretString::new(token))
        .token_type("Bearer")
        .build()
        .into_token_response(None, issued_at)
        .unwrap()
}

/// A [`Secret`] yielding fixed bytes and no key identity.
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

/// A 256-bit AES-GCM cipher over all-zero key bytes, reporting **no** key
/// identity (the cipher's `key_id()` is `None`, so no kid sidecar is emitted).
pub(crate) async fn test_cipher() -> AesGcmKey {
    AesGcmKey::from_secret(
        TestSecret(SecretBytes::new(vec![0u8; 32])).mapped(OctBytes::new("A256GCM")),
    )
    .await
    .unwrap()
}

/// Like [`test_cipher`] but reports a fixed key identity `kid`, exercising the
/// kid-sidecar set path on save and the `CipherMatch` path on load.
pub(crate) async fn test_cipher_with_kid(kid: &str) -> AesGcmKey {
    aes_key_with_kid(kid, 0).await
}

/// A 256-bit AES-GCM cipher over key bytes `[byte; 32]` reporting identity
/// `kid`. Distinct `byte` values yield genuinely different keys, and the same
/// `(kid, byte)` reconstructs the "same" key twice (e.g. once for a decryptor
/// set and once as the encryptor) — the shape multi-key rotation tests need.
pub(crate) async fn aes_key_with_kid(kid: &str, byte: u8) -> AesGcmKey {
    AesGcmKey::from_secret(
        TestSecret(SecretBytes::new(vec![byte; 32])).mapped(OctBytes::new("A256GCM").with_kid(kid)),
    )
    .await
    .unwrap()
}

/// [`test_cipher`] wrapped in the v1 sealer the cookie stores use — the value
/// the `.sealer(…)` builders now take.
pub(crate) async fn test_sealer() -> AeadV1Sealer<AesGcmKey> {
    AeadV1Sealer::new(test_cipher().await)
}

/// [`test_cipher_with_kid`] wrapped in the v1 sealer, for the kid-sidecar path.
pub(crate) async fn test_sealer_with_kid(kid: &str) -> AeadV1Sealer<AesGcmKey> {
    AeadV1Sealer::new(test_cipher_with_kid(kid).await)
}

/// Build a [`HeaderMap`] from `(name, value)` pairs, panicking on invalid
/// header names/values (test-only convenience).
pub(crate) fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.insert(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

/// Turns response `Set-Cookie` values into the `Cookie` header a browser would
/// send back, omitting clears and stripping response-only attributes.
pub(crate) fn request_cookies(set_cookies: &[HeaderValue]) -> HeaderMap {
    let pairs = set_cookies
        .iter()
        .filter_map(|header| {
            let pair = header.to_str().ok()?.split(';').next()?;
            let (_, value) = pair.split_once('=')?;
            (!value.is_empty()).then(|| pair.to_owned())
        })
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        HeaderMap::new()
    } else {
        header_map(&[(http::header::COOKIE.as_str(), &pairs.join("; "))])
    }
}

/// Engine session policy with the common secure, root-scoped test defaults.
pub(crate) fn test_session_policy(max_lifetime: Option<std::time::Duration>) -> SessionPolicy {
    SessionPolicy::builder()
        .secure(true)
        .maybe_max_lifetime(max_lifetime)
        .browser_callback_path(crate::RoutePath::root())
        .build()
}

/// Counters captured by [`with_metrics`]: `(name, sorted (label, value)
/// pairs, count)`.
pub(crate) type CapturedCounters = Vec<(String, Vec<(String, String)>, u64)>;

/// Drives `fut` on a current-thread runtime with a thread-local debugging
/// recorder installed, returning the output and every counter it emitted.
pub(crate) fn with_metrics<T>(fut: impl Future<Output = T>) -> (T, CapturedCounters) {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let out = metrics::with_local_recorder(&recorder, || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    });
    let counters = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _unit, _desc, value)| {
            let DebugValue::Counter(count) = value else {
                return None;
            };
            let key = key.key();
            let mut labels: Vec<(String, String)> = key
                .labels()
                .map(|l| (l.key().to_owned(), l.value().to_owned()))
                .collect();
            labels.sort();
            Some((key.name().to_owned(), labels, count))
        })
        .collect();
    (out, counters)
}

/// The value of the counter matching `name` and exactly `labels` (order
/// insensitive), adding `name=""` when omitted, or 0 if never emitted.
#[cfg(feature = "metrics")]
pub(crate) fn counter_value(
    counters: &CapturedCounters,
    name: &str,
    labels: &[(&str, &str)],
) -> u64 {
    let mut expected: Vec<(String, String)> = labels
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    if !expected.iter().any(|(key, _)| key == "name") {
        expected.push(("name".to_owned(), String::new()));
    }
    expected.sort();
    counters
        .iter()
        .find(|(n, l, _)| n == name && *l == expected)
        .map_or(0, |(_, _, count)| *count)
}
