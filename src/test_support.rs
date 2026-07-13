//! Shared fixtures for the crate's unit tests.
//!
//! Hoisted here so the per-module `#[cfg(test)]` blocks don't each reinvent
//! the AEAD cipher doubles and header builders. Compiled only under `cfg(test)`
//! and reachable as `crate::test_support::*`.

use http::{HeaderMap, HeaderName, HeaderValue};
use huskarl::core::{
    Error,
    jwk::OctBytes,
    platform::MaybeSendBoxFuture,
    secrets::{Secret, SecretBytes, SecretOutput},
};
use huskarl_crypto_native::aead::AesGcmKey;

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
