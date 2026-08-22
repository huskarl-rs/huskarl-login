# Getting started: a minimal login

A working login needs four pieces wired together:

1. an **OAuth grant** ([`AuthorizationCodeGrant`](crate::client::grant::authorization_code::AuthorizationCodeGrant),
   from `huskarl`) that drives the Authorization Code flow — its endpoints and
   signing keys come from OIDC discovery, and it holds the client id and the
   **`redirect_uri`**;
2. a **sealer** — your AEAD key wrapped for cookie sealing;
3. a **session store** that seals sessions into cookies; and
4. the [`LoginEngine`](crate::engine::LoginEngine) that ties them together.

The client-facing origin (scheme + host) is **not** configured on the login
side — the engine takes it from the grant's `redirect_uri`. So
[`LoginConfig`](crate::LoginConfig) only needs the callback path and scopes; a
front-proxy path prefix goes in `base_path`, nothing else about the URL.

```rust,no_run
use std::sync::Arc;

use huskarl_login::client::grant::authorization_code::AuthorizationCodeGrant;
use huskarl_login::core::client_auth::NoAuth;
use huskarl_login::core::crypto::seal::AeadV1Sealer;
use huskarl_login::core::jwk::JwksSource;
use huskarl_login::core::server_metadata::AuthorizationServerMetadata;
use huskarl_login::engine::LoginEngine;
use huskarl_login::{CookieSessionStore, LoginConfig, SessionLifetime};
# use huskarl_crypto_native::aead::AesGcmKey;
# use huskarl_login::core::http::HttpClient;

// `http_client` is any `HttpClient` (e.g. `huskarl-reqwest`'s `ReqwestClient`);
// `key` is your AEAD key — an `AesGcmKey` built from a 32-byte secret.
# async fn wire(
#     http_client: impl HttpClient + Clone + 'static,
#     key: AesGcmKey,
# ) -> Result<Arc<LoginEngine<CookieSessionStore>>, Box<dyn std::error::Error>> {
// 1. Discover the authorization server's endpoints and keys from its issuer,
//    then build the grant that drives the OAuth flow.
let metadata = AuthorizationServerMetadata::oidc_fetch()
    .http_client(&http_client)
    .issuer("https://auth.example.com")
    .call()
    .await?;
//    `builder_from_metadata` fails when the metadata omits an endpoint the
//    grant needs, naming the absent field in the error.
let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)?
    .client_id("my-client")
    .client_auth(NoAuth)
    .http_client(http_client.clone())
    .redirect_uri("https://app.example.com/callback")
    .jws_verifier_factory(JwksSource::builder().http_client(http_client).build())
    .build()
    .await?;

// 2. + 3. Seal sessions into browser cookies. Wrap the AEAD key in the v1
//    sealer — or pass a KMS/Vault-backed `AeadSealerUnsealer` instead.
//    `CookieSession` is the default session type, so no type parameter here.
let store = CookieSessionStore::builder()
    .sealer(AeadV1Sealer::new(key))
    .cookie_name("session".parse()?)
    .build();

// 4a. Login config: only the callback mount path and requested scopes. The
//     origin comes from the grant's `redirect_uri`; add `.base_path("/app")`
//     only when a front proxy mounts the app under a path prefix.
let config = LoginConfig::builder()
    .callback_path("/callback")
    .scope(vec!["openid".to_owned()])
    .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
    .build()?;

// 4b. The engine. It reconstructs the base URL from the grant's redirect_uri,
//     and defaults the login-state cookie's sealer to the store's.
let engine = LoginEngine::builder()
    .config(config)
    .grant(grant)
    .session_store(store)
    .build()?;

Ok(Arc::new(engine))
# }
```

From here, drive `engine` from your framework's request lifecycle. That glue —
running the engine at the right points and delivering everything it returns —
is the subject of the [adapter guide](crate::_docs::guide::adapter); the
reference adapters `huskarl-axum` and `huskarl-pingora` implement it for you.

To populate application-specific session fields from the login, attach a
[`SessionEnricher`](crate::SessionEnricher) — see the [enrichment
guide](crate::_docs::guide::enrichment). To keep session data server-side
instead of in cookies, use a
[`StoreBackedSessionStore`](crate::StoreBackedSessionStore) — see the
[external-store guide](crate::_docs::guide::external_store).
