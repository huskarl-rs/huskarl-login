# Build a login engine

Build and run a small program that discovers an OIDC provider and constructs a
[`LoginEngine`](crate::engine::LoginEngine) with encrypted cookie sessions.
When it succeeds, it prints `Login engine ready` and exits. Connecting this
engine to HTTP routes is the next step after this tutorial.

This exercise is for integrators learning the underlying library. For application
or proxy setup, start with
[`huskarl-axum`](https://docs.rs/huskarl-axum/latest/huskarl_axum/) or
[`huskarl-pingora`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/);
those adapters manage the HTTP lifecycle for you.

## 1. Prepare a client registration

You need Rust 1.92 or later, OpenSSL for generating a development key, and
access to an OIDC provider. Register a **public client** that supports the
Authorization Code flow with PKCE and requires no client secret. This example
uses `NoAuth`; a registration that requires client authentication needs a
different grant configuration.

Register `http://localhost:3000/callback` as the redirect URI. Note your issuer
URL and client ID. The provider must be reachable from your machine and permit
that redirect URI. The program below performs discovery but does not start an
HTTP server or complete a browser login.

## 2. Create the project

```sh
cargo new login-demo
cd login-demo
```

Add these dependencies to the generated `Cargo.toml`:

```toml
[dependencies]
huskarl-login = "0.4"
huskarl-crypto-native = "0.11"
huskarl-reqwest = { version = "0.9", features = ["rustls-tls"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Set the following environment variables in the same terminal. Replace the
issuer and client ID with your registration's values:

```sh
export OIDC_ISSUER='https://your-provider.example.com'
export OIDC_CLIENT_ID='your-client-id'
export LOGIN_COOKIE_KEY="$(openssl rand -base64 32)"
```

`LOGIN_COOKIE_KEY` contains a random 256-bit AES key. Generate it once for this
exercise. In a deployed service, load a stable key from your secret-management
system; generating a new key on every start invalidates existing cookies.

## 3. Build the engine

Replace `src/main.rs` with:

```rust,no_run
use std::{env, sync::Arc, time::Duration};

use huskarl_crypto_native::{NativeVerifierPlatform, aead::AesGcmKey};
use huskarl_login::client::grant::authorization_code::AuthorizationCodeGrant;
use huskarl_login::core::{
    client_auth::NoAuth,
    crypto::seal::AeadV1Sealer,
    jwk::{JwksSource, OctBytes},
    secrets::{EnvVarSecret, encodings::Base64Encoding},
    server_metadata::AuthorizationServerMetadata,
};
use huskarl_login::engine::LoginEngine;
use huskarl_login::prelude::*;
use huskarl_login::{CookieSessionStore, LoginConfig, SessionLifetime};
use huskarl_reqwest::ReqwestClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = env::var("OIDC_ISSUER")?;
    let client_id = env::var("OIDC_CLIENT_ID")?;
    let http_client = ReqwestClient::builder().build().await?;
    let key_source = EnvVarSecret::new("LOGIN_COOKIE_KEY", &Base64Encoding)?;
    let key = AesGcmKey::from_secret(
        key_source.mapped(OctBytes::new("A256GCM")),
    ).await?;

    // Discover the provider's endpoints and configure the OAuth grant.
    let metadata = AuthorizationServerMetadata::oidc_fetch()
        .http_client(&http_client)
        .issuer(&issuer)
        .call()
        .await?;
    let grant = AuthorizationCodeGrant::builder_from_metadata(&metadata)?
        .client_id(client_id)
        .client_auth(NoAuth)
        .http_client(http_client.clone())
        .redirect_uri("http://localhost:3000/callback")
        .jws_verifier_platform(Arc::new(NativeVerifierPlatform))
        .jws_verifier_factory(JwksSource::builder().http_client(http_client).build())
        .build()
        .await?;

    // Encrypt sessions with the key loaded above.
    let store: CookieSessionStore = CookieSessionStore::builder()
        .sealer(AeadV1Sealer::new(key))
        .cookie_name("session".parse()?)
        .build();

    // Give this example an eight-hour absolute session lifetime.
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec!["openid".to_owned()])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_secs(8 * 60 * 60)))
        .build()?;

    let engine = LoginEngine::builder()
        .config(config)
        .grant(grant)
        .session_store(store)
        .build()?;
    let _engine = Arc::new(engine);

    println!("Login engine ready");
    Ok(())
}
```

The grant holds the public redirect URI. `LoginConfig` supplies its callback
path, requested scopes, and session lifetime. The engine derives the public
origin from that redirect URI and uses the session store's key for login-state
cookies too. The local HTTP URI produces cookies suitable for this exercise;
use an HTTPS redirect URI for a deployed service.

## 4. Run and check the result

```sh
cargo run
```

After compilation and provider discovery, expect:

```text
Login engine ready
```

If a variable is missing, set it in the terminal running `cargo run`. If key
loading fails, check that `LOGIN_COOKIE_KEY` decodes to 32 bytes. If discovery
fails, verify the issuer URL and network access. Missing required provider
metadata is reported by `builder_from_metadata` with the absent field's name.

You have now constructed a shared engine that can start login, process
callbacks, and load or refresh sessions. The success message checks discovery
and construction; client registration and browser login are exercised when an
HTTP adapter calls the engine.

## Next steps

- Integrate the engine with your framework using
  [Build a framework adapter](crate::_docs::how_to::adapter).
- Add profile fields with [Build an application session](crate::_docs::how_to::enrichment),
  or [implement an external store](crate::_docs::how_to::external_store).
- Choose lifetime policy and verify deployment behavior with
  [Choose and configure a deployment](crate::_docs::how_to::deployment).

For a browser walkthrough with an existing adapter, return to the
[Axum](https://docs.rs/huskarl-axum/latest/huskarl_axum/) or
[Pingora](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/) documentation.
