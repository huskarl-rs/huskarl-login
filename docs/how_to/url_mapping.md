# Configure public and ingress URLs

Use this guide when constructing an engine behind a proxy that changes the
application's path prefix. If you use Axum or Pingora, configure routing through
that adapter; the mapping below describes the engine's expectations.

## Define the two views of the application

Suppose the browser sees `https://example.com/app`, while the engine receives
requests under `/internal`:

| Resource | Public URL | Path received by the engine |
| --- | --- | --- |
| Callback | `https://example.com/app/callback` | `/internal/callback` |
| Logout | `https://example.com/app/logout` | `/internal/logout` |
| Protected page | `https://example.com/app/reports?year=2026` | `/internal/reports?year=2026` |

Register the **public callback URL** with the provider and set it as the grant's
`redirect_uri`. The public HTTPS scheme determines cookie security even if the
proxy communicates with the application over HTTP.

## Build the mapping and derive the callback

Prefer [`PublicUrlMapping`](crate::core::url_mapping::PublicUrlMapping) when
configuring these prefixes together. Derive the callback path from the same
redirect URI you pass to the grant:

```rust
use std::time::Duration;
use huskarl_login::{LoginConfig, LogoutConfig, SessionLifetime, url};
use huskarl_login::core::url_mapping::PublicUrlMapping;

let redirect_uri: http::Uri = "https://example.com/app/callback".parse()?;
let mapping = PublicUrlMapping::new("https://example.com/app", "/internal")?;
let callback = url::callback_path(&mapping, &redirect_uri, None)?;
assert_eq!(callback.as_str(), "/internal/callback");

let config = LoginConfig::builder()
    .url_mapping(mapping)
    .callback_path(callback.as_str())
    .scope(vec!["openid".to_owned()])
    .session_lifetime(SessionLifetime::Bounded(Duration::from_secs(8 * 60 * 60)))
    .logout(LogoutConfig::builder()
        .path("/internal/logout")
        .post_logout_redirect_uri("https://example.com/app/signed-out")
        .build()?)
    .build()?;

assert_eq!(config.browser_callback_path.as_str(), "/app/callback");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Make `/app/signed-out` publicly accessible. If provider logout is configured,
register that post-logout redirect with the provider too.

For an existing integration using separate settings, `.base_path("/app")` and
`.strip_prefix("/internal")` express the same prefixes. Keep callback and logout
paths in engine coordinates. Do not combine these setters with `url_mapping`;
the builder derives both fields from the mapping.

## Pass consistent request paths

Pass the as-received URI to both
[`try_handle_login_route`](crate::engine::LoginEngine::try_handle_login_route)
and [`redirect_to_login`](crate::engine::LoginEngine::redirect_to_login).
Recover it before calling the engine if a nested framework router has stripped
the mount point. An adapter starting from a trusted public URL override can use
[`incoming_uri`](crate::engine::LoginEngine::incoming_uri) to convert it to engine
coordinates. Forwarded headers alone do not configure the engine's public origin.

Use browser coordinates for session-cookie paths: `/` covers all routes in this
example; `/app` also covers the callback and logout. Both stores require logout
coverage, and the store-backed driver requires callback coverage as well.

## Verify the round trip

Visit the protected page, sign in, and confirm the return URL retains `/app`
and its query without exposing `/internal`. Check that the callback reaches the
engine and that a same-origin logout POST returns to the public signed-out page.
Construction failures identify mismatched callback paths, origins, or cookie
scopes; see [`ConfigError`](crate::ConfigError).
