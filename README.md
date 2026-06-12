<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Shared login core for huskarl framework integrations.

This crate contains the framework-agnostic login logic shared by
`huskarl-axum` and `huskarl-pingora`: configuration, session drivers,
session enrichment, cookie helpers, URL helpers, and session store traits.
The OAuth flow itself is driven by a
[`huskarl::grant::authorization_code::AuthorizationCodeGrant`](https://docs.rs/huskarl/latest/huskarl/grant/authorization_code/grant/struct.AuthorizationCodeGrant.html), passed
directly to the [`engine::LoginEngine`](https://docs.rs/huskarl-login/latest/huskarl_login/engine/struct.LoginEngine.html).

# Session model

Session creation follows one model regardless of where sessions live: the
framework prepares a *seed* ([`SessionState`](https://docs.rs/huskarl-login/latest/huskarl_login/session_state/struct.SessionState.html), plus the session key for
store-backed sessions), a [`SessionEnricher`](https://docs.rs/huskarl-login/latest/huskarl_login/enrich/trait.SessionEnricher.html) builds the application’s
session type from the seed and the [`CompletedLogin`](https://docs.rs/huskarl-login/latest/huskarl_login/completed_login/struct.CompletedLogin.html) (mapping ID token
claims, calling the OIDC `UserInfo` endpoint, …), and the chosen backend
stores it:

- [`CookieSessionStore`](https://docs.rs/huskarl-login/latest/huskarl_login/cookie_session/struct.CookieSessionStore.html) seals the session into chunked, AEAD-encrypted
  browser cookies — no server-side storage.
- [`StoreBackedSessionStore`](https://docs.rs/huskarl-login/latest/huskarl_login/store_session/struct.StoreBackedSessionStore.html) keeps an encrypted pointer cookie and
  persists the session via an [`ExternalSessionStore`](https://docs.rs/huskarl-login/latest/huskarl_login/store_session/trait.ExternalSessionStore.html) (Redis, a
  database, …).

The default enricher, [`NoEnrichment`](https://docs.rs/huskarl-login/latest/huskarl_login/enrich/struct.NoEnrichment.html), converts the seed straight into
the session type via `From`; pass a custom one to the store builders’
`build_with_enricher` finisher.

The canonical [`SessionDriver`](https://docs.rs/huskarl-login/latest/huskarl_login/session/trait.SessionDriver.html) interface returns `Vec<HeaderValue>` from
mutating methods (`save`, `touch`, `delete`). Framework crates that need a
different interface (e.g. Pingora’s `&mut ResponseHeader`) adapt with a
small helper that appends the returned headers.

# Platform support

Trait bounds use `huskarl::core::platform`’s `MaybeSend` / `MaybeSendSync`
markers rather than bare `Send` / `Sync`: on native targets they are
equivalent to `Send + Sync`, while on `wasm32` (assumed single-threaded)
the requirement disappears. Time and sleeping likewise go through
`huskarl::core::platform`, so the crate compiles for
`wasm32-unknown-unknown` and WASI targets.

<!-- cargo-reedme: end -->
