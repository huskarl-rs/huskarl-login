<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Framework-agnostic login core shared by `huskarl-axum` and
`huskarl-pingora`: configuration, session drivers, session enrichment,
cookie and URL helpers, and session store traits.

The OAuth flow is driven by a
[`huskarl::grant::authorization_code::AuthorizationCodeGrant`](https://docs.rs/huskarl/latest/huskarl/grant/authorization_code/grant/struct.AuthorizationCodeGrant.html) passed to the
[`engine::LoginEngine`](https://docs.rs/huskarl-login/latest/huskarl_login/engine/struct.LoginEngine.html). A [`SessionEnricher`](https://docs.rs/huskarl-login/latest/huskarl_login/enrich/trait.SessionEnricher.html) builds the application’s
session type from a framework-prepared seed and the [`CompletedLogin`](https://docs.rs/huskarl-login/latest/huskarl_login/completed_login/struct.CompletedLogin.html); the
session is then stored by a [`CookieSessionStore`](https://docs.rs/huskarl-login/latest/huskarl_login/cookie_session/struct.CookieSessionStore.html) (sealed into AEAD
browser cookies) or a [`StoreBackedSessionStore`](https://docs.rs/huskarl-login/latest/huskarl_login/store_session/struct.StoreBackedSessionStore.html) (persisted via an
[`ExternalSessionStore`](https://docs.rs/huskarl-login/latest/huskarl_login/store_session/trait.ExternalSessionStore.html) behind a pointer cookie).

Trait bounds use `huskarl::core::platform`’s `MaybeSend` / `MaybeSendSync`
markers, so the crate also compiles for `wasm32` and WASI targets.

# Guides and explanation

The API items here are the reference docs. For task-oriented how-to guides
(enrichment, implementing an external store, refresh-token rotation) and
design explanation (the session model, liveness, cookie security), see the
[`_docs`](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/) module.

<!-- cargo-reedme: end -->
