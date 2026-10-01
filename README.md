<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Framework-neutral OAuth 2.0 and `OpenID` Connect login for Rust services.

`huskarl-login` contains the framework-independent policy and state machine
shared by adapters such as `huskarl-axum` and `huskarl-pingora`. The central
type is [`engine::LoginEngine`](https://docs.rs/huskarl-login/latest/huskarl_login/engine/struct.LoginEngine.html). It starts and completes the Authorization
Code flow, validates and refreshes sessions, and handles logout. A framework
adapter is responsible for calling the engine and delivering its response
and cookie outputs.

# Mental model

A successful callback produces a [`CompletedLogin`](https://docs.rs/huskarl-login/latest/huskarl_login/completed_login/struct.CompletedLogin.html). A [`SessionEnricher`](https://docs.rs/huskarl-login/latest/huskarl_login/enrich/trait.SessionEnricher.html)
combines it with framework-managed state to build the application’s
[`Session`](https://docs.rs/huskarl-login/latest/huskarl_login/session_state/trait.Session.html). A session driver then persists that value:

```text
authorization code ─▶ CompletedLogin ─┐
                                      ├─▶ SessionEnricher ─▶ Session ─▶ store
                     managed state ───┘
```

Choose [`CookieSessionStore`](https://docs.rs/huskarl-login/latest/huskarl_login/cookie_session/struct.CookieSessionStore.html) to keep the encrypted session in the browser.
Choose [`StoreBackedSessionStore`](https://docs.rs/huskarl-login/latest/huskarl_login/store_session/struct.StoreBackedSessionStore.html) to keep only an encrypted lookup key in
the browser and store the session through an [`ExternalSessionStore`](https://docs.rs/huskarl-login/latest/huskarl_login/store_session/trait.ExternalSessionStore.html).
With fully stateless cookie sessions, logout clears the browser’s cookies but
cannot selectively invalidate copied cookies that are still valid. Delayed
responses can also reinstall older session cookies. These are architectural
limitations, not implementation bugs. Use store-backed sessions when you need
server-enforced revocation and protection against stale session updates.

# Documentation

- New to the crate? Follow the [getting-started
  tutorial](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/tutorial/getting_started/).
- Integrating a framework or backend? Use the [how-to
  guides](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/).
- Evaluating the design or security trade-offs? Read the
  [explanations](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/explanation/).
- Looking up behavior and contracts? The public API items are the reference
  documentation; [`engine`](https://docs.rs/huskarl-login/latest/huskarl_login/engine/), [`LoginConfig`](https://docs.rs/huskarl-login/latest/huskarl_login/config/struct.LoginConfig.html), and [`prelude`](https://docs.rs/huskarl-login/latest/huskarl_login/prelude/) are useful
  entry points.

Trait bounds use [`core::platform`](https://docs.rs/huskarl_core/latest/huskarl_core/platform/)’s `MaybeSend` and `MaybeSendSync`
markers, allowing the crate to compile for native, `wasm32`, and WASI
targets.

<!-- cargo-reedme: end -->
