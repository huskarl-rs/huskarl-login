<!-- cargo-reedme: start -->

<!-- cargo-reedme: info-start

    Do not edit this region by hand
    ===============================

    This region was generated from Rust documentation comments by `cargo-reedme` using this command:

        cargo +nightly reedme --all-features

    for more info: https://github.com/nik-rev/cargo-reedme

cargo-reedme: info-end -->

Framework-neutral OAuth 2.0 and `OpenID` Connect login for Rust services.

`huskarl-login` is the underlying engine used by
[`huskarl-axum`](https://docs.rs/huskarl-axum/latest/huskarl_axum/) and
[`huskarl-pingora`](https://docs.rs/huskarl-pingora/latest/huskarl_pingora/).
Start with your adapter’s documentation to add login to an application or
proxy. Use this crate’s docs to customize sessions and storage, understand
shared behavior, or integrate the engine with another framework.

Integrators can start with [Build a login engine](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/tutorial/getting_started/),
then [Build a framework adapter](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/adapter/). The central type,
[`engine::LoginEngine`](https://docs.rs/huskarl-login/latest/huskarl_login/engine/struct.LoginEngine.html), starts and completes the Authorization Code flow,
validates and refreshes sessions, and handles logout. The adapter decides
which routes require authentication and delivers the engine’s responses
and cookie updates.

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
responses can also reinstall older session cookies. Use store-backed sessions
when you need server-enforced revocation and protection against stale updates.

# Documentation

| You want to | Start here |
| --- | --- |
| Understand sessions, refresh, and lifetime policy | [Explanations](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/explanation/) |
| Add claims or application data to a session | [Build an application session](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/enrichment/) |
| Use a database or other session backend | [Implement an external session store](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/external_store/) |
| Configure or troubleshoot a deployment | [How-to guides](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/) |
| Learn how to assemble the engine | [Engine tutorial](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/tutorial/getting_started/) |
| Integrate another framework or proxy | [Adapter guide](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/adapter/) and [`engine`](https://docs.rs/huskarl-login/latest/huskarl_login/engine/) |
| Look up an API contract | [`LoginConfig`](https://docs.rs/huskarl-login/latest/huskarl_login/config/struct.LoginConfig.html), [`Session`](https://docs.rs/huskarl-login/latest/huskarl_login/session_state/trait.Session.html), [`SessionDriver`](https://docs.rs/huskarl-login/latest/huskarl_login/session/trait.SessionDriver.html), [`ExternalSessionStore`](https://docs.rs/huskarl-login/latest/huskarl_login/store_session/trait.ExternalSessionStore.html) |

# Features and imports

- `metrics`: opt-in counters; the application must install a recorder. See
  [Observe login failures](https://docs.rs/huskarl-login/latest/huskarl_login/_docs/how_to/observability/) and the [`metrics`](https://docs.rs/huskarl-login/latest/huskarl_login/metrics/) catalog.
- `test-support`: deterministic store doubles for integration tests, exposed
  in `testing`. Enable it on a dev-dependency.

[`prelude`](https://docs.rs/huskarl-login/latest/huskarl_login/prelude/) imports upstream extension traits for method calls; import this
crate’s types and the traits you implement explicitly. The [`client`](https://docs.rs/huskarl/latest/huskarl/) and
[`core`](https://docs.rs/huskarl_core/latest/huskarl_core/) re-exports provide the matching OAuth and cryptography APIs.

Trait bounds use [`core::platform`](https://docs.rs/huskarl_core/latest/huskarl_core/platform/)’s `MaybeSend` and `MaybeSendSync`
markers, allowing the crate to compile for native, `wasm32`, and WASI
targets.

<!-- cargo-reedme: end -->
