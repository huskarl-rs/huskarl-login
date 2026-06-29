# Building the session: enrichment

After a successful login the framework hands you a *seed* and the
[`CompletedLogin`](crate::CompletedLogin); you turn them into your session type.
How you do that depends on whether construction needs network I/O. The three
recipes below go from least to most involved. All use
[`CookieSessionStore`](crate::CookieSessionStore); for
[`StoreBackedSessionStore`](crate::StoreBackedSessionStore) only the seed type
changes (to [`PersistedSessionState`](crate::PersistedSessionState)).

## 1. No claims, no I/O — `build()`

If the session type implements `From<Seed>`, finish the builder with `build()`
and the default [`NoEnrichment`](crate::NoEnrichment) does the rest. Nothing to
write here beyond the `From` impl.

## 2. Map ID token claims, no I/O — `build_with_claims`

The common case: the session is the seed plus a few ID token claims, no network
call. Pass a synchronous closure — no `SessionEnricher` impl, no
`Box::pin(async move { … })`:

```rust
use huskarl::core::crypto::cipher::AeadCipher;
use huskarl_login::{CookieSessionStore, Session, SessionState};
# struct MySession {
#     state: SessionState,
#     email: Option<String>,
# }
# impl Session for MySession {
#     fn state(&self) -> &SessionState { &self.state }
#     fn set_state(&mut self, state: SessionState) { self.state = state; }
# }
# fn attach(cipher: impl AeadCipher + 'static) -> CookieSessionStore<MySession> {
let store = CookieSessionStore::<MySession>::builder()
    .cipher(cipher)
    .cookie_name("session".parse().unwrap())
    .cookie_path("/".parse().unwrap())
    .build_with_claims(|state, completed| {
        Ok(MySession {
            state,
            email: completed
                .id_token_claims()
                .and_then(|c| c.profile.email.clone()),
        })
    });
# store
# }
```

Returning `Err` from the closure fails session creation (the callback responds
500). For non-standard claims, use `claims.extra.get("…")`.

## 3. A named, reusable enricher — `SessionEnricher`

The same no-I/O mapping written as a type, when you want to name and reuse it:

```rust
use huskarl::core::platform::MaybeSendBoxFuture;
use huskarl_login::{CompletedLogin, SessionEnricher, SessionError, SessionState};
# struct MySession {
#     state: SessionState,
#     email: Option<String>,
#     name: Option<String>,
# }

struct ClaimsEnricher;

impl SessionEnricher<SessionState, MySession> for ClaimsEnricher {
    fn build_session<'a>(
        &'a self,
        seed: SessionState,
        completed: &'a CompletedLogin,
    ) -> MaybeSendBoxFuture<'a, Result<MySession, SessionError>> {
        Box::pin(async move {
            let claims = completed.id_token_claims();
            Ok(MySession {
                state: seed,
                email: claims.and_then(|c| c.profile.email.clone()),
                name: claims.and_then(|c| c.profile.name.clone()),
            })
        })
    }
}
```

## 4. Call the `UserInfo` endpoint — `SessionEnricher` with I/O

When the session needs claims the ID token doesn't carry, the enricher owns its
clients and awaits them. Attach it with `build_with_enricher`:

```rust
use std::sync::Arc;

use huskarl::{
    core::{http::HttpClient, platform::MaybeSendBoxFuture},
    userinfo::UserInfoClient,
};
use huskarl_login::{
    CompletedLogin, CookieSessionStore, SessionEnricher, SessionError, SessionErrorKind,
    SessionState,
};
# struct MySession {
#     state: SessionState,
#     email: Option<String>,
#     name: Option<String>,
# }

struct UserInfoEnricher {
    http_client: Arc<dyn HttpClient>,
    userinfo: UserInfoClient,
}

impl SessionEnricher<SessionState, MySession> for UserInfoEnricher {
    fn build_session<'a>(
        &'a self,
        seed: SessionState,
        completed: &'a CompletedLogin,
    ) -> MaybeSendBoxFuture<'a, Result<MySession, SessionError>> {
        Box::pin(async move {
            let sub = seed.sub.clone().ok_or_else(|| {
                SessionError::new(SessionErrorKind::Store, "no subject in session seed")
            })?;
            let info = self
                .userinfo
                .get(
                    &self.http_client,
                    completed.token_response().access_token(),
                    &sub,
                )
                .await?;
            Ok(MySession {
                state: seed,
                email: info.profile.email,
                name: info.profile.name,
            })
        })
    }
}

# fn attach(
#     cipher: impl huskarl::core::crypto::cipher::AeadCipher + 'static,
#     http_client: Arc<dyn HttpClient>,
#     userinfo: UserInfoClient,
# ) -> CookieSessionStore<MySession> {
let store = CookieSessionStore::<MySession>::builder()
    .cipher(cipher)
    .cookie_name("session".parse().unwrap())
    .cookie_path("/".parse().unwrap())
    .build_with_enricher(UserInfoEnricher {
        http_client,
        userinfo,
    });
# store
# }
```

An error from a `UserInfo` call is a [`huskarl::core::Error`] and converts with
`?` directly; a local mapping failure is a
[`SessionError::new`](crate::SessionError::new) with a
[`Store`](crate::SessionErrorKind) kind. An enricher that treats its extra data
as optional should catch its own errors and return a partially-populated
session instead of failing the login.

The same enricher type serves a store-backed deployment by implementing
`SessionEnricher<PersistedSessionState, MySession>` — only the seed type
changes.

## Customizing the `Session` trait

Beyond *building* the session, a custom session type can override two
[`Session`](crate::Session) methods to change runtime behavior. Both default to
the [`SessionState`](crate::SessionState) baseline.

### Storing the `id_token` for RP-initiated logout

[`SessionState`](crate::SessionState) does not keep the raw `id_token` JWT (it
would add ~1 KB to every cookie request). If your IdP supports RP-initiated
logout and you want clean logout UX — no OP confirmation page — store the
`id_token` in your type and override [`Session::id_token`](crate::Session::id_token)
so the engine can send it as `id_token_hint`:

```rust
# use huskarl::token::IdToken;
# use huskarl_login::{Session, SessionState};
# struct MySession {
#     state: SessionState,
#     id_token: Option<IdToken>,
# }
impl Session for MySession {
    fn id_token(&self) -> Option<&IdToken> {
        self.id_token.as_ref()
    }
    // ...other methods
#     fn state(&self) -> &SessionState { &self.state }
#     fn set_state(&mut self, state: SessionState) { self.state = state; }
}
```

### Updating custom fields on token refresh

If any of your custom fields derive from a token response, override
[`Session::apply_refresh`](crate::Session::apply_refresh) to update them
alongside the [`SessionState`](crate::SessionState):

```rust
# use huskarl::{core::platform::Duration, grant::core::TokenResponse};
# use huskarl_login::{Session, SessionState};
# struct MySession { state: SessionState }
# impl Session for MySession {
#     fn state(&self) -> &SessionState { &self.state }
#     fn set_state(&mut self, state: SessionState) { self.state = state; }
fn apply_refresh(&mut self, token_response: &TokenResponse, default_lifetime: Duration) {
    let new_state = self.state().refreshed(token_response, default_lifetime);
    self.set_state(new_state);
    // update your own fields from token_response here
}
# }
```
