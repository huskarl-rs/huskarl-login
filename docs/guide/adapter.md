# Implementing a framework adapter

The [`LoginEngine`](crate::engine::LoginEngine) is framework-neutral: it takes
`http` types in (`HeaderMap`, `Method`, `Uri`) and hands back
[`LoginResponse`](crate::engine::LoginResponse) values and
[`SetCookies`](crate::engine::SetCookies) guards. An adapter is the glue that
runs the engine at the right points in a framework's request lifecycle and
delivers *everything* the engine returns. This guide builds one against a
neutral `Response` stand-in; the final section maps the pieces onto the two
reference adapters, `huskarl-axum` (a tower middleware) and `huskarl-pingora`
(proxy filter phases).

An adapter owns three things:

1. a shared engine handle (typically `Arc<LoginEngine<SD>>`),
2. a [`PersistFailurePolicy`](crate::PersistFailurePolicy) (the provided
   [`DefaultPersistFailurePolicy`](crate::DefaultPersistFailurePolicy) unless
   the application overrides it), and
3. two small lowering helpers, written once — the subject of the next two
   sections.

## Lowering `LoginResponse`

Lower with [`into_parts`](crate::engine::LoginResponse::into_parts), which
materializes a redirect's `Location`, its `Cache-Control: no-store`, and its
`Set-Cookie` headers for you:

```rust
use bytes::Bytes;
use http::{HeaderName, HeaderValue, StatusCode};
use huskarl_login::engine::LoginResponse;

/// Stand-in for the framework's response type.
struct Response {
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Bytes,
}

fn lower(resp: LoginResponse) -> Response {
    let (status, headers, body) = resp.into_parts();
    Response { status, headers, body }
}
```

Avoid matching the [`Redirect`](crate::engine::LoginResponse::Redirect) variant
field-by-field: its `set_cookies` are load-bearing (after the callback they
mint the initial session cookie; after logout they clear it), and a
destructuring that drops the field compiles fine and strands every new login.

## Delivering `SetCookies`

[`SetCookies`](crate::engine::SetCookies) is a drop-guard around session
`Set-Cookie` headers the engine owes the client. Write one helper that appends
them to a response and marks it non-cacheable, and route every `SetCookies`
you receive through it:

```rust
# use bytes::Bytes;
# use http::{HeaderName, HeaderValue, StatusCode};
# struct Response {
#     status: StatusCode,
#     headers: Vec<(HeaderName, HeaderValue)>,
#     body: Bytes,
# }
use http::header;
use huskarl_login::engine::SetCookies;

fn attach_cookies(resp: &mut Response, set_cookies: SetCookies) {
    if !set_cookies.is_empty() {
        // Session cookies must never enter a shared cache — see the
        // response-caching guide.
        resp.headers
            .push((header::CACHE_CONTROL, HeaderValue::from_static("no-store")));
    }
    resp.headers
        .extend(set_cookies.into_iter().map(|v| (header::SET_COOKIE, v)));
}
```

Two contract points, both covered in depth elsewhere:

- **Never drop a non-empty guard.** A dropped re-sealed session cookie after a
  refresh with rotation strands the rotated refresh token and kills the
  session; the guard logs an error if it happens. The one legitimate
  non-delivery — the response is already gone — is spelled
  [`discard`](crate::engine::SetCookies::discard).
- **`Cache-Control: no-store` is part of delivery.** The engine marks its own
  responses; cookies attached to the *inner handler's* response are the
  adapter's responsibility — see the
  [response-caching guide](crate::_docs::guide::caching).

## The request lifecycle

With the helpers in place, the adapter's per-request work is one function.
The order matters and is the same in every adapter:

```rust
# use bytes::Bytes;
# use http::{HeaderName, HeaderValue};
# struct Response {
#     status: StatusCode,
#     headers: Vec<(HeaderName, HeaderValue)>,
#     body: Bytes,
# }
# fn lower(resp: huskarl_login::engine::LoginResponse) -> Response {
#     let (status, headers, body) = resp.into_parts();
#     Response { status, headers, body }
# }
# fn attach_cookies(resp: &mut Response, set_cookies: huskarl_login::engine::SetCookies) {
#     if !set_cookies.is_empty() {
#         resp.headers.push((
#             http::header::CACHE_CONTROL,
#             HeaderValue::from_static("no-store"),
#         ));
#     }
#     resp.headers
#         .extend(set_cookies.into_iter().map(|v| (http::header::SET_COOKIE, v)));
# }
# async fn inner_handler<S>(_session: Option<&S>) -> Response {
#     Response {
#         status: StatusCode::OK,
#         headers: Vec::new(),
#         body: Bytes::new(),
#     }
# }
use http::{header, HeaderMap, Method, StatusCode, Uri};
use huskarl_login::{
    PersistFailurePolicy, SessionDriver,
    engine::{is_cors_preflight, LoadedSession, LoginEngine},
};

async fn handle_request<SD: SessionDriver>(
    engine: &LoginEngine<SD>,
    policy: &dyn PersistFailurePolicy,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Response {
    // 1. CORS preflights carry no cookies and must not be answered with a
    //    login redirect — pass them through untouched.
    if is_cors_preflight(method, headers) {
        return inner_handler::<SD::SessionType>(None).await;
    }

    // 2. The engine's own routes: the OAuth callback and logout. `None`
    //    means "not mine" and the request falls through to the app.
    if let Some(resp) = engine.try_handle_login_route(method, headers, uri).await {
        return lower(resp);
    }

    // 3. Load and validate the session. This never redirects; it only
    //    reports which state the request is in.
    let loaded = match engine.load_session(headers).await {
        Ok(loaded) => loaded,
        Err(e) => {
            // The session store failed — authentication is unknowable.
            let status = if e.is_retryable() {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return lower(engine.render_error(status, "session unavailable"));
        }
    };

    // 4. One arm per session state.
    match loaded {
        // No session: ask the client to authenticate. The engine picks a
        // 302-to-the-AS for browser navigations and a 401 for API/XHR
        // requests. (On routes that don't require auth, run the inner
        // handler anonymously instead.)
        LoadedSession::Missing => lower(engine.redirect_to_login(headers, uri).await),

        // A session was presented but torn down (expired, refresh rejected,
        // …). Same as Missing, except the clears for the stale cookies must
        // reach whatever response goes out — anonymous ones included.
        LoadedSession::Cleared { clears, .. } => {
            let mut resp = lower(engine.redirect_to_login(headers, uri).await);
            attach_cookies(&mut resp, clears);
            resp
        }

        // The access token expired and the refresh failed transiently.
        // Fail the *request*, not the session: a retryable error, never an
        // anonymous fallback or a login redirect (both would misfire against
        // the same unavailable authorization server).
        LoadedSession::RefreshUnavailable => {
            let mut resp = lower(
                engine.render_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable"),
            );
            resp.headers
                .push((header::RETRY_AFTER, HeaderValue::from_static("5")));
            resp
        }

        // Authenticated and fully persisted. `set_cookies` is usually empty;
        // after an eager token refresh it re-seals the session cookies and
        // must reach the response.
        LoadedSession::Active { session, set_cookies } => {
            let mut resp = inner_handler(Some(&session)).await;
            attach_cookies(&mut resp, set_cookies);
            resp
        }

        // Authenticated, but the eager persist of a refreshed session
        // failed — a save is owed after the inner handler responds.
        LoadedSession::ActivePending { pending } => {
            let mut resp = inner_handler(Some(pending.session())).await;
            match pending.commit(engine, headers).await {
                Ok(set_cookies) => {
                    attach_cookies(&mut resp, set_cookies);
                    resp
                }
                // The retry failed too. The policy decides whether the
                // handler's response still goes out (its side effects have
                // already happened) or is replaced to force a clean retry.
                Err(e) => match policy.handle(&e) {
                    Some(replacement) => lower(replacement),
                    None => resp,
                },
            }
        }
    }
}
```

Step 4's `match` is total on purpose:
[`LoadedSession`](crate::engine::LoadedSession) is not `#[non_exhaustive]`, so
a future session state is a compile error in your adapter rather than a
silently mishandled request.

How the session reaches the inner handler is the framework's idiom — a request
extension, a context value, a handler argument. For the `ActivePending` arm,
[`PendingPersist::session_arc`](crate::engine::PendingPersist::session_arc)
hands out a shared handle that never needs to be returned:
[`commit`](crate::engine::PendingPersist::commit) proceeds on a clone if a
handle is still alive. The arm is also the easiest to leave untested, since it
only arises when an eager persist fails — which is why
[`PendingPersist::new`](crate::engine::PendingPersist::new) is public: adapter
tests can fabricate the deferred-persist path without arranging a failing
store.

## Serving the session on public routes

Most applications have routes that don't require authentication. The split
belongs *after* `load_session`, not before it: run the same lifecycle, and
only change what `Missing` and `Cleared` mean — serve the inner handler
anonymously instead of redirecting. Two invariants survive the split:

- `Cleared`'s clears still go out on the anonymous response; dropping them
  keeps the browser re-presenting a dead session on every request.
- `Active`'s `set_cookies` still go out even though the route is public — an
  eager refresh can happen on any authenticated request.

## Application-initiated saves and deletes

Beyond the lifecycle above, expose the engine's explicit persistence methods
to the application in whatever shape fits the framework:

- [`save_session`](crate::engine::LoginEngine::save_session) after the
  application mutated its session. It is a whole-session, last-writer-wins
  write; for store-backed sessions mutated concurrently, prefer
  [`StoreBackedSessionStore::update`](crate::StoreBackedSessionStore::update),
  which merges via compare-and-swap and returns no cookies to deliver.
- [`delete_session`](crate::engine::LoginEngine::delete_session) to end a
  session outside the logout route.

Both return [`SetCookies`](crate::engine::SetCookies) — route them through the
same `attach_cookies` helper. If the application deletes the session while an
`ActivePending` persist is in flight, the owed save is moot: spell that with
[`abandon`](crate::engine::PendingPersist::abandon) instead of letting the
drop guard fire.

## URIs behind a front proxy

Pass the engine the URI *as your server received it* — including any path
prefix a front proxy adds. [`LoginConfig::strip_prefix`](crate::LoginConfig)
tells the engine what to remove when it reconstructs the browser-facing URL
(the post-login return URL, the login-state cookie `Path`); the configured
[`callback_path`](crate::LoginConfig) and logout path are matched against the
engine-side path as-is.

If the framework rewrites the request URI before your adapter sees it (a
nested router that strips its mount point, say), recover the original first —
`huskarl-axum` does this by preferring a request extension carrying the
as-received URL over the possibly-rewritten `Request::uri`. What matters is
that the *same* URI feeds both `try_handle_login_route` and
`redirect_to_login`, so route matching and the post-login return URL agree.

## Mapping onto real frameworks

The lifecycle is identical in both reference adapters; what differs is where
its pieces land.

**Buffered middleware (`huskarl-axum`).** A tower service runs the whole
function in one stack frame: the inner handler is `inner.call(request)`, the
session travels as a request extension, and the `ActivePending` commit happens
after the inner future resolves but before the response is returned — so the
[`PersistFailurePolicy`](crate::PersistFailurePolicy) can still replace the
response wholesale. The lifecycle is also split into three composable layers —
login routes (step 2), session loading (steps 1 and 3–4), and a
require-session gate that owns the `redirect_to_login` decision — mounted so
the login routes sit outside the gate. Split designs need a guard against
misassembly: the loader inserts a marker extension, and a gate that finds it
missing fails closed with a 500 rather than redirect-looping every request to
the authorization server.

**Proxy filters (`huskarl-pingora`).** There is no single stack frame from
request to response, so the lifecycle splits across proxy phases and the
in-flight state is carried on the per-request context:

- The *request filter* runs steps 1–4. Engine-authored responses (callback,
  redirects, errors) are written directly and end the request; otherwise the
  session, any un-committed [`PendingPersist`](crate::engine::PendingPersist),
  the owed cookie headers, and a **clone of the request headers** (`commit`
  and `delete_session` need them after the request parts are gone) are
  stashed on the context and the request proceeds upstream.
- The *response-header filter* is the persist phase: append the owed cookies
  to the upstream's `&mut ResponseHeader` (the response is the upstream's —
  the adapter can only append, converting the `Vec<HeaderValue>` shape as
  noted in [the session model](crate::_docs::explanation::session_model)) and
  commit the pending persist. The upstream body is already committed, so a
  `PersistFailurePolicy` replacement response degrades to failing the request
  with the replacement's *status*.
- A *logging/end-of-request phase* is the fallback for requests that never
  reached the response filter (the proxy answered early, or upstream failed):
  commit the owed persist so the store is right, and
  [`discard`](crate::engine::SetCookies::discard) the returned cookies — the
  response is already gone, which is exactly the case `discard` exists for.

The engine's design assumes adapters like this exist: refreshes are persisted
*eagerly* inside `load_session` precisely so that an adapter with no reliable
post-response phase only ever risks losing a retry, not the rotated refresh
token — see the [refresh explanation](crate::_docs::explanation::refresh).
