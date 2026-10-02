# Choose and configure a deployment

Use this guide alongside your Axum or Pingora deployment instructions, or when
deploying a custom integration. It covers the session and provider decisions
shared by those adapters. Start with the storage choice, then configure the
service and verify its behavior.

## Choose session storage

| You need | Choose | Limit to accept |
|---|---|---|
| Sessions without a server-side session database | Cookie sessions | A delayed response can replace newer cookies or restore them after logout. Copied valid cookies cannot be individually revoked. |
| Server-side session revocation and protection against stale stored updates | Store-backed sessions with a shared backend | The backend must support the driver's atomic updates; deletion must succeed for revocation to take effect. |

**Neither choice prevents simultaneous requests from exchanging the same
refresh token.** This can happen on one server as well as across replicas.
If your provider rejects that reuse, resolve it before rollout as described
under [Refresh concurrency](#refresh-concurrency).

For the store-backed option, follow
[Implement an external session store](crate::_docs::how_to::external_store).

## Configure the deployment

| Setting | What to do | Why it matters |
|---|---|---|
| Public origin | Serve HTTPS and register the exact public HTTPS callback as the grant's redirect URI | Its scheme determines secure-cookie policy, even when another server terminates TLS |
| Cookie keys | Load keys from managed secret storage and retain them across restarts | Generating a new key invalidates existing cookies |
| Replicas | Share compatible key rings, cookie names, paths, and login configuration; share the backend for store-backed sessions | Any replica must be able to read the same session |
| Logout | Preserve the browser's `Origin`, use POST, and redirect to a public signed-out page | Logout requires the configured application origin; a protected destination can immediately start login again |
| Responses | Preserve every `Set-Cookie` header and exclude personalized responses from shared caches | Cookies may span multiple chunks, and private responses need protection even when no cookie changes |

The redirect URI configures cookie policy; it does not enable a TLS listener.
Do not substitute an internal HTTP callback when TLS terminates at a reverse
proxy. Forwarded headers do not replace the grant's configured public origin.

Follow [Rotate cookie encryption keys](crate::_docs::how_to::cookie_keys) for
key-ring construction and rollout. For prefix rewriting, use
[Configure public and ingress URLs](crate::_docs::how_to::url_mapping). Configure
[idle-timeout tracking](crate::_docs::how_to::liveness) if required by your session
policy, and follow the [caching guide](crate::_docs::how_to::caching) for response
policy. Never log keys, cookie values, or tokens.

## Limits configuration cannot remove

### Refresh concurrency

*Refresh coordination* means preventing simultaneous requests from exchanging
the same refresh token. The engine has no built-in coordinator. Shared cookie
keys, sticky sessions, a shared token cache, and store-backed revision checks
do not coordinate its provider calls. Changing the refresh margin only changes
when the calls begin.

Check the provider's reuse policy. If it requires one exchange at a time,
your integration must coordinate the engine's actual exchange path, or use
provider behavior compatible with independent exchanges. A reuse grace period
only tolerates bounded delays. The
[rotation guide](crate::_docs::how_to::rotation) explains the exchange path and
how to test concurrent requests across replicas.

### Cookie response ordering and logout

Browsers accept `Set-Cookie` updates in arrival order without comparing session
revisions. For cookie sessions, a delayed response can therefore restore an
older refresh token or a session cleared by logout. Store-backed sessions keep
authoritative state on the server: after successful record deletion, restoring
an old pointer does not restore the session.

Local logout also leaves the provider's SSO session intact. A new sign-in may
succeed without a password. Ending provider SSO requires a separate provider
logout integration. These are separate decisions from session-cookie clearing.

### Response delivery

A successful token exchange or database write does not prove the browser
received updated cookies. Timeouts, disconnected clients, and middleware that
replaces responses can lose an update. With cookie sessions, that can lose a
rotated refresh token. Follow your adapter's deployment guide for its response
lifecycle and test the failure paths in your own stack.

## Verify before rollout

Use staging with the intended provider policy, session sizes, and replica layout:

- Sign in over the public HTTPS origin, then restart and switch replicas.
- Run the [rotation checks](crate::_docs::how_to::rotation), including concurrent
  refresh, delayed responses, and logout during refresh. A sequential sign-in
  and refresh test covers only the basic flow.
- Confirm updated cookies return on the next browser request. Check header-size
  limits, cookie clearing, and private-response caching through every hop.
- Exercise the adapter's timeout, routing, and response-handling paths.

Record the provider reuse policy and accepted cookie-ordering limits. Monitor
refresh rejections, persistence or revocation failures, and unexpected repeat
logins. Use [Troubleshoot browser login](crate::_docs::how_to::troubleshooting)
when behavior differs from the staging checks, with the
[diagnostic hooks and counters](crate::_docs::how_to::observability) enabled as needed.
