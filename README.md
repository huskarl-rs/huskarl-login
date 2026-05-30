# huskarl-login

Shared login core for huskarl framework integrations. Implements the OAuth 2.0
Authorization Code Grant decision tree — callback handling, session lifecycle,
token refresh — and is consumed by framework adapters such as `huskarl-axum`
and `huskarl-pingora`.

## Deployment requirements

### Refresh-token reuse grace period

This library performs **no client-side coordination between concurrent token
refreshes**. In a distributed deployment, two requests for the same session can
arrive at different replicas at the same time, both observe that the access
token is near expiry, and both call your authorization server's token endpoint
with the same refresh token.

For this to work without destroying sessions, the authorization server must
provide a refresh-token reuse grace period — variously called "leeway", "reuse
interval", or "rotation grace". Within this window the AS accepts the same
refresh token from multiple requests instead of treating the second use as a
replay. Without one, the second refresh fails with `invalid_grant`; and if the
AS has strict reuse-detection enabled it may invalidate the entire
refresh-token family, terminating both sessions on the next request.

Most major IdPs support a configurable grace period (Auth0, Keycloak, Okta,
and others). Check your authorization server's documentation and confirm the
value is non-zero before deploying at scale.

If your AS cannot provide a grace period, refresh races must be coordinated
outside this library — for example a Redis `SETNX` lock or a Postgres advisory
lock keyed by session ID. An in-process lock is intentionally not provided:
it would pass single-replica tests and then silently fail the moment a second
replica was added.
