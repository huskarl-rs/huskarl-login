# Deploy refresh-token rotation safely

Use this guide before enabling provider refresh-token rotation or changing a
deployment's refresh behavior. You need access to the provider configuration,
your adapter, and a staging deployment with the same replica layout as production.
This concerns OAuth refresh tokens; cookie encryption-key rotation is described
in [Cookie security](crate::_docs::explanation::cookie_security).

## 1. Establish the provider's reuse behavior

Check the provider's documentation and configuration for concurrent reuse of one
refresh token. Record whether reuse is rejected, revokes the token family, or
is accepted within a grace period. If multiple exchanges succeed, determine
which returned credentials remain usable.

Exercise this behavior with a disposable staging session. Send concurrent
requests when its access token enters the refresh window, then verify that a
subsequent request can still refresh successfully. Match the tested concurrency
to your deployment, including requests handled by different replicas.

If reuse invalidates the retained credentials, resolve exchange coordination
before rollout. A grace period only tolerates bounded delays; passing this
check does not establish safety for arbitrary request delays.

## 2. Inspect the engine's actual exchange path

`LoginEngine` calls `RefreshGrant::exchange` directly. The client's `TokenCache`
and `RefreshTokenStore` abstractions are not integrated into this path, and the
engine has no built-in refresh coordinator configuration.

If your provider requires serialized exchanges, confirm that your integration
coordinates this actual call across replicas. Installing a shared token cache
alone does not do so. If no such integration exists, deployment requires either
building it or selecting provider behavior compatible with independent exchanges.

The store-backed revision guard protects database writes. It does not serialize
provider requests or prevent provider-side token-family revocation. See
[Concurrent refresh](crate::_docs::explanation::refresh#concurrent-refresh)
for the distinction.

## 3. Check persistence and browser delivery

Use your adapter's integration tests to exercise these cases:

| Case | Expected outcome |
|------|------------------|
| Refresh succeeds | Every returned `SetCookies` value reaches the response |
| Eager persistence fails | `ActivePending` is committed after the handler returns, before sending the response; a second failure reaches `PersistFailurePolicy` |
| An old store-backed refresh finishes late | It adopts the newer stored revision instead of overwriting it |
| Logout deletes a record while a refresh is pending | The pending write does not recreate the record |
| Refresh is temporarily unavailable after access-token expiry | The request gets a retryable error; the session is retained |

For cookie sessions, also delay a response until after a later refresh or logout.
An old `Set-Cookie` response can restore older browser state. A revision inside
the cookie cannot prevent this because browsers do not compare revisions.

If globally effective revocation or protection from stored-state rollback is
required, use the store-backed driver. Cookie deployments must accept the
browser ordering limitation. Recovery through an authoritative shared refresh
record requires an integration beyond the current cookie driver.

## 4. Check writers before rollout

Route application mutations through
[`StoreBackedSessionStore::update`](crate::StoreBackedSessionStore::update)
and preserve refresh fields. Use
[`PendingPersist::commit`](crate::engine::PendingPersist::commit) for pending
refreshes. Whole-session saves reject mismatched refresh revisions, tokens, or
expiry; direct backend writes bypass these protections.

When upgrading from binaries that predate these checks, identify and replace
those writers too. See
[Revision persistence and upgrades](crate::_docs::explanation::refresh#revision-persistence-and-upgrades).

## 5. Roll out and observe

Repeat the staging checks with your intended
[`token_refresh_margin`](crate::LoginConfig) and provider configuration.
The margin changes when refresh begins; it does not fix concurrency races.

During rollout, monitor refresh rejections, persistence failures, dropped-cookie
guard errors, and unexpected repeat logins. If these increase, stop expanding
the rollout and reproduce the failing schedule in staging before changing
refresh timing. Preserve the provider-policy and concurrency test results as
part of the deployment's assumptions.
