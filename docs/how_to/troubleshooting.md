# Troubleshoot browser login

Start with the symptom below. Use the browser's Network panel to follow the
redirect chain and inspect status codes, cookie names and attributes. Correlate
that request with application logs. Avoid copying cookie values, authorization
codes, or tokens into shared diagnostics.

## Login repeatedly returns to the provider

1. Find the callback response. It should return session `Set-Cookie` headers.
   If they are missing, check that the adapter converts `LoginResponse` with
   [`into_parts`](crate::engine::LoginResponse::into_parts) and forwards every
   header, including repeated `Set-Cookie` headers.
2. Inspect the next request to the application. If it lacks the session cookie,
   check the browser's rejected-cookie reason, the host, `Path`, and `Secure`.
   An HTTPS redirect URI causes the engine to issue secure cookies; use the
   browser-facing scheme in the grant configuration.
3. If the cookie is sent but rejected, confirm that every replica can unseal it.
   Keep keys stable across restarts and retain old unsealing keys during rotation.
4. If a store-backed pointer is accepted but its record is missing, check record
   deletion and the backend TTL. A missing record ends the session.

After correction, clear this application's old cookies and start one new login.
Keep a single tab open for the first check. If it succeeds only until a refresh,
continue with the refresh section below.

## The callback returns 400, 404, or 405

- **400:** Check the error response and corresponding logs. A missing, expired,
  or invalid login-state cookie can invalidate the callback. Restart login from
  the application instead of replaying a bookmarked callback URL. Also check
  the provider's error response and registration settings.
- **404:** Confirm the HTTP framework routes the callback through the login
  layer, and that its path matches `LoginConfig::callback_path`. With Axum,
  register the callback route or an appropriate fallback before adding the
  login route layer. Behind a proxy, check `base_path` and `strip_prefix` against
  the path the engine actually receives.
- **405:** The callback accepts GET. Check whether the provider is configured
  to POST the authorization response; use a query response for this integration.

The grant's redirect URI must match the provider registration and the public
callback URL. Read the [adapter guide](crate::_docs::how_to::adapter) for proxy
and framework routing details.

## A cookie is absent, rejected, or too large

Inspect attributes and browser rejection reasons before changing configuration:

| Observation | Check |
|---|---|
| Cookie sent to one route but absent on another | Cookie `Path` must cover the intended route; both drivers require logout coverage, and store-backed sessions also require callback coverage |
| Cookie rejected after changing HTTP/HTTPS | The grant's redirect URI determines secure-cookie policy |
| Configured cookie name is rejected | Supply a bare name such as `session`; the engine derives `__Host-` or `__Secure-` |
| Login fails while saving a large session | Check the store's chunk budget and reduce custom fields or choose server-side storage |
| Proxy rejects a request before it reaches the app | Inspect request-header size limits and existing cookie sizes |

Do not raise the chunk budget without checking every proxy and server header
limit on the path. See [Cookie security](crate::_docs::explanation::cookie_security).

## Logout fails or appears to sign in again

- **405:** Use a form with `method="post"` and the configured logout path.
  An address-bar visit or ordinary link sends GET.
- **403:** The POST must carry the exact public application's `Origin`. Check
  scheme, host, and port against the grant's redirect URI. Preserve `Origin`
  through your proxy; a sibling subdomain is a different origin.
- **New login immediately after logout:** Redirect to a public page. A protected
  destination starts login again, and the provider's existing SSO session may
  allow it without a password. Local logout and provider logout are separate.
- **Cookie clears are missing:** Forward all headers in the logout response.
  For store-backed sessions, inspect revocation failures too: clearing this
  browser's pointer does not revoke copied pointers if backend deletion failed.

A successful local logout normally returns `303 See Other` and cookie clears.
For browser-state limitations, see
[Cookie security](crate::_docs::explanation::cookie_security#browser-state-and-logout).

## Requests fail when tokens refresh

Distinguish a temporary provider failure from a rejected session:

| Result | Action |
|---|---|
| `RefreshUnavailable` / retryable response after token expiry | Check provider availability and retry; preserve the session |
| Conclusive refresh rejection, such as `invalid_grant` | Check provider expiry, revocation, and concurrent refresh-token reuse |
| `ActivePending` followed by a persistence error | Check backend availability and that the adapter commits after the handler returns, before sending the response |
| Log reports a dropped non-empty `SetCookies` guard | Trace every adapter branch and deliver its returned cookies |

If failures correlate with multiple tabs or replicas, follow
[Deploy refresh-token rotation safely](crate::_docs::how_to::rotation).
A shared token cache alone does not coordinate the login engine's refresh path.
For the reasoning behind retained sessions and retryable responses, read
[Token refresh](crate::_docs::explanation::refresh).

## Sessions expire sooner than expected

1. Check the configured absolute lifetime and the deadline frozen into sessions
   when they were created. Raising the configured limit does not extend those
   existing sessions; start a new login to check the new limit.
2. Check provider refresh-token lifetime and revocation, especially with a
   delegated session lifetime.
3. For store-backed sessions, check the persisted deadline and whether each
   successful write retains the TTL. Check clock skew and premature cleanup.
4. If liveness tracking is attached, check the idle timeout and which requests
   count as activity. Background polling may intentionally not keep a session
   active.

See [Session lifetime policy](crate::_docs::explanation::session_lifetime),
[Server-side liveness](crate::_docs::explanation::liveness), and the
[storage TTL contract](crate::ExternalSessionStore#ttl-contract).
