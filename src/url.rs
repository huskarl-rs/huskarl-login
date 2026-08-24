//! URL reconstruction and logout URL building.

use serde::Serialize;

use crate::config::RoutePath;

/// Reconstructs the client-facing URL to redirect back to after login.
///
/// `base` is the reconstructed base URL (the grant's `redirect_uri` origin
/// joined with the config's `base_path`); it carries scheme and authority.
///
/// Returns `None` if `strip_prefix` is set but does not match the request path.
pub fn original_url(
    base: &http::Uri,
    strip_prefix: Option<&RoutePath>,
    req_uri: &http::Uri,
) -> Option<String> {
    let req_path = req_uri.path();
    let stripped = match strip_prefix {
        Some(prefix) => {
            if let Some(s) = prefix.strip_from(req_path) {
                s
            } else {
                log::error!(
                    "strip_prefix {prefix:?} did not match request path {req_path:?}; \
                 check your LoginConfig.strip_prefix setting",
                );
                return None;
            }
        }
        None => req_path,
    };

    let new_path = crate::config::join_base_path(base, stripped);

    // `base_url` is an `EndpointUrl`, so scheme and authority are guaranteed
    // present by construction; the `else` is unreachable in practice.
    let (Some(scheme), Some(authority)) = (
        base.scheme_str(),
        base.authority().map(http::uri::Authority::as_str),
    ) else {
        return None;
    };
    Some(match req_uri.query() {
        Some(q) => format!("{scheme}://{authority}{new_path}?{q}"),
        None => format!("{scheme}://{authority}{new_path}"),
    })
}

/// Builds the end-session URL, appending `id_token_hint`, `client_id`, and
/// `post_logout_redirect_uri` query parameters when present.
///
/// # Errors
///
/// [`serde_html_form::ser::Error`] if the parameters fail to serialize.
pub fn build_end_session_url(
    endpoint: &http::Uri,
    id_token_hint: Option<&str>,
    client_id: Option<&str>,
    post_logout_redirect_uri: Option<&str>,
) -> Result<String, serde_html_form::ser::Error> {
    #[derive(Serialize)]
    struct EndSessionParams<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        id_token_hint: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_id: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        post_logout_redirect_uri: Option<&'a str>,
    }

    let params = EndSessionParams {
        id_token_hint,
        client_id,
        post_logout_redirect_uri,
    };
    if id_token_hint.is_none() && client_id.is_none() && post_logout_redirect_uri.is_none() {
        return Ok(endpoint.to_string());
    }
    let query = serde_html_form::to_string(&params)?;
    let base = endpoint.to_string();
    Ok(if base.contains('?') {
        format!("{base}&{query}")
    } else {
        format!("{base}?{query}")
    })
}

/// Returns the reconstructed `base` URL as a string (scheme, authority, and path).
pub fn base_url_as_string(base: &http::Uri) -> String {
    // The reconstructed base carries scheme and authority by construction;
    // the `else` (raw URI string) is unreachable in practice.
    let (Some(scheme), Some(authority)) = (
        base.scheme_str(),
        base.authority().map(http::uri::Authority::as_str),
    ) else {
        return base.to_string();
    };
    let path = base.path();
    if path.is_empty() || path == "/" {
        format!("{scheme}://{authority}/")
    } else {
        format!("{scheme}://{authority}{path}")
    }
}

/// Returns the default post-logout redirect: the reconstructed base URL.
pub fn default_post_logout_redirect(base: &http::Uri) -> String {
    base_url_as_string(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reconstructed base URL (origin + `base_path`) the engine passes in.
    fn base(s: &str) -> http::Uri {
        s.parse().unwrap()
    }

    fn strip(s: &str) -> RoutePath {
        s.parse().unwrap()
    }

    // -- build_end_session_url tests --

    #[test]
    fn end_session_url_no_params() {
        let endpoint: http::Uri = "https://auth.example.com/logout".parse().unwrap();
        let url = build_end_session_url(&endpoint, None, None, None).unwrap();
        assert_eq!(url, "https://auth.example.com/logout");
    }

    #[test]
    fn end_session_url_with_id_token_hint() {
        let endpoint: http::Uri = "https://auth.example.com/logout".parse().unwrap();
        let url =
            build_end_session_url(&endpoint, Some("eyJhbGciOiJSUzI1NiJ9.e30.sig"), None, None)
                .unwrap();
        assert!(url.contains("id_token_hint=eyJhbGciOiJSUzI1NiJ9.e30.sig"));
        assert!(url.starts_with("https://auth.example.com/logout?"));
    }

    #[test]
    fn end_session_url_with_client_id() {
        // The common stock case: no id_token_hint (built-in sessions don't
        // store the JWT), so client_id is what lets the OP honor the redirect.
        let endpoint: http::Uri = "https://auth.example.com/logout".parse().unwrap();
        let url = build_end_session_url(
            &endpoint,
            None,
            Some("my-client"),
            Some("https://app.example.com/"),
        )
        .unwrap();
        assert!(url.contains("client_id=my-client"));
        assert!(url.contains("post_logout_redirect_uri="));
    }

    #[test]
    fn end_session_url_with_post_logout_redirect() {
        let endpoint: http::Uri = "https://auth.example.com/logout".parse().unwrap();
        let url =
            build_end_session_url(&endpoint, None, None, Some("https://app.example.com/")).unwrap();
        assert!(url.contains("post_logout_redirect_uri="));
        assert!(url.contains("app.example.com"));
    }

    #[test]
    fn end_session_url_preserves_existing_query() {
        let endpoint: http::Uri = "https://auth.example.com/logout?foo=bar".parse().unwrap();
        let url =
            build_end_session_url(&endpoint, None, None, Some("https://app.example.com/")).unwrap();
        assert!(url.contains("foo=bar"));
        assert!(url.contains("post_logout_redirect_uri="));
        // existing query separator is &, not ?
        assert!(url.contains("foo=bar&post_logout_redirect_uri="));
    }

    // -- default_post_logout_redirect tests --

    #[test]
    fn default_post_logout_redirect_simple() {
        assert_eq!(
            default_post_logout_redirect(&base("https://app.example.com")),
            "https://app.example.com/"
        );
    }

    #[test]
    fn default_post_logout_redirect_with_path() {
        assert_eq!(
            default_post_logout_redirect(&base("https://app.example.com/myapp")),
            "https://app.example.com/myapp"
        );
    }

    // -- original_url tests --

    #[test]
    fn original_url_simple_path() {
        let uri: http::Uri = "/page".parse().unwrap();
        assert_eq!(
            original_url(&base("https://app.example.com"), None, &uri),
            Some("https://app.example.com/page".into())
        );
    }

    #[test]
    fn original_url_root_path() {
        let uri: http::Uri = "/".parse().unwrap();
        assert_eq!(
            original_url(&base("https://app.example.com"), None, &uri),
            Some("https://app.example.com/".into())
        );
    }

    #[test]
    fn original_url_preserves_query_string() {
        let uri: http::Uri = "/search?q=hello&page=1".parse().unwrap();
        assert_eq!(
            original_url(&base("https://app.example.com"), None, &uri),
            Some("https://app.example.com/search?q=hello&page=1".into())
        );
    }

    #[test]
    fn original_url_base_url_with_path() {
        let uri: http::Uri = "/page".parse().unwrap();
        assert_eq!(
            original_url(&base("https://app.example.com/base"), None, &uri),
            Some("https://app.example.com/base/page".into())
        );
    }

    #[test]
    fn original_url_base_url_with_trailing_slash() {
        let uri: http::Uri = "/page".parse().unwrap();
        assert_eq!(
            original_url(&base("https://app.example.com/base/"), None, &uri),
            Some("https://app.example.com/base/page".into())
        );
    }

    #[test]
    fn original_url_strip_prefix_removes_prefix() {
        let uri: http::Uri = "/internal/page".parse().unwrap();
        assert_eq!(
            original_url(
                &base("https://app.example.com"),
                Some(&strip("/internal")),
                &uri
            ),
            Some("https://app.example.com/page".into())
        );
    }

    #[test]
    fn original_url_strip_prefix_preserves_query() {
        let uri: http::Uri = "/internal/page?foo=bar".parse().unwrap();
        assert_eq!(
            original_url(
                &base("https://app.example.com"),
                Some(&strip("/internal")),
                &uri
            ),
            Some("https://app.example.com/page?foo=bar".into())
        );
    }

    #[test]
    fn original_url_strip_prefix_mismatch_returns_none() {
        let uri: http::Uri = "/other/page".parse().unwrap();
        assert_eq!(
            original_url(
                &base("https://app.example.com"),
                Some(&strip("/internal")),
                &uri
            ),
            None
        );
    }

    #[test]
    fn original_url_strip_prefix_segment_collision_returns_none() {
        let uri: http::Uri = "/application/page".parse().unwrap();
        assert_eq!(
            original_url(&base("https://app.example.com"), Some(&strip("/app")), &uri),
            None
        );
    }

    #[test]
    fn original_url_strip_prefix_with_base_path() {
        let uri: http::Uri = "/internal/page".parse().unwrap();
        assert_eq!(
            original_url(
                &base("https://app.example.com/base"),
                Some(&strip("/internal")),
                &uri
            ),
            Some("https://app.example.com/base/page".into())
        );
    }
}
