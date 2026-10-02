use std::time::Duration;

use rstest::rstest;

use super::*;
use crate::test_support::header_map as req;

fn default_policy_config() -> LoginConfig {
    LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .build()
        .unwrap()
}

#[test]
fn delegated_session_lifetime_has_no_crate_side_bound() {
    assert_eq!(
        default_policy_config().session_lifetime.bound(),
        None,
        "delegated lifetime imposes no crate-side cap"
    );
    assert_eq!(
        SessionLifetime::Bounded(Duration::from_hours(8)).bound(),
        Some(Duration::from_hours(8))
    );
}

#[test]
fn rejects_zero_default_token_lifetime() {
    let err = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .default_token_lifetime(Duration::ZERO)
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidDuration {
            field: "default_token_lifetime",
            ..
        }
    ));
}

#[test]
fn rejects_zero_login_state_ttl() {
    let err = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .login_state_ttl(Duration::ZERO)
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidDuration {
            field: "login_state_ttl",
            ..
        }
    ));
}

#[test]
fn rejects_zero_bounded_lifetime_but_allows_delegated() {
    let err = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::ZERO))
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidDuration {
            field: "session_lifetime",
            ..
        }
    ));
    // Delegation stays valid — the AS bounds the session instead.
    assert_eq!(default_policy_config().session_lifetime.bound(), None);
}

#[test]
fn rejects_refresh_margin_at_or_above_token_lifetime() {
    let err = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .default_token_lifetime(Duration::from_secs(60))
        .token_refresh_margin(Duration::from_secs(60))
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidDuration {
            field: "token_refresh_margin",
            ..
        }
    ));
}

#[test]
fn login_config_activity_policy_defaults_first_party() {
    assert_eq!(
        default_policy_config().activity_policy,
        ActivityPolicy::FirstParty
    );
}

#[test]
fn first_party_counts_same_origin_fetch() {
    let h = req(&[
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "cors"),
    ]);
    assert!(ActivityPolicy::FirstParty.counts_as_activity(&h));
}

#[test]
fn first_party_excludes_cross_site_fetch() {
    let h = req(&[("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "cors")]);
    assert!(!ActivityPolicy::FirstParty.counts_as_activity(&h));
}

#[test]
fn first_party_counts_cross_site_navigation() {
    // A genuine inbound link click — cross-site but a top-level navigation.
    let h = req(&[
        ("sec-fetch-site", "cross-site"),
        ("sec-fetch-mode", "navigate"),
    ]);
    assert!(ActivityPolicy::FirstParty.counts_as_activity(&h));
}

#[test]
fn first_party_counts_requests_without_fetch_metadata() {
    // Non-browser / legacy client: treated as first-party, counts.
    assert!(ActivityPolicy::FirstParty.counts_as_activity(&http::HeaderMap::new()));
}

#[test]
fn navigations_only_excludes_same_origin_fetch() {
    let h = req(&[
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "cors"),
    ]);
    assert!(!ActivityPolicy::NavigationsOnly.counts_as_activity(&h));
}

#[test]
fn navigations_only_counts_navigation() {
    let h = req(&[("sec-fetch-mode", "navigate")]);
    assert!(ActivityPolicy::NavigationsOnly.counts_as_activity(&h));
}

#[test]
fn all_requests_counts_cross_site_fetch() {
    let h = req(&[("sec-fetch-site", "cross-site"), ("sec-fetch-mode", "cors")]);
    assert!(ActivityPolicy::AllRequests.counts_as_activity(&h));
}

#[test]
fn first_party_counts_legacy_xhr_without_fetch_metadata() {
    // An old browser / jQuery XHR sends no Sec-Fetch-* — it cannot be
    // classified cross-site, so an active user on such a client must still
    // count as activity and never idle out under the default policy.
    let h = req(&[
        ("x-requested-with", "XMLHttpRequest"),
        ("accept", "application/json"),
    ]);
    assert!(ActivityPolicy::FirstParty.counts_as_activity(&h));
}

#[test]
fn navigations_only_counts_legacy_navigation_via_accept() {
    // Even the strict policy must keep counting genuine page loads from
    // old browsers: with no Sec-Fetch-*, `Accept: text/html` is the
    // navigation signal.
    let h = req(&[("accept", "text/html,application/xhtml+xml")]);
    assert!(ActivityPolicy::NavigationsOnly.counts_as_activity(&h));
}

#[test]
fn login_config_token_refresh_margin_defaults_30s() {
    assert_eq!(
        default_policy_config().token_refresh_margin,
        Duration::from_secs(30)
    );
}

#[test]
fn login_config_default_token_lifetime_defaults_1h() {
    assert_eq!(
        default_policy_config().default_token_lifetime,
        Duration::from_hours(1)
    );
}

#[test]
fn login_config_login_state_ttl_defaults_600s() {
    assert_eq!(
        default_policy_config().login_state_ttl,
        Duration::from_mins(10)
    );
}

#[test]
fn login_config_lifetime_fields_override() {
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(1)))
        .token_refresh_margin(Duration::from_mins(1))
        .default_token_lifetime(Duration::from_hours(2))
        .login_state_ttl(Duration::from_mins(30))
        .build()
        .unwrap();
    assert_eq!(
        config.session_lifetime,
        SessionLifetime::Bounded(Duration::from_hours(1))
    );
    assert_eq!(config.token_refresh_margin, Duration::from_mins(1));
    assert_eq!(config.default_token_lifetime, Duration::from_hours(2));
    assert_eq!(config.login_state_ttl, Duration::from_mins(30));
}

#[test]
fn login_config_callback_path_must_start_with_slash() {
    let err = LoginConfig::builder()
        .callback_path("callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .build()
        .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidCallbackPath { .. }));
}

#[test]
fn login_config_callback_path_must_not_contain_query_or_fragment() {
    for path in ["/callback?foo=bar", "/callback#section", "/callback;Secure"] {
        let err = LoginConfig::builder()
            .callback_path(path)
            .scope(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidCallbackPath { .. }));
    }
}

#[test]
fn login_config_paths_reject_control_characters() {
    for path in [
        "/callback\r\nSet-Cookie: x=y",
        "/callback\0",
        "/callback\n",
        "/callback\t",
    ] {
        let err = LoginConfig::builder()
            .callback_path(path)
            .scope(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .build()
            .unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidCallbackPath { .. }),
            "expected reject for {path:?}, got {err:?}"
        );
    }
}

#[test]
fn login_config_strip_prefix_must_start_with_slash() {
    let err = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .strip_prefix("internal")
        .build()
        .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidStripPrefix { .. }));
}

#[test]
fn login_config_strip_prefix_must_not_contain_query_fragment_or_semicolon() {
    for prefix in ["/internal?foo", "/internal#bar", "/internal;baz"] {
        let err = LoginConfig::builder()
            .callback_path("/callback")
            .scope(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .strip_prefix(prefix)
            .build()
            .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidStripPrefix { .. }));
    }
}

#[test]
fn login_config_logout_defaults_none() {
    assert!(default_policy_config().logout.is_none());
}

#[test]
fn login_config_logout_accepted() {
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .logout(LogoutConfig::builder().path("/logout").build().unwrap())
        .build()
        .unwrap();
    assert_eq!(config.logout.unwrap().path, "/logout");
}

#[test]
fn logout_config_path_must_start_with_slash() {
    // Path shape is now validated eagerly by LogoutConfig::builder.
    let err = LogoutConfig::builder().path("logout").build().unwrap_err();
    assert!(matches!(err, ConfigError::InvalidLogoutPath { .. }));
}

#[test]
fn logout_config_path_must_not_contain_query_fragment_or_semicolon() {
    for path in ["/logout?foo=bar", "/logout#section", "/logout;Secure"] {
        let err = LogoutConfig::builder().path(path).build().unwrap_err();
        assert!(matches!(err, ConfigError::InvalidLogoutPath { .. }));
    }
}

#[test]
fn logout_config_end_session_endpoint_absolute_accepted() {
    let config = LogoutConfig::builder()
        .path("/logout")
        .end_session_endpoint("https://auth.example.com/logout".parse().unwrap())
        .build()
        .unwrap();
    assert_eq!(
        config.end_session_endpoint.unwrap().as_uri().to_string(),
        "https://auth.example.com/logout"
    );
}

#[test]
fn login_config_post_logout_redirect_uri_must_be_absolute() {
    let err = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .logout(
            LogoutConfig::builder()
                .path("/logout")
                .post_logout_redirect_uri("/signed-out")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap_err();
    assert!(matches!(
        err,
        ConfigError::InvalidPostLogoutRedirectUri { .. }
    ));
}

#[test]
fn login_config_post_logout_redirect_uri_absolute_accepted() {
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .logout(
            LogoutConfig::builder()
                .path("/logout")
                .post_logout_redirect_uri("https://app.example.com/signed-out")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let logout = config.logout.unwrap();
    assert_eq!(
        logout.post_logout_redirect_uri.unwrap(),
        "https://app.example.com/signed-out"
    );
}

#[test]
fn login_config_cookie_prefix_rejects_unsafe_characters() {
    for prefix in ["bad prefix", "bad;prefix", "bad=prefix", "préfixe", ""] {
        let err = LoginConfig::builder()
            .callback_path("/callback")
            .scope(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .login_cookie_prefix(prefix)
            .build()
            .unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidLoginCookiePrefix { .. }),
            "expected reject for {prefix:?}, got {err:?}"
        );
    }
}

#[test]
fn login_config_cookie_prefix_accepts_safe_characters() {
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .login_cookie_prefix("my-app_2")
        .build()
        .unwrap();
    assert_eq!(config.login_cookie_prefix.as_str(), "my-app_2");
}

// -- browser_callback_path tests --

#[rstest]
#[case::direct("/callback", None, None, "/callback")]
#[case::base_path("/callback", Some("/base"), None, "/base/callback")]
#[case::strip_prefix("/internal/callback", None, Some("/internal"), "/callback")]
#[case::base_and_strip(
    "/internal/callback",
    Some("/base"),
    Some("/internal"),
    "/base/callback"
)]
fn browser_callback_path_mapping(
    #[case] callback_path: &str,
    #[case] base_path: Option<&str>,
    #[case] strip_prefix: Option<&str>,
    #[case] expected: &str,
) {
    let config = LoginConfig::builder()
        .callback_path(callback_path)
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .maybe_base_path(base_path.map(str::to_owned))
        .maybe_strip_prefix(strip_prefix.map(str::to_owned))
        .build()
        .unwrap();
    assert_eq!(config.browser_callback_path, expected);
}

#[test]
fn browser_logout_path_uses_the_same_external_path_mapping() {
    let config = LoginConfig::builder()
        .callback_path("/internal/callback")
        .base_path("/base")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .strip_prefix("/internal")
        .logout(
            LogoutConfig::builder()
                .path("/internal/logout")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();

    assert_eq!(config.browser_callback_path, "/base/callback");
    assert_eq!(
        config.browser_logout_path.as_ref().map(RoutePath::as_str),
        Some("/base/logout")
    );
}

// -- RoutePath tests --

#[test]
fn route_path_new_accepts_and_rejects() {
    assert_eq!(RoutePath::new("/callback").unwrap(), "/callback");
    assert_eq!(
        RoutePath::new("no-leading-slash").unwrap_err().reason,
        "must start with '/'"
    );
    assert!(RoutePath::new("/a;b").is_err());
    assert!(RoutePath::new("/a?b").is_err());
    assert!(RoutePath::new("/a\r\nb").is_err());
    assert!(RoutePath::new("/café").is_err());
    assert!(RoutePath::new("/caf%C3%A9").is_ok());
}

#[test]
fn route_path_prefix_stripping_observes_segment_boundaries() {
    let prefix = RoutePath::new("/app").unwrap();
    assert_eq!(prefix.strip_from("/app"), Some("/"));
    assert_eq!(prefix.strip_from("/app/page"), Some("/page"));
    assert_eq!(prefix.strip_from("/application"), None);

    let root = RoutePath::root();
    assert_eq!(root.strip_from("/app/page"), Some("/app/page"));

    let trailing_slash = RoutePath::new("/app/").unwrap();
    assert_eq!(trailing_slash.strip_from("/app/page"), Some("/page"));
    assert_eq!(trailing_slash.strip_from("/app/"), Some("/"));
}

#[test]
fn route_path_try_from() {
    assert!(RoutePath::try_from("/ok").is_ok());
    assert!(RoutePath::try_from("/bad;x".to_owned()).is_err());
    // `?`/`try_into()` ergonomics for callers.
    let p: RoutePath = "/scope".try_into().unwrap();
    assert_eq!(p, "/scope");
}

#[test]
fn base_path_with_semicolon_rejected_as_unsafe_cookie_scope() {
    // `base_path` becomes part of the browser_callback_path cookie `Path`; a
    // `;` would inject a stray cookie attribute, so the build must reject it
    // rather than emit an unsafe Set-Cookie.
    let err = LoginConfig::builder()
        .callback_path("/callback")
        .base_path("/a;b")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .build()
        .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidBasePath { .. }));
}

// -- ConfigError Display tests --

#[test]
fn config_error_display_callback_path() {
    let err = ConfigError::InvalidCallbackPath {
        path: "foo".into(),
        reason: "must start with '/'",
    };
    let s = err.to_string();
    assert!(s.contains("callback_path"));
    assert!(s.contains("foo"));
    assert!(s.contains("must start with '/'"));
}

#[test]
fn config_error_display_base_path() {
    let err = ConfigError::InvalidBasePath {
        path: "x".into(),
        reason: "reason",
    };
    assert!(err.to_string().contains("base_path"));
}

#[test]
fn config_error_display_strip_prefix() {
    let err = ConfigError::InvalidStripPrefix {
        prefix: "p".into(),
        reason: "reason",
    };
    assert!(err.to_string().contains("strip_prefix"));
}

#[test]
fn config_error_display_logout_path() {
    let err = ConfigError::InvalidLogoutPath {
        path: "p".into(),
        reason: "reason",
    };
    assert!(err.to_string().contains("logout path"));
}

#[test]
fn config_error_display_post_logout_redirect_uri() {
    let err = ConfigError::InvalidPostLogoutRedirectUri {
        url: "u".into(),
        reason: "reason",
    };
    assert!(err.to_string().contains("post_logout_redirect_uri"));
}

#[test]
fn config_error_display_login_cookie_prefix() {
    let err = ConfigError::InvalidLoginCookiePrefix {
        prefix: "p".into(),
        reason: "reason",
    };
    assert!(err.to_string().contains("login_cookie_prefix"));
}

#[test]
fn strip_prefix_not_matching_callback_path_is_rejected() {
    // The engine sees prefixed paths, so a callback_path outside the
    // prefix is contradictory — previously this fell back silently and
    // produced a mis-scoped login cookie.
    let err = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .strip_prefix("/other")
        .build()
        .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidCallbackPath { .. }));
}

#[test]
fn strip_prefix_segment_collision_in_callback_path_is_rejected() {
    let err = LoginConfig::builder()
        .callback_path("/application/callback")
        .base_path("/public")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .strip_prefix("/app")
        .build()
        .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidCallbackPath { .. }));
}

#[test]
fn strip_prefix_not_matching_logout_path_is_rejected() {
    let err = LoginConfig::builder()
        .callback_path("/internal/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .strip_prefix("/internal")
        .logout(LogoutConfig::builder().path("/logout").build().unwrap())
        .build()
        .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidLogoutPath { .. }));
}

#[test]
fn strip_prefix_segment_collision_in_logout_path_is_rejected() {
    let err = LoginConfig::builder()
        .callback_path("/app/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .strip_prefix("/app")
        .logout(
            LogoutConfig::builder()
                .path("/application/logout")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap_err();
    assert!(matches!(err, ConfigError::InvalidLogoutPath { .. }));
}

#[test]
fn strip_prefix_matching_both_paths_is_accepted() {
    let config = LoginConfig::builder()
        .callback_path("/internal/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .strip_prefix("/internal")
        .logout(
            LogoutConfig::builder()
                .path("/internal/logout")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    assert_eq!(config.browser_callback_path, "/callback");
}
