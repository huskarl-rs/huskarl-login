use super::*;

#[tokio::test]
async fn engine_reconstructs_base_url_from_grant_redirect_uri() {
    // The origin is not configured on LoginConfig; the engine takes it from the
    // grant's redirect_uri (https://app.example.com). Reconstructing the
    // post-login redirect proves it used that origin.
    let e = engine(MockSessionStore::empty()).await;
    let uri: http::Uri = "/dashboard".parse().unwrap();
    assert_eq!(
        crate::url::original_url(&e.base_url, e.config.strip_prefix.as_ref(), &uri).as_deref(),
        Some("https://app.example.com/dashboard"),
    );
}

#[tokio::test]
async fn engine_stamps_store_secure_from_https_base_url() {
    // default_config uses an https base_url, so the engine must stamp the
    // store with the secure policy at construction.
    let e = engine(MockSessionStore::empty()).await;
    assert_eq!(e.session_store.applied_policy(), Some((true, None)));
}

#[tokio::test]
async fn engine_stamps_store_insecure_from_http_redirect_uri() {
    // `secure` comes from the grant's redirect_uri scheme; an http redirect_uri
    // must stamp the store insecure.
    let http_grant = AuthorizationCodeGrant::builder()
        .client_id("client")
        .http_client(FailingHttp::new(false).0)
        .client_auth(NoAuth)
        .token_endpoint("https://auth.example.com/token".parse().unwrap())
        .authorization_endpoint("https://auth.example.com/authorize".parse().unwrap())
        .redirect_uri("http://app.example.com/callback")
        .build()
        .await
        .unwrap();
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(http_grant)
        .session_store(MockSessionStore::empty())
        .sealer(test_sealer().await)
        .build()
        .unwrap();
    assert_eq!(e.session_store.applied_policy(), Some((false, None)));
}

#[tokio::test]
async fn engine_stamps_store_with_bounded_session_lifetime() {
    // A Bounded lifetime reaches the driver so cookie Max-Age (and any
    // store-side deadlines) can be clamped to the session cap.
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::Bounded(Duration::from_hours(8)))
        .build()
        .unwrap();
    let e = engine_with_config(MockSessionStore::empty(), config).await;
    assert_eq!(
        e.session_store.applied_policy(),
        Some((true, Some(Duration::from_hours(8))))
    );
}

#[tokio::test]
async fn engine_recomputes_browser_paths_after_config_mutation() {
    let mut config = LoginConfig::builder()
        .callback_path("/app/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .logout(LogoutConfig::builder().path("/app/logout").build().unwrap())
        .build()
        .unwrap();
    // Simulate an adapter adjusting the public route configuration after the
    // builder ran. The stale derived value still says `/app/logout`.
    config.logout.as_mut().unwrap().path = "/logout".parse().unwrap();
    assert_eq!(
        config
            .browser_logout_path
            .as_ref()
            .map(crate::RoutePath::as_str),
        Some("/app/logout")
    );

    let store = StoreBackedSessionStore::builder()
        .external(RevocableExternalStore::<PersistedSessionState>::default())
        .sealer(test_sealer().await)
        .cookie_name("session".parse().unwrap())
        .cookie_path("/app".parse().unwrap())
        .build();
    let mut grant = test_grant(FailingHttp::new(false).0).await;
    grant.redirect_uri = "https://app.example.com/app/callback".to_owned();
    let result = LoginEngine::builder()
        .config(config)
        .grant(grant)
        .session_store(store)
        .build();

    let Err(error) = result else {
        panic!("the recomputed logout path must fail cookie-scope validation");
    };
    assert!(matches!(
        error,
        crate::ConfigError::InvalidSessionCookiePath {
            route: "logout",
            ..
        }
    ));
}

#[tokio::test]
async fn engine_revalidates_durations_after_config_mutation() {
    let mut config = default_config();
    config.login_state_ttl = Duration::ZERO;

    let result = LoginEngine::builder()
        .config(config)
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(MockSessionStore::empty())
        .sealer(test_sealer().await)
        .build();

    let Err(error) = result else {
        panic!("mutated duration must be revalidated at the engine boundary");
    };
    assert!(matches!(
        error,
        crate::ConfigError::InvalidDuration {
            field: "login_state_ttl",
            ..
        }
    ));
}

#[tokio::test]
async fn engine_revalidates_logout_redirect_after_config_mutation() {
    let mut config = config_with_logout();
    config.logout.as_mut().unwrap().post_logout_redirect_uri = Some("/signed-out".to_owned());

    let result = LoginEngine::builder()
        .config(config)
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(MockSessionStore::empty())
        .sealer(test_sealer().await)
        .build();

    let Err(error) = result else {
        panic!("mutated logout redirect must be revalidated at the engine boundary");
    };
    assert!(matches!(
        error,
        crate::ConfigError::InvalidPostLogoutRedirectUri { .. }
    ));
}

#[tokio::test]
async fn engine_defaults_login_state_cipher_to_store_cipher() {
    // Omitting `.sealer()` must default the login-state seal to the store's own
    // AEAD cipher — the two seals are AAD-domain-separated, so sharing one key
    // is safe. Moving this defaulting into the builder means every adapter gets
    // it (and its safety argument) for free instead of reimplementing it. Build
    // the engine WITHOUT a cipher over a store whose `session_aead_cipher()` is
    // the shared test key, then confirm the login-state cookie it seals unseals
    // under that same key.
    let store = MockSessionStore::empty().with_cipher(Arc::new(test_sealer().await));
    let e = LoginEngine::builder()
        .config(default_config())
        .grant(test_grant(FailingHttp::new(false).0).await)
        .session_store(store)
        .build()
        .unwrap();

    let uri = "/dashboard".parse().unwrap();
    let r = e.redirect_to_login(&nav_headers(), &uri).await;
    let hdrs = r.headers();

    // The `state` the engine minted is carried in the authorize redirect; it
    // is the AAD the login-state cookie was sealed under.
    let location = hdrs
        .iter()
        .find(|(n, _)| *n == http::header::LOCATION)
        .map(|(_, v)| v.to_str().unwrap())
        .expect("Location header");
    let state = location
        .split_once("state=")
        .and_then(|(_, rest)| rest.split('&').next())
        .expect("state param");

    // The login-state cookie value the engine emitted.
    let cookie_value = hdrs
        .iter()
        .filter(|(n, _)| *n == http::header::SET_COOKIE)
        .find_map(|(_, v)| {
            let s = v.to_str().ok()?;
            s.contains("huskarl_login_").then(|| {
                s.split_once('=')
                    .unwrap()
                    .1
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned()
            })
        })
        .expect("login-state cookie");

    // Independently rebuild a sealer over the same fixed test key and unseal:
    // success proves the engine sealed with the store's cipher (the default),
    // not some unrelated key.
    let bundle = URL_SAFE_NO_PAD.decode(&cookie_value).unwrap();
    let sealer = AeadV1Sealer::new(test_cipher().await);
    let plaintext = sealer
        .unseal(&bundle, &super::super::login_state_aad(state), None)
        .await
        .expect("login-state cookie unseals under the store cipher");
    let decoded =
        crate::cookie::decode_payload::<super::super::LoginStateCookie>(&plaintext).unwrap();
    assert!(
        decoded.original_url.contains("dashboard"),
        "unsealed original_url should round-trip the request path, got {}",
        decoded.original_url
    );
}

#[tokio::test]
async fn engine_rejects_callback_and_mapping_disagreement() {
    let mut config = default_config();
    config.callback_path = "/wrong".parse().unwrap();
    assert!(matches!(
        LoginEngine::builder()
            .config(config)
            .grant(test_grant(FailingHttp::new(false).0).await)
            .session_store(MockSessionStore::empty())
            .build(),
        Err(crate::ConfigError::InvalidRedirectUri { .. })
    ));
    let config = LoginConfig::builder()
        .callback_path("/callback")
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .url_mapping(
            crate::core::url_mapping::PublicUrlMapping::new("https://other.example", "/").unwrap(),
        )
        .build()
        .unwrap();
    assert!(matches!(
        LoginEngine::builder()
            .config(config)
            .grant(test_grant(FailingHttp::new(false).0).await)
            .session_store(MockSessionStore::empty())
            .build(),
        Err(crate::ConfigError::InvalidRedirectUri { .. })
    ));
}

#[tokio::test]
async fn engine_mapping_derives_callback_and_resolves_public_overrides_once() {
    let mapping =
        crate::core::url_mapping::PublicUrlMapping::new("https://app.example.com/gateway", "/edge")
            .unwrap();
    let redirect: http::Uri = "https://app.example.com/gateway/app/callback"
        .parse()
        .unwrap();
    let callback = crate::url::callback_path(&mapping, &redirect, None).unwrap();
    let config = LoginConfig::builder()
        .callback_path(callback.as_str())
        .scope(vec![])
        .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
        .url_mapping(mapping)
        .build()
        .unwrap();
    let mut grant = test_grant(FailingHttp::new(false).0).await;
    grant.redirect_uri = redirect.to_string();
    let engine = LoginEngine::builder()
        .config(config)
        .grant(grant)
        .session_store(MockSessionStore::empty())
        .build()
        .unwrap();
    assert_eq!(engine.config().callback_path.as_str(), "/edge/app/callback");
    assert_eq!(
        engine.config().browser_callback_path.as_str(),
        "/gateway/app/callback"
    );
    assert_eq!(
        engine
            .incoming_uri(
                &"https://app.example.com/gateway/app/dashboard?q=a%20b"
                    .parse()
                    .unwrap()
            )
            .unwrap(),
        "/edge/app/dashboard?q=a%20b"
    );
    assert!(
        engine
            .incoming_uri(
                &"https://other.example/gateway/app/dashboard"
                    .parse()
                    .unwrap()
            )
            .is_err()
    );
}

#[tokio::test]
async fn engine_mapping_preserves_exact_prefix_callback_and_cookie_paths() {
    for suffix in ["", "/"] {
        let mapping = crate::core::url_mapping::PublicUrlMapping::new(
            "https://app.example.com/gateway",
            "/edge",
        )
        .unwrap();
        let redirect: http::Uri = format!("https://app.example.com/gateway{suffix}")
            .parse()
            .unwrap();
        let callback = crate::url::callback_path(&mapping, &redirect, None).unwrap();
        let config = LoginConfig::builder()
            .callback_path(callback.as_str())
            .scope(vec![])
            .session_lifetime(SessionLifetime::DelegatedToAuthorizationServer)
            .logout(
                crate::LogoutConfig::builder()
                    .path(callback.as_str())
                    .build()
                    .unwrap(),
            )
            .url_mapping(mapping)
            .build()
            .unwrap();
        assert_eq!(config.browser_callback_path.as_str(), redirect.path());
        assert_eq!(
            config.browser_logout_path.as_ref().unwrap().as_str(),
            redirect.path()
        );
        let mut grant = test_grant(FailingHttp::new(false).0).await;
        grant.redirect_uri = redirect.to_string();
        let engine = LoginEngine::builder()
            .config(config)
            .grant(grant)
            .session_store(MockSessionStore::empty())
            .build()
            .unwrap();
        assert_eq!(
            engine.config().browser_callback_path.as_str(),
            redirect.path()
        );
        assert_eq!(
            engine
                .config()
                .browser_logout_path
                .as_ref()
                .unwrap()
                .as_str(),
            redirect.path()
        );
        let incoming = engine.incoming_uri(&redirect).unwrap();
        assert_eq!(incoming.path(), callback.as_str());
        assert_eq!(
            crate::url::original_url(
                &engine.base_url,
                engine.config.strip_prefix.as_ref(),
                &incoming
            )
            .unwrap(),
            redirect.to_string()
        );
    }
}
