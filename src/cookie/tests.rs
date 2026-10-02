use rstest::rstest;

use super::*;

#[rstest]
#[case::subsecond(Duration::from_nanos(1), 1)]
#[case::fractional_second(Duration::from_millis(1_001), 2)]
#[case::whole_seconds(Duration::from_secs(2), 2)]
fn cookie_max_age_rounding(#[case] duration: Duration, #[case] expected: u64) {
    assert_eq!(cookie_max_age_seconds(duration), expected);
}

#[test]
fn get_cookie_present() {
    let mut headers = http::HeaderMap::new();
    headers.insert(header::COOKIE, "foo=bar".parse().unwrap());
    assert_eq!(get_cookie(&headers, "foo"), Some("bar"));
}

#[test]
fn get_cookie_missing() {
    let mut headers = http::HeaderMap::new();
    headers.insert(header::COOKIE, "foo=bar".parse().unwrap());
    assert_eq!(get_cookie(&headers, "baz"), None);
}

#[test]
fn get_cookie_multiple_pairs() {
    let mut headers = http::HeaderMap::new();
    headers.insert(header::COOKIE, "a=1; b=2; c=3".parse().unwrap());
    assert_eq!(get_cookie(&headers, "a"), Some("1"));
    assert_eq!(get_cookie(&headers, "b"), Some("2"));
    assert_eq!(get_cookie(&headers, "c"), Some("3"));
}

#[test]
fn get_cookie_whitespace_trimmed() {
    let mut headers = http::HeaderMap::new();
    headers.insert(header::COOKIE, " foo = bar ".parse().unwrap());
    assert_eq!(get_cookie(&headers, "foo"), Some("bar"));
}

#[test]
fn strip_cookies_removes_selected_and_preserves_unrelated_pairs() {
    let mut headers = http::HeaderMap::new();
    headers.append(
        header::COOKIE,
        "session.0=secret; theme=dark".parse().unwrap(),
    );
    headers.append(
        header::COOKIE,
        "session.kid=key; locale=da".parse().unwrap(),
    );

    strip_cookies(&mut headers, |name| name.starts_with("session."));

    assert_eq!(
        headers.get(header::COOKIE).unwrap(),
        "theme=dark; locale=da"
    );
}

#[test]
fn strip_cookies_removes_cookie_header_when_nothing_remains() {
    let mut headers = http::HeaderMap::new();
    headers.insert(header::COOKIE, "session=value".parse().unwrap());

    strip_cookies(&mut headers, |name| name == "session");

    assert!(!headers.contains_key(header::COOKIE));
}

#[test]
fn get_cookie_empty_headers() {
    let headers = http::HeaderMap::new();
    assert_eq!(get_cookie(&headers, "foo"), None);
}

#[test]
fn get_cookie_multiple_cookie_headers() {
    let mut headers = http::HeaderMap::new();
    headers.append(header::COOKIE, "a=1".parse().unwrap());
    headers.append(header::COOKIE, "b=2".parse().unwrap());
    assert_eq!(get_cookie(&headers, "a"), Some("1"));
    assert_eq!(get_cookie(&headers, "b"), Some("2"));
}

#[test]
fn get_cookie_value_with_equals() {
    let mut headers = http::HeaderMap::new();
    headers.insert(header::COOKIE, "token=abc=def".parse().unwrap());
    // split_once on '=' means value is "abc=def"
    assert_eq!(get_cookie(&headers, "token"), Some("abc=def"));
}

// -- login_state_cookie_name tests --

#[rstest]
#[case::secure_root(
    "abc123",
    true,
    "/",
    DEFAULT_LOGIN_COOKIE_PREFIX,
    "__Host-huskarl_login_abc123"
)]
#[case::secure_subpath(
    "abc123",
    true,
    "/app",
    DEFAULT_LOGIN_COOKIE_PREFIX,
    "__Secure-huskarl_login_abc123"
)]
#[case::insecure(
    "abc123",
    false,
    "/",
    DEFAULT_LOGIN_COOKIE_PREFIX,
    "huskarl_login_abc123"
)]
#[case::custom_prefix("mystate", true, "/", "custom", "__Host-custom_mystate")]
fn login_state_cookie_name_cases(
    #[case] state: &str,
    #[case] secure: bool,
    #[case] path: &str,
    #[case] prefix: &str,
    #[case] expected: &str,
) {
    assert_eq!(
        login_state_cookie_name(state, secure, path, prefix),
        expected
    );
}

// -- login_state_cookie_names tests --

#[test]
fn login_state_names_finds_all_matching_cookies() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        header::COOKIE,
        "__Host-huskarl_login_aaa=1; other=x; __Host-huskarl_login_bbb=2"
            .parse()
            .unwrap(),
    );
    let names = login_state_cookie_names(&headers, "__Host-huskarl_login_");
    assert_eq!(
        names,
        vec!["__Host-huskarl_login_aaa", "__Host-huskarl_login_bbb"]
    );
}

#[test]
fn login_state_names_spans_multiple_cookie_headers_and_dedups() {
    let mut headers = http::HeaderMap::new();
    headers.append(
        header::COOKIE,
        "__Host-huskarl_login_aaa=1".parse().unwrap(),
    );
    headers.append(
        header::COOKIE,
        "__Host-huskarl_login_aaa=dup; __Host-huskarl_login_bbb=2"
            .parse()
            .unwrap(),
    );
    let names = login_state_cookie_names(&headers, "__Host-huskarl_login_");
    assert_eq!(
        names,
        vec!["__Host-huskarl_login_aaa", "__Host-huskarl_login_bbb"]
    );
}

#[test]
fn login_state_names_skips_invalid_state_suffixes() {
    // Suffixes outside the state charset (or empty) are not login-state
    // cookies this crate minted — never splice them into a Set-Cookie.
    let mut headers = http::HeaderMap::new();
    headers.insert(
        header::COOKIE,
        "__Host-huskarl_login_=empty; __Host-huskarl_login_a.b=dot; \
         __Host-huskarl_login_ok-1=x"
            .parse()
            .unwrap(),
    );
    let names = login_state_cookie_names(&headers, "__Host-huskarl_login_");
    assert_eq!(names, vec!["__Host-huskarl_login_ok-1"]);
}

#[test]
fn login_state_names_empty_without_matches() {
    let mut headers = http::HeaderMap::new();
    headers.insert(header::COOKIE, "session=abc; foo=bar".parse().unwrap());
    assert_eq!(
        login_state_cookie_names(&headers, "__Host-huskarl_login_"),
        [] as [String; 0]
    );
}

// -- is_valid_oauth_state tests --

#[test]
fn state_accepts_alphanumeric_and_url_safe_chars() {
    assert!(is_valid_oauth_state("abc123"));
    assert!(is_valid_oauth_state("AbC-_xyz"));
}

#[test]
fn state_rejects_empty() {
    assert!(!is_valid_oauth_state(""));
}

#[test]
fn state_rejects_overly_long() {
    let long = "a".repeat(MAX_OAUTH_STATE_LEN + 1);
    assert!(!is_valid_oauth_state(&long));
}

#[test]
fn state_rejects_separators_and_specials() {
    for s in [
        "abc;def", "abc=def", "abc def", "abc\nxyz", "abc/def", "abc+def", "abc.def",
    ] {
        assert!(!is_valid_oauth_state(s), "expected reject: {s:?}");
    }
}

#[test]
fn state_rejects_non_ascii() {
    assert!(!is_valid_oauth_state("café"));
}

// -- session_cookie_name tests --

#[rstest]
#[case::secure_root(true, "/", "__Host-sess")]
#[case::insecure_root(false, "/", "sess")]
#[case::secure_subpath(true, "/app", "__Secure-sess")]
#[case::insecure_subpath(false, "/app", "sess")]
fn session_cookie_name_cases(#[case] secure: bool, #[case] path: &str, #[case] expected: &str) {
    assert_eq!(session_cookie_name("sess", secure, path), expected);
}

// -- CookieName tests --

#[test]
fn cookie_name_new_accepts_and_rejects() {
    assert_eq!(
        CookieName::new("huskarl_session").unwrap().as_str(),
        "huskarl_session"
    );
    assert_eq!(CookieName::new("").unwrap_err().reason, "must not be empty");
    // Separators that would corrupt/inject into Set-Cookie.
    assert!(CookieName::new("bad;name").is_err());
    assert!(CookieName::new("a=b").is_err());
    assert!(CookieName::new("has space").is_err());
    // `.` is reserved for the chunk/kid sidecar namespace.
    assert!(CookieName::new("base.kid").is_err());
}

#[test]
fn cookie_name_rejects_explicit_security_prefixes() {
    // The prefix is derived from the deployment; an explicit one could
    // contradict it (`__Host-` on http or off `Path=/`) and browsers drop
    // such Set-Cookies silently. Browsers match prefixes
    // case-insensitively, so validation must too.
    for name in [
        "__Host-sess",
        "__Secure-sess",
        "__host-sess",
        "__HOST-sess",
        "__SeCuRe-sess",
    ] {
        let err = CookieName::new(name).unwrap_err();
        assert!(
            err.reason.contains("derived from the deployment"),
            "expected prefix rejection for {name:?}, got: {}",
            err.reason
        );
    }
    // Similar-looking names that carry no browser prefix semantics pass.
    assert!(CookieName::new("__internal").is_ok());
    assert!(CookieName::new("_Host-ish").is_ok());
}

#[test]
fn cookie_name_try_from() {
    assert!(CookieName::try_from("ok_name").is_ok());
    assert!(CookieName::try_from("bad;x".to_owned()).is_err());
    let n: CookieName = "scoped".try_into().unwrap();
    assert_eq!(n.as_str(), "scoped");
}

// -- kid sidecar tests --

#[test]
fn kid_cookie_name_suffixes_base() {
    assert_eq!(kid_cookie_name("huskarl_session"), "huskarl_session.kid");
}

#[test]
fn get_kid_cookie_decodes_present_value() {
    let mut headers = http::HeaderMap::new();
    let encoded = encode_kid("arn:aws:kms:us-east-1:111:key/abc");
    headers.insert(
        header::COOKIE,
        format!("huskarl_session.kid={encoded}").parse().unwrap(),
    );
    assert_eq!(
        get_kid_cookie(&headers, "huskarl_session").as_deref(),
        Some("arn:aws:kms:us-east-1:111:key/abc")
    );
}

#[test]
fn get_kid_cookie_absent_returns_none() {
    let headers = http::HeaderMap::new();
    assert_eq!(get_kid_cookie(&headers, "huskarl_session"), None);
}

#[test]
fn get_kid_cookie_invalid_base64_returns_none() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        header::COOKIE,
        "huskarl_session.kid=!!!notbase64!!!".parse().unwrap(),
    );
    assert_eq!(get_kid_cookie(&headers, "huskarl_session"), None);
}

#[test]
fn get_kid_cookie_invalid_utf8_returns_none() {
    let mut headers = http::HeaderMap::new();
    // base64url of [0xff, 0xfe, 0xfd] — valid base64 but not valid UTF-8.
    let bad = URL_SAFE_NO_PAD.encode([0xff_u8, 0xfe, 0xfd]);
    headers.insert(
        header::COOKIE,
        format!("huskarl_session.kid={bad}").parse().unwrap(),
    );
    assert_eq!(get_kid_cookie(&headers, "huskarl_session"), None);
}
