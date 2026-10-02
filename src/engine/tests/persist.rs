use super::*;

// ── PendingPersist::commit ────────────────────────────────────────────────

#[tokio::test]
async fn commit_calls_store_save() {
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let loaded = e.load_session(&HeaderMap::new()).await.unwrap();
    let (session, _) = expect_active(loaded);
    // The public constructor: what adapter tests use to fabricate the
    // deferred-persist path without arranging a failing store.
    let pending = PendingPersist::builder()
        .session(session)
        .token_response(token_response_fixture())
        .expected_refresh_revision(0)
        .build();
    let set_cookies = pending.commit(&e, &api_headers()).await.unwrap();
    assert!(e.session_store.save_called());
    assert_ne!(set_cookies.into_headers(), [] as [HeaderValue; 0]);
}

#[test]
fn cancelled_commit_counts_only_an_unpolled_persist_as_dropped() {
    use std::{
        sync::atomic::AtomicUsize,
        task::{Context, Waker},
    };

    for poll_commit in [false, true] {
        let probe = Arc::new(AtomicUsize::new(0));
        let ((), counters) = crate::test_support::with_metrics(async {
            let store = MockSessionStore {
                suspend_save: true,
                ..MockSessionStore::empty()
            };
            let e = engine(store).await;
            let pending = PendingPersist::builder()
                .session(valid_session())
                .token_response(token_response_fixture())
                .expected_refresh_revision(0)
                .build()
                .with_drop_probe(probe.clone());
            let headers = api_headers();
            let mut commit = Box::pin(pending.commit(&e, &headers));
            if poll_commit {
                let mut context = Context::from_waker(Waker::noop());
                assert!(commit.as_mut().poll(&mut context).is_pending());
            }
            assert_eq!(e.session_store.save_called(), poll_commit);
            drop(commit);
        });
        assert_eq!(probe.load(Ordering::Relaxed), usize::from(!poll_commit));
        #[cfg(feature = "metrics")]
        assert_eq!(
            crate::test_support::counter_value(
                &counters,
                "huskarl.session.dropped",
                &[("operation", "persist")]
            ),
            u64::from(!poll_commit)
        );
        if poll_commit || !cfg!(feature = "metrics") {
            assert_eq!(counters, [] as [(std::string::String, std::vec::Vec<(std::string::String, std::string::String)>, u64); 0]);
        }
    }
}

#[test]
fn pending_persist_drop_guard_detects_a_dropped_persist() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let probe = Arc::new(AtomicUsize::new(0));
    let dropped = PendingPersist::builder()
        .session(valid_session())
        .token_response(token_response_fixture())
        .expected_refresh_revision(0)
        .build()
        .with_drop_probe(Arc::clone(&probe));
    drop(dropped);
    assert_eq!(
        probe.load(Ordering::Relaxed),
        1,
        "a dropped owed persist must be detected"
    );
}

#[tokio::test]
async fn pending_persist_drop_guard_stays_silent_for_defused_guards() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    let probe = Arc::new(AtomicUsize::new(0));

    // `commit` defuses the guard (consuming the returned cookies keeps the
    // `SetCookies` guard quiet too — this test is about the persist guard).
    let e = engine(MockSessionStore::with_session(valid_session())).await;
    let committed = PendingPersist::builder()
        .session(valid_session())
        .token_response(token_response_fixture())
        .expected_refresh_revision(0)
        .build()
        .with_drop_probe(Arc::clone(&probe));
    let _cookies = committed
        .commit(&e, &api_headers())
        .await
        .unwrap()
        .into_headers();

    // So does `abandon`, the explicit non-commit verb.
    let abandoned = PendingPersist::builder()
        .session(valid_session())
        .token_response(token_response_fixture())
        .expected_refresh_revision(0)
        .build()
        .with_drop_probe(Arc::clone(&probe));
    abandoned.abandon();

    // An armed guard dropped by panic unwinding stays silent too: the owed
    // persist is collateral of the panic, not a separate bug to report.
    let unwind_probe = Arc::clone(&probe);
    let result = std::panic::catch_unwind(move || {
        let _armed = PendingPersist::builder()
            .session(valid_session())
            .token_response(token_response_fixture())
            .expected_refresh_revision(0)
            .build()
            .with_drop_probe(unwind_probe);
        panic!("handler panic");
    });
    assert!(result.is_err());

    assert_eq!(probe.load(Ordering::Relaxed), 0);
}

// ── DefaultPersistFailurePolicy ───────────────────────────────────────────

#[test]
fn default_persist_failure_policy_maps_kinds_and_is_no_store() {
    use super::super::PersistFailurePolicy as _;
    use crate::DefaultPersistFailurePolicy;
    let policy = DefaultPersistFailurePolicy;
    for (kind, expected) in [
        (SessionErrorKind::Conflict, StatusCode::CONFLICT),
        (SessionErrorKind::Crypto, StatusCode::INTERNAL_SERVER_ERROR),
        (
            SessionErrorKind::Encoding,
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
        (SessionErrorKind::Store, StatusCode::INTERNAL_SERVER_ERROR),
        (
            SessionErrorKind::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (SessionErrorKind::Gone, StatusCode::UNAUTHORIZED),
    ] {
        let err = SessionError::from(kind);
        let resp = policy
            .handle(&err)
            .expect("default policy replaces the response");
        assert_eq!(resp.status(), expected, "kind {kind:?}");
        // Session-adjacent responses are never cacheable.
        let no_store = resp
            .headers()
            .iter()
            .any(|(n, v)| *n == http::header::CACHE_CONTROL && v.as_bytes() == b"no-store");
        assert!(no_store, "persist-failure response must be no-store");
        let response_headers = resp.headers();
        let challenge = response_headers
            .iter()
            .find(|(name, _)| *name == http::header::WWW_AUTHENTICATE)
            .map(|(_, value)| value.as_bytes());
        assert_eq!(
            challenge,
            (kind == SessionErrorKind::Gone).then_some(b"Cookie".as_slice()),
            "only a gone session should request re-authentication"
        );
    }
}

// ── SetCookies drop guard ─────────────────────────────────────────────────

#[test]
fn set_cookies_drop_guard_fires_when_cookies_are_discarded() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::super::SetCookies;

    let probe = Arc::new(AtomicUsize::new(0));

    // The bug the guard exists for: matching `Active { session, .. }` takes
    // the session and drops the re-sealed cookies on the floor. Rust cannot
    // flag the `..` pattern at compile time, so the guard detects the drop
    // at runtime.
    // The `..` residue of a partially-moved local drops when the local's
    // scope ends, hence the inner block.
    let session = {
        let loaded = LoadedSession::Active {
            session: valid_session(),
            set_cookies: SetCookies::new(vec![HeaderValue::from_static("a=b")])
                .with_drop_probe(Arc::clone(&probe)),
        };
        match loaded {
            LoadedSession::Active { session, .. } => session,
            _ => unreachable!(),
        }
    };
    assert_eq!(
        probe.load(Ordering::Relaxed),
        1,
        "discarded cookies must be detected"
    );
    drop(session);
}

#[test]
fn set_cookies_drop_guard_stays_silent_for_consumed_and_empty_guards() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::super::SetCookies;

    let probe = Arc::new(AtomicUsize::new(0));

    // Consuming into headers defuses the guard.
    let consumed =
        SetCookies::new(vec![HeaderValue::from_static("a=b")]).with_drop_probe(Arc::clone(&probe));
    assert_eq!(consumed.len(), 1);
    assert_eq!(
        consumed.into_headers(),
        vec![HeaderValue::from_static("a=b")]
    );

    // So does consuming by iteration (the `extend(set_cookies)` shape).
    let iterated =
        SetCookies::new(vec![HeaderValue::from_static("c=d")]).with_drop_probe(Arc::clone(&probe));
    let mut sink: Vec<HeaderValue> = vec![];
    sink.extend(iterated);
    assert_eq!(sink.len(), 1);

    // So does the explicit non-delivery verb, for the path where the
    // response is already gone.
    let undeliverable =
        SetCookies::new(vec![HeaderValue::from_static("e=f")]).with_drop_probe(Arc::clone(&probe));
    undeliverable.discard();

    // The steady state — nothing owed — drops silently.
    let empty = SetCookies::default().with_drop_probe(Arc::clone(&probe));
    assert!(empty.is_empty());
    drop(empty);

    // A non-empty guard dropped by panic unwinding stays silent too: the
    // cookies are collateral of the panic, not a separate bug to report.
    let unwind_probe = Arc::clone(&probe);
    let result = std::panic::catch_unwind(move || {
        let _guarded =
            SetCookies::new(vec![HeaderValue::from_static("e=f")]).with_drop_probe(unwind_probe);
        panic!("handler panic");
    });
    assert!(result.is_err());

    assert_eq!(probe.load(Ordering::Relaxed), 0);
}
