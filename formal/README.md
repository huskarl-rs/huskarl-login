# Session lifecycle model

This is an executable design model of the refresh/persist/deliver boundary in
`huskarl-login`, with separate cookie and store-backed behavior. It is a first
bounded safety analysis, not a verification of the Rust implementation or an
OAuth security proof.

## Run

From the repository root, with Docker running and Python 3.9+ available:

```sh
mise run model
```

This downloads TLC v1.7.4 into `target/formal/` if needed, verifies its checksum
through the runner, and runs all scenarios using the pinned Java container.
Logs and counterexample traces are saved in `target/formal/results/`. The jar
is reused on subsequent runs; the checks always run. All generated files are
under the already-ignored `target/` directory.

To run the checker directly instead:

Requires Python 3.9+ and Java 21, or Docker with the `--docker` option. Download
the pinned [TLA+ tools release v1.7.4](https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4):

```sh
curl -fL https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar \
  -o /tmp/huskarl-tla2tools-1.7.4.jar
python3 formal/check.py --jar /tmp/huskarl-tla2tools-1.7.4.jar \
  --output /tmp/huskarl-tlc-results
```

For Docker, add `--docker` to the Python command. The runner uses a Java image
pinned by digest, mounts the model and jar read-only, and disables container
network access. Docker may need to pull the image on its first run.

The runner verifies the jar's SHA-256, uses one TLC worker, and checks each
configuration's declared expectation. An expected counterexample counts as
success only if TLC reports that specific violated invariant; parsing errors
and unrelated violations fail the run. Full output, including counterexample
state traces, goes to the requested output directory. Nothing is downloaded by
the runner itself except Docker's normal image acquisition.

## Scope and assumptions

- One existing session and two or three requests, each refreshing at most once.
  There is no new login or session-key reuse after logout.
- `WholeSessionSaves` adds one application request that loads a token/revision
  snapshot and later attempts a whole-session save. `GuardSave` requires the
  revision still to match at the atomic CAS commit. `GuardWholeRefreshState`
  additionally requires the token/expiry state to match the stored value;
  mismatches and missing records do not write. Replacing application payload fields is omitted from
  this action: those fields remain last-writer-wins within a refresh generation.
- `PendingWholeSaves` also lets the whole-save writer copy a request's own
  refreshed in-memory session while its refresh persist is pending. This retains
  the original revision, matching the current driver error path.
- Load, exchange, save, response delivery, and logout delivery are separate
  actions. Requests may pause between any of these actions; responses may be
  dropped. A completed logout response can overtake an earlier refresh response.
- Token values represent protected refresh-token/expiry generations, not
  credentials. This abstracts expiry-only changes for non-rotating tokens too. `CoordinatedRefresh`
  assumes exchanges of the same input converge on the same output. With it off,
  the abstract AS accepts reused inputs during a grace window and issues distinct
  tokens. Neither setting models the actual cache algorithm, reuse rejection,
  cache expiry, or token-family revocation.
- Store saves represent the successful CAS linearization point, applying the
  refresh to the latest record. An absent record cannot be recreated. CAS
  conflicts/retries and backend implementation correctness are abstracted away.
  `GuardRefresh` enables the fixed revision precondition. Each request captures
  `expectedRevision` at load; a committed refresh increments the stored revision.
  A mismatched expected revision skips the write. Application updates do not
  increment the refresh revision. Historical store counterexamples disable the
  guard to demonstrate the defect.
- One independent application update is allowed. Refresh leaves that field
  untouched, matching the built-in session refresh behavior. Custom
  `Session::apply_refresh` implementations can violate that assumption.
- Cookie saves prepare an entire coherent cookie bundle; delivery replaces the
  browser's bundle. Chunk parsing, partial header handling, and cryptography are
  outside this model. Store refreshes emit no replacement pointer cookie.
- `SaveFailure` models a failure before commit. `LostAcknowledgement` models
  a durable store write followed by an error. Both retain the original expected
  revision for a deferred retry. `RetryPersist` permits one deferred retry;
  either attempt may fail.
- Logout models successful record deletion in store mode and browser clearing
  in both modes. Failed revocation is not claimed to invalidate a record.
- There is no clock, expiry, idle tracking, handler execution, AS logout, or
  refresh rejection. A request may be delayed across another refresh generation;
  the model does not establish the real-time conditions needed for that delay.
- No fairness or temporal progress property is asserted. Deadlock checking is
  disabled because finite requests terminate and some never load after logout.
  Stuttering is allowed by `Spec`; these runs check safety only.

## Mapping to Rust

| Model action | Implementation boundary |
|---|---|
| `Load` | `LoginEngine::load_session` / `SessionDriver::load` |
| `Exchange` | `LoginEngine::refresh_with_retry` returning a token response |
| `Save` (store) | `StoreBackedSessionStore::apply_refresh_and_save` and `commit_refresh` |
| `Save` (cookie) | `CookieSessionStore::save_session` preparing cookie headers |
| `SaveFailure` / `LostAcknowledgement` / `retry` | `LoadedSession::ActivePending` and `PendingPersist::commit` |
| `Deliver` / `DropResponse` | Adapter delivery of `SetCookies`, outside this crate |
| `Logout` / `DeliverLogout` | `handle_logout` revocation followed by adapter delivery |
| `UpdateApplication` | A successful `StoreBackedSessionStore::update` |
| `LoadWholeSession` / `LoadPendingWholeSession` / `SaveWholeSession` | An application's loaded snapshot and `save_session` CAS commit |

`NoResurrection` and `ApplicationUpdatesPreserved` check the consequences of
the modeled store contract, not the CAS implementation itself. The interesting
ordering question is what happens when a successfully merged refresh is stale
relative to another refresh: preserving application fields does not imply
preserving the newest token.

## Checks and findings

The suite contains twelve passing safety configurations and seven expected
counterexamples. All nineteen expectations matched on 2026-09-27 using the
pinned tools. The three-request guarded store runs explored 37,430 distinct
states with coordinated exchanges and 97,866 without coordination, including
lost acknowledgements. Both satisfy token monotonicity, deletion, and
application-preservation invariants under the model's assumptions.

The three-request whole-session-save scenarios explore 228,650 states with
coordinated exchanges and 558,966 without. Both prevent token rollback with
the whole-save guards enabled. The historical configuration disables both
whole-save guards and reproduces rollback while the refresh-commit guard
remains enabled. The application-preservation invariant covers the modeled
merge-safe update; it does not claim that whole-session replacement merges
application payload fields.

The three-request pending-whole-save scenarios now pass with coordinated
exchanges (371,262 distinct states) and uncoordinated exchanges (1,041,666).
Whole-session saves cannot publish refreshed tokens under the pre-exchange
revision because `GuardWholeRefreshState` rejects a token/expiry mismatch.

The historical pending counterexample disables only `GuardWholeRefreshState`:
A and B load revision 0 and receive tokens 1 and 2. B's eager save fails, then
B whole-saves token 2 under revision 0. A commits token 1 against revision 0,
advancing to revision 1; B's deferred retry adopts token 1. Keeping this negative
configuration verifies that removing the new check restores the defect.
`pending_whole_save_rejects_uncommitted_refresh` guards the fixed Rust behavior.
Pending refreshes must use `PendingPersist::commit`, which checks the original
revision and advances it on commit.

The two historical store negative configurations set `GuardRefresh = FALSE`.
They still exhibit token regression, confirming that removing the guard restores
the counterexample. The three cookie negative configurations remain unchanged:
uncoordinated exchange results can arrive out of order, same-input coordination
cannot prevent cross-generation delivery rollback, and delayed cookies can
restore a session after logout.

The guard addresses stored-state ordering, not provider-side credential validity.
The model does not include token-family revocation. Independent exchanges can
still invalidate the winning result at the provider. The actual engine directly
calls the refresh grant; the client's cache abstractions are not automatically
part of that path.

Both retry settings satisfy the selected two-request safety checks. **This does
not justify removing deferred persistence.** No recovery/liveness property is
checked, and both settings permit loss after failures. A follow-up model needs
explicit availability, response-delivery, and scheduling assumptions to compare
recovery guarantees fairly.

## Rust regression coverage

Run the original schedules with:

```sh
cargo test delayed_refresh -- --nocapture
```

- `store_session::tests::delayed_refresh_save_preserves_newer_generation`:
  A and B load token 0. A saves token 1; C loads it and saves token 2. B then
  attempts to save the same token-1 response that A used. The driver adopts
  stored token 2 and its expiry/revision without another database write.
- `cookie_session::tests::delayed_refresh_delivery_reproduces_token_regression`:
  the real cookie driver seals A's and B's token-1 responses. A is delivered;
  C loads token 1 and its token-2 response is delivered. Finally B's delayed
  cookies replace token 2. This characterization still asserts the current
  cookie limitation; it is not a desired guarantee.

Additional Rust tests cover failures before commit, a backend that commits then
returns an error, duplicate retries, non-rotating refresh responses, revision
changes during a CAS conflict, logout, revision overflow, and deserialization
of older sessions. The engine deferred-retry test changes the in-memory revision
and verifies that the original expected revision is still passed to the driver.
Whole-session save tests also cover stale-revision rejection, a refresh racing
the CAS attempt, retries around unrelated writes, and bounded conflict retries.
Pending-state tests cover changed tokens, expiry-only changes without rotation,
and a successful deferred commit after the whole save is rejected. Serialization
tests verify that comparison uses whole-second expiry precision and that the
stored expiry is preserved exactly. Run these with `cargo test whole_save` and
`cargo test whole_session_save`.

The schedules use controlled token responses and issuance times rather than a
real AS or refresh cache. They establish driver behavior, not an end-to-end
provider/cache reproduction or a measured real-world failure rate.

## Next steps

1. Design an explicit exchange-coordination integration if provider policy
   requires it; the revision guard is not exchange serialization.
2. Add time and frozen lifetime checks, then recovery/liveness properties under
   stated fairness and availability assumptions. Current safety checks do not
   establish eventual recovery or justify dropping deferred persistence.

Keep this abstraction and its action mapping synchronized when changing refresh
or persistence contracts. Add implementation regression tests for confirmed
counterexamples; a passing model does not establish that Rust refines it.
