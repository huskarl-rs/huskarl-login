------------------------- MODULE SessionLifecycle -------------------------
EXTENDS Integers, FiniteSets, TLC

CONSTANTS Mode, Requests, RetryPersist, CoordinatedRefresh, GuardRefresh, WholeSessionSaves, GuardSave, PendingWholeSaves, GuardWholeRefreshState
ASSUME /\ Mode \in {"store", "cookie"}
       /\ Requests # {}
       /\ RetryPersist \in BOOLEAN
       /\ CoordinatedRefresh \in BOOLEAN
       /\ GuardRefresh \in BOOLEAN
       /\ WholeSessionSaves \in BOOLEAN
       /\ GuardSave \in BOOLEAN
       /\ PendingWholeSaves \in BOOLEAN
       /\ GuardWholeRefreshState \in BOOLEAN

(* One existing session, no new login. Token generations abstract the
   protected refresh token + expiry state (including non-rotating refreshes).
   -1 represents an absent browser cookie. The store cookie is a pointer.
   Persistence is atomic at the successful CAS linearization point; this
   abstraction does not verify the backend CAS implementation itself. *)
VARIABLES writer, phase, snapshot, refreshed, response, revision, expectedRevision,
          browser, record, exists, deleted, issuer,
          appVersion, expectedAppVersion,
          logoutPhase, logoutDelivered, highWater, regressed

vars == <<writer, phase, snapshot, refreshed, response, revision, expectedRevision, browser, record, exists,
          deleted, issuer, appVersion, expectedAppVersion, logoutPhase,
          logoutDelivered, highWater, regressed>>

Init ==
    /\ writer = [phase |-> "new", token |-> 0, revision |-> 0]
    /\ revision = 0
    /\ expectedRevision = [r \in Requests |-> 0]
    /\ phase = [r \in Requests |-> "new"]
    /\ snapshot = [r \in Requests |-> 0]
    /\ refreshed = [r \in Requests |-> 0]
    /\ response = [r \in Requests |-> "none"]
    /\ browser = 0
    /\ record = 0
    /\ exists = TRUE
    /\ deleted = FALSE
    /\ issuer = 0
    /\ appVersion = 0
    /\ expectedAppVersion = 0
    /\ logoutPhase = "new"
    /\ logoutDelivered = FALSE
    /\ highWater = 0
    /\ regressed = FALSE

Load(r) ==
    /\ phase[r] = "new"
    /\ browser # -1
    /\ Mode = "cookie" \/ exists
    /\ expectedRevision' = [expectedRevision EXCEPT ![r] = revision]
    /\ snapshot' = [snapshot EXCEPT ![r] = IF Mode = "store" THEN record ELSE browser]
    /\ phase' = [phase EXCEPT ![r] = "loaded"]
    /\ UNCHANGED <<writer, revision, refreshed, response, browser, record, exists, deleted,
                   issuer, appVersion, expectedAppVersion, logoutPhase,
                   logoutDelivered, highWater, regressed>>

(* Coordinated exchanges of the same input converge on the same output.
   Uncoordinated exchanges model an AS grace window that accepts stale inputs
   and issues distinct tokens. Reuse rejection / token-family revocation is
   deliberately outside this first model. *)
Exchange(r) ==
    /\ phase[r] = "loaded"
    /\ LET token == IF CoordinatedRefresh THEN snapshot[r] + 1 ELSE issuer + 1
       IN /\ refreshed' = [refreshed EXCEPT ![r] = token]
          /\ issuer' = IF token > issuer THEN token ELSE issuer
    /\ phase' = [phase EXCEPT ![r] = "save"]
    /\ UNCHANGED <<writer, revision, expectedRevision, snapshot, response, browser, record, exists, deleted,
                   appVersion, expectedAppVersion, logoutPhase,
                   logoutDelivered, highWater, regressed>>

TransientExchangeFailure(r) ==
    /\ phase[r] = "loaded"
    /\ phase' = [phase EXCEPT ![r] = "done"]
    /\ UNCHANGED <<writer, revision, expectedRevision, snapshot, refreshed, response, browser, record, exists,
                   deleted, issuer, appVersion, expectedAppVersion,
                   logoutPhase, logoutDelivered, highWater, regressed>>

CanCommit(r) == exists /\ (~GuardRefresh \/ expectedRevision[r] = revision)

SaveResult(r, target) ==
    /\ phase[r] \in {"save", "retry"}
    /\ phase' = [phase EXCEPT ![r] = target]
    /\ IF Mode = "store"
          THEN /\ record' = IF CanCommit(r) THEN refreshed[r] ELSE record
               /\ revision' = IF CanCommit(r) THEN revision + 1 ELSE revision
               /\ response' = [response EXCEPT ![r] = IF exists THEN "none" ELSE "clear"]
               /\ highWater' = IF CanCommit(r) /\ refreshed[r] > highWater THEN refreshed[r] ELSE highWater
               /\ regressed' = (regressed \/ (CanCommit(r) /\ refreshed[r] < highWater))
          ELSE /\ response' = [response EXCEPT ![r] = "set"]
               /\ UNCHANGED <<writer, revision, record, highWater, regressed>>
    /\ UNCHANGED <<writer, expectedRevision, snapshot, refreshed, browser, exists, deleted, issuer,
                   appVersion, expectedAppVersion, logoutPhase, logoutDelivered>>

Save(r) == SaveResult(r, "deliver")

(* A durable write followed by a lost acknowledgement. Retrying retains the
   pre-exchange expectedRevision, including when another refresh intervenes. *)
LostAcknowledgement(r) ==
    /\ Mode = "store"
    /\ CanCommit(r)
    /\ SaveResult(r, IF phase[r] = "save" /\ RetryPersist THEN "retry" ELSE "done")

(* One eager attempt and at most one deferred retry, matching PendingPersist.
   Cookie-mode failure abstracts sealing/serialization failure. *)
SaveFailure(r) ==
    /\ phase[r] \in {"save", "retry"}
    /\ Mode = "cookie" \/ exists
    /\ phase' = [phase EXCEPT ![r] =
          IF @ = "save" /\ RetryPersist THEN "retry" ELSE "done"]
    /\ UNCHANGED <<writer, revision, expectedRevision, snapshot, refreshed, response, browser, record, exists,
                   deleted, issuer, appVersion, expectedAppVersion,
                   logoutPhase, logoutDelivered, highWater, regressed>>

Deliver(r) ==
    /\ phase[r] = "deliver"
    /\ phase' = [phase EXCEPT ![r] = "done"]
    /\ browser' = CASE response[r] = "set" -> refreshed[r]
                       [] response[r] = "clear" -> -1
                       [] OTHER -> browser
    /\ highWater' = IF response[r] = "set" /\ refreshed[r] > highWater
                       THEN refreshed[r] ELSE highWater
    /\ regressed' = (regressed \/ (response[r] = "set" /\ refreshed[r] < highWater))
    /\ UNCHANGED <<writer, revision, expectedRevision, snapshot, refreshed, response, record, exists, deleted,
                   issuer, appVersion, expectedAppVersion, logoutPhase, logoutDelivered>>

DropResponse(r) ==
    /\ phase[r] = "deliver"
    /\ phase' = [phase EXCEPT ![r] = "done"]
    /\ UNCHANGED <<writer, revision, expectedRevision, snapshot, refreshed, response, browser, record, exists,
                   deleted, issuer, appVersion, expectedAppVersion,
                   logoutPhase, logoutDelivered, highWater, regressed>>

(* A successful backend deletion; failed logout revocation is not claimed
   to revoke anything. Browser delivery remains a separate event. *)
Logout ==
    /\ logoutPhase = "new"
    /\ logoutPhase' = "deliver"
    /\ exists' = IF Mode = "store" THEN FALSE ELSE exists
    /\ deleted' = IF Mode = "store" THEN TRUE ELSE deleted
    /\ UNCHANGED <<writer, revision, expectedRevision, phase, snapshot, refreshed, response, browser, record,
                   issuer, appVersion, expectedAppVersion, logoutDelivered,
                   highWater, regressed>>

DeliverLogout ==
    /\ logoutPhase = "deliver"
    /\ logoutPhase' = "done"
    /\ browser' = -1
    /\ logoutDelivered' = TRUE
    /\ UNCHANGED <<writer, revision, expectedRevision, phase, snapshot, refreshed, response, record, exists,
                   deleted, issuer, appVersion, expectedAppVersion, highWater, regressed>>

(* One independent application mutation; refresh merges against fresh state. *)
UpdateApplication ==
    /\ Mode = "store" /\ exists /\ expectedAppVersion = 0
    /\ appVersion' = 1
    /\ expectedAppVersion' = 1
    /\ UNCHANGED <<writer, revision, expectedRevision, phase, snapshot, refreshed, response, browser, record,
                   exists, deleted, issuer, logoutPhase, logoutDelivered,
                   highWater, regressed>>

(* One application request saves an unchanged token snapshot. Application
   payload replacement is omitted: whole-session saves are last-writer-wins
   for those fields, unlike the merge-safe UpdateApplication action. *)
LoadWholeSession ==
    /\ WholeSessionSaves /\ Mode = "store" /\ exists /\ browser # -1
    /\ writer.phase = "new"
    /\ writer' = [phase |-> "loaded", token |-> record, revision |-> revision]
    /\ UNCHANGED <<phase, snapshot, refreshed, response, revision, expectedRevision,
                   browser, record, exists, deleted, issuer, appVersion, expectedAppVersion,
                   logoutPhase, logoutDelivered, highWater, regressed>>

(* A handler snapshots its own refreshed in-memory session while the eager
   persist is pending. Its revision is still the one observed before exchange. *)
LoadPendingWholeSession(r) ==
    /\ WholeSessionSaves /\ PendingWholeSaves /\ Mode = "store"
    /\ writer.phase = "new" /\ phase[r] = "retry"
    /\ writer' = [phase |-> "loaded", token |-> refreshed[r], revision |-> expectedRevision[r]]
    /\ UNCHANGED <<phase, snapshot, refreshed, response, revision, expectedRevision,
                   browser, record, exists, deleted, issuer, appVersion, expectedAppVersion,
                   logoutPhase, logoutDelivered, highWater, regressed>>

SaveWholeSession ==
    /\ WholeSessionSaves /\ Mode = "store" /\ writer.phase = "loaded"
    /\ writer' = [writer EXCEPT !.phase = "done"]
    /\ LET accepted == exists
                       /\ (~GuardSave \/ writer.revision = revision)
                       /\ (~GuardWholeRefreshState \/ writer.token = record)
       IN /\ record' = IF accepted THEN writer.token ELSE record
          /\ revision' = IF accepted THEN writer.revision ELSE revision
          /\ highWater' = IF accepted /\ writer.token > highWater THEN writer.token ELSE highWater
          /\ regressed' = (regressed \/ (accepted /\ writer.token < highWater))
    /\ UNCHANGED <<phase, snapshot, refreshed, response, expectedRevision,
                   browser, exists, deleted, issuer, appVersion, expectedAppVersion,
                   logoutPhase, logoutDelivered>>

Next == (\E r \in Requests : Load(r) \/ Exchange(r) \/ Save(r)
          \/ TransientExchangeFailure(r) \/ SaveFailure(r) \/ LostAcknowledgement(r)
          \/ Deliver(r) \/ DropResponse(r) \/ LoadPendingWholeSession(r))
        \/ Logout \/ DeliverLogout \/ UpdateApplication \/ LoadWholeSession \/ SaveWholeSession

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ writer \in [phase: {"new", "loaded", "done"}, token: 0..Cardinality(Requests), revision: 0..(2 * Cardinality(Requests))]
    /\ revision \in 0..(2 * Cardinality(Requests))
    /\ expectedRevision \in [Requests -> 0..(2 * Cardinality(Requests))]
    /\ phase \in [Requests -> {"new", "loaded", "save", "retry", "deliver", "done"}]
    /\ snapshot \in [Requests -> 0..Cardinality(Requests)]
    /\ refreshed \in [Requests -> 0..Cardinality(Requests)]
    /\ response \in [Requests -> {"none", "set", "clear"}]
    /\ browser \in {-1} \cup (0..Cardinality(Requests))
    /\ record \in 0..Cardinality(Requests)
    /\ issuer \in 0..Cardinality(Requests)
    /\ highWater \in 0..Cardinality(Requests)
    /\ appVersion \in 0..1 /\ expectedAppVersion \in 0..1
    /\ logoutPhase \in {"new", "deliver", "done"}
    /\ <<exists, deleted, logoutDelivered, regressed>> \in BOOLEAN \X BOOLEAN \X BOOLEAN \X BOOLEAN

NoResurrection == Mode = "store" => (deleted => ~exists)
ApplicationUpdatesPreserved == appVersion = expectedAppVersion
NoTokenRegression == ~regressed
LogoutStaysEffective == logoutDelivered =>
    (IF Mode = "store" THEN ~exists ELSE browser = -1)
=============================================================================
