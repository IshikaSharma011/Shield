# Integrated Security Engine

`SecurityEngine` provides one entry point for validating a signed task request.
It composes the existing modules; it does not replace their APIs.

## Complete execution flow

1. **Create and sign:** A sender calls `SecurityEngine::create_signed_request`
   with a `DeviceIdentity`, a task ID, and parameters. `TaskRequest::new`
   creates a random request ID and nonce and records the current timestamp.
   Phase 2 serializes all request fields canonically and signs those exact
   bytes with Ed25519.
2. **Authenticate:** `process_request` sends the detached signed request to
   `DeviceRegistry`. The registry looks up the registered public key and
   verifies the signature. Unknown or revoked devices and modified requests
   are rejected.
3. **Check replay:** The replay module checks maximum age and permitted clock
   skew, then atomically checks and stores the request ID and nonce in SQLite.
   Concurrent copies cannot both reserve the same device-scoped identifier.
4. **Authorize:** The authorization module checks that the device has an
   explicit grant for the predefined task and that every parameter matches
   that task's schema. Authentication alone does not authorize a task.
5. **Audit and return:** Each stage records its decision, and the engine records
   the final pipeline outcome. It returns either a typed rejection or a
   `SimulatedTaskApproval` message. The result means the request passed Shield's
   checks; it does not run a task or operating-system command.

Any failed check stops the pipeline. If the required audit write fails, the
engine rejects the request. If the database is unavailable, replay checks and
audit writes fail closed.

## Result types

`RequestValidation` is either `Accepted(SimulatedTaskApproval)` or
`Rejected(RejectedRequest)`. The approval contains the request ID, device ID,
task ID, and a message that explicitly says no task ran. A rejection identifies
the phase: authentication, replay protection, authorization, or audit storage.
Before authentication succeeds, request and device identifiers are omitted
from the returned rejection because the request cannot yet be trusted.

The project does not add transport or networking. Integrators must call the
pipeline after obtaining the signed request through their own trusted input
boundary. There is no operating-system command executor.

The Phase 8 terminal shell calls the same engine methods for authentication,
authorization, and full request processing. Its database is in memory and
isolated from the normal registry database.
