# Shield Architecture

Shield is a standalone cybersecurity framework for the DaemonONE distributed
operating environment. The project is organized as a Rust library with a
command-line application for development and demonstration.

## Phase 0: project foundation

The project starts as a Rust library with a small command-line application.
Application behavior belongs in the library (`src/lib.rs` and its modules);
`src/main.rs` is only the command-line entry point. The initial CLI displays a
welcome message and supports the standard `--help` and `--version` options.

The command-line parser is Clap. The error module uses Rust's standard error
traits.

## Phase 1: device identity

`src/device_identity.rs` creates a random UUID and Ed25519 signing key. The
private key and UUID are encoded into a small versioned bundle and persisted
only through the OS credential store. A device identity can be loaded from
that store. The library exposes the ID and a public-key enrollment string;
its debug and display output do not reveal the private key.

The CLI provides `identity create`, `identity show`, and
`identity export-public-key`. If native secure storage is unavailable, these
operations return an error and do not write a plaintext fallback file.

## Phase 2: signed requests

`src/signature.rs` defines task requests and a deterministic, versioned binary
format. It serializes the protocol marker and version, device and request IDs,
timestamp, nonce, task ID, and sorted parameters. `sign_request` signs the
exact serialized bytes with the sender's `DeviceIdentity`. Verification
strictly parses those same bytes, checks the request device ID against the
registered device ID supplied by the caller, and verifies the detached
signature with the separately supplied registered public key.

Request bytes and signature bytes are separate fields in `SignedRequest`.
This phase adds no trusted-device registry, network communication, timestamp
expiry check, or replay detection.

## Phase 3: trusted device registry

`src/device_registry.rs` stores device IDs, validated Ed25519 public keys,
names, registration times, and trusted/revoked status in SQLite. Enrollment
requires an operator-provided SHA-256 fingerprint that matches the supplied
public key. Unique database constraints prevent a device ID or public key
from being registered twice.

Authentication uses the untrusted request's device ID only to find a registry
record. It rejects unknown and revoked devices, then verifies the Phase 2
signature with the key read from SQLite. The request cannot supply its own
trusted key. Enrollment is separate from authentication; both are separate
from task authorization.

## Phase 4: task authorization

`src/authorization.rs` defines a small fixed catalog of task IDs and parameter
schemas. A device receives no task permissions automatically. An operator
explicitly grants a catalog task to a currently trusted device; grants are
stored in the same SQLite registry and are checked on each authorization.
Authorization accepts an `AuthenticatedRequest`, a value produced only after
registry-backed signature verification, then rechecks current trust, grant,
and exact parameter names and allowed values. It returns a structured allowed
or denied result and never runs a command.

## Phase 5: replay protection

`src/replay_protection.rs` checks the timestamp of an authenticated request
against a configurable maximum age and clock-skew allowance. It then stores
the request ID and nonce in the registry's SQLite database in an immediate
transaction. Both fields are unique within the authenticated device's scope.
The existing Phase 2 signed format already binds the device ID, request ID,
timestamp, nonce, task ID, and parameters. The request constructor obtains IDs
and nonces from the operating-system random source. A nonce alone is not
treated as proof of freshness; the verifier checks persistent state and time.

Expired replay records are removed during a later check only after their
request validity window ends. Clearing the database or restoring an old copy
can erase replay history. The system clock must be reasonably accurate; a
clock that moves backward or forward can cause valid requests to be denied or
affect expiry decisions. This phase still has no network protocol or
server-issued challenge.

## Intended objectives

Future work may include SQLite audit logging and integration interfaces.

## Scope boundary

Authentication checks that a trusted, non-revoked record's public key signed
the request. Authorization is a separate decision based on task allow-list,
device grant, and parameter schema.
Requests are checked for age and prior use in the local registry. There is no
network communication, audit logging, or system-command execution. The project
is an academic demonstration, not a security certification.
