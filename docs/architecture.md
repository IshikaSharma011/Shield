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
from task authorization, which is not implemented yet.

## Intended objectives

Future work may include task authorization, replay prevention, SQLite audit
logging, and integration interfaces. These features are not implemented in
Phase 3.

## Scope boundary

Authentication checks that a trusted, non-revoked record's public key signed
the request. It does not decide whether the requested task is authorized.
Requests are not checked for age or prior use, so timestamps and nonces do
not yet prevent replay. There is no network communication, audit logging, or
system-command execution. The project is an academic demonstration, not a
security certification.
