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

## Intended objectives

Future work may include trusted-device authentication and revocation, task
authorization, replay prevention, SQLite audit logging, and integration
interfaces. These features are not implemented in Phase 2.

## Scope boundary

This phase verifies that the supplied registered public key signed a request;
it does not decide whether the sender is trusted or whether the requested task
is authorized. Requests are not checked for age or prior use, so timestamps
and nonces are signed but do not yet prevent replay. There is no network
communication, audit logging, or system-command execution. Key rotation does
not notify peers holding an old public key, and remote revocation is not
implemented. The project is an academic demonstration, not a security
certification.
