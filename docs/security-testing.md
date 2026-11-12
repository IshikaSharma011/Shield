# Security Testing Guide

This guide describes how to run Shield's existing checks and what security behaviors its tests cover. Tests are evidence that selected cases behave as expected; they are not a security proof or a substitute for independent review.

## Local prerequisites

- Stable Rust and Cargo.
- The repository's `Cargo.lock` file.
- A working SQLite build environment. The project enables rusqlite's bundled SQLite feature.

The normal tests use in-memory databases or temporary database files. Device identity tests use generated random keys. They do not require a production credential-store entry. The interactive CLI identity commands do require an available OS credential store.

## Required checks

Run from the project root:

```sh
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

CI runs these four checks on stable Rust. `cargo clippy --all-targets` includes library, binary, and test targets; `-D warnings` makes lint warnings fail the check.

## Existing security coverage

| Area | Representative behaviors tested |
| --- | --- |
| Identity | Unique device IDs and public keys; public-key export; private key omitted from `Debug`; credential-store failure does not fall back to a file. |
| Signature format | Deterministic/versioned encoding; valid signature; modified bytes; incorrect key; malformed request/signature; every security-relevant field is covered. |
| Registry | Fingerprint-checked enrollment; unknown, duplicate, or revoked devices; authentication with registry key; persistence and transactional failures. |
| Authorization | Explicit grant required; valid task and parameters; unknown task; ungranted device; invalid, missing, or unexpected parameters; revoked status. |
| Replay prevention | New request accepted; repeated request ID or nonce rejected; expired and excessive-future timestamps rejected; device-scoped uniqueness; concurrent duplicates cannot both be accepted. |
| Database | Schema creation and reopen; migrations; persistence; constraints; audit records; corruption and transaction failures. |
| Security engine | Accepted request; unknown/revoked device; modified request; invalid signature; unauthorized task; duplicate request; expired request; audit/database failure. |
| Demo shell | Invalid menu input; menu actions call engine interfaces; visible results and test-data flow. |

Integration tests are in `tests/`; focused module tests are colocated with the implementation under `src/`.

## Manual academic checks

1. Run `cargo run -- --help` and `cargo run -- --version`.
2. Run `cargo run -- demo --setup-demo-data` and confirm the UI labels the generated record as test data.
3. Submit a valid `status.report` request with `format=summary` and observe the simulated approval.
4. Submit the same request again and observe replay rejection.
5. Attempt an ungranted task or a parameter value outside the task schema and observe authorization rejection.
6. View audit rows and confirm they contain decisions and fixed reasons, not request parameters, signatures, nonces, or private keys.
7. Exit and confirm the in-memory demo data is gone on the next launch.

Do not use a real production registry database for the demo. The demo is designed to use an isolated in-memory database.

## Dependency advisory audit

If `cargo-audit` is installed and its advisory database is available, run:

```sh
cargo audit
```

The current review environment did not have the `cargo-audit` subcommand installed, so no RustSec advisory scan was completed. Install and run it separately before a release, then review each advisory and the dependency's reachability and remediation. Do not treat the absence of a local audit result as a clean scan.

## Limits of the test suite

The tests do not assess the security of platform credential stores, memory exposure, OS account configuration, malicious local database access, dependency supply-chain compromise, real network transport, distributed revocation, trusted time, or denial-of-service resistance. They also do not resolve the race between a revocation and a request already being processed. These require design work, platform-specific review, and independent assessment beyond unit and integration tests.
