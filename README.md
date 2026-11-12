# Shield

Shield is a Rust cybersecurity framework demonstration for the DaemonONE distributed operating environment. It demonstrates device identity, Ed25519 request signatures, manually managed device trust, task allow-list authorization, replay checks, SQLite audit records, and a terminal walkthrough.

Shield is an academic engineering project. It has no network transport and does not execute requested tasks or operating-system commands. It is not a production security product and has not received an independent security review.

## Problem statement

Distributed systems need a way to distinguish known devices, verify that requests were signed by an enrolled device, decide whether that device may request a specific operation, and reject stale or repeated requests. This project demonstrates those decisions as separate security stages and records them in a local database. It focuses on the security interface and evaluation flow rather than on a network protocol or task runner.

## Objectives

- Create a device identity with a random UUID and Ed25519 signing key.
- Keep the private key in the operating-system credential store.
- Sign a versioned canonical representation of each request.
- Enroll and revoke trusted devices through explicit operator actions.
- Authenticate requests against registered public keys.
- Allow only predefined tasks and validated parameter values.
- Reject expired and replayed requests using persistent SQLite state.
- Record security decisions without storing request payloads or key material.
- Provide a beginner-friendly interactive demonstration and reusable Rust interfaces.

## Features

- **Device identity:** UUID and Ed25519 key creation, identity display, and public-key export.
- **Signed requests:** deterministic, versioned encoding; the signature covers the exact request bytes, including device ID, request ID, task, parameters, timestamp, and nonce.
- **Manual trust registry:** fingerprint-confirmed enrollment, registered-key authentication, and device revocation.
- **Task authorization:** fixed task catalog, explicit per-device grants, and strict parameter schemas. Authorization returns a decision; it does not execute a task.
- **Replay prevention:** timestamp window checks and atomic, device-scoped request-ID and nonce reservations in SQLite.
- **Security audit:** persisted decision metadata that excludes signatures, request parameters, nonces, and private keys.
- **Integrated pipeline:** authentication, replay checking, authorization, and auditing produce a typed acceptance or rejection result.
- **Interactive demo:** an in-memory database keeps demonstration records separate from a normal registry database. Optional sample records are explicitly labeled test data.

## Technology stack

Shield uses stable Rust (edition 2021), Cargo, SQLite, and the following direct dependencies:

| Dependency | Purpose |
| --- | --- |
| `clap` | Command-line parsing and generated help/version output. |
| `ed25519-dalek` | Ed25519 signing and signature verification. |
| `keyring` | Access to the operating-system credential store for identity persistence. |
| `rand_core` | Cryptographically secure operating-system randomness. |
| `rusqlite` | Parameterized SQLite access, transactions, and bundled SQLite. |
| `sha2` | SHA-256 public-key fingerprints used during manual enrollment. |
| `uuid` | Device and request identifiers. |
| `zeroize` | Clears selected temporary secret buffers where supported. |

`Cargo.lock` records the resolved dependency versions for reproducible application builds. Error handling uses standard-library traits and module-specific error types; there is no general-purpose error-handling dependency.

## Architecture

The library contains the security logic. `src/main.rs` parses CLI input and calls library operations.

```text
DeviceIdentity -> canonical TaskRequest -> Ed25519 signature
                                      |
                                      v
SecurityEngine -> registered-key authentication
               -> timestamp and SQLite replay check
               -> task allow-list and device permission check
               -> audit event -> simulated approval or rejection
```

| Module | Responsibility |
| --- | --- |
| `device_identity` | Generate/load identity and expose safe public-key display/export. |
| `signature` | Canonical request encoding, signing, and verification. |
| `device_registry` | Manual enrollment, registered public keys, trust state, revocation, and permissions. |
| `authorization` | Fixed task catalog, grants, parameter validation, and authorization decisions. |
| `replay_protection` | Request timestamp checks and persistent replay reservations. |
| `database` | SQLite schema migrations, constraints, transactions, and audit storage. |
| `security_engine` | Ordered request-validation pipeline and typed results. |
| `demo_shell` | Interactive interface that calls the library and engine. |

See [docs/architecture.md](docs/architecture.md) for the detailed flow and [docs/threat-model.md](docs/threat-model.md) for security boundaries and assumptions.

## Installation

Install a stable Rust toolchain with Cargo, then build from the project directory:

```sh
cargo check
cargo build
```

The `keyring` backend requires a usable credential service for the current operating-system account. If it cannot access that service, identity persistence fails; Shield does not fall back to a plaintext key file.

## Usage

Show CLI options and the application version:

```sh
cargo run -- --help
cargo run -- --version
```

Create and view a local identity or export its public enrollment data:

```sh
cargo run -- identity create
cargo run -- identity show
cargo run -- identity export-public-key
```

Enrollment is an operator-managed process. Share the device ID, public key, and fingerprint through a suitable out-of-band channel, compare the fingerprint independently, then enroll the public key in the receiving registry:

```sh
cargo run -- registry enroll --database shield-registry.sqlite3 \
  --device-id <UUID> --name <NAME> \
  --public-key <ED25519_PUBLIC_KEY> \
  --fingerprint <SHA256_FINGERPRINT>
cargo run -- registry list --database shield-registry.sqlite3
cargo run -- registry revoke --database shield-registry.sqlite3 --device-id <UUID>
```

Grant a predefined task explicitly. A trusted device receives no task grants by default:

```sh
cargo run -- authorization tasks
cargo run -- registry grant-task --database shield-registry.sqlite3 \
  --device-id <UUID> --task-id status.report
cargo run -- registry revoke-task --database shield-registry.sqlite3 \
  --device-id <UUID> --task-id status.report
```

The registry database is local state. Keep it under appropriate access controls and do not treat enrollment in one copy as automatically shared with other machines. Local `shield-registry.sqlite3` database files are covered by `.gitignore`.

## Academic demonstration

Run the isolated interactive demo:

```sh
cargo run -- demo
```

To begin with one labeled sample device and its limited `status.report` permission:

```sh
cargo run -- demo --setup-demo-data
```

Suggested walkthrough:

1. Choose **2** to show the sample test device.
2. Choose **3**, select it, request `status.report`, and enter `summary` for `format`.
3. Use **4** to show signature authentication and **5** to show task authorization.
4. Use **6** to submit a request twice and observe replay rejection.
5. Use **8** to run the complete pipeline, including an unauthorized task attempt.
6. Choose **7** to view audit events and **9** to exit.

Demo registrations, grants, replay records, and logs exist only in the process's in-memory database and disappear when it exits. The demo does not alter a registry database file, use networking, or execute tasks. For all menu options and a fuller walkthrough, see [docs/demo-shell.md](docs/demo-shell.md).

## Testing

Run the same core checks used by CI:

```sh
cargo fmt --check
cargo check
cargo clippy --all-targets -- -D warnings
cargo test
```

See [docs/security-testing.md](docs/security-testing.md) for coverage, test scenarios, and audit-tool guidance. Passing tests show that the tested cases behave as expected; they do not establish security against all attackers.

## Limitations

- There is no network transport, peer discovery, remote challenge, or registry synchronization.
- The CLI has no task executor. An accepted request means only that the local checks passed; no operation was run.
- The credential-store protection depends on the host operating system, account, and store configuration. A loaded key exists in process memory while in use.
- Trust, permissions, replay history, and audit records are local SQLite state. Database access, tampering, rollback, or restoration can affect security decisions.
- Replay protection is limited to the database instance and depends on a sufficiently accurate system clock. Clock rollback and database rollback are not solved.
- Authentication and authorization are sequential database checks, not one transaction with revocation. A revocation concurrent with an already-running request may race with the final decision.
- Audit logs have no automatic retention policy and are not tamper-evident against a local database administrator.
- Key rotation and distribution of revocation information are manual. Replacing a local key does not revoke copies of the previous public key held elsewhere.
- The demo's displayed fingerprint confirmation models an operator interaction; it does not prove an independent out-of-band comparison.
- This academic project has not had an independent security assessment and is not production-ready.

## Future scope

Potential future phases could define a reviewed network protocol, authenticated transport, registry synchronization, managed key rotation and revocation distribution, stronger database and audit protections, concurrency semantics for revocation, and a carefully sandboxed task adapter. Those capabilities are not implemented in this release.

## Project documentation

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat-model.md)
- [Security testing guide](docs/security-testing.md)
- [Device identity and key lifecycle](docs/device-identity.md)
- [Request signature format](docs/signature-format.md)
- [Device registration](docs/device-registry.md)
- [Task authorization](docs/authorization.md)
- [Replay protection](docs/replay-protection.md)
- [SQLite database and backups](docs/database.md)
- [Security engine](docs/security-engine.md)
- [Terminal demonstration](docs/demo-shell.md)

## License

MIT. See [LICENSE](LICENSE).
