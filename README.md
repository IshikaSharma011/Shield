# Shield

Shield is a standalone cybersecurity framework being developed in Rust for
the DaemonONE distributed operating environment.

## Current status: Phase 4

Shield creates a device identity with a random UUID and Ed25519 key pair. It
stores the private key in the operating system's credential store and displays
or exports only the public key. The CLI also prints a welcome message and
supports `--help` and `--version`.

Phase 3 supports explicit manual enrollment with a SHA-256 public-key
fingerprint, SQLite-backed trusted-device records, authentication using
Phase 2 signatures, and revocation. Phase 4 adds a predefined task allow-list,
explicit per-device task grants, and strict parameter validation. Authorization
returns a decision only; this demonstration does not execute tasks or commands.
It does not reject replayed requests, communicate over a network, or write
security audit logs. Do not use this phase as a production security system.

## Planned objectives

- Prevent replayed and expired requests.
- Record security decisions in SQLite without logging private key material.
- Provide an interactive terminal demonstration and integration-ready
  interfaces.

Device identity creation, signed requests, trusted-device enrollment,
authentication, revocation, and allow-list authorization are implemented.
Replay prevention, networking, and security audit logging remain planned work.

## Requirements

- Stable Rust toolchain with Cargo.

## Build and run

```sh
cargo run
cargo run -- --help
cargo run -- --version
cargo run -- identity create
cargo run -- identity show
cargo run -- identity export-public-key
cargo run -- registry list --database shield-registry.sqlite3
cargo run -- registry enroll --database shield-registry.sqlite3 --device-id <UUID> --name <NAME> --public-key <ED25519_PUBLIC_KEY> --fingerprint <SHA256_FINGERPRINT>
cargo run -- registry revoke --database shield-registry.sqlite3 --device-id <UUID>
cargo run -- authorization tasks
cargo run -- registry grant-task --database shield-registry.sqlite3 --device-id <UUID> --task-id status.report
cargo run -- registry revoke-task --database shield-registry.sqlite3 --device-id <UUID> --task-id status.report
```

## Project layout

- `src/lib.rs` and `src/`: library API, configuration, and error structure.
- `src/main.rs`: small command-line entry point.
- `tests/`: integration tests.
- `docs/device-identity.md`: identity generation, storage, and key lifecycle.
- `docs/signature-format.md`: request serialization and signature verification.
- `docs/device-registry.md`: enrollment, authentication, and revocation.
- `docs/authorization.md`: predefined tasks, grants, and parameter rules.
- `docs/architecture.md`: architecture and phase boundaries.
- `docs/threat-model.md`: current security scope and limitations.

## Dependency

Clap parses command-line arguments. `uuid` creates random device IDs,
`ed25519-dalek` creates and verifies Ed25519 signatures, and `rand_core`
supplies the operating-system random source. `uuid` represents device and
request IDs. `keyring` accesses native OS credential stores. `rusqlite` stores
public registry records and task grants, and `sha2` computes enrollment fingerprints.
`zeroize` clears temporary private-key buffers where practical. Error handling
uses Rust's standard library.

## Key lifecycle limitations

Keys are currently created once per OS account credential entry. Replacing a
key does not notify other installations that enrolled the old public key.
Revocation is stored in the local registry; registry changes are not shared
with peers automatically.

## License

MIT. See [LICENSE](LICENSE).
