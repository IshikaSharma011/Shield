# Shield

Shield is a standalone cybersecurity framework being developed in Rust for
the DaemonONE distributed operating environment.

## Current status: Phase 2

Shield creates a device identity with a random UUID and Ed25519 key pair. It
stores the private key in the operating system's credential store and displays
or exports only the public key. The CLI also prints a welcome message and
supports `--help` and `--version`.

Phase 2 can create and verify signed request messages, but it does not
authenticate trusted devices, authorize tasks, reject replayed requests,
communicate over a network, or write security audit logs. The caller must
provide the public key already registered for the request's device ID. Do not
use this phase as a production security system.

## Planned objectives

- Enroll and revoke trusted devices.
- Authorize tasks using explicit allow-lists.
- Prevent replayed and expired requests.
- Record security decisions in SQLite without logging private key material.
- Provide an interactive terminal demonstration and integration-ready
  interfaces.

Device identity creation, public-key export, and request signing and
verification are implemented. Trusted-device registration and authentication,
authorization, replay prevention, and revocation are planned work.

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
```

## Project layout

- `src/lib.rs` and `src/`: library API, configuration, and error structure.
- `src/main.rs`: small command-line entry point.
- `tests/`: integration tests.
- `docs/device-identity.md`: identity generation, storage, and key lifecycle.
- `docs/signature-format.md`: request serialization and signature verification.
- `docs/architecture.md`: architecture and phase boundaries.
- `docs/threat-model.md`: current security scope and limitations.

## Dependency

Clap parses command-line arguments. `uuid` creates random device IDs,
`ed25519-dalek` creates and verifies Ed25519 signatures, and `rand_core`
supplies the operating-system random source. `uuid` represents device and
request IDs. `keyring` accesses native OS credential stores. `zeroize` clears
temporary private-key buffers where practical. Error handling uses Rust's
standard library.

## Key lifecycle limitations

Keys are currently created once per OS account credential entry. Replacing a
key does not notify devices that already enrolled the old public key. Shield
does not yet provide a trusted-device registry or a remote revocation flow;
those peers must be updated manually until a later phase implements one.

## License

MIT. See [LICENSE](LICENSE).
