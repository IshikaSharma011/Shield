# Shield

Shield is a standalone cybersecurity framework being developed in Rust for
the DaemonONE distributed operating environment.

## Current status: Phase 1

Shield creates a device identity with a random UUID and Ed25519 key pair. It
stores the private key in the operating system's credential store and displays
or exports only the public key. The CLI also prints a welcome message and
supports `--help` and `--version`.

Phase 1 does not authenticate trusted devices, authorize tasks, prevent replay
attacks, communicate over a network, or write security audit logs. The OS
credential store must be available; Shield does not fall back to a plaintext
file. Do not use this phase as a production security system.

## Planned objectives

- Enroll and revoke trusted devices.
- Sign requests with Ed25519 and verify them against registered public keys.
- Authorize tasks using explicit allow-lists.
- Prevent replayed and expired requests.
- Record security decisions in SQLite without logging private key material.
- Provide an interactive terminal demonstration and integration-ready
  interfaces.

The objectives above describe planned work. Device identity creation and
public-key export are implemented; authentication and revocation are not.

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
- `docs/architecture.md`: architecture and phase boundaries.
- `docs/threat-model.md`: current security scope and limitations.

## Dependency

Clap parses command-line arguments. `uuid` creates random device IDs,
`ed25519-dalek` creates Ed25519 signing keys, and `rand_core` supplies the
operating-system random source. `keyring` accesses native OS credential
stores. `zeroize` clears temporary private-key buffers where practical. Error
handling uses Rust's standard library.

## Key lifecycle limitations

Keys are currently created once per OS account credential entry. Replacing a
key does not notify devices that already enrolled the old public key. Shield
does not yet provide a trusted-device registry or a remote revocation flow;
those peers must be updated manually until a later phase implements one.

## License

MIT. See [LICENSE](LICENSE).
