# Shield

Shield is a standalone cybersecurity framework being developed in Rust for
the DaemonONE distributed operating environment.

## Current status: Phase 0

The current application is a project foundation. It prints a welcome message
and supports `--help` and `--version`. It does not yet authenticate devices,
authorize tasks, prevent replay attacks, communicate over a network, or write
security audit logs. Do not use it to protect production systems.

## Planned objectives

- Manage device identities and trusted-device enrollment and revocation.
- Sign requests with Ed25519 and verify them against registered public keys.
- Authorize tasks using explicit allow-lists.
- Prevent replayed and expired requests.
- Record security decisions in SQLite without logging private key material.
- Provide an interactive terminal demonstration and integration-ready
  interfaces.

The objectives above describe planned work. Only the Phase 0 features listed
under current status are implemented so far.

## Requirements

- Stable Rust toolchain with Cargo.

## Build and run

```sh
cargo run
cargo run -- --help
cargo run -- --version
```

## Project layout

- `src/lib.rs` and `src/`: library API, configuration, and error structure.
- `src/main.rs`: small command-line entry point.
- `tests/`: integration tests.
- `docs/architecture.md`: architecture and phase boundaries.
- `docs/threat-model.md`: current security scope and limitations.

## Dependency

Clap provides command-line parsing and generated help/version options. The
initial error type uses Rust's standard library, so no error-handling
dependency is needed yet.

## License

MIT. See [LICENSE](LICENSE).
