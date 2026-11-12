# Initial Architecture

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

## Intended objectives

Future work may include request signing and verification, trusted-device
authentication and revocation, task authorization, replay prevention, SQLite
audit logging, and integration interfaces. These features are not implemented
in Phase 1.

## Scope boundary

This phase does not authenticate remote devices, authorize tasks, communicate
over a network, persist security events, or execute system commands. Key
rotation does not notify peers holding the old public key, and remote
revocation is not implemented. The project is an academic demonstration, not
a security certification.
