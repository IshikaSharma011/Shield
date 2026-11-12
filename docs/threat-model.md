# Initial Threat Model

## System in scope

Phase 1 consists of a local Rust CLI and library. It creates a UUID and
Ed25519 key pair, persists the private key bundle through the OS credential
store, and displays or exports public identity data.

## Security objectives

The private signing key should not be written to ordinary files, printed, or
included in debug output. Shield fails closed if it cannot access the native
credential store. Public-key enrollment data can be displayed for manual
sharing.

## Out of scope

Device impersonation, forged signatures, replayed requests, unauthorized task
execution, key theft from a compromised OS account, malicious network traffic,
and audit-log tampering are not mitigated because the corresponding controls
do not yet exist. A local attacker who can access an unlocked credential store
may be able to retrieve the signing key.

## Assumptions and limitations

The CLI runs as the invoking user. OS credential-store protection depends on
the host OS, account configuration, and whether the store is unlocked. The
key is present in process memory while loaded; clearing temporary buffers
cannot guarantee removal of every runtime or operating-system copy. There is
no hardware-backed key storage, trust registry, or remote revocation. Replacing
a local key cannot revoke an old public key already copied by another device.
Tests establish expected behavior, not effectiveness against a determined
attacker.
