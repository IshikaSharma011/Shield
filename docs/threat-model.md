# Shield Threat Model

## System in scope

Phase 2 consists of a local Rust CLI and library. It creates device
identities, serializes task requests in a deterministic versioned format,
signs the exact request bytes, and verifies signatures against public keys
provided separately by the caller.

## Security objectives

The private signing key should not be written to ordinary files, printed, or
included in debug output. Shield fails closed if it cannot access the native
credential store. Public-key enrollment data can be displayed for manual
sharing. A verifier must retrieve the registered public key independently
using the request's device ID; the request itself contains no public key.

## Out of scope

The signature detects request modification and proves possession of the
private key corresponding to the supplied public key. This is not by itself
trusted-device authentication or task authorization. Replayed requests,
expired timestamps, unauthorized task execution, network threats, and
audit-log tampering are not mitigated. A local attacker who can access an
unlocked credential store may be able to retrieve the signing key.

## Assumptions and limitations

The CLI runs as the invoking user. OS credential-store protection depends on
the host OS, account configuration, and whether the store is unlocked. The
key is present in process memory while loaded; clearing temporary buffers
cannot guarantee removal of every runtime or operating-system copy. There is
no hardware-backed key storage, trust registry, or remote revocation. Replacing
a local key cannot revoke an old public key already copied by another device.
The request parser imposes size limits, but the caller still must apply
authorization, expiry, and replay checks in later phases. Tests establish
expected behavior, not effectiveness against a determined attacker.
