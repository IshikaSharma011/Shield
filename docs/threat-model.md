# Shield Threat Model

## System in scope

Phase 8 consists of a local Rust CLI and library. It creates device
identities, serializes and signs requests, stores manually enrolled public-key
records with trusted or revoked status in SQLite, and evaluates task requests
against explicit per-device grants and predefined parameter schemas. It also
checks authenticated requests for timestamp validity and records replay keys
and security decisions in the migrated SQLite database. The integrated
security engine composes authentication, replay checks, and authorization and
returns a simulated approval or structured rejection. The interactive
demonstration uses only an in-memory database and ephemeral test identities,
so it cannot change a normal registry database.

## Security objectives

The private signing key should not be written to ordinary files, printed, or
included in debug output. Shield fails closed if it cannot access the native
credential store. Public-key enrollment data can be displayed for manual
sharing. A verifier must retrieve the registered public key independently
using the request's device ID; the request itself contains no public key.

## Out of scope

The signature detects request modification and proves possession of the
private key corresponding to the supplied public key. This is not by itself
trusted-device authentication or task authorization. Replay checks use local
SQLite state and do not provide cross-machine protection. Network threats,
network threats, actual task execution, and audit-log tampering are not
mitigated. A local attacker who can access an
unlocked credential store may be able to retrieve the signing key.

## Assumptions and limitations

The CLI runs as the invoking user. OS credential-store protection depends on
the host OS, account configuration, and whether the store is unlocked. The
key is present in process memory while loaded; clearing temporary buffers
cannot guarantee removal of every runtime or operating-system copy. There is
no hardware-backed key storage or automatic registry synchronization.
Tampering with or restoring an old copy of the local database could
change trust, permission, or replay decisions. The authorization catalog is
intentionally small and fixed, and authorization only returns a decision; no
task runner is present. System clock error can reject otherwise valid requests
or affect timestamp decisions. Client timestamps cannot establish trusted time.
Replacing a local key cannot revoke an old public key already copied by
another installation. Replay records are retained until their request cannot
pass the configured age check, then deleted during a later replay check. An
operator must preserve the database and its backups to preserve replay history.
Security-log records have no automatic retention limit and can grow without
bound; an operator must define and apply a retention policy. Failed
authentication logs can include a device ID claimed by an unauthenticated
request, so that field is not proof of identity.
The request parser imposes size limits, and authorization applies the current
allow-list and parameter schemas.
Tests establish expected behavior, not effectiveness against a determined
attacker.
