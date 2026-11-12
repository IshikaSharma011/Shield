# Shield Threat Model

## Purpose and current system

This document describes the implemented local Shield demonstration. Shield is intended to teach device identity, request signing, explicit trust enrollment, task authorization, replay checks, and audit recording for the DaemonONE distributed operating environment. There is no network listener, transport protocol, remote device discovery, or task executor.

The system consists of a Rust CLI/library, an operating-system credential-store entry for the local signing identity, and a local SQLite registry. An optional interactive demo uses an in-memory SQLite database and ephemeral identities. It does not update an existing registry file.

## Security objectives

- Keep the local private signing key out of ordinary files, SQLite, debug output, and audit logs.
- Generate identity and request randomness from the operating-system random source.
- Sign every security-relevant request field in a versioned canonical representation.
- Authenticate only against a public key that was manually enrolled in the registry.
- Separate authentication from task authorization.
- Permit only known tasks, explicit device grants, and schema-valid parameters.
- Reject stale, excessively future-dated, or previously accepted requests according to local policy and state.
- Fail closed when required storage, verification, or audit operations fail.
- Keep audit records useful for demonstrations without recording signatures, nonces, request parameters, or private keys.

## Assets

- Ed25519 private signing key and its device ID association.
- Enrolled public keys and trusted/revoked status.
- Per-device task grants and the compiled-in authorization catalog.
- Replay history used to reject previously accepted request IDs and nonces.
- Audit records that explain security decisions.

## Trust boundaries

1. **Local OS account to credential service:** key protection depends on the OS credential backend, account permissions, and whether the credential store is unlocked. Shield does not use a plaintext-file fallback. A key loaded for signing is present in process memory.
2. **Operator to device registry:** enrollment is a manual trust decision. The operator must compare a fingerprint through a separately trusted channel. The demo's same-session confirmation only simulates this process.
3. **Request bytes to verifier:** all request bytes, identifiers, parameters, timestamps, and signatures are untrusted until parsing and verification succeed. The verifier obtains the public key from the local registry rather than from the request.
4. **Application to SQLite:** local database permissions determine who can change trust, permission, replay, and audit state. SQL parameters prevent value-based SQL injection; they do not protect a database from an administrator who can modify the file.
5. **Clock to freshness check:** timestamp validation assumes a reasonably accurate, non-rollback system clock. Client timestamps do not establish trusted time.

## Threats addressed by implemented controls

| Threat | Current control | Limit |
| --- | --- | --- |
| Request fields changed after signing | Verify Ed25519 over exact canonical request bytes. | Does not protect data in transit because no transport exists. |
| Unknown or revoked identity attempts authentication | Registry lookup and status check before signature acceptance. | Trust state is local to one database copy. |
| Request supplies its own public key | Ignore request-supplied key material; use the registered key. | Manual enrollment remains a trust-on-operator process. |
| A valid signature requests an unauthorized task | Separate catalog, per-device grant, and parameter-schema checks. | Catalog is small and compiled into this demonstration. |
| Old or concurrent duplicate request is submitted | Timestamp policy, device-scoped SQLite uniqueness constraints, and immediate transaction. | Database rollback, clock rollback, or deleting replay history weakens this control. |
| Storage or audit write fails | Security operations return errors or reject the pipeline result. State-changing operations with audit writes use transactions. | A local attacker can alter or delete the database outside the running process. |
| Secret material leaks through normal formatting or logs | Private key is encapsulated; identity and request debug output redact secret fields; logs exclude key material and request payloads. | This is not a memory-forensics guarantee; process dumps and host compromise are out of scope. |

## Out of scope

Shield does not currently mitigate network interception, endpoint compromise, denial of service, malicious OS administrators, device discovery spoofing, database-file tampering, log deletion, or compromise of an unlocked credential store. It does not provide TLS, peer synchronization, server-issued challenges, hardware-backed keys, remote revocation propagation, or independent trusted time. It does not run commands or provide a remote shell.

## Concurrency and revocation limitation

Replay uniqueness is atomic at the database level. The entire request pipeline, however, is not one transaction. A request can authenticate, then another connection can revoke the device while the first request proceeds through replay and authorization checks. Authorization rechecks the device state, which narrows the race, but a revocation can still occur after that check and before the final response. Shield therefore does not promise immediate linearizable revocation for already-running requests. A production service would need an explicit concurrency model, such as a transaction or serialized policy decision boundary covering revocation and acceptance.

## Database rollback, backup, and retention

The registry database contains public keys, trust state, permissions, replay records, and audit metadata. Restoring an older copy can restore a previously trusted state or remove replay history. Protect database files and backups with OS access controls; test restores on a separate copy. See [database.md](database.md) for backup guidance. Audit logs have no automatic retention policy and are not tamper-evident; an operator must manage retention and protect the database.

## Key lifecycle limitations

Key rotation is not automated. Replacing a key locally does not inform other registry copies or revoke an old public key already enrolled elsewhere. Revocation is manual and local. A compromised OS account or unlocked credential store may expose the signing key. Zeroizing selected temporary buffers does not guarantee removal of every copy from process memory, runtime internals, swap, or crash dumps.

## Security claims and evidence

Shield demonstrates checks that are implemented and exercised by its tests; tests do not prove that the overall system is secure. The project is not production-ready and has not undergone an independent security assessment, formal protocol review, penetration test, or deployment review. Passing compilation, lint, or unit tests must not be described as certification or proof of security.
