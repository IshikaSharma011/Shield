# Shield Architecture

Shield is a Rust library and command-line demonstration for the DaemonONE distributed operating environment. The library owns security decisions; `src/main.rs` parses CLI arguments and presents results. The code currently implements a local demonstration pipeline, not a distributed service.

## Component map

| Component | Main responsibility | Persistent state |
| --- | --- | --- |
| `config` | Application name and welcome text. | None |
| `device_identity` | Generate a random UUID and Ed25519 key pair, persist the identity in the OS credential store, and expose public information. | Private identity bundle in the OS credential store only. |
| `signature` | Validate and serialize task requests in a versioned deterministic format; sign and verify the exact encoded bytes. | None |
| `device_registry` | Manually enroll public keys after fingerprint comparison; look up trusted devices, revoke them, and manage task grants. | SQLite registry records and permissions. |
| `authorization` | Apply the predefined task catalog, per-device grant, and parameter schema. | Reads and writes SQLite permissions. |
| `replay_protection` | Enforce request time limits and atomically reserve device-scoped request IDs and nonces. | SQLite replay records. |
| `database` | Initialize and migrate the schema, enforce constraints, run transactions, and store audit events. | SQLite database. |
| `security_engine` | Call authentication, replay checks, authorization, and auditing in order; return typed results. | Uses the registry database. |
| `demo_shell` | Collect menu input and display results by calling the engine and its existing interfaces. | In-memory SQLite for the process lifetime. |

The CLI supports identity creation, display and public-key export; registry enrollment, listing, and revocation; task grant management; task-catalog display; and the interactive demo. The `--help` and `--version` flags are provided by Clap.

## Request path

1. **Create:** `TaskRequest::new` creates a random request ID and nonce and captures a millisecond Unix timestamp. Callers provide a device ID, task ID, and parameter map.
2. **Encode:** `TaskRequest::serialize` encodes a magic value, format version, IDs, timestamp, nonce, task, and sorted parameters. The parser rejects unsupported versions, invalid field encodings, oversized values, unsorted/duplicate keys, and trailing data.
3. **Sign:** `sign_request` signs the exact serialized bytes with the local Ed25519 private key. The detached signature is stored separately from the request bytes.
4. **Authenticate:** the registry uses the request device ID to look up a locally registered public key and status. It rejects unknown or revoked devices and verifies the exact bytes against that stored key. Request-supplied key material is not trusted.
5. **Check freshness and replay:** `ReplayProtection` checks the timestamp against its maximum-age and clock-skew policy. A SQLite immediate transaction checks and inserts the device-scoped request ID and nonce, using uniqueness constraints to prevent concurrent duplicate reservations.
6. **Authorize:** `AuthorizationEngine` checks that the task is in the fixed catalog, the device is currently trusted, a grant exists, and the parameter names and values satisfy that task's schema.
7. **Audit and respond:** stage and pipeline decisions are written to `security_logs`. If the required final audit write fails, the engine returns a rejection. Otherwise it returns an accepted simulated approval or a structured rejection. No task is executed.

Authentication establishes that a request signature matches an enrolled public key. Authorization separately decides whether that trusted device may request the specified catalog task with those parameters. A signature by itself does not grant permission.

## SQLite data model

- `trusted_devices` stores a unique device ID and public key, name, enrollment timestamp, and `trusted` or `revoked` status.
- `approved_tasks` contains the identifiers Shield recognizes from its compiled-in catalog.
- `device_permissions` links devices to tasks using a composite primary key and foreign keys.
- `used_nonces` uses `(device_id, request_id)` as its primary key and `(device_id, nonce)` as a unique constraint. It stores expiry for safe cleanup after the corresponding request is no longer valid.
- `security_logs` stores timestamp, category, decision, optional IDs, and a fixed reason. It intentionally does not foreign-key device IDs so unknown claimed IDs can be audited.

SQLite foreign-key enforcement is enabled when the connection is initialized. Schema changes are versioned with `PRAGMA user_version` and transactional migrations. Values are passed through rusqlite parameters. State-changing operations that include audit rows use a transaction so an audit failure rolls back the corresponding change. See [database.md](database.md) for backup, migration, and retention details.

## Demo boundary

The interactive demo creates an in-memory database on each launch. Sample data is created only when `--setup-demo-data` is specified, and the UI labels it as test data. The local demo confirms its displayed fingerprint in the same interaction; that is a teaching simulation, not independent out-of-band verification. Demo data is not written into a normal registry database file.

## Concurrency and consistency

The replay reservation uses an immediate write transaction and database uniqueness constraints, so competing connections cannot both reserve the same device-scoped request ID or nonce. This is tested using independent SQLite connections.

The complete pipeline is not one transaction. Authentication, replay checking, authorization, and audit writes occur in sequence. Authorization rechecks current device status, but a revocation from another process can still race between that status check and the final response. The current interface does not promise linearizable revocation. A future network service would need explicit request/revocation ordering and transaction semantics.

## Scope boundary

Implemented capabilities are local identity management, signatures, manual registration and revocation, task decisioning, replay state, auditing, the pipeline, and the demonstration menu. Network communication, device discovery, synchronization, remote challenges, actual task execution, hardware-backed keys, and tamper-evident audit storage are not implemented. This architecture is suitable for an academic demonstration and interface exploration; it is not a production security certification.
