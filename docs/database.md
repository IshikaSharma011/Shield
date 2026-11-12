# SQLite Database

Phase 6 centralizes SQLite setup and versioned schema migrations in
`src/database.rs`. `DeviceRegistry::open` opens this shared database and applies
any pending migrations before registry, permission, replay, or audit operations
run. Migrations use a transaction and update SQLite's `user_version` only when
the migration succeeds. Existing Phase 5 permission and replay rows are copied
into the new table names. The old tables are retained so the migration does
not discard existing data.

## Tables and relationships

| Table | Purpose and relationships |
| --- | --- |
| `trusted_devices` | One row per enrolled device. Its primary key is the device ID; the public key is also unique. It stores only a public key and registration metadata, never a private key. |
| `approved_tasks` | Primary-key task IDs and descriptions for Shield's predefined task catalog. Permissions can refer only to a catalog entry. |
| `device_permissions` | Many-to-many link between devices and approved tasks. The `(device_id, task_id)` composite primary key prevents duplicate grants; both columns are foreign keys. |
| `used_nonces` | Replay records scoped to a device. `(device_id, request_id)` is the primary key and `(device_id, nonce)` is unique. Both are foreign-keyed to `trusted_devices`. Expiry supports safe cleanup after requests are no longer valid. |
| `security_logs` | Persisted decision metadata: event time, category, outcome, optional device/request/task IDs, and a fixed reason. It deliberately does not foreign-key the device ID so failed authentication attempts for unknown claimed IDs can be recorded. No request parameters, nonces, signatures, or private keys are stored. |

Replay validation and insertion run in an immediate transaction. Enrollment,
revocation, and permission changes write their audit row in the same database
transaction as the state change. A storage or audit failure rolls back the
operation. Authentication, authorization, and replay rejections are logged as
separate decision events when the database can accept the log row.

## Safe backup and restore

Use SQLite's online backup API while Shield may be active. If using a simple
file copy, stop all Shield processes that use the database first, then copy the
database file. Keep backups under the same access controls as the original,
store them in a protected location, and test restores using a separate copy.
Never include device private keys in a database backup; Shield stores them in
the operating-system credential store.

Restoring an older database also restores older trust, permission, and replay
state. That can re-enable revoked devices or allow previously seen requests to
be treated as new, so restore decisions are security-sensitive.

## Audit log retention

The log has no automatic pruning in this phase. It will grow as decisions are
recorded. Operators should define a retention period that matches their
demonstration or deployment needs, preserve required records, and remove old
entries through a reviewed SQLite maintenance procedure. Log rows contain
decision metadata, but rejected authentication rows may include a device ID
claimed by an untrusted request.
