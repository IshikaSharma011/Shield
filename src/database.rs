//! Versioned SQLite storage shared by the registry and security modules.

use std::{
    fmt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::{params, Connection, TransactionBehavior};
use uuid::Uuid;

const LATEST_SCHEMA_VERSION: i64 = 2;

const MIGRATION_1: &str = "CREATE TABLE IF NOT EXISTS trusted_devices (
    device_id TEXT PRIMARY KEY NOT NULL,
    public_key BLOB NOT NULL UNIQUE CHECK (length(public_key) = 32),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    registered_at INTEGER NOT NULL CHECK (registered_at >= 0),
    status TEXT NOT NULL CHECK (status IN ('trusted', 'revoked'))
);
CREATE TABLE IF NOT EXISTS approved_tasks (
    task_id TEXT PRIMARY KEY NOT NULL,
    description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_permissions (
    device_id TEXT NOT NULL REFERENCES trusted_devices(device_id) ON DELETE CASCADE,
    task_id TEXT NOT NULL REFERENCES approved_tasks(task_id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, task_id)
);
CREATE TABLE IF NOT EXISTS used_nonces (
    device_id TEXT NOT NULL REFERENCES trusted_devices(device_id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,
    nonce BLOB NOT NULL CHECK (length(nonce) = 32),
    expires_at INTEGER NOT NULL CHECK (expires_at >= 0),
    PRIMARY KEY (device_id, request_id),
    UNIQUE (device_id, nonce)
);
CREATE TABLE IF NOT EXISTS security_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at INTEGER NOT NULL CHECK (occurred_at >= 0),
    category TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('accepted', 'rejected')),
    device_id TEXT,
    request_id TEXT,
    task_id TEXT,
    reason TEXT
);";

const MIGRATION_2: &str = "CREATE INDEX IF NOT EXISTS idx_security_logs_time
    ON security_logs(occurred_at);
CREATE INDEX IF NOT EXISTS idx_security_logs_device
    ON security_logs(device_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_used_nonces_expiry
    ON used_nonces(expires_at);";

/// An open SQLite database with all supported migrations applied.
pub struct Database {
    pub(crate) connection: Connection,
}

impl Database {
    /// Opens or creates a database file and applies pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let connection = Connection::open(path).map_err(map_database_error)?;
        Self::from_connection(connection)
    }

    /// Opens a migrated in-memory database, primarily for tests.
    pub fn open_in_memory() -> Result<Self, DatabaseError> {
        let connection = Connection::open_in_memory().map_err(map_database_error)?;
        Self::from_connection(connection)
    }

    pub(crate) fn from_connection(connection: Connection) -> Result<Self, DatabaseError> {
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(map_database_error)?;
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(map_database_error)?;

        let mut database = Self { connection };
        database.migrate()?;
        Ok(database)
    }

    /// Returns the schema version currently stored in SQLite.
    pub fn schema_version(&self) -> Result<i64, DatabaseError> {
        self.connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(map_database_error)
    }

    /// Lists currently approved task identifiers in stable order.
    pub fn approved_tasks(&self) -> Result<Vec<String>, DatabaseError> {
        let mut statement = self
            .connection
            .prepare("SELECT task_id FROM approved_tasks ORDER BY task_id")
            .map_err(map_database_error)?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(map_database_error)?;
        rows.map(|row| row.map_err(map_database_error)).collect()
    }

    /// Lists permissions currently assigned to a device.
    pub fn device_permissions(&self, device_id: Uuid) -> Result<Vec<String>, DatabaseError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT task_id FROM device_permissions
                 WHERE device_id = ?1 ORDER BY task_id",
            )
            .map_err(map_database_error)?;
        let rows = statement
            .query_map([device_id.to_string()], |row| row.get::<_, String>(0))
            .map_err(map_database_error)?;
        rows.map(|row| row.map_err(map_database_error)).collect()
    }

    /// Returns audit rows in chronological insertion order. The caller must
    /// choose a bounded limit to avoid loading an unbounded history.
    pub fn security_logs(&self, limit: usize) -> Result<Vec<SecurityLog>, DatabaseError> {
        let limit = i64::try_from(limit).map_err(|_| DatabaseError::StorageUnavailable)?;
        let mut statement = self
            .connection
            .prepare(
                "SELECT log_id, occurred_at, category, decision, device_id,
                        request_id, task_id, reason
                 FROM security_logs ORDER BY log_id LIMIT ?1",
            )
            .map_err(map_database_error)?;
        let rows = statement
            .query_map([limit], |row| {
                Ok(SecurityLog {
                    log_id: row.get(0)?,
                    occurred_at: row.get(1)?,
                    category: row.get(2)?,
                    decision: row.get(3)?,
                    device_id: row.get(4)?,
                    request_id: row.get(5)?,
                    task_id: row.get(6)?,
                    reason: row.get(7)?,
                })
            })
            .map_err(map_database_error)?;
        rows.map(|row| row.map_err(map_database_error)).collect()
    }

    /// Records a security event without request parameters, signatures, or
    /// private-key material.
    pub fn record_security_event(&self, event: &SecurityEvent<'_>) -> Result<(), DatabaseError> {
        let transaction = self
            .connection
            .unchecked_transaction()
            .map_err(map_database_error)?;
        insert_security_event(&transaction, event)?;
        transaction.commit().map_err(map_database_error)
    }

    fn migrate(&mut self) -> Result<(), DatabaseError> {
        let current = self.schema_version()?;
        if current > LATEST_SCHEMA_VERSION {
            return Err(DatabaseError::UnsupportedSchemaVersion(current));
        }

        if current < 1 {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(map_database_error)?;
            transaction
                .execute_batch(MIGRATION_1)
                .map_err(map_database_error)?;
            seed_approved_tasks(&transaction)?;
            migrate_legacy_tables(&transaction)?;
            validate_schema(&transaction)?;
            transaction
                .execute_batch("PRAGMA user_version = 1;")
                .map_err(map_database_error)?;
            transaction.commit().map_err(map_database_error)?;
        }

        if current < 2 {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(map_database_error)?;
            transaction
                .execute_batch(MIGRATION_2)
                .map_err(map_database_error)?;
            transaction
                .execute_batch("PRAGMA user_version = 2;")
                .map_err(map_database_error)?;
            transaction.commit().map_err(map_database_error)?;
        }
        Ok(())
    }
}

/// A privacy-conscious audit row. `reason` should be a fixed, reviewed reason
/// string; request parameters and signature bytes must never be supplied.
#[derive(Debug, Clone, Copy)]
pub struct SecurityEvent<'a> {
    pub category: &'static str,
    pub accepted: bool,
    pub device_id: Option<Uuid>,
    pub request_id: Option<Uuid>,
    pub task_id: Option<&'a str>,
    pub reason: Option<&'static str>,
}

/// A persisted audit record that excludes request parameters and key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityLog {
    pub log_id: i64,
    pub occurred_at: i64,
    pub category: String,
    pub decision: String,
    pub device_id: Option<String>,
    pub request_id: Option<String>,
    pub task_id: Option<String>,
    pub reason: Option<String>,
}

pub(crate) fn insert_security_event(
    connection: &Connection,
    event: &SecurityEvent<'_>,
) -> Result<(), DatabaseError> {
    let occurred_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DatabaseError::ClockUnavailable)?
        .as_millis();
    let occurred_at = i64::try_from(occurred_at).map_err(|_| DatabaseError::ClockUnavailable)?;
    connection
        .execute(
            "INSERT INTO security_logs
             (occurred_at, category, decision, device_id, request_id, task_id, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                occurred_at,
                event.category,
                if event.accepted {
                    "accepted"
                } else {
                    "rejected"
                },
                event.device_id.map(|id| id.to_string()),
                event.request_id.map(|id| id.to_string()),
                event.task_id,
                event.reason,
            ],
        )
        .map_err(map_database_error)?;
    Ok(())
}

fn seed_approved_tasks(connection: &Connection) -> Result<(), DatabaseError> {
    for task in crate::authorization::TASKS {
        connection
            .execute(
                "INSERT OR IGNORE INTO approved_tasks (task_id, description)
                 VALUES (?1, ?2)",
                params![task.task_id, task.description],
            )
            .map_err(map_database_error)?;
    }
    Ok(())
}

fn migrate_legacy_tables(connection: &Connection) -> Result<(), DatabaseError> {
    if table_exists(connection, "device_task_permissions")? {
        connection
            .execute_batch(
                "INSERT OR IGNORE INTO device_permissions (device_id, task_id)
                 SELECT legacy.device_id, legacy.task_id
                 FROM device_task_permissions AS legacy
                 INNER JOIN approved_tasks AS tasks ON tasks.task_id = legacy.task_id
                 INNER JOIN trusted_devices AS devices ON devices.device_id = legacy.device_id;",
            )
            .map_err(map_database_error)?;
    }

    if table_exists(connection, "replay_requests")? {
        connection
            .execute_batch(
                "INSERT OR IGNORE INTO used_nonces (device_id, request_id, nonce, expires_at)
                 SELECT legacy.device_id, legacy.request_id, legacy.nonce, legacy.expires_at
                 FROM replay_requests AS legacy
                 INNER JOIN trusted_devices AS devices ON devices.device_id = legacy.device_id;",
            )
            .map_err(map_database_error)?;
    }
    Ok(())
}

fn validate_schema(connection: &Connection) -> Result<(), DatabaseError> {
    for query in [
        "SELECT device_id, public_key, name, registered_at, status FROM trusted_devices LIMIT 0",
        "SELECT task_id, description FROM approved_tasks LIMIT 0",
        "SELECT device_id, task_id FROM device_permissions LIMIT 0",
        "SELECT device_id, request_id, nonce, expires_at FROM used_nonces LIMIT 0",
        "SELECT log_id, occurred_at, category, decision, device_id, request_id, task_id, reason FROM security_logs LIMIT 0",
    ] {
        connection
            .prepare(query)
            .map_err(map_database_error)?;
    }
    Ok(())
}

fn table_exists(connection: &Connection, table_name: &str) -> Result<bool, DatabaseError> {
    connection
        .query_row(
            "SELECT EXISTS (
                SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1
             )",
            [table_name],
            |row| row.get(0),
        )
        .map_err(map_database_error)
}

fn map_database_error(error: rusqlite::Error) -> DatabaseError {
    match error {
        rusqlite::Error::SqliteFailure(ref failure, _)
            if matches!(
                failure.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase
            ) =>
        {
            DatabaseError::CorruptDatabase
        }
        _ => DatabaseError::StorageUnavailable,
    }
}

/// Database initialization, migration, and persistence failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseError {
    StorageUnavailable,
    CorruptDatabase,
    UnsupportedSchemaVersion(i64),
    ClockUnavailable,
}

impl fmt::Display for DatabaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorageUnavailable => formatter.write_str("The SQLite database is unavailable."),
            Self::CorruptDatabase => {
                formatter.write_str("The SQLite database is corrupt or invalid.")
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(
                    formatter,
                    "Database schema version {version} is newer than this Shield version supports."
                )
            }
            Self::ClockUnavailable => {
                formatter.write_str("The system clock is unavailable or invalid.")
            }
        }
    }
}

impl std::error::Error for DatabaseError {}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, time::SystemTime};

    use super::{Database, DatabaseError, SecurityEvent};

    fn temporary_database_path() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("shield-database-{unique}.sqlite3"))
    }

    #[test]
    fn database_creation_and_reopen_apply_current_migrations() {
        let path = temporary_database_path();
        {
            let database = Database::open(&path).expect("create database");
            assert_eq!(database.schema_version().expect("read version"), 2);
        }
        let database = Database::open(&path).expect("reopen database");
        assert_eq!(database.schema_version().expect("read version"), 2);
        drop(database);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[test]
    fn audit_events_persist_without_secret_payload_fields() {
        let path = temporary_database_path();
        let device_id =
            uuid::Uuid::parse_str("01010101-0101-4101-8101-010101010101").expect("valid test UUID");
        {
            let database = Database::open(&path).expect("create database");
            database
                .record_security_event(&SecurityEvent {
                    category: "test",
                    accepted: false,
                    device_id: Some(device_id),
                    request_id: None,
                    task_id: Some("status.report"),
                    reason: Some("test rejection"),
                })
                .expect("record audit event");
            database
                .record_security_event(&SecurityEvent {
                    category: "test",
                    accepted: true,
                    device_id: Some(device_id),
                    request_id: Some(
                        uuid::Uuid::parse_str("02020202-0202-4202-8202-020202020202")
                            .expect("valid request UUID"),
                    ),
                    task_id: Some("registry.list"),
                    reason: None,
                })
                .expect("record accepted audit event");
        }
        let database = Database::open(&path).expect("reopen database");
        let saved = database.security_logs(10).expect("read audit rows");
        assert_eq!(saved.len(), 2);
        assert_eq!(saved[0].decision, "rejected");
        assert_eq!(saved[0].reason.as_deref(), Some("test rejection"));
        assert_eq!(saved[1].decision, "accepted");
        drop(database);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[test]
    fn existing_phase_five_permissions_and_replay_rows_are_migrated() {
        let path = temporary_database_path();
        let device_id = "01010101-0101-4101-8101-010101010101";
        let connection = rusqlite::Connection::open(&path).expect("create legacy database");
        connection
            .execute_batch(
                "CREATE TABLE trusted_devices (
                    device_id TEXT PRIMARY KEY NOT NULL,
                    public_key BLOB NOT NULL UNIQUE CHECK(length(public_key) = 32),
                    name TEXT NOT NULL,
                    registered_at INTEGER NOT NULL,
                    status TEXT NOT NULL
                );
                CREATE TABLE device_task_permissions (
                    device_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    PRIMARY KEY(device_id, task_id)
                );
                CREATE TABLE replay_requests (
                    device_id TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    expires_at INTEGER NOT NULL,
                    PRIMARY KEY(device_id, request_id),
                    UNIQUE(device_id, nonce)
                );",
            )
            .expect("create old schema tables");
        connection
            .execute(
                "INSERT INTO trusted_devices VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    device_id,
                    vec![7_u8; 32],
                    "legacy device",
                    100_i64,
                    "trusted"
                ],
            )
            .expect("insert old device");
        connection
            .execute(
                "INSERT INTO device_task_permissions VALUES (?1, ?2)",
                rusqlite::params![device_id, "registry.list"],
            )
            .expect("insert old permission");
        connection
            .execute(
                "INSERT INTO replay_requests VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    device_id,
                    "02020202-0202-4202-8202-020202020202",
                    vec![9_u8; 32],
                    999_999_i64
                ],
            )
            .expect("insert old replay row");
        drop(connection);

        let database = Database::open(&path).expect("migrate existing database");
        assert_eq!(
            database
                .device_permissions(device_id.parse().expect("valid device ID"))
                .expect("read permissions"),
            vec!["registry.list"]
        );
        let replay_count: i64 = database
            .connection
            .query_row("SELECT count(*) FROM used_nonces", [], |row| row.get(0))
            .expect("read migrated nonce count");
        assert_eq!(replay_count, 1);
        drop(database);
        std::fs::remove_file(path).expect("remove migrated database");
    }

    #[test]
    fn failed_audit_insert_rolls_back_its_transaction() {
        let database = Database::open_in_memory().expect("open database");
        database
            .connection
            .execute_batch(
                "CREATE TRIGGER reject_audit_insert BEFORE INSERT ON security_logs
                 BEGIN SELECT RAISE(ABORT, 'forced test failure'); END;",
            )
            .expect("install failure trigger");

        assert!(database
            .record_security_event(&SecurityEvent {
                category: "test",
                accepted: true,
                device_id: None,
                request_id: None,
                task_id: None,
                reason: None,
            })
            .is_err());
        assert!(database
            .security_logs(10)
            .expect("read audit log")
            .is_empty());
    }

    #[test]
    fn failed_migration_does_not_advance_schema_version() {
        let path = temporary_database_path();
        let connection = rusqlite::Connection::open(&path).expect("create raw database");
        connection
            .execute_batch(
                "CREATE TABLE trusted_devices (invalid_schema TEXT);
                 PRAGMA user_version = 0;",
            )
            .expect("prepare incompatible legacy table");
        drop(connection);

        assert!(Database::open(&path).is_err());
        let connection = rusqlite::Connection::open(&path).expect("reopen raw database");
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("read untouched version");
        assert_eq!(version, 0);
        drop(connection);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[test]
    fn database_rejects_corrupt_non_sqlite_file() {
        let path = temporary_database_path();
        std::fs::write(&path, b"not a sqlite database").expect("write invalid database file");

        assert_eq!(
            Database::open(&path).err(),
            Some(DatabaseError::CorruptDatabase)
        );
        std::fs::remove_file(path).expect("remove invalid database file");
    }
}
