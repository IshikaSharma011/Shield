//! Persistent trusted-device enrollment, authentication, and revocation.

use std::{
    fmt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::VerifyingKey;
use rusqlite::{params, ErrorCode, OptionalExtension};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    database::{insert_security_event, Database, DatabaseError, SecurityEvent},
    signature::{SignatureError, SignedRequest, TaskRequest},
};

/// Current trust state for a manually enrolled device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    Trusted,
    Revoked,
}

impl DeviceStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Revoked => "revoked",
        }
    }

    fn from_str(value: &str) -> Result<Self, RegistryError> {
        match value {
            "trusted" => Ok(Self::Trusted),
            "revoked" => Ok(Self::Revoked),
            _ => Err(RegistryError::CorruptRecord),
        }
    }
}

impl fmt::Display for DeviceStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Trusted => "trusted",
            Self::Revoked => "revoked",
        })
    }
}

/// Public information stored for one enrolled device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredDevice {
    pub device_id: Uuid,
    pub public_key: [u8; 32],
    pub name: String,
    /// Unix time in milliseconds.
    pub registered_at: u64,
    pub status: DeviceStatus,
}

/// A SQLite-backed collection of manually trusted devices.
pub struct DeviceRegistry {
    database: Database,
}

/// A request that has passed registry lookup and signature verification.
/// Its private fields prevent callers from manufacturing an authenticated
/// request by constructing a `TaskRequest` directly.
pub struct AuthenticatedRequest {
    request: TaskRequest,
}

impl AuthenticatedRequest {
    pub fn request(&self) -> &TaskRequest {
        &self.request
    }

    pub fn device_id(&self) -> Uuid {
        self.request.device_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskPermissionStatus {
    UnknownDevice,
    Revoked,
    NotGranted,
    Granted,
}

impl DeviceRegistry {
    /// Opens or creates a registry database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        Database::open(path)
            .map(|database| Self { database })
            .map_err(map_storage_error)
    }

    /// Opens a temporary in-memory registry, primarily useful for tests and
    /// short-lived demonstrations.
    pub fn open_in_memory() -> Result<Self, RegistryError> {
        Database::open_in_memory()
            .map(|database| Self { database })
            .map_err(map_storage_error)
    }

    /// Manually enrolls a device after comparing the supplied fingerprint
    /// with the fingerprint verified out of band by the operator.
    pub fn enroll(
        &self,
        device_id: Uuid,
        public_key: [u8; 32],
        name: &str,
        confirmed_fingerprint: &str,
    ) -> Result<RegisteredDevice, RegistryError> {
        let name = name.trim();
        if name.is_empty() || name.len() > 128 {
            self.record_security_event(&SecurityEvent {
                category: "device_enrollment",
                accepted: false,
                device_id: Some(device_id),
                request_id: None,
                task_id: None,
                reason: Some("invalid device name"),
            })?;
            return Err(RegistryError::InvalidName);
        }
        if VerifyingKey::from_bytes(&public_key).is_err() {
            self.record_security_event(&SecurityEvent {
                category: "device_enrollment",
                accepted: false,
                device_id: Some(device_id),
                request_id: None,
                task_id: None,
                reason: Some("invalid public key"),
            })?;
            return Err(RegistryError::InvalidPublicKey);
        }

        let fingerprint = public_key_fingerprint(&public_key);
        if !fingerprint.eq_ignore_ascii_case(confirmed_fingerprint) {
            self.record_security_event(&SecurityEvent {
                category: "device_enrollment",
                accepted: false,
                device_id: Some(device_id),
                request_id: None,
                task_id: None,
                reason: Some("fingerprint mismatch"),
            })?;
            return Err(RegistryError::FingerprintMismatch);
        }

        let registered_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RegistryError::ClockUnavailable)?
            .as_millis()
            .try_into()
            .map_err(|_| RegistryError::ClockUnavailable)?;
        let registered_at_db =
            i64::try_from(registered_at).map_err(|_| RegistryError::ClockUnavailable)?;

        let transaction = self
            .database
            .connection
            .unchecked_transaction()
            .map_err(map_database_error)?;
        transaction
            .execute(
                "INSERT INTO trusted_devices
                    (device_id, public_key, name, registered_at, status)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    device_id.to_string(),
                    public_key.as_slice(),
                    name,
                    registered_at_db,
                    DeviceStatus::Trusted.as_str(),
                ],
            )
            .map_err(map_database_error)?;
        insert_security_event(
            &transaction,
            &SecurityEvent {
                category: "device_enrollment",
                accepted: true,
                device_id: Some(device_id),
                request_id: None,
                task_id: None,
                reason: None,
            },
        )
        .map_err(map_storage_error)?;
        transaction.commit().map_err(map_database_error)?;

        Ok(RegisteredDevice {
            device_id,
            public_key,
            name: name.to_owned(),
            registered_at,
            status: DeviceStatus::Trusted,
        })
    }

    /// Returns the record for a device ID, or `None` if it is not registered.
    pub fn get(&self, device_id: Uuid) -> Result<Option<RegisteredDevice>, RegistryError> {
        let row = self
            .database
            .connection
            .query_row(
                "SELECT device_id, public_key, name, registered_at, status
                 FROM trusted_devices WHERE device_id = ?1",
                [device_id.to_string()],
                read_record,
            )
            .optional()
            .map_err(map_database_error)?;
        row.map(decode_record).transpose()
    }

    /// Returns all records, ordered by their device ID.
    pub fn list(&self) -> Result<Vec<RegisteredDevice>, RegistryError> {
        let mut statement = self
            .database
            .connection
            .prepare(
                "SELECT device_id, public_key, name, registered_at, status
                 FROM trusted_devices ORDER BY device_id",
            )
            .map_err(map_database_error)?;
        let rows = statement
            .query_map([], read_record)
            .map_err(map_database_error)?;
        rows.map(|row| {
            let row = row.map_err(map_database_error)?;
            decode_record(row)
        })
        .collect()
    }

    /// Returns the explicitly assigned task IDs for one registered device.
    pub fn permissions(&self, device_id: Uuid) -> Result<Vec<String>, RegistryError> {
        self.database
            .device_permissions(device_id)
            .map_err(map_storage_error)
    }

    /// Returns a bounded slice of persisted security decisions.
    pub fn security_logs(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::database::SecurityLog>, RegistryError> {
        self.database
            .security_logs(limit)
            .map_err(map_storage_error)
    }

    /// Marks an enrolled device as revoked. Repeating the operation is safe
    /// and returns the already-revoked record.
    pub fn revoke(&self, device_id: Uuid) -> Result<RegisteredDevice, RegistryError> {
        let mut device = self.get(device_id)?.ok_or(RegistryError::UnknownDevice)?;
        let transaction = self
            .database
            .connection
            .unchecked_transaction()
            .map_err(map_database_error)?;
        if device.status == DeviceStatus::Trusted {
            transaction
                .execute(
                    "UPDATE trusted_devices SET status = ?1 WHERE device_id = ?2",
                    params![DeviceStatus::Revoked.as_str(), device_id.to_string()],
                )
                .map_err(map_database_error)?;
            device.status = DeviceStatus::Revoked;
        }
        insert_security_event(
            &transaction,
            &SecurityEvent {
                category: "device_revocation",
                accepted: true,
                device_id: Some(device_id),
                request_id: None,
                task_id: None,
                reason: None,
            },
        )
        .map_err(map_storage_error)?;
        transaction.commit().map_err(map_database_error)?;
        Ok(device)
    }

    /// Authenticates a signed request using only the public key in this
    /// registry. The request's device ID is untrusted until verification; no
    /// key is accepted from request data.
    pub fn authenticate(
        &self,
        signed_request: &SignedRequest,
    ) -> Result<TaskRequest, RegistryError> {
        self.authenticate_request(signed_request)
            .map(|authenticated| authenticated.request)
    }

    /// Authenticates a request and returns a proof-bearing value suitable for
    /// authorization. Unlike a raw `TaskRequest`, this value can only be
    /// created after registry and signature checks succeed.
    pub fn authenticate_request(
        &self,
        signed_request: &SignedRequest,
    ) -> Result<AuthenticatedRequest, RegistryError> {
        let parsed = TaskRequest::deserialize(signed_request.request_bytes()).ok();
        let result = self.authenticate_request_inner(signed_request);
        let authenticated = result.is_ok();
        let device_id = result
            .as_ref()
            .map(|request| request.device_id())
            .ok()
            .or_else(|| {
                parsed
                    .as_ref()
                    .and_then(|request| self.get(request.device_id).ok().flatten())
                    .map(|device| device.device_id)
            });
        let request_id = parsed.as_ref().map(|request| request.request_id);
        let task_id = parsed
            .as_ref()
            .and_then(|request| approved_task_id(&request.task_id));
        let reason = result.as_ref().err().map(registry_audit_reason);
        self.record_security_event(&SecurityEvent {
            category: "authentication",
            accepted: authenticated,
            device_id,
            request_id,
            task_id,
            reason,
        })?;
        result
    }

    fn authenticate_request_inner(
        &self,
        signed_request: &SignedRequest,
    ) -> Result<AuthenticatedRequest, RegistryError> {
        let untrusted_request = TaskRequest::deserialize(signed_request.request_bytes())
            .map_err(RegistryError::RequestVerification)?;
        let device = self
            .get(untrusted_request.device_id)?
            .ok_or(RegistryError::UnknownDevice)?;
        if device.status == DeviceStatus::Revoked {
            return Err(RegistryError::RevokedDevice);
        }

        let registered_key = VerifyingKey::from_bytes(&device.public_key)
            .map_err(|_| RegistryError::CorruptRecord)?;
        let request = signed_request
            .verify(device.device_id, &registered_key)
            .map_err(RegistryError::RequestVerification)?;
        Ok(AuthenticatedRequest { request })
    }

    pub(crate) fn record_security_event(
        &self,
        event: &SecurityEvent<'_>,
    ) -> Result<(), RegistryError> {
        self.database
            .record_security_event(event)
            .map_err(|_| RegistryError::AuditUnavailable)
    }

    pub(crate) fn grant_task_permission(
        &self,
        device_id: Uuid,
        task_id: &str,
    ) -> Result<bool, RegistryError> {
        let transaction = self
            .database
            .connection
            .unchecked_transaction()
            .map_err(map_database_error)?;
        let status = transaction
            .query_row(
                "SELECT status FROM trusted_devices WHERE device_id = ?1",
                [device_id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(map_database_error)?;
        match status.as_deref() {
            Some("trusted") => {}
            Some("revoked") => {
                insert_security_event(
                    &transaction,
                    &SecurityEvent {
                        category: "permission_grant",
                        accepted: false,
                        device_id: Some(device_id),
                        request_id: None,
                        task_id: approved_task_id(task_id),
                        reason: Some("device revoked"),
                    },
                )
                .map_err(map_storage_error)?;
                transaction.commit().map_err(map_database_error)?;
                return Err(RegistryError::RevokedDevice);
            }
            _ => {
                insert_security_event(
                    &transaction,
                    &SecurityEvent {
                        category: "permission_grant",
                        accepted: false,
                        device_id: Some(device_id),
                        request_id: None,
                        task_id: approved_task_id(task_id),
                        reason: Some("unknown device"),
                    },
                )
                .map_err(map_storage_error)?;
                transaction.commit().map_err(map_database_error)?;
                return Err(RegistryError::UnknownDevice);
            }
        }

        let changed = transaction
            .execute(
                "INSERT OR IGNORE INTO device_permissions (device_id, task_id)
                 VALUES (?1, ?2)",
                params![device_id.to_string(), task_id],
            )
            .map_err(map_database_error)?;
        insert_security_event(
            &transaction,
            &SecurityEvent {
                category: "permission_grant",
                accepted: true,
                device_id: Some(device_id),
                request_id: None,
                task_id: Some(task_id),
                reason: if changed == 0 {
                    Some("permission already existed")
                } else {
                    None
                },
            },
        )
        .map_err(map_storage_error)?;
        transaction.commit().map_err(map_database_error)?;
        Ok(changed > 0)
    }

    pub(crate) fn revoke_task_permission(
        &self,
        device_id: Uuid,
        task_id: &str,
    ) -> Result<bool, RegistryError> {
        let transaction = self
            .database
            .connection
            .unchecked_transaction()
            .map_err(map_database_error)?;
        let changed = transaction
            .execute(
                "DELETE FROM device_permissions WHERE device_id = ?1 AND task_id = ?2",
                params![device_id.to_string(), task_id],
            )
            .map_err(map_database_error)?;
        let known_device = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM trusted_devices WHERE device_id = ?1)",
                [device_id.to_string()],
                |row| row.get::<_, bool>(0),
            )
            .map_err(map_database_error)?;
        insert_security_event(
            &transaction,
            &SecurityEvent {
                category: "permission_revocation",
                accepted: true,
                device_id: known_device.then_some(device_id),
                request_id: None,
                task_id: Some(task_id),
                reason: if changed == 0 {
                    Some("permission did not exist")
                } else {
                    None
                },
            },
        )
        .map_err(map_storage_error)?;
        transaction.commit().map_err(map_database_error)?;
        Ok(changed > 0)
    }

    pub(crate) fn task_permission_status(
        &self,
        device_id: Uuid,
        task_id: &str,
    ) -> Result<TaskPermissionStatus, RegistryError> {
        let row = self
            .database
            .connection
            .query_row(
                "SELECT status, EXISTS (
                    SELECT 1 FROM device_permissions
                    WHERE device_id = trusted_devices.device_id AND task_id = ?2
                 )
                 FROM trusted_devices WHERE device_id = ?1",
                params![device_id.to_string(), task_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()
            .map_err(map_database_error)?;

        let Some((status, has_permission)) = row else {
            return Ok(TaskPermissionStatus::UnknownDevice);
        };
        if DeviceStatus::from_str(&status)? == DeviceStatus::Revoked {
            return Ok(TaskPermissionStatus::Revoked);
        }
        if has_permission {
            Ok(TaskPermissionStatus::Granted)
        } else {
            Ok(TaskPermissionStatus::NotGranted)
        }
    }

    /// Atomically reserves a fresh request ID and nonce for one authenticated
    /// device. The immediate transaction serializes concurrent attempts.
    pub(crate) fn record_fresh_request(
        &self,
        device_id: Uuid,
        request_id: Uuid,
        nonce: &[u8; 32],
        task_id: &str,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<(), ReplayRecordError> {
        let now_db = i64::try_from(now_ms).map_err(|_| ReplayRecordError::StorageUnavailable)?;
        let expiry_db =
            i64::try_from(expires_at_ms).map_err(|_| ReplayRecordError::StorageUnavailable)?;
        self.database
            .connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|_| ReplayRecordError::StorageUnavailable)?;

        // rusqlite's checked transaction API needs `&mut Connection`. This
        // registry intentionally exposes shared-reference methods, so keep
        // the explicit transaction scoped here and always commit or roll back.
        let result = (|| {
            let status = self
                .database
                .connection
                .query_row(
                    "SELECT status FROM trusted_devices WHERE device_id = ?1",
                    [device_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|_| ReplayRecordError::StorageUnavailable)?;
            match status.as_deref() {
                Some("trusted") => {}
                Some("revoked") => return Err(ReplayRecordError::RevokedDevice),
                _ => return Err(ReplayRecordError::UnknownDevice),
            }

            self.database
                .connection
                .execute("DELETE FROM used_nonces WHERE expires_at < ?1", [now_db])
                .map_err(|_| ReplayRecordError::StorageUnavailable)?;

            let device_id_text = device_id.to_string();
            let request_id_text = request_id.to_string();
            let request_seen = self
                .database
                .connection
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM used_nonces
                     WHERE device_id = ?1 AND request_id = ?2)",
                    params![device_id_text, request_id_text],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| ReplayRecordError::StorageUnavailable)?;
            if request_seen {
                return Err(ReplayRecordError::RepeatedRequestId);
            }

            let nonce_seen = self
                .database
                .connection
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM used_nonces
                     WHERE device_id = ?1 AND nonce = ?2)",
                    params![device_id_text, nonce.as_slice()],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|_| ReplayRecordError::StorageUnavailable)?;
            if nonce_seen {
                return Err(ReplayRecordError::ReusedNonce);
            }

            self.database
                .connection
                .execute(
                    "INSERT INTO used_nonces (device_id, request_id, nonce, expires_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![device_id_text, request_id_text, nonce.as_slice(), expiry_db],
                )
                .map_err(|_| ReplayRecordError::StorageUnavailable)?;
            insert_security_event(
                &self.database.connection,
                &SecurityEvent {
                    category: "replay_protection",
                    accepted: true,
                    device_id: Some(device_id),
                    request_id: Some(request_id),
                    task_id: approved_task_id(task_id),
                    reason: None,
                },
            )
            .map_err(|_| ReplayRecordError::StorageUnavailable)?;
            Ok(())
        })();

        match result {
            Ok(()) => match self.database.connection.execute_batch("COMMIT") {
                Ok(()) => Ok(()),
                Err(_) => {
                    let _ = self.database.connection.execute_batch("ROLLBACK");
                    Err(ReplayRecordError::StorageUnavailable)
                }
            },
            Err(error) => {
                let _ = self.database.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayRecordError {
    RepeatedRequestId,
    ReusedNonce,
    UnknownDevice,
    RevokedDevice,
    StorageUnavailable,
}

/// Returns a SHA-256 fingerprint suitable for manual comparison. The hash is
/// over the 32 raw public-key bytes, not the formatted export string.
pub fn public_key_fingerprint(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    format!("SHA256:{}", encode_hex(&digest))
}

/// Parses the `ed25519:<hex>` public-key representation produced by Shield.
pub fn parse_public_key_export(value: &str) -> Result<[u8; 32], RegistryError> {
    let encoded = value
        .strip_prefix("ed25519:")
        .ok_or(RegistryError::InvalidPublicKey)?;
    if encoded.len() != 64 {
        return Err(RegistryError::InvalidPublicKey);
    }

    let mut bytes = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_digit(pair[0]).ok_or(RegistryError::InvalidPublicKey)?;
        let low = decode_hex_digit(pair[1]).ok_or(RegistryError::InvalidPublicKey)?;
        bytes[index] = (high << 4) | low;
    }
    VerifyingKey::from_bytes(&bytes).map_err(|_| RegistryError::InvalidPublicKey)?;
    Ok(bytes)
}

type RawDeviceRecord = (String, Vec<u8>, String, i64, String);

fn read_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawDeviceRecord> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

fn decode_record(row: RawDeviceRecord) -> Result<RegisteredDevice, RegistryError> {
    let (device_id, public_key, name, registered_at, status) = row;
    let device_id = Uuid::parse_str(&device_id).map_err(|_| RegistryError::CorruptRecord)?;
    let public_key = public_key
        .try_into()
        .map_err(|_| RegistryError::CorruptRecord)?;
    VerifyingKey::from_bytes(&public_key).map_err(|_| RegistryError::CorruptRecord)?;
    let registered_at = u64::try_from(registered_at).map_err(|_| RegistryError::CorruptRecord)?;

    Ok(RegisteredDevice {
        device_id,
        public_key,
        name,
        registered_at,
        status: DeviceStatus::from_str(&status)?,
    })
}

fn map_database_error(error: rusqlite::Error) -> RegistryError {
    match error {
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            RegistryError::DuplicateIdentity
        }
        _ => RegistryError::StorageUnavailable,
    }
}

fn map_storage_error(error: DatabaseError) -> RegistryError {
    match error {
        DatabaseError::ClockUnavailable => RegistryError::ClockUnavailable,
        DatabaseError::CorruptDatabase | DatabaseError::UnsupportedSchemaVersion(_) => {
            RegistryError::CorruptRecord
        }
        DatabaseError::StorageUnavailable => RegistryError::StorageUnavailable,
    }
}

fn approved_task_id(task_id: &str) -> Option<&'static str> {
    crate::authorization::TASKS
        .iter()
        .find(|task| task.task_id == task_id)
        .map(|task| task.task_id)
}

fn registry_audit_reason(error: &RegistryError) -> &'static str {
    match error {
        RegistryError::StorageUnavailable | RegistryError::AuditUnavailable => {
            "registry storage unavailable"
        }
        RegistryError::CorruptRecord => "registry record invalid",
        RegistryError::InvalidName => "invalid device name",
        RegistryError::InvalidPublicKey => "invalid public key",
        RegistryError::FingerprintMismatch => "fingerprint mismatch",
        RegistryError::DuplicateIdentity => "duplicate device identity",
        RegistryError::UnknownDevice => "unknown device",
        RegistryError::RevokedDevice => "revoked device",
        RegistryError::RequestVerification(_) => "request signature verification failed",
        RegistryError::ClockUnavailable => "system clock unavailable",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Errors raised while enrolling, loading, revoking, or authenticating a
/// device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    StorageUnavailable,
    CorruptRecord,
    InvalidName,
    InvalidPublicKey,
    FingerprintMismatch,
    DuplicateIdentity,
    UnknownDevice,
    RevokedDevice,
    RequestVerification(SignatureError),
    ClockUnavailable,
    AuditUnavailable,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorageUnavailable => formatter.write_str("The device registry is unavailable."),
            Self::CorruptRecord => {
                formatter.write_str("The device registry contains an invalid record.")
            }
            Self::InvalidName => {
                formatter.write_str("A device name must contain 1 to 128 UTF-8 bytes.")
            }
            Self::InvalidPublicKey => {
                formatter.write_str("The Ed25519 public key is malformed or invalid.")
            }
            Self::FingerprintMismatch => formatter.write_str(
                "The public-key fingerprint does not match the independently verified fingerprint.",
            ),
            Self::DuplicateIdentity => formatter.write_str(
                "That device ID or public key is already registered; no record was changed.",
            ),
            Self::UnknownDevice => formatter.write_str("The device is not registered."),
            Self::RevokedDevice => formatter.write_str("The device has been revoked."),
            Self::RequestVerification(error) => write!(formatter, "{error}"),
            Self::ClockUnavailable => {
                formatter.write_str("The system clock could not provide a valid registration time.")
            }
            Self::AuditUnavailable => {
                formatter.write_str("The security decision could not be stored in the audit log.")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        device_identity::DeviceIdentity,
        signature::{sign_request, SignatureError, TaskRequest},
    };

    use super::{public_key_fingerprint, DeviceRegistry, DeviceStatus, RegistryError};

    fn new_identity() -> DeviceIdentity {
        DeviceIdentity::generate().expect("OS randomness should be available")
    }

    fn request_for(identity: &DeviceIdentity) -> TaskRequest {
        TaskRequest::new(identity.device_id(), "status.report", BTreeMap::new())
            .expect("create request")
    }

    fn enroll(registry: &DeviceRegistry, identity: &DeviceIdentity) {
        let public_key = identity.public_key_bytes();
        registry
            .enroll(
                identity.device_id(),
                public_key,
                "test device",
                &public_key_fingerprint(&public_key),
            )
            .expect("enroll test device");
    }

    #[test]
    fn trusted_device_authenticates() {
        let registry = DeviceRegistry::open_in_memory().expect("open test registry");
        let identity = new_identity();
        enroll(&registry, &identity);
        let signed = sign_request(&request_for(&identity), &identity).expect("sign request");

        let authenticated = registry
            .authenticate(&signed)
            .expect("trusted device should authenticate");

        assert_eq!(authenticated.device_id, identity.device_id());
    }

    #[test]
    fn unknown_device_is_rejected() {
        let registry = DeviceRegistry::open_in_memory().expect("open test registry");
        let identity = new_identity();
        let signed = sign_request(&request_for(&identity), &identity).expect("sign request");

        assert_eq!(
            registry.authenticate(&signed),
            Err(RegistryError::UnknownDevice)
        );
    }

    #[test]
    fn revoked_device_is_rejected() {
        let registry = DeviceRegistry::open_in_memory().expect("open test registry");
        let identity = new_identity();
        enroll(&registry, &identity);
        let signed = sign_request(&request_for(&identity), &identity).expect("sign request");
        let revoked = registry
            .revoke(identity.device_id())
            .expect("revoke device");

        assert_eq!(revoked.status, DeviceStatus::Revoked);
        assert_eq!(
            registry.authenticate(&signed),
            Err(RegistryError::RevokedDevice)
        );
    }

    #[test]
    fn incorrect_registered_public_key_is_rejected() {
        let registry = DeviceRegistry::open_in_memory().expect("open test registry");
        let sender = new_identity();
        let incorrect_key = new_identity().public_key_bytes();
        registry
            .enroll(
                sender.device_id(),
                incorrect_key,
                "misregistered key",
                &public_key_fingerprint(&incorrect_key),
            )
            .expect("enroll supplied key after matching its fingerprint");
        let signed = sign_request(&request_for(&sender), &sender).expect("sign request");

        assert_eq!(
            registry.authenticate(&signed),
            Err(RegistryError::RequestVerification(
                SignatureError::InvalidSignature
            ))
        );
    }

    #[test]
    fn duplicate_device_registration_is_rejected_without_overwriting() {
        let registry = DeviceRegistry::open_in_memory().expect("open test registry");
        let identity = new_identity();
        enroll(&registry, &identity);
        let fingerprint = public_key_fingerprint(&identity.public_key_bytes());

        assert_eq!(
            registry.enroll(
                identity.device_id(),
                identity.public_key_bytes(),
                "replacement name",
                &fingerprint,
            ),
            Err(RegistryError::DuplicateIdentity)
        );
        let saved = registry
            .get(identity.device_id())
            .expect("query device")
            .expect("device remains registered");
        assert_eq!(saved.name, "test device");
    }

    #[test]
    fn duplicate_public_key_is_rejected_for_a_second_device_id() {
        let registry = DeviceRegistry::open_in_memory().expect("open test registry");
        let identity = new_identity();
        enroll(&registry, &identity);
        let fingerprint = public_key_fingerprint(&identity.public_key_bytes());
        let another_id = uuid::Builder::from_random_bytes([0x24; 16]).into_uuid();

        assert_eq!(
            registry.enroll(
                another_id,
                identity.public_key_bytes(),
                "duplicate key",
                &fingerprint,
            ),
            Err(RegistryError::DuplicateIdentity)
        );
    }

    #[test]
    fn registration_and_revocation_persist_after_reopening_database() {
        let identity = new_identity();
        let path =
            std::env::temp_dir().join(format!("shield-registry-{}.sqlite3", identity.device_id()));
        {
            let registry = DeviceRegistry::open(&path).expect("open file-backed registry");
            enroll(&registry, &identity);
            registry
                .grant_task_permission(identity.device_id(), "registry.list")
                .expect("persist permission");
            registry
                .revoke(identity.device_id())
                .expect("revoke device");
        }

        let registry = DeviceRegistry::open(&path).expect("reopen file-backed registry");
        let saved = registry
            .get(identity.device_id())
            .expect("query device")
            .expect("record persists");
        assert_eq!(saved.status, DeviceStatus::Revoked);
        assert_eq!(
            registry
                .permissions(identity.device_id())
                .expect("read persisted permission"),
            vec!["registry.list"]
        );
        drop(registry);
        std::fs::remove_file(path).expect("remove temporary test database");
    }

    #[test]
    fn failed_audit_write_rolls_back_device_enrollment() {
        let registry = DeviceRegistry::open_in_memory().expect("open test registry");
        let identity = new_identity();
        registry
            .database
            .connection
            .execute_batch(
                "CREATE TRIGGER reject_audit_insert BEFORE INSERT ON security_logs
                 BEGIN SELECT RAISE(ABORT, 'forced test failure'); END;",
            )
            .expect("install test failure trigger");
        let public_key = identity.public_key_bytes();

        assert_eq!(
            registry.enroll(
                identity.device_id(),
                public_key,
                "transaction test",
                &public_key_fingerprint(&public_key),
            ),
            Err(RegistryError::StorageUnavailable)
        );
        assert_eq!(
            registry
                .get(identity.device_id())
                .expect("query rolled back record"),
            None
        );
    }

    #[test]
    fn enrollment_rejects_unverified_fingerprint() {
        let registry = DeviceRegistry::open_in_memory().expect("open test registry");
        let identity = new_identity();

        assert_eq!(
            registry.enroll(
                identity.device_id(),
                identity.public_key_bytes(),
                "test device",
                "SHA256:incorrect",
            ),
            Err(RegistryError::FingerprintMismatch)
        );
    }

    #[test]
    fn public_key_export_parsing_matches_fingerprint_input() {
        let identity = new_identity();
        let public_key = identity.public_key_bytes();
        let exported = identity.public_key_export();
        let parsed = super::parse_public_key_export(&exported).expect("parse public key export");

        assert_eq!(parsed, public_key);
        assert_eq!(
            super::public_key_fingerprint(&parsed),
            public_key_fingerprint(&public_key)
        );
    }
}
