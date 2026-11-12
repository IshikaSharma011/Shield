//! Timestamp validation and durable, atomic request replay detection.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::device_registry::{AuthenticatedRequest, DeviceRegistry, ReplayRecordError};

const DEFAULT_MAXIMUM_AGE: Duration = Duration::from_secs(5 * 60);
const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(30);

/// Validates a signed request's time and atomically records its ID and nonce
/// in the SQLite registry. Nonce and request-ID uniqueness are scoped to one
/// authenticated device.
#[derive(Debug, Clone, Copy)]
pub struct ReplayProtection {
    maximum_age_ms: u64,
    allowed_clock_skew_ms: u64,
}

impl Default for ReplayProtection {
    fn default() -> Self {
        Self {
            maximum_age_ms: duration_millis(DEFAULT_MAXIMUM_AGE)
                .expect("the built-in age limit fits in milliseconds"),
            allowed_clock_skew_ms: duration_millis(DEFAULT_CLOCK_SKEW)
                .expect("the built-in clock skew fits in milliseconds"),
        }
    }
}

impl ReplayProtection {
    /// Creates replay protection with a maximum request age and permitted
    /// client clock skew. The maximum age must be greater than zero.
    pub fn new(
        maximum_age: Duration,
        allowed_clock_skew: Duration,
    ) -> Result<Self, ReplayConfigurationError> {
        let maximum_age_ms = duration_millis(maximum_age)?;
        if maximum_age_ms == 0 {
            return Err(ReplayConfigurationError::MaximumAgeMustBePositive);
        }
        Ok(Self {
            maximum_age_ms,
            allowed_clock_skew_ms: duration_millis(allowed_clock_skew)?,
        })
    }

    /// Rejects stale or excessively future-dated requests, then atomically
    /// reserves their request ID and nonce in the registry. This method must
    /// receive a request authenticated against the registry's stored key.
    pub fn check_and_record(
        &self,
        registry: &DeviceRegistry,
        authenticated: &AuthenticatedRequest,
    ) -> Result<(), ReplayRejectionReason> {
        self.check_and_record_at(registry, authenticated, current_time_millis()?)
    }

    fn check_and_record_at(
        &self,
        registry: &DeviceRegistry,
        authenticated: &AuthenticatedRequest,
        now_ms: u64,
    ) -> Result<(), ReplayRejectionReason> {
        let request = authenticated.request();
        let timestamp = request.timestamp;

        if timestamp > now_ms {
            if timestamp - now_ms > self.allowed_clock_skew_ms {
                return Err(ReplayRejectionReason::FutureTimestamp);
            }
        } else if now_ms - timestamp > self.maximum_age_ms {
            return Err(ReplayRejectionReason::ExpiredRequest);
        }

        // Keep a record until the request can no longer pass the age check.
        // This also accounts for requests accepted within the allowed future
        // clock-skew window.
        let expires_at_ms = timestamp
            .checked_add(self.maximum_age_ms)
            .ok_or(ReplayRejectionReason::InvalidTimestamp)?;

        registry
            .record_fresh_request(
                request.device_id,
                request.request_id,
                &request.nonce,
                now_ms,
                expires_at_ms,
            )
            .map_err(map_record_error)
    }
}

fn duration_millis(duration: Duration) -> Result<u64, ReplayConfigurationError> {
    u64::try_from(duration.as_millis()).map_err(|_| ReplayConfigurationError::DurationTooLarge)
}

fn current_time_millis() -> Result<u64, ReplayRejectionReason> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ReplayRejectionReason::ClockUnavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| ReplayRejectionReason::ClockUnavailable)
}

fn map_record_error(error: ReplayRecordError) -> ReplayRejectionReason {
    match error {
        ReplayRecordError::RepeatedRequestId => ReplayRejectionReason::RepeatedRequestId,
        ReplayRecordError::ReusedNonce => ReplayRejectionReason::ReusedNonce,
        ReplayRecordError::UnknownDevice => ReplayRejectionReason::UnknownDevice,
        ReplayRecordError::RevokedDevice => ReplayRejectionReason::RevokedDevice,
        ReplayRecordError::StorageUnavailable => ReplayRejectionReason::StorageUnavailable,
    }
}

/// Clear reasons why replay protection did not accept a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRejectionReason {
    ExpiredRequest,
    FutureTimestamp,
    InvalidTimestamp,
    RepeatedRequestId,
    ReusedNonce,
    UnknownDevice,
    RevokedDevice,
    ClockUnavailable,
    StorageUnavailable,
}

impl std::fmt::Display for ReplayRejectionReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ExpiredRequest => "The request has expired.",
            Self::FutureTimestamp => "The request timestamp is beyond the permitted clock skew.",
            Self::InvalidTimestamp => "The request timestamp cannot be represented safely.",
            Self::RepeatedRequestId => "This device has already submitted this request ID.",
            Self::ReusedNonce => "This device has already submitted this nonce.",
            Self::UnknownDevice => "The authenticated device is no longer registered.",
            Self::RevokedDevice => "The device has been revoked.",
            Self::ClockUnavailable => "The system clock is unavailable or invalid.",
            Self::StorageUnavailable => "Replay-protection storage is unavailable.",
        })
    }
}

impl std::error::Error for ReplayRejectionReason {}

/// Errors from invalid replay-policy configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayConfigurationError {
    MaximumAgeMustBePositive,
    DurationTooLarge,
}

impl std::fmt::Display for ReplayConfigurationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::MaximumAgeMustBePositive => "The maximum request age must be greater than zero.",
            Self::DurationTooLarge => "The replay-policy duration is too large.",
        })
    }
}

impl std::error::Error for ReplayConfigurationError {}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        sync::{Arc, Barrier},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use crate::{
        device_identity::DeviceIdentity,
        device_registry::{public_key_fingerprint, DeviceRegistry},
        signature::{sign_request, TaskRequest},
    };

    use super::{ReplayProtection, ReplayRejectionReason};

    fn setup() -> (DeviceRegistry, DeviceIdentity) {
        let registry = DeviceRegistry::open_in_memory().expect("open test registry");
        let identity = DeviceIdentity::generate().expect("generate test identity");
        let public_key = identity.public_key_bytes();
        registry
            .enroll(
                identity.device_id(),
                public_key,
                "replay test device",
                &public_key_fingerprint(&public_key),
            )
            .expect("enroll test identity");
        (registry, identity)
    }

    fn authenticated_request(
        registry: &DeviceRegistry,
        identity: &DeviceIdentity,
        timestamp: Option<u64>,
        nonce: Option<[u8; 32]>,
    ) -> crate::device_registry::AuthenticatedRequest {
        let mut request = TaskRequest::new(identity.device_id(), "status.report", BTreeMap::new())
            .expect("create signed request");
        if let Some(timestamp) = timestamp {
            request.timestamp = timestamp;
        }
        if let Some(nonce) = nonce {
            request.nonce = nonce;
        }
        let signed = sign_request(&request, identity).expect("sign request");
        registry
            .authenticate_request(&signed)
            .expect("authenticate request")
    }

    fn now_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_millis() as u64
    }

    fn short_policy() -> ReplayProtection {
        ReplayProtection::new(Duration::from_secs(2), Duration::from_secs(1))
            .expect("valid replay policy")
    }

    #[test]
    fn new_authenticated_request_is_accepted_and_recorded() {
        let (registry, identity) = setup();
        let authenticated = authenticated_request(&registry, &identity, None, None);

        assert_eq!(
            short_policy().check_and_record(&registry, &authenticated),
            Ok(())
        );
    }

    #[test]
    fn repeated_request_id_is_rejected() {
        let (registry, identity) = setup();
        let authenticated = authenticated_request(&registry, &identity, None, None);
        let protection = short_policy();
        protection
            .check_and_record(&registry, &authenticated)
            .expect("first submission accepted");

        assert_eq!(
            protection.check_and_record(&registry, &authenticated),
            Err(ReplayRejectionReason::RepeatedRequestId)
        );
    }

    #[test]
    fn reused_nonce_with_a_different_request_id_is_rejected() {
        let (registry, identity) = setup();
        let first = authenticated_request(&registry, &identity, None, None);
        let nonce = first.request().nonce;
        let second = authenticated_request(&registry, &identity, None, Some(nonce));
        let protection = short_policy();
        protection
            .check_and_record(&registry, &first)
            .expect("first submission accepted");

        assert_eq!(
            protection.check_and_record(&registry, &second),
            Err(ReplayRejectionReason::ReusedNonce)
        );
    }

    #[test]
    fn expired_request_is_rejected() {
        let (registry, identity) = setup();
        let old_timestamp = now_millis().saturating_sub(10_000);
        let authenticated = authenticated_request(&registry, &identity, Some(old_timestamp), None);

        assert_eq!(
            short_policy().check_and_record(&registry, &authenticated),
            Err(ReplayRejectionReason::ExpiredRequest)
        );
    }

    #[test]
    fn timestamp_outside_future_clock_skew_is_rejected() {
        let (registry, identity) = setup();
        let future_timestamp = now_millis() + 60_000;
        let authenticated =
            authenticated_request(&registry, &identity, Some(future_timestamp), None);

        assert_eq!(
            short_policy().check_and_record(&registry, &authenticated),
            Err(ReplayRejectionReason::FutureTimestamp)
        );
    }

    #[test]
    fn nonce_uniqueness_is_scoped_to_authenticated_device() {
        let (registry, first_identity) = setup();
        let second_identity = DeviceIdentity::generate().expect("generate second identity");
        let public_key = second_identity.public_key_bytes();
        registry
            .enroll(
                second_identity.device_id(),
                public_key,
                "second replay test device",
                &public_key_fingerprint(&public_key),
            )
            .expect("enroll second identity");
        let nonce = [0x77; 32];
        let first = authenticated_request(&registry, &first_identity, None, Some(nonce));
        let second = authenticated_request(&registry, &second_identity, None, Some(nonce));
        let protection = short_policy();

        protection
            .check_and_record(&registry, &first)
            .expect("first device accepted");
        assert_eq!(protection.check_and_record(&registry, &second), Ok(()));
    }

    #[test]
    fn concurrent_duplicate_requests_cannot_both_be_accepted() {
        let identity = DeviceIdentity::generate().expect("generate identity");
        let path =
            std::env::temp_dir().join(format!("shield-replay-{}.sqlite3", identity.device_id()));
        let first_registry = DeviceRegistry::open(&path).expect("open registry");
        let public_key = identity.public_key_bytes();
        first_registry
            .enroll(
                identity.device_id(),
                public_key,
                "concurrency test device",
                &public_key_fingerprint(&public_key),
            )
            .expect("enroll identity");
        let authenticated = Arc::new(authenticated_request(
            &first_registry,
            &identity,
            None,
            None,
        ));
        let second_registry = DeviceRegistry::open(&path).expect("open second registry connection");
        let barrier = Arc::new(Barrier::new(2));
        let workers = [first_registry, second_registry].map(|registry| {
            let authenticated = Arc::clone(&authenticated);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                short_policy().check_and_record(&registry, &authenticated)
            })
        });
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker thread completes"))
            .collect();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(ReplayRejectionReason::RepeatedRequestId))
                .count(),
            1
        );
        std::fs::remove_file(path).expect("remove test database");
    }

    #[test]
    fn zero_maximum_age_is_rejected_as_invalid_configuration() {
        assert!(ReplayProtection::new(Duration::ZERO, Duration::ZERO).is_err());
    }
}
