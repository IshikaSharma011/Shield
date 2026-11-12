//! Ordered request-validation pipeline combining Shield's security modules.

use std::{collections::BTreeMap, path::Path};

use uuid::Uuid;

use crate::{
    authorization::{AuthorizationDecision, AuthorizationEngine, RejectionReason},
    database::{SecurityEvent, SecurityLog},
    device_identity::DeviceIdentity,
    device_registry::{AuthenticatedRequest, DeviceRegistry, RegistryError},
    replay_protection::{ReplayProtection, ReplayRejectionReason},
    signature::{sign_request, SignatureError, SignedRequest, TaskRequest},
};

/// Coordinates one request through signature authentication, replay checks,
/// authorization, and final decision auditing.
pub struct SecurityEngine {
    registry: DeviceRegistry,
    authorization: AuthorizationEngine,
    replay_protection: ReplayProtection,
}

/// A completed pipeline result. Accepted requests receive only a simulated
/// approval; this type does not represent task execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestValidation {
    Accepted(SimulatedTaskApproval),
    Rejected(RejectedRequest),
}

/// Structured, non-executing approval returned after every check succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulatedTaskApproval {
    pub request_id: Uuid,
    pub device_id: Uuid,
    pub task_id: String,
    pub message: &'static str,
}

/// Details about a request rejected by one pipeline stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRequest {
    /// Available only if signature authentication succeeded.
    pub request_id: Option<Uuid>,
    /// Available only if signature authentication succeeded.
    pub device_id: Option<Uuid>,
    pub reason: SecurityRejectionReason,
}

/// Rejection categories preserve the responsible security layer's reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityRejectionReason {
    Authentication(RegistryError),
    Replay(ReplayRejectionReason),
    Authorization(RejectionReason),
    AuditUnavailable,
}

impl SecurityEngine {
    /// Opens a persistent database and uses the default replay policy.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let registry = DeviceRegistry::open(path)?;
        Ok(Self::new(registry, ReplayProtection::default()))
    }

    /// Builds an engine around an existing registry and replay policy.
    pub fn new(registry: DeviceRegistry, replay_protection: ReplayProtection) -> Self {
        Self {
            registry,
            authorization: AuthorizationEngine,
            replay_protection,
        }
    }

    /// Provides access to enrollment and permission management operations.
    pub fn registry(&self) -> &DeviceRegistry {
        &self.registry
    }

    /// Runs the existing registry-backed signature authentication step.
    pub fn verify_device_authentication(
        &self,
        signed_request: &SignedRequest,
    ) -> Result<AuthenticatedRequest, RegistryError> {
        self.registry.authenticate_request(signed_request)
    }

    /// Runs the existing allow-list authorization step for an authenticated
    /// request. This does not perform replay checking or execute a task.
    pub fn check_task_authorization(
        &self,
        authenticated: &AuthenticatedRequest,
    ) -> crate::authorization::AuthorizationResult {
        self.authorization.authorize(&self.registry, authenticated)
    }

    /// Reads recent audit rows through the registry's migrated SQLite store.
    pub fn security_audit_logs(&self, limit: usize) -> Result<Vec<SecurityLog>, RegistryError> {
        self.registry.security_logs(limit)
    }

    /// Creates and signs a request using an identity supplied by the caller.
    /// Request IDs and nonces are generated with the OS random source by
    /// `TaskRequest::new`.
    pub fn create_signed_request(
        identity: &DeviceIdentity,
        task_id: impl Into<String>,
        parameters: BTreeMap<String, String>,
    ) -> Result<SignedRequest, SignatureError> {
        let request = TaskRequest::new(identity.device_id(), task_id, parameters)?;
        sign_request(&request, identity)
    }

    /// Processes one signed request through authentication, replay checks,
    /// authorization, and final auditing. It never executes the task.
    pub fn process_request(&self, signed_request: &SignedRequest) -> RequestValidation {
        let authenticated = match self.registry.authenticate_request(signed_request) {
            Ok(authenticated) => authenticated,
            Err(error) => {
                let reason = if error == RegistryError::AuditUnavailable {
                    SecurityRejectionReason::AuditUnavailable
                } else {
                    SecurityRejectionReason::Authentication(error)
                };
                return self.reject(None, reason);
            }
        };

        if let Err(reason) = self
            .replay_protection
            .check_and_record(&self.registry, &authenticated)
        {
            return self.reject(
                Some(&authenticated),
                SecurityRejectionReason::Replay(reason),
            );
        }

        let authorization = self.authorization.authorize(&self.registry, &authenticated);
        match authorization.decision {
            AuthorizationDecision::Allowed => {
                let approval = SimulatedTaskApproval {
                    request_id: authorization.request_id,
                    device_id: authorization.device_id,
                    task_id: authorization.task_id,
                    message: "Task approved for demonstration; no task was executed.",
                };
                if self.record_pipeline_decision(true, Some(&authenticated), None) {
                    RequestValidation::Accepted(approval)
                } else {
                    self.reject(
                        Some(&authenticated),
                        SecurityRejectionReason::AuditUnavailable,
                    )
                }
            }
            AuthorizationDecision::Denied(RejectionReason::AuditUnavailable) => self.reject(
                Some(&authenticated),
                SecurityRejectionReason::AuditUnavailable,
            ),
            AuthorizationDecision::Denied(reason) => self.reject(
                Some(&authenticated),
                SecurityRejectionReason::Authorization(reason),
            ),
        }
    }

    fn reject(
        &self,
        authenticated: Option<&AuthenticatedRequest>,
        reason: SecurityRejectionReason,
    ) -> RequestValidation {
        let persisted =
            self.record_pipeline_decision(false, authenticated, Some(audit_reason(&reason)));
        let reason = if persisted {
            reason
        } else {
            SecurityRejectionReason::AuditUnavailable
        };
        self.rejection(authenticated, reason)
    }

    fn rejection(
        &self,
        authenticated: Option<&AuthenticatedRequest>,
        reason: SecurityRejectionReason,
    ) -> RequestValidation {
        RequestValidation::Rejected(RejectedRequest {
            request_id: authenticated.map(|request| request.request().request_id),
            device_id: authenticated.map(AuthenticatedRequest::device_id),
            reason,
        })
    }

    fn record_pipeline_decision(
        &self,
        accepted: bool,
        authenticated: Option<&AuthenticatedRequest>,
        reason: Option<&'static str>,
    ) -> bool {
        let request = authenticated.map(AuthenticatedRequest::request);
        let task_id = request.and_then(|request| {
            crate::authorization::TASKS
                .iter()
                .find(|task| task.task_id == request.task_id)
                .map(|task| task.task_id)
        });
        self.registry
            .record_security_event(&SecurityEvent {
                category: "request_pipeline",
                accepted,
                device_id: authenticated.map(AuthenticatedRequest::device_id),
                request_id: request.map(|request| request.request_id),
                task_id,
                reason,
            })
            .is_ok()
    }
}

fn audit_reason(reason: &SecurityRejectionReason) -> &'static str {
    match reason {
        SecurityRejectionReason::Authentication(RegistryError::UnknownDevice) => "unknown device",
        SecurityRejectionReason::Authentication(RegistryError::RevokedDevice) => "revoked device",
        SecurityRejectionReason::Authentication(RegistryError::RequestVerification(_)) => {
            "request signature verification failed"
        }
        SecurityRejectionReason::Authentication(_) => "authentication rejected",
        SecurityRejectionReason::Replay(reason) => match reason {
            ReplayRejectionReason::ExpiredRequest => "request expired",
            ReplayRejectionReason::FutureTimestamp => "timestamp outside clock-skew window",
            ReplayRejectionReason::InvalidTimestamp => "invalid timestamp",
            ReplayRejectionReason::RepeatedRequestId => "request ID already used",
            ReplayRejectionReason::ReusedNonce => "nonce already used",
            ReplayRejectionReason::UnknownDevice => "unknown device",
            ReplayRejectionReason::RevokedDevice => "revoked device",
            ReplayRejectionReason::ClockUnavailable => "system clock unavailable",
            ReplayRejectionReason::StorageUnavailable => "replay storage unavailable",
        },
        SecurityRejectionReason::Authorization(reason) => match reason {
            RejectionReason::UnknownTask => "unknown task",
            RejectionReason::UnknownDevice => "unknown device",
            RejectionReason::RevokedDevice => "revoked device",
            RejectionReason::TaskNotGranted => "task permission missing",
            RejectionReason::MissingParameter(_) => "required parameter missing",
            RejectionReason::UnexpectedParameter => "unexpected parameter",
            RejectionReason::InvalidParameterValue(_) => "parameter value not allowed",
            RejectionReason::RegistryUnavailable => "registry unavailable",
            RejectionReason::AuditUnavailable => "audit storage unavailable",
        },
        SecurityRejectionReason::AuditUnavailable => "audit storage unavailable",
    }
}

impl std::fmt::Display for SecurityRejectionReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Authentication(error) => write!(formatter, "Authentication rejected: {error}"),
            Self::Replay(reason) => write!(formatter, "Replay check rejected: {reason}"),
            Self::Authorization(reason) => write!(
                formatter,
                "Authorization rejected: {}",
                authorization_reason_text(reason)
            ),
            Self::AuditUnavailable => {
                formatter.write_str("The final security decision could not be audited.")
            }
        }
    }
}

impl std::error::Error for SecurityRejectionReason {}

fn authorization_reason_text(reason: &RejectionReason) -> &'static str {
    match reason {
        RejectionReason::UnknownTask => "the task is not in the allow-list",
        RejectionReason::UnknownDevice => "the device is not registered",
        RejectionReason::RevokedDevice => "the device has been revoked",
        RejectionReason::TaskNotGranted => "the device does not have this task permission",
        RejectionReason::MissingParameter(_) => "a required parameter is missing",
        RejectionReason::UnexpectedParameter => "the request contains an unexpected parameter",
        RejectionReason::InvalidParameterValue(_) => "a parameter value is not allowed",
        RejectionReason::RegistryUnavailable => "the registry is unavailable",
        RejectionReason::AuditUnavailable => "the audit log is unavailable",
    }
}
