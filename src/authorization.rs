//! Deny-by-default task authorization using a small, predefined allow-list.

use std::{collections::BTreeMap, fmt};

use uuid::Uuid;

use crate::device_registry::{
    AuthenticatedRequest, DeviceRegistry, RegistryError, TaskPermissionStatus,
};

/// Parameter constraints for one predefined task.
#[derive(Debug, Clone, Copy)]
pub struct ParameterSchema {
    pub name: &'static str,
    pub required: bool,
    pub allowed_values: &'static [&'static str],
}

/// A task the demonstration framework recognizes. These definitions describe
/// authorization only; they do not execute tasks or system commands.
#[derive(Debug, Clone, Copy)]
pub struct TaskDefinition {
    pub task_id: &'static str,
    pub description: &'static str,
    pub parameters: &'static [ParameterSchema],
}

const NO_PARAMETERS: &[ParameterSchema] = &[];
const STATUS_PARAMETERS: &[ParameterSchema] = &[ParameterSchema {
    name: "format",
    required: true,
    allowed_values: &["summary", "detailed"],
}];
const DEVICE_INFO_PARAMETERS: &[ParameterSchema] = &[ParameterSchema {
    name: "section",
    required: true,
    allowed_values: &["identity", "registry"],
}];

/// Fixed task catalog. No task accepts a command or shell string.
pub const TASKS: &[TaskDefinition] = &[
    TaskDefinition {
        task_id: "status.report",
        description: "Request a structured status report",
        parameters: STATUS_PARAMETERS,
    },
    TaskDefinition {
        task_id: "registry.list",
        description: "Request a list of registered devices",
        parameters: NO_PARAMETERS,
    },
    TaskDefinition {
        task_id: "device.info",
        description: "Request a predefined device information section",
        parameters: DEVICE_INFO_PARAMETERS,
    },
];

/// Why a request was denied. Variants deliberately avoid echoing untrusted
/// parameter values into terminal output or logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectionReason {
    UnknownTask,
    UnknownDevice,
    RevokedDevice,
    TaskNotGranted,
    MissingParameter(&'static str),
    UnexpectedParameter,
    InvalidParameterValue(&'static str),
    RegistryUnavailable,
}

/// The authorization outcome for a signed and authenticated task request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationDecision {
    Allowed,
    Denied(RejectionReason),
}

/// Structured result suitable for a caller to inspect or display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationResult {
    pub request_id: Uuid,
    pub device_id: Uuid,
    pub task_id: String,
    pub decision: AuthorizationDecision,
}

/// Authorization engine over the registry's explicit per-device grants.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuthorizationEngine;

impl AuthorizationEngine {
    pub fn tasks(&self) -> &'static [TaskDefinition] {
        TASKS
    }

    /// Grants a known task to a currently trusted device. Returns true only
    /// when a new grant was inserted; repeating a grant is safe.
    pub fn grant_task(
        &self,
        registry: &DeviceRegistry,
        device_id: Uuid,
        task_id: &str,
    ) -> Result<bool, AuthorizationError> {
        if find_task(task_id).is_none() {
            return Err(AuthorizationError::UnknownTask);
        }
        registry
            .grant_task_permission(device_id, task_id)
            .map_err(AuthorizationError::Registry)
    }

    /// Removes a task grant. Unknown task IDs are rejected to catch operator
    /// mistakes; removing an existing grant returns true.
    pub fn revoke_task(
        &self,
        registry: &DeviceRegistry,
        device_id: Uuid,
        task_id: &str,
    ) -> Result<bool, AuthorizationError> {
        if find_task(task_id).is_none() {
            return Err(AuthorizationError::UnknownTask);
        }
        registry
            .revoke_task_permission(device_id, task_id)
            .map_err(AuthorizationError::Registry)
    }

    /// Checks catalog membership, current device trust, explicit permission,
    /// then the task's exact parameter schema. Every failure denies access.
    pub fn authorize(
        &self,
        registry: &DeviceRegistry,
        authenticated: &AuthenticatedRequest,
    ) -> AuthorizationResult {
        let request = authenticated.request();
        let decision = if let Some(task) = find_task(&request.task_id) {
            match registry.task_permission_status(request.device_id, task.task_id) {
                Ok(TaskPermissionStatus::UnknownDevice) => {
                    AuthorizationDecision::Denied(RejectionReason::UnknownDevice)
                }
                Ok(TaskPermissionStatus::Revoked) => {
                    AuthorizationDecision::Denied(RejectionReason::RevokedDevice)
                }
                Ok(TaskPermissionStatus::NotGranted) => {
                    AuthorizationDecision::Denied(RejectionReason::TaskNotGranted)
                }
                Ok(TaskPermissionStatus::Granted) => {
                    match validate_parameters(task, &request.parameters) {
                        Ok(()) => AuthorizationDecision::Allowed,
                        Err(reason) => AuthorizationDecision::Denied(reason),
                    }
                }
                Err(_) => AuthorizationDecision::Denied(RejectionReason::RegistryUnavailable),
            }
        } else {
            AuthorizationDecision::Denied(RejectionReason::UnknownTask)
        };

        AuthorizationResult {
            request_id: request.request_id,
            device_id: request.device_id,
            task_id: request.task_id.clone(),
            decision,
        }
    }
}

fn find_task(task_id: &str) -> Option<&'static TaskDefinition> {
    TASKS.iter().find(|task| task.task_id == task_id)
}

fn validate_parameters(
    task: &TaskDefinition,
    parameters: &BTreeMap<String, String>,
) -> Result<(), RejectionReason> {
    for schema in task.parameters {
        match parameters.get(schema.name) {
            None if schema.required => return Err(RejectionReason::MissingParameter(schema.name)),
            None => {}
            Some(value) if !schema.allowed_values.contains(&value.as_str()) => {
                return Err(RejectionReason::InvalidParameterValue(schema.name));
            }
            Some(_) => {}
        }
    }
    if parameters
        .keys()
        .any(|name| !task.parameters.iter().any(|schema| schema.name == name))
    {
        return Err(RejectionReason::UnexpectedParameter);
    }
    Ok(())
}

#[derive(Debug)]
pub enum AuthorizationError {
    UnknownTask,
    Registry(RegistryError),
}

impl fmt::Display for AuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTask => {
                formatter.write_str("The task ID is not in the predefined allow-list.")
            }
            Self::Registry(error) => write!(formatter, "Could not update task permission: {error}"),
        }
    }
}

impl std::error::Error for AuthorizationError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        device_identity::DeviceIdentity,
        device_registry::{public_key_fingerprint, DeviceRegistry},
        signature::{sign_request, TaskRequest},
    };

    use super::{AuthorizationDecision, AuthorizationEngine, RejectionReason};

    fn setup() -> (DeviceRegistry, DeviceIdentity, AuthorizationEngine) {
        let registry = DeviceRegistry::open_in_memory().expect("open registry");
        let identity = DeviceIdentity::generate().expect("generate identity");
        let key = identity.public_key_bytes();
        registry
            .enroll(
                identity.device_id(),
                key,
                "authorized test device",
                &public_key_fingerprint(&key),
            )
            .expect("enroll device");
        (registry, identity, AuthorizationEngine)
    }

    fn authenticate(
        registry: &DeviceRegistry,
        identity: &DeviceIdentity,
        task_id: &str,
        parameters: BTreeMap<String, String>,
    ) -> crate::device_registry::AuthenticatedRequest {
        let request =
            TaskRequest::new(identity.device_id(), task_id, parameters).expect("create request");
        let signed = sign_request(&request, identity).expect("sign request");
        registry
            .authenticate_request(&signed)
            .expect("authenticate request")
    }

    fn result_reason(result: &super::AuthorizationResult) -> Option<&RejectionReason> {
        match &result.decision {
            AuthorizationDecision::Allowed => None,
            AuthorizationDecision::Denied(reason) => Some(reason),
        }
    }

    #[test]
    fn explicitly_granted_task_with_valid_parameters_is_allowed() {
        let (registry, identity, engine) = setup();
        engine
            .grant_task(&registry, identity.device_id(), "status.report")
            .expect("grant task");
        let mut parameters = BTreeMap::new();
        parameters.insert("format".to_owned(), "summary".to_owned());
        let authenticated = authenticate(&registry, &identity, "status.report", parameters);

        let result = engine.authorize(&registry, &authenticated);
        assert_eq!(result.decision, AuthorizationDecision::Allowed);
        assert_eq!(result.device_id, identity.device_id());
    }

    #[test]
    fn ungranted_task_is_denied_by_default() {
        let (registry, identity, engine) = setup();
        let authenticated = authenticate(&registry, &identity, "registry.list", BTreeMap::new());

        assert_eq!(
            result_reason(&engine.authorize(&registry, &authenticated)),
            Some(&RejectionReason::TaskNotGranted)
        );
    }

    #[test]
    fn another_trusted_device_does_not_inherit_a_task_grant() {
        let (registry, first, engine) = setup();
        let second = DeviceIdentity::generate().expect("generate second identity");
        let key = second.public_key_bytes();
        registry
            .enroll(
                second.device_id(),
                key,
                "second device",
                &public_key_fingerprint(&key),
            )
            .expect("enroll second device");
        engine
            .grant_task(&registry, first.device_id(), "registry.list")
            .expect("grant only to first device");
        let authenticated = authenticate(&registry, &second, "registry.list", BTreeMap::new());

        assert_eq!(
            result_reason(&engine.authorize(&registry, &authenticated)),
            Some(&RejectionReason::TaskNotGranted)
        );
    }

    #[test]
    fn invalid_allow_list_value_is_denied() {
        let (registry, identity, engine) = setup();
        engine
            .grant_task(&registry, identity.device_id(), "status.report")
            .expect("grant task");
        let mut parameters = BTreeMap::new();
        parameters.insert("format".to_owned(), "shell; whoami".to_owned());
        let authenticated = authenticate(&registry, &identity, "status.report", parameters);

        assert_eq!(
            result_reason(&engine.authorize(&registry, &authenticated)),
            Some(&RejectionReason::InvalidParameterValue("format"))
        );
    }

    #[test]
    fn unknown_task_is_denied() {
        let (registry, identity, engine) = setup();
        let authenticated = authenticate(&registry, &identity, "shell.execute", BTreeMap::new());

        assert_eq!(
            result_reason(&engine.authorize(&registry, &authenticated)),
            Some(&RejectionReason::UnknownTask)
        );
    }

    #[test]
    fn unexpected_parameter_is_denied_even_when_task_is_granted() {
        let (registry, identity, engine) = setup();
        engine
            .grant_task(&registry, identity.device_id(), "registry.list")
            .expect("grant task");
        let mut parameters = BTreeMap::new();
        parameters.insert("command".to_owned(), "anything".to_owned());
        let authenticated = authenticate(&registry, &identity, "registry.list", parameters);

        assert_eq!(
            result_reason(&engine.authorize(&registry, &authenticated)),
            Some(&RejectionReason::UnexpectedParameter)
        );
    }

    #[test]
    fn missing_required_parameter_is_denied() {
        let (registry, identity, engine) = setup();
        engine
            .grant_task(&registry, identity.device_id(), "status.report")
            .expect("grant task");
        let authenticated = authenticate(&registry, &identity, "status.report", BTreeMap::new());

        assert_eq!(
            result_reason(&engine.authorize(&registry, &authenticated)),
            Some(&RejectionReason::MissingParameter("format"))
        );
    }

    #[test]
    fn revoked_device_is_denied_even_after_authentication_proof_was_created() {
        let (registry, identity, engine) = setup();
        engine
            .grant_task(&registry, identity.device_id(), "registry.list")
            .expect("grant task");
        let authenticated = authenticate(&registry, &identity, "registry.list", BTreeMap::new());
        registry
            .revoke(identity.device_id())
            .expect("revoke device");

        assert_eq!(
            result_reason(&engine.authorize(&registry, &authenticated)),
            Some(&RejectionReason::RevokedDevice)
        );
    }
}
