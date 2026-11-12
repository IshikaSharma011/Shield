use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use shield::{
    authorization::AuthorizationEngine,
    database::Database,
    device_identity::DeviceIdentity,
    device_registry::{public_key_fingerprint, DeviceRegistry, RegistryError},
    replay_protection::ReplayProtection,
    security_engine::{
        RequestValidation, SecurityEngine, SecurityRejectionReason, SimulatedTaskApproval,
    },
    signature::{sign_request, SignedRequest, TaskRequest},
};

fn new_identity() -> DeviceIdentity {
    DeviceIdentity::generate_ephemeral().expect("generate ephemeral identity")
}

fn setup(authorized: bool) -> (SecurityEngine, DeviceIdentity) {
    let registry = DeviceRegistry::open_in_memory().expect("open in-memory registry");
    let identity = new_identity();
    enroll(&registry, &identity);
    if authorized {
        AuthorizationEngine
            .grant_task(&registry, identity.device_id(), "status.report")
            .expect("grant report task");
    }
    (
        SecurityEngine::new(registry, ReplayProtection::default()),
        identity,
    )
}

fn enroll(registry: &DeviceRegistry, identity: &DeviceIdentity) {
    let public_key = identity.public_key_bytes();
    registry
        .enroll(
            identity.device_id(),
            public_key,
            "pipeline integration device",
            &public_key_fingerprint(&public_key),
        )
        .expect("enroll identity");
}

fn request(identity: &DeviceIdentity) -> TaskRequest {
    let mut parameters = BTreeMap::new();
    parameters.insert("format".to_owned(), "summary".to_owned());
    TaskRequest::new(identity.device_id(), "status.report", parameters).expect("create request")
}

fn sign(request: &TaskRequest, identity: &DeviceIdentity) -> SignedRequest {
    sign_request(request, identity).expect("sign request")
}

fn reason(result: RequestValidation) -> SecurityRejectionReason {
    match result {
        RequestValidation::Rejected(rejected) => rejected.reason,
        RequestValidation::Accepted(_) => panic!("request should be rejected"),
    }
}

#[test]
fn valid_trusted_request_completes_pipeline_with_simulated_approval_and_audit() {
    let identity = new_identity();
    let path = std::env::temp_dir().join(format!("shield-engine-{}.sqlite3", identity.device_id()));
    let engine = SecurityEngine::open(&path).expect("open engine");
    enroll(engine.registry(), &identity);
    AuthorizationEngine
        .grant_task(engine.registry(), identity.device_id(), "status.report")
        .expect("grant task");
    let signed = SecurityEngine::create_signed_request(
        &identity,
        "status.report",
        BTreeMap::from([("format".to_owned(), "summary".to_owned())]),
    )
    .expect("create signed request");

    let result = engine.process_request(&signed);
    assert!(matches!(
        result,
        RequestValidation::Accepted(SimulatedTaskApproval {
            message: "Task approved for demonstration; no task was executed.",
            ..
        })
    ));
    drop(engine);

    let database = Database::open(&path).expect("reopen pipeline database");
    let logs = database.security_logs(20).expect("read pipeline logs");
    assert!(logs
        .iter()
        .any(|log| { log.category == "request_pipeline" && log.decision == "accepted" }));
    drop(database);
    std::fs::remove_file(path).expect("remove test database");
}

#[test]
fn unknown_device_is_rejected() {
    let registry = DeviceRegistry::open_in_memory().expect("open empty registry");
    let engine = SecurityEngine::new(registry, ReplayProtection::default());
    let identity = new_identity();
    let signed = sign(&request(&identity), &identity);

    assert_eq!(
        reason(engine.process_request(&signed)),
        SecurityRejectionReason::Authentication(RegistryError::UnknownDevice)
    );
}

#[test]
fn revoked_device_is_rejected() {
    let (engine, identity) = setup(true);
    engine
        .registry()
        .revoke(identity.device_id())
        .expect("revoke device");
    let signed = sign(&request(&identity), &identity);

    assert_eq!(
        reason(engine.process_request(&signed)),
        SecurityRejectionReason::Authentication(RegistryError::RevokedDevice)
    );
}

#[test]
fn modified_request_is_rejected_by_signature_verification() {
    let (engine, identity) = setup(true);
    let signed = sign(&request(&identity), &identity);
    let mut bytes = signed.request_bytes().to_vec();
    bytes[45] ^= 1; // nonce byte in the serialized, signed request
    let modified = SignedRequest::from_parts(bytes, signed.signature_bytes())
        .expect("retain detached signature");

    assert!(matches!(
        reason(engine.process_request(&modified)),
        SecurityRejectionReason::Authentication(RegistryError::RequestVerification(_))
    ));
}

#[test]
fn invalid_signature_is_rejected() {
    let (engine, identity) = setup(true);
    let signed = sign(&request(&identity), &identity);
    let invalid = SignedRequest::from_parts(signed.request_bytes().to_vec(), &[0_u8; 64])
        .expect("construct correctly sized invalid signature");

    assert!(matches!(
        reason(engine.process_request(&invalid)),
        SecurityRejectionReason::Authentication(RegistryError::RequestVerification(_))
    ));
}

#[test]
fn unauthorized_task_is_rejected_after_authentication_and_replay_checks() {
    let (engine, identity) = setup(false);
    let signed = sign(&request(&identity), &identity);

    assert_eq!(
        reason(engine.process_request(&signed)),
        SecurityRejectionReason::Authorization(
            shield::authorization::RejectionReason::TaskNotGranted
        )
    );
}

#[test]
fn repeated_nonce_is_rejected_by_persistent_replay_stage() {
    let (engine, identity) = setup(true);
    let first_request = request(&identity);
    let first = sign(&first_request, &identity);
    assert!(matches!(
        engine.process_request(&first),
        RequestValidation::Accepted(_)
    ));

    let mut second_request = request(&identity);
    second_request.nonce = first_request.nonce;
    let second = sign(&second_request, &identity);
    assert_eq!(
        reason(engine.process_request(&second)),
        SecurityRejectionReason::Replay(
            shield::replay_protection::ReplayRejectionReason::ReusedNonce
        )
    );
}

#[test]
fn expired_request_is_rejected() {
    let (engine, identity) = setup(true);
    let mut expired_request = request(&identity);
    expired_request.timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64
        - 10 * 60 * 1000;
    let signed = sign(&expired_request, &identity);

    assert_eq!(
        reason(engine.process_request(&signed)),
        SecurityRejectionReason::Replay(
            shield::replay_protection::ReplayRejectionReason::ExpiredRequest
        )
    );
}

#[test]
fn database_audit_failure_fails_closed() {
    let identity = new_identity();
    let path = std::env::temp_dir().join(format!(
        "shield-engine-failure-{}.sqlite3",
        identity.device_id()
    ));
    let engine = SecurityEngine::open(&path).expect("open engine");
    enroll(engine.registry(), &identity);
    AuthorizationEngine
        .grant_task(engine.registry(), identity.device_id(), "status.report")
        .expect("grant task");
    let external = rusqlite::Connection::open(&path).expect("open second database connection");
    external
        .execute_batch(
            "CREATE TRIGGER fail_security_logs BEFORE INSERT ON security_logs
             BEGIN SELECT RAISE(ABORT, 'forced integration failure'); END;",
        )
        .expect("install audit failure trigger");
    drop(external);
    let signed = sign(&request(&identity), &identity);

    assert_eq!(
        reason(engine.process_request(&signed)),
        SecurityRejectionReason::AuditUnavailable
    );
    drop(engine);
    std::fs::remove_file(path).expect("remove test database");
}
