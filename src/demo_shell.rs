//! Interactive, in-memory terminal demonstration of the Shield security engine.

use std::{
    collections::BTreeMap,
    fmt::Display,
    io::{self, BufRead, Write},
};

use crate::{
    authorization::{AuthorizationDecision, AuthorizationEngine},
    device_identity::DeviceIdentity,
    device_registry::{public_key_fingerprint, DeviceRegistry},
    error::ShieldError,
    replay_protection::ReplayProtection,
    security_engine::{RequestValidation, SecurityEngine},
    signature::{SignedRequest, TaskRequest},
};

const MAX_AUDIT_ROWS: usize = 100;

struct DemoDevice {
    identity: DeviceIdentity,
    name: String,
}

struct DemoRequest {
    request_id: uuid::Uuid,
    device_id: uuid::Uuid,
    task_id: String,
    signed: SignedRequest,
}

/// Runs the demonstration using the process terminal.
pub fn run_interactive(setup_demo_data: bool) -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    run_with_io(stdin.lock(), stdout.lock(), setup_demo_data)
}

/// Runs the shell with injectable input and output, which also makes menu
/// behavior straightforward to test without launching a terminal.
pub fn run_with_io<R: BufRead, W: Write>(
    input: R,
    output: W,
    setup_demo_data: bool,
) -> io::Result<()> {
    run_with_identity_factory(
        input,
        output,
        setup_demo_data,
        DeviceIdentity::generate_ephemeral,
    )
}

fn run_with_identity_factory<R: BufRead, W: Write, F>(
    mut input: R,
    mut output: W,
    setup_demo_data: bool,
    mut generate_identity: F,
) -> io::Result<()>
where
    F: FnMut() -> Result<DeviceIdentity, ShieldError>,
{
    let registry = DeviceRegistry::open_in_memory().map_err(other_error)?;
    let engine = SecurityEngine::new(registry, ReplayProtection::default());
    let mut devices = Vec::new();
    let mut requests = Vec::new();

    writeln!(output, "========================================")?;
    writeln!(output, "          SHIELD SECURITY DEMO")?;
    writeln!(output, "========================================")?;
    writeln!(output, "This session uses an in-memory database.")?;
    writeln!(output, "It will not change any existing registry file.")?;
    writeln!(output, "No network or operating-system commands are used.")?;

    if setup_demo_data {
        if let Err(error) =
            setup_test_data(&engine, &mut devices, &mut output, &mut generate_identity)
        {
            writeln!(output, "Could not set up demo test data: {error}")?;
        }
    }

    loop {
        print_menu(&mut output)?;
        let Some(choice) = prompt(&mut input, &mut output, "Select 1-9: ")? else {
            writeln!(output, "\nInput ended. Exiting the demo.")?;
            break;
        };

        match choice.trim() {
            "1" => register_device(
                &engine,
                &mut devices,
                &mut input,
                &mut output,
                &mut generate_identity,
            )?,
            "2" => list_devices(&engine, &mut output)?,
            "3" => create_signed_request(&devices, &mut requests, &mut input, &mut output)?,
            "4" => verify_authentication(&engine, &requests, &mut input, &mut output)?,
            "5" => check_authorization(&engine, &requests, &mut input, &mut output)?,
            "6" => demonstrate_replay(&engine, &devices, &mut requests, &mut output)?,
            "7" => show_audit_logs(&engine, &mut output)?,
            "8" => run_complete_simulation(&engine, &devices, &mut requests, &mut output)?,
            "9" => {
                writeln!(output, "Shield demo closed. No task was executed.")?;
                break;
            }
            _ => writeln!(output, "Invalid menu choice. Enter a number from 1 to 9.")?,
        }
    }
    Ok(())
}

fn print_menu<W: Write>(output: &mut W) -> io::Result<()> {
    writeln!(output)?;
    writeln!(output, "1. Register trusted device")?;
    writeln!(output, "2. List registered devices")?;
    writeln!(output, "3. Create signed task request")?;
    writeln!(output, "4. Verify device authentication")?;
    writeln!(output, "5. Check task authorization")?;
    writeln!(output, "6. Demonstrate replay attack")?;
    writeln!(output, "7. View security audit logs")?;
    writeln!(output, "8. Run complete security simulation")?;
    writeln!(output, "9. Exit")
}

fn setup_test_data<W: Write>(
    engine: &SecurityEngine,
    devices: &mut Vec<DemoDevice>,
    output: &mut W,
    generate_identity: &mut impl FnMut() -> Result<DeviceIdentity, ShieldError>,
) -> io::Result<()> {
    let identity = generate_identity().map_err(other_error)?;
    let public_key = identity.public_key_bytes();
    let name = "DEMO TEST DEVICE";
    let fingerprint = public_key_fingerprint(&public_key);
    engine
        .registry()
        .enroll(identity.device_id(), public_key, name, &fingerprint)
        .map_err(other_error)?;
    AuthorizationEngine
        .grant_task(engine.registry(), identity.device_id(), "status.report")
        .map_err(other_error)?;
    devices.push(DemoDevice {
        identity,
        name: name.to_owned(),
    });
    writeln!(output)?;
    writeln!(output, "[TEST DATA] Added one temporary test device.")?;
    writeln!(output, "[TEST DATA] Granted only status.report.")?;
    writeln!(
        output,
        "[TEST DATA] The device and grant disappear when this session ends."
    )
}

fn register_device<R: BufRead, W: Write>(
    engine: &SecurityEngine,
    devices: &mut Vec<DemoDevice>,
    input: &mut R,
    output: &mut W,
    generate_identity: &mut impl FnMut() -> Result<DeviceIdentity, ShieldError>,
) -> io::Result<()> {
    let Some(name) = prompt(input, output, "Device display name: ")? else {
        return Ok(());
    };
    let name = name.trim();
    if name.is_empty() || name.len() > 128 {
        writeln!(output, "Enter a name from 1 to 128 UTF-8 bytes.")?;
        return Ok(());
    }

    let identity = match generate_identity() {
        Ok(identity) => identity,
        Err(error) => {
            writeln!(
                output,
                "Could not create an ephemeral device identity: {error}"
            )?;
            return Ok(());
        }
    };
    let public_key = identity.public_key_bytes();
    let fingerprint = public_key_fingerprint(&public_key);
    writeln!(
        output,
        "Generated an in-memory identity. Its private key was not displayed or stored in SQLite."
    )?;
    writeln!(output, "Device ID: {}", identity.device_id())?;
    writeln!(output, "Public key: {}", identity.public_key_export())?;
    writeln!(output, "Fingerprint: {fingerprint}")?;
    writeln!(
        output,
        "For this local demonstration, compare and confirm the displayed fingerprint."
    )?;
    let Some(confirmed_fingerprint) = prompt(input, output, "Confirm fingerprint: ")? else {
        return Ok(());
    };
    let device_id = identity.device_id();
    match engine
        .registry()
        .enroll(device_id, public_key, name, confirmed_fingerprint.trim())
    {
        Ok(device) => {
            writeln!(
                output,
                "Registered trusted device {}.",
                clean_cell(&device.name)
            )?;
            devices.push(DemoDevice {
                identity,
                name: name.to_owned(),
            });
        }
        Err(error) => {
            writeln!(output, "Registration rejected: {error}")?;
            return Ok(());
        }
    }

    let Some(grant_now) = prompt(input, output, "Grant one task permission now? [y/N]: ")? else {
        return Ok(());
    };
    if !matches!(grant_now.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        writeln!(output, "No task permission was granted.")?;
        return Ok(());
    }
    print_task_catalog(output)?;
    let Some(task_id) = prompt(input, output, "Task ID to grant: ")? else {
        return Ok(());
    };
    match AuthorizationEngine.grant_task(engine.registry(), device_id, task_id.trim()) {
        Ok(true) => writeln!(output, "Granted {} to {}.", task_id.trim(), device_id)?,
        Ok(false) => writeln!(output, "That device already had this permission.")?,
        Err(error) => writeln!(output, "Permission was not granted: {error}")?,
    }
    Ok(())
}

fn list_devices<W: Write>(engine: &SecurityEngine, output: &mut W) -> io::Result<()> {
    match engine.registry().list() {
        Ok(devices) if devices.is_empty() => {
            writeln!(output, "No devices are registered in this demo session.")
        }
        Ok(devices) => {
            writeln!(output, "DEVICE ID                               | NAME                 | STATUS   | FINGERPRINT")?;
            writeln!(output, "----------------------------------------+----------------------+----------+------------")?;
            for device in devices {
                writeln!(
                    output,
                    "{} | {:20} | {:8} | {}",
                    device.device_id,
                    clean_cell(&device.name),
                    device.status,
                    public_key_fingerprint(&device.public_key)
                )?;
            }
            Ok(())
        }
        Err(error) => writeln!(output, "Could not list devices: {error}"),
    }
}

fn create_signed_request<R: BufRead, W: Write>(
    devices: &[DemoDevice],
    requests: &mut Vec<DemoRequest>,
    input: &mut R,
    output: &mut W,
) -> io::Result<()> {
    let Some(device_index) = select_device(devices, input, output)? else {
        return Ok(());
    };
    let Some(task_id) = prompt(input, output, "Task ID (see allow-list below): ")? else {
        return Ok(());
    };
    print_task_catalog(output)?;
    let task_id = task_id.trim().to_owned();
    let mut parameters = BTreeMap::new();
    if let Some(task) = AuthorizationEngine
        .tasks()
        .iter()
        .find(|task| task.task_id == task_id)
    {
        for schema in task.parameters {
            let allowed = schema.allowed_values.join(", ");
            let label = if schema.required {
                "required"
            } else {
                "optional"
            };
            let Some(value) = prompt(
                input,
                output,
                &format!("Parameter {} ({label}; allowed: {allowed}): ", schema.name),
            )?
            else {
                return Ok(());
            };
            if !value.is_empty() || schema.required {
                parameters.insert(schema.name.to_owned(), value.trim().to_owned());
            }
        }
    }

    match SecurityEngine::create_signed_request(
        &devices[device_index].identity,
        task_id.clone(),
        parameters,
    ) {
        Ok(signed) => {
            let request_id = TaskRequest::deserialize(signed.request_bytes())
                .map(|request| request.request_id)
                .map_err(other_error)?;
            requests.push(DemoRequest {
                request_id,
                device_id: devices[device_index].identity.device_id(),
                task_id: task_id.clone(),
                signed,
            });
            writeln!(
                output,
                "Signed request #{} created for task {task_id}.",
                requests.len()
            )?;
            writeln!(output, "Request ID: {request_id}")?;
            writeln!(
                output,
                "The signature and request are kept separate; no private key was shown."
            )
        }
        Err(error) => writeln!(output, "Could not create the signed request: {error}"),
    }
}

fn verify_authentication<R: BufRead, W: Write>(
    engine: &SecurityEngine,
    requests: &[DemoRequest],
    input: &mut R,
    output: &mut W,
) -> io::Result<()> {
    let Some(index) = select_request(requests, input, output)? else {
        return Ok(());
    };
    match engine.verify_device_authentication(&requests[index].signed) {
        Ok(authenticated) => writeln!(
            output,
            "Authentication successful for device {}.",
            authenticated.device_id()
        ),
        Err(error) => writeln!(output, "Authentication rejected: {error}"),
    }
}

fn check_authorization<R: BufRead, W: Write>(
    engine: &SecurityEngine,
    requests: &[DemoRequest],
    input: &mut R,
    output: &mut W,
) -> io::Result<()> {
    let Some(index) = select_request(requests, input, output)? else {
        return Ok(());
    };
    let authenticated = match engine.verify_device_authentication(&requests[index].signed) {
        Ok(authenticated) => authenticated,
        Err(error) => {
            writeln!(
                output,
                "Authorization was not checked because authentication failed: {error}"
            )?;
            return Ok(());
        }
    };
    let result = engine.check_task_authorization(&authenticated);
    match result.decision {
        AuthorizationDecision::Allowed => writeln!(
            output,
            "Authorization approved for task {}.",
            result.task_id
        ),
        AuthorizationDecision::Denied(reason) => {
            writeln!(
                output,
                "Authorization rejected for task {}: {reason:?}",
                result.task_id
            )
        }
    }
}

fn demonstrate_replay<W: Write>(
    engine: &SecurityEngine,
    devices: &[DemoDevice],
    requests: &mut Vec<DemoRequest>,
    output: &mut W,
) -> io::Result<()> {
    let Some(device) = device_with_permission(engine, devices, "status.report") else {
        writeln!(
            output,
            "Replay demo needs a registered in-memory device granted status.report."
        )?;
        writeln!(output, "Use option 1 to register a device and explicitly grant that task, or start with --setup-demo-data.")?;
        return Ok(());
    };
    let signed = match SecurityEngine::create_signed_request(
        &device.identity,
        "status.report",
        BTreeMap::from([("format".to_owned(), "summary".to_owned())]),
    ) {
        Ok(signed) => signed,
        Err(error) => {
            writeln!(
                output,
                "Could not create a replay demonstration request: {error}"
            )?;
            return Ok(());
        }
    };
    let decoded = TaskRequest::deserialize(signed.request_bytes()).map_err(other_error)?;
    requests.push(DemoRequest {
        request_id: decoded.request_id,
        device_id: device.identity.device_id(),
        task_id: "status.report".to_owned(),
        signed,
    });
    writeln!(
        output,
        "Submitting a fresh signed request, then submitting the same bytes and nonce again:"
    )?;
    show_pipeline_result(
        output,
        "First submission",
        &engine.process_request(&requests.last().expect("just inserted request").signed),
    )?;
    let replay_result = engine.process_request(&requests.last().expect("request retained").signed);
    show_pipeline_result(output, "Replay submission", &replay_result)?;
    if let RequestValidation::Rejected(rejected) = replay_result {
        writeln!(output, "Replay rejection reason: {}", rejected.reason)?;
    }
    writeln!(
        output,
        "Request {} has one device-scoped replay record.",
        decoded.request_id
    )
}

fn show_audit_logs<W: Write>(engine: &SecurityEngine, output: &mut W) -> io::Result<()> {
    match engine.security_audit_logs(MAX_AUDIT_ROWS) {
        Ok(logs) if logs.is_empty() => writeln!(
            output,
            "No audit events have been recorded in this session."
        ),
        Ok(logs) => {
            writeln!(output, "ID | TIME (UNIX MS) | CATEGORY             | DECISION | DEVICE                                  | TASK           | REASON")?;
            writeln!(output, "---+----------------+----------------------+----------+-----------------------------------------+----------------+----------------")?;
            for log in logs {
                writeln!(
                    output,
                    "{:>2} | {:>14} | {:20} | {:8} | {:39} | {:14} | {}",
                    log.log_id,
                    log.occurred_at,
                    clean_cell(&log.category),
                    clean_cell(&log.decision),
                    clean_cell(log.device_id.as_deref().unwrap_or("-")),
                    clean_cell(log.task_id.as_deref().unwrap_or("-")),
                    clean_cell(log.reason.as_deref().unwrap_or("-"))
                )?;
            }
            Ok(())
        }
        Err(error) => writeln!(output, "Could not read audit events: {error}"),
    }
}

fn run_complete_simulation<W: Write>(
    engine: &SecurityEngine,
    devices: &[DemoDevice],
    requests: &mut Vec<DemoRequest>,
    output: &mut W,
) -> io::Result<()> {
    let Some(device) = device_with_permission(engine, devices, "status.report") else {
        writeln!(
            output,
            "Complete simulation needs a device explicitly granted status.report."
        )?;
        writeln!(
            output,
            "Register and grant one with option 1, or start with --setup-demo-data."
        )?;
        return Ok(());
    };

    writeln!(output, "\n--- Complete security simulation ---")?;
    let valid = SecurityEngine::create_signed_request(
        &device.identity,
        "status.report",
        BTreeMap::from([("format".to_owned(), "summary".to_owned())]),
    )
    .map_err(other_error)?;
    let decoded = TaskRequest::deserialize(valid.request_bytes()).map_err(other_error)?;
    requests.push(DemoRequest {
        request_id: decoded.request_id,
        device_id: device.identity.device_id(),
        task_id: "status.report".to_owned(),
        signed: valid,
    });
    let valid_index = requests.len() - 1;
    show_pipeline_result(
        output,
        "Valid trusted request",
        &engine.process_request(&requests[valid_index].signed),
    )?;

    let ungranted_task = AuthorizationEngine.tasks().iter().find(|task| {
        engine
            .registry()
            .permissions(device.identity.device_id())
            .is_ok_and(|permissions| {
                !permissions
                    .iter()
                    .any(|permission| permission == task.task_id)
            })
    });
    if let Some(task) = ungranted_task {
        let parameters = if task.task_id == "device.info" {
            BTreeMap::from([("section".to_owned(), "identity".to_owned())])
        } else {
            BTreeMap::new()
        };
        if let Ok(unauthorized) =
            SecurityEngine::create_signed_request(&device.identity, task.task_id, parameters)
        {
            requests.push(DemoRequest {
                request_id: TaskRequest::deserialize(unauthorized.request_bytes())
                    .map_err(other_error)?
                    .request_id,
                device_id: device.identity.device_id(),
                task_id: task.task_id.to_owned(),
                signed: unauthorized,
            });
            show_pipeline_result(
                output,
                "Authenticated but ungranted task",
                &engine.process_request(&requests.last().expect("just inserted request").signed),
            )?;
        }
    } else {
        writeln!(output, "No ungranted task is available for this device.")?;
    }

    let replay = engine.process_request(&requests[valid_index].signed);
    show_pipeline_result(output, "Replayed valid request", &replay)?;
    if let RequestValidation::Rejected(rejected) = replay {
        writeln!(output, "Replay rejection reason: {}", rejected.reason)?;
    }
    writeln!(
        output,
        "The approved result was simulated only; no task was executed."
    )?;
    writeln!(output, "Valid request ID: {}", decoded.request_id)
}

fn show_pipeline_result<W: Write>(
    output: &mut W,
    label: &str,
    result: &RequestValidation,
) -> io::Result<()> {
    match result {
        RequestValidation::Accepted(approval) => writeln!(
            output,
            "{label}: APPROVED — {} (device {}, task {})",
            approval.message, approval.device_id, approval.task_id
        ),
        RequestValidation::Rejected(rejected) => {
            writeln!(output, "{label}: REJECTED — {}", rejected.reason)
        }
    }
}

fn device_with_permission<'a>(
    engine: &SecurityEngine,
    devices: &'a [DemoDevice],
    task_id: &str,
) -> Option<&'a DemoDevice> {
    devices.iter().find(|device| {
        engine
            .registry()
            .permissions(device.identity.device_id())
            .is_ok_and(|permissions| permissions.iter().any(|permission| permission == task_id))
    })
}

fn select_device<R: BufRead, W: Write>(
    devices: &[DemoDevice],
    input: &mut R,
    output: &mut W,
) -> io::Result<Option<usize>> {
    if devices.is_empty() {
        writeln!(
            output,
            "No in-memory device identity is available. Register one with option 1."
        )?;
        return Ok(None);
    }
    for (index, device) in devices.iter().enumerate() {
        writeln!(
            output,
            "{}. {} ({})",
            index + 1,
            clean_cell(&device.name),
            device.identity.device_id()
        )?;
    }
    let Some(input_value) = prompt(input, output, "Device number: ")? else {
        return Ok(None);
    };
    match parse_selection(&input_value, devices.len()) {
        Some(index) => Ok(Some(index)),
        None => {
            writeln!(output, "Invalid device number. No action was taken.")?;
            Ok(None)
        }
    }
}

fn select_request<R: BufRead, W: Write>(
    requests: &[DemoRequest],
    input: &mut R,
    output: &mut W,
) -> io::Result<Option<usize>> {
    if requests.is_empty() {
        writeln!(
            output,
            "No signed requests are available. Create one with option 3."
        )?;
        return Ok(None);
    }
    for (index, request) in requests.iter().enumerate() {
        writeln!(
            output,
            "{}. {} — task {} — device {}",
            index + 1,
            request.request_id,
            clean_cell(&request.task_id),
            request.device_id
        )?;
    }
    let Some(input_value) = prompt(input, output, "Request number: ")? else {
        return Ok(None);
    };
    match parse_selection(&input_value, requests.len()) {
        Some(index) => Ok(Some(index)),
        None => {
            writeln!(output, "Invalid request number. No action was taken.")?;
            Ok(None)
        }
    }
}

fn print_task_catalog<W: Write>(output: &mut W) -> io::Result<()> {
    writeln!(output, "Predefined task allow-list:")?;
    for task in AuthorizationEngine.tasks() {
        writeln!(output, "- {}: {}", task.task_id, task.description)?;
        for parameter in task.parameters {
            writeln!(
                output,
                "  {}{}: {}",
                parameter.name,
                if parameter.required {
                    " (required)"
                } else {
                    " (optional)"
                },
                parameter.allowed_values.join(", ")
            )?;
        }
    }
    Ok(())
}

fn prompt<R: BufRead, W: Write>(
    input: &mut R,
    output: &mut W,
    label: &str,
) -> io::Result<Option<String>> {
    write!(output, "{label}")?;
    output.flush()?;
    let mut value = String::new();
    if input.read_line(&mut value)? == 0 {
        Ok(None)
    } else {
        Ok(Some(value.trim_end_matches(['\r', '\n']).to_owned()))
    }
}

fn parse_selection(value: &str, count: usize) -> Option<usize> {
    let selected = value.trim().parse::<usize>().ok()?;
    (1..=count).contains(&selected).then_some(selected - 1)
}

fn clean_cell(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn other_error(error: impl Display) -> io::Error {
    io::Error::other(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::{
        device_identity::DeviceIdentity, device_registry::public_key_fingerprint,
        error::ShieldError,
    };

    use super::run_with_identity_factory;

    #[test]
    fn register_menu_action_uses_engine_enrollment_and_explicit_grant() {
        let identity = DeviceIdentity::generate_ephemeral().expect("generate test identity");
        let fingerprint = public_key_fingerprint(&identity.public_key_bytes());
        let input = format!("1\nProfessor test device\n{fingerprint}\ny\nstatus.report\n9\n");
        let mut identity = Some(identity);
        let mut output = Vec::new();

        run_with_identity_factory(Cursor::new(input), &mut output, false, move || {
            identity
                .take()
                .ok_or_else(|| ShieldError::new("test identity already used"))
        })
        .expect("run registration menu flow");

        let output = String::from_utf8(output).expect("UTF-8 shell output");
        assert!(output.contains("Registered trusted device Professor test device."));
        assert!(output.contains("Granted status.report to"));
        assert!(output.contains("Shield demo closed."));
    }
}
