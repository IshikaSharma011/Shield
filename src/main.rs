use clap::{Parser, Subcommand};
use shield::{
    authorization::AuthorizationEngine,
    device_identity::DeviceIdentity,
    device_registry::{parse_public_key_export, public_key_fingerprint, DeviceRegistry},
};
use std::{error::Error, path::PathBuf};
use uuid::Uuid;

#[derive(Debug, Subcommand)]
enum Command {
    /// Create, display, or export the local device identity.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Manage manually enrolled trusted devices.
    Registry {
        #[command(subcommand)]
        action: RegistryAction,
    },
    /// Show the predefined, non-executing task allow-list.
    Authorization {
        #[command(subcommand)]
        action: AuthorizationAction,
    },
    /// Start the isolated, in-memory interactive security demonstration.
    Demo {
        /// Explicitly load temporary, labeled sample test data.
        #[arg(long)]
        setup_demo_data: bool,
    },
}

#[derive(Debug, Subcommand)]
enum IdentityAction {
    /// Create a new identity in the OS credential store.
    Create,
    /// Display the saved device ID and public key.
    Show,
    /// Print only the public key for manual enrollment.
    ExportPublicKey,
}

#[derive(Debug, Subcommand)]
enum RegistryAction {
    /// Enroll a device after verifying its public-key fingerprint out of band.
    Enroll {
        #[arg(long, value_name = "PATH")]
        database: PathBuf,
        #[arg(long)]
        device_id: Uuid,
        #[arg(long)]
        name: String,
        #[arg(long, value_name = "ED25519_PUBLIC_KEY")]
        public_key: String,
        #[arg(long, value_name = "SHA256_FINGERPRINT")]
        fingerprint: String,
    },
    /// List registered devices and their trust status.
    List {
        #[arg(long, value_name = "PATH")]
        database: PathBuf,
    },
    /// Revoke a previously enrolled device.
    Revoke {
        #[arg(long, value_name = "PATH")]
        database: PathBuf,
        #[arg(long)]
        device_id: Uuid,
    },
    /// Grant a predefined task to a trusted device.
    GrantTask {
        #[arg(long, value_name = "PATH")]
        database: PathBuf,
        #[arg(long)]
        device_id: Uuid,
        #[arg(long)]
        task_id: String,
    },
    /// Remove a task grant from a device.
    RevokeTask {
        #[arg(long, value_name = "PATH")]
        database: PathBuf,
        #[arg(long)]
        device_id: Uuid,
        #[arg(long)]
        task_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum AuthorizationAction {
    /// List predefined tasks and their allowed parameter values.
    Tasks,
}

#[derive(Debug, Parser)]
#[command(
    name = "shield",
    about = "Shield security framework demonstration",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        None => println!("{}", shield::welcome_message()),
        Some(Command::Identity { action }) => match action {
            IdentityAction::Create => {
                let identity = DeviceIdentity::create()?;
                println!("Device identity created.\n{identity}");
            }
            IdentityAction::Show => {
                let identity = DeviceIdentity::load()?;
                println!("{identity}");
                println!(
                    "Public key fingerprint: {}",
                    public_key_fingerprint(&identity.public_key_bytes())
                );
            }
            IdentityAction::ExportPublicKey => {
                println!("{}", DeviceIdentity::load()?.public_key_export());
            }
        },
        Some(Command::Registry { action }) => match action {
            RegistryAction::Enroll {
                database,
                device_id,
                name,
                public_key,
                fingerprint,
            } => {
                let registry = DeviceRegistry::open(database)?;
                let public_key = parse_public_key_export(&public_key)?;
                let device = registry.enroll(device_id, public_key, &name, &fingerprint)?;
                println!(
                    "Enrolled trusted device {} ({})",
                    device.name, device.device_id
                );
            }
            RegistryAction::List { database } => {
                let registry = DeviceRegistry::open(database)?;
                for device in registry.list()? {
                    println!(
                        "{} | {} | {} | {} | {}",
                        device.device_id,
                        device.name,
                        device.status,
                        device.registered_at,
                        public_key_fingerprint(&device.public_key)
                    );
                }
            }
            RegistryAction::Revoke {
                database,
                device_id,
            } => {
                let registry = DeviceRegistry::open(database)?;
                let device = registry.revoke(device_id)?;
                println!("Revoked device {} ({})", device.name, device.device_id);
            }
            RegistryAction::GrantTask {
                database,
                device_id,
                task_id,
            } => {
                let registry = DeviceRegistry::open(database)?;
                let changed = AuthorizationEngine.grant_task(&registry, device_id, &task_id)?;
                println!(
                    "{} permission for {task_id} on {device_id}",
                    if changed { "Granted" } else { "Already had" }
                );
            }
            RegistryAction::RevokeTask {
                database,
                device_id,
                task_id,
            } => {
                let registry = DeviceRegistry::open(database)?;
                let changed = AuthorizationEngine.revoke_task(&registry, device_id, &task_id)?;
                println!(
                    "{} permission for {task_id} on {device_id}",
                    if changed { "Revoked" } else { "No existing" }
                );
            }
        },
        Some(Command::Authorization { action }) => match action {
            AuthorizationAction::Tasks => {
                for task in AuthorizationEngine.tasks() {
                    println!("{} — {}", task.task_id, task.description);
                    for parameter in task.parameters {
                        println!(
                            "  {}{}: {}",
                            parameter.name,
                            if parameter.required {
                                " (required)"
                            } else {
                                ""
                            },
                            parameter.allowed_values.join(", ")
                        );
                    }
                }
            }
        },
        Some(Command::Demo { setup_demo_data }) => {
            shield::demo_shell::run_interactive(setup_demo_data)?;
        }
    }
    Ok(())
}
