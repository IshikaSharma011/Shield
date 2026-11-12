use clap::{Parser, Subcommand};
use shield::{device_identity::DeviceIdentity, error::ShieldError};

#[derive(Debug, Subcommand)]
enum Command {
    /// Create, display, or export the local device identity.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
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

fn run() -> Result<(), ShieldError> {
    let cli = Cli::parse();
    match cli.command {
        None => println!("{}", shield::welcome_message()),
        Some(Command::Identity { action }) => match action {
            IdentityAction::Create => {
                let identity = DeviceIdentity::create()?;
                println!("Device identity created.\n{identity}");
            }
            IdentityAction::Show => println!("{}", DeviceIdentity::load()?),
            IdentityAction::ExportPublicKey => {
                println!("{}", DeviceIdentity::load()?.public_key_export());
            }
        },
    }
    Ok(())
}
