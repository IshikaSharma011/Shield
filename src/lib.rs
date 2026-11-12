pub mod authorization;
pub mod config;
pub mod database;
pub mod device_identity;
pub mod device_registry;
pub mod error;
pub mod replay_protection;
pub mod security_engine;
pub mod signature;

/// Returns the welcome message shown by the command-line application.
pub fn welcome_message() -> &'static str {
    config::WELCOME_MESSAGE
}
