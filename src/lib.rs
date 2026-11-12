pub mod config;
pub mod device_identity;
pub mod device_registry;
pub mod error;
pub mod signature;

/// Returns the welcome message shown by the command-line application.
pub fn welcome_message() -> &'static str {
    config::WELCOME_MESSAGE
}
