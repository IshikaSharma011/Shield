//! A small, dependency-free error type for library operations.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShieldError {
    message: String,
}

impl ShieldError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ShieldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ShieldError {}
