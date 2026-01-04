//! Error types for the r-token authentication library.
//!
//! This module defines error types that can occur during token management operations.

use std::fmt::Formatter;

/// Errors that can occur during token management operations.
///
/// This error type implements `std::error::Error` and `actix_web::ResponseError`,
/// allowing it to be used seamlessly in actix-web handlers.
///
/// # Examples
///
/// ```rust
/// use r_token::{RTokenManager, RTokenError};
///
/// let manager = RTokenManager::new();
/// let result = manager.login("user123");
///
/// match result {
///     Ok(token) => println!("Token generated: {}", token),
///     Err(RTokenError::MutexPoisoned) => eprintln!("Failed to acquire lock"),
/// }
/// ```
#[derive(Debug)]
pub enum RTokenError {
    /// The internal mutex protecting the token store has been poisoned.
    ///
    /// This typically occurs when a thread panics while holding the lock.
    /// In most cases, this indicates a critical error in the application.
    MutexPoisoned,
}

impl std::fmt::Display for RTokenError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RTokenError::MutexPoisoned => write!(f, "Token manager mutex poisoned"),
        }
    }
}

impl std::error::Error for RTokenError {}

impl actix_web::ResponseError for RTokenError {}