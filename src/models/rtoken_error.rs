//! Error types for r-token.
//!
//! The library intentionally keeps its own error type small. It is primarily used
//! by [`crate::RTokenManager`] methods and can also be returned from actix-web handlers
//! because it implements `actix_web::ResponseError`.
//!
//! ## 繁體中文
//!
//! r-token 的錯誤型別。
//!
//! 本庫的錯誤型別刻意保持精簡，主要由 [`crate::RTokenManager`] 方法回傳。
//! 因為實作了 `actix_web::ResponseError`，也可以直接作為 actix-web handler 的錯誤型別使用。

use std::fmt::Formatter;

/// Errors returned by r-token.
///
/// ## 繁體中文
///
/// r-token 會回傳的錯誤集合。
#[derive(Debug)]
pub enum RTokenError {
    /// The internal mutex has been poisoned.
    ///
    /// ## 繁體中文
    ///
    /// 內部 mutex 發生 poisoned。
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

#[cfg(feature = "actix")]
impl actix_web::ResponseError for RTokenError {}
