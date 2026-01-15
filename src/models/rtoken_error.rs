//! ## 日本語
//!
//! r-token のエラー型です。
//!
//! このライブラリのエラー型は意図的に小さく保っています。主に
//! [`crate::RTokenManager`] の各メソッドから返されます。また `actix_web::ResponseError`
//! を実装しているため、actix-web の handler からそのまま返すこともできます。
//!
//! ## English
//!
//! Error types for r-token.
//!
//! The library intentionally keeps its own error type small. It is primarily used
//! by [`crate::RTokenManager`] methods and can also be returned from actix-web handlers
//! because it implements `actix_web::ResponseError`.

use std::fmt::Formatter;

/// ## 日本語
///
/// r-token が返すエラーの一覧です。
///
/// ## English
///
/// Errors returned by r-token.
#[derive(Debug)]
pub enum RTokenError {
    /// ## 日本語
    ///
    /// 内部 mutex が poisoned 状態になりました。
    ///
    /// ## English
    ///
    /// The internal mutex has been poisoned.
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
