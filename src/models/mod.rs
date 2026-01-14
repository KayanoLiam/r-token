//! Internal types used by the public API.
//!
//! This module contains small data structures used by [`crate::RTokenManager`]
//! and the extractor logic.
//!
//! ## 繁體中文
//!
//! 提供給公開 API 使用的內部型別。
//!
//! 這個模組包含 [`crate::RTokenManager`] 與 Extractor 驗證流程會用到的資料結構。

mod rtoken_error;
mod rtoken_info;

pub use rtoken_error::RTokenError;
pub(crate) use rtoken_info::RTokenInfo;
