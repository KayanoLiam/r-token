//! ## 日本語
//!
//! 公開 API で利用する内部型です。
//!
//! このモジュールには [`crate::RTokenManager`] や extractor の認証処理で使われる
//! 小さなデータ構造が含まれます。
//!
//! ## English
//!
//! Internal types used by the public API.
//!
//! This module contains small data structures used by [`crate::RTokenManager`]
//! and the extractor logic.

mod rtoken_error;
mod rtoken_info;

pub use rtoken_error::RTokenError;
pub(crate) use rtoken_info::RTokenInfo;
