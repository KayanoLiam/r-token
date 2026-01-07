#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::empty_loop)]
#![deny(clippy::indexing_slicing)]
#![deny(unused)]
//! # r-token
//!
//! A small, in-memory token authentication helper for actix-web.
//!
//! The library exposes two main building blocks:
//! - [`RTokenManager`]: issues and revokes tokens (UUID v4) and keeps an in-memory store.
//! - [`RUser`]: an actix-web extractor that validates `Authorization` automatically.
//!
//! ## How authentication works
//!
//! 1. Your login handler calls [`RTokenManager::login`] with a user id and a TTL (seconds).
//! 2. The token is returned to the client (typically as plain text or JSON).
//! 3. The client sends the token back via `Authorization` header:
//!    - `Authorization: <token>`
//!    - `Authorization: Bearer <token>`
//! 4. Any handler that declares an [`RUser`] parameter becomes a protected endpoint. If extraction
//!    succeeds, the request is considered authenticated; otherwise actix-web returns an error.
//!
//! ## 繁體中文
//!
//! 這是一個為 actix-web 設計的輕量級、純記憶體 token 驗證輔助庫。
//!
//! 主要由兩個元件構成：
//! - [`RTokenManager`]: 產生/註銷 token（UUID v4），並在記憶體中維護映射表。
//! - [`RUser`]: actix-web 的 Extractor，會自動從 `Authorization` 讀取並驗證 token。
//!
//! ## 驗證流程
//!
//! 1. 登入端點呼叫 [`RTokenManager::login`]，傳入使用者 id 與 TTL（秒）。
//! 2. token 回傳給客戶端（常見為純文字或 JSON）。
//! 3. 客戶端透過 `Authorization` header 送回 token（支援 `Bearer ` 前綴或不帶前綴）。
//! 4. 任何 handler 只要宣告 [`RUser`] 參數即視為受保護端點；Extractor 成功才會進入 handler。

mod models;
mod memory;
#[cfg(feature = "redis")]
mod redis;

pub use crate::models::RTokenError;
pub use crate::memory::RTokenManager;
#[cfg(feature = "actix")]
pub use crate::memory::RUser;
#[cfg(feature = "redis")]
pub use crate::redis::RTokenRedisManager;
