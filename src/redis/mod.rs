//! ## 日本語
//!
//! Redis/Valkey バックエンドの実装です。
//!
//! `redis` feature により [`RTokenRedisManager`] が利用可能になります。
//! また、`actix` または `axum` feature が有効な場合は extractor の [`RRedisUser`] も re-export します。
//!
//! ## English
//!
//! Redis/Valkey-backed implementation.
//!
//! Enabling the `redis` feature makes [`RTokenRedisManager`] available.
//! When `actix` or `axum` is enabled, the extractor [`RRedisUser`] is also re-exported.

mod rtoken_redis_manager;

#[cfg(any(feature = "actix", feature = "axum"))]
pub use rtoken_redis_manager::RRedisUser;
pub use rtoken_redis_manager::RTokenRedisManager;
