//! Redis/Valkey-backed token manager.
//!
//! This module provides a minimal token store implementation backed by Redis-compatible
//! servers (Redis or Valkey). It mirrors the in-memory manager's behavior, but persists
//! tokens in Redis and relies on Redis TTL for expiration.
//!
//! ## 繁體中文
//!
//! 基於 Redis/Valkey 的 token 管理器。
//!
//! 本模組提供一個以 Redis 相容伺服器（Redis 或 Valkey）為後端的最小化 token 儲存實作。
//! 行為上對齊記憶體版管理器，但 token 會存放在 Redis，並利用 Redis 的 TTL 自動過期。

use redis::AsyncCommands;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A token manager backed by Redis/Valkey.
///
/// Tokens are stored as `prefix + token` keys with `user_id` as the value, and the
/// key expiration is controlled by Redis TTL (seconds).
///
/// ## 繁體中文
///
/// 以 Redis/Valkey 為後端的 token 管理器。
///
/// token 會以 `prefix + token` 作為 key，value 存放 `user_id`，並透過 Redis 的 TTL（秒）
/// 來控制到期時間。
#[derive(Clone)]
pub struct RTokenRedisManager {
    prefix: String,
    connection: Arc<Mutex<redis::aio::ConnectionManager>>,
}

impl RTokenRedisManager {
    /// Creates a new manager from an existing async Redis connection manager.
    ///
    /// The `prefix` is normalized to always end with `:`.
    ///
    /// ## 繁體中文
    ///
    /// 使用既有的非同步 Redis 連線管理器建立新的管理器。
    ///
    /// `prefix` 會被正規化，確保一定以 `:` 結尾。
    pub fn new(prefix: impl Into<String>, connection: redis::aio::ConnectionManager) -> Self {
        let mut prefix = prefix.into();
        if !prefix.ends_with(':') {
            prefix.push(':');
        }

        Self {
            prefix,
            connection: Arc::new(Mutex::new(connection)),
        }
    }

    /// Connects to Redis/Valkey and creates a manager.
    ///
    /// ## 繁體中文
    ///
    /// 連線至 Redis/Valkey 並建立管理器。
    pub async fn connect(
        redis_url: &str,
        prefix: impl Into<String>,
    ) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        let connection = client.get_connection_manager().await?;
        Ok(Self::new(prefix, connection))
    }

    /// Builds the Redis key for a token.
    ///
    /// ## 繁體中文
    ///
    /// 依照 prefix 組合 token 的 Redis key。
    fn key(&self, token: &str) -> String {
        format!("{}{}", self.prefix, token)
    }

    /// Issues a new token for `user_id` and stores it in Redis with TTL.
    ///
    /// `ttl_seconds` is interpreted as seconds. Expired tokens are removed automatically
    /// by Redis.
    ///
    /// ## 繁體中文
    ///
    /// 為 `user_id` 簽發新 token，並以 TTL 方式寫入 Redis。
    ///
    /// `ttl_seconds` 以秒為單位。token 到期後會由 Redis 自動移除。
    pub async fn login(
        &self,
        user_id: &str,
        ttl_seconds: u64,
    ) -> Result<String, redis::RedisError> {
        let token = uuid::Uuid::new_v4().to_string();
        let key = self.key(&token);
        let mut connection = self.connection.lock().await;
        let _: () = connection.set_ex(key, user_id, ttl_seconds).await?;
        Ok(token)
    }

    /// Revokes a token by deleting it from Redis.
    ///
    /// This operation is idempotent: deleting a non-existing token is treated as success.
    ///
    /// ## 繁體中文
    ///
    /// 透過從 Redis 刪除 key 來註銷 token。
    ///
    /// 此操作具冪等性：刪除不存在的 token 也視為成功。
    pub async fn logout(&self, token: &str) -> Result<(), redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.connection.lock().await;
        let _: i64 = connection.del(key).await?;
        Ok(())
    }

    /// Validates a token and returns the associated `user_id` if present.
    ///
    /// Returns `Ok(None)` when the token does not exist or has expired.
    ///
    /// ## 繁體中文
    ///
    /// 驗證 token，若存在則回傳對應的 `user_id`。
    ///
    /// 當 token 不存在或已過期時，回傳 `Ok(None)`。
    pub async fn validate(&self, token: &str) -> Result<Option<String>, redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.connection.lock().await;
        let user_id: Option<String> = connection.get(key).await?;
        Ok(user_id)
    }
}
