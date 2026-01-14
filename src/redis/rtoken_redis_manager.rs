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

#[cfg(feature = "rbac")]
use crate::models::RTokenInfo;

#[cfg(feature = "actix")]
use actix_web::web;

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
    // Redis 里 token key 的前缀。
    // 例如 prefix="r_token:token:"，token="abc" 时，最终 key 为 "r_token:token:abc"。
    //
    // 这样做的目的：
    // 1) 避免不同项目/不同环境的 key 冲突
    // 2) 方便后续做批量清理或按前缀筛选
    prefix: String,

    // 共享的异步连接管理器（Redis/Valkey 兼容）。
    //
    // 为什么用 Arc：
    // - actix-web 的 app_data 里通常会 clone manager 放到多个 worker/handler 使用
    // - clone 时我们只想增加引用计数，而不是复制连接
    //
    // 为什么用 tokio::Mutex：
    // - ConnectionManager 不是 “每个方法都可并发安全调用” 的句柄
    // - 用 Mutex 保证同一时刻只有一个任务在使用这条连接
    //
    // 说明：这种写法实现最简单，但高并发下会形成串行瓶颈。
    // 如果追求更高吞吐，后续可以换成连接池（每次从池中拿一条连接）。
    connection: Arc<Mutex<redis::aio::ConnectionManager>>,
}

#[cfg(feature = "actix")]
#[derive(Debug)]
/// An authenticated request context extracted from actix-web using Redis/Valkey backend.
///
/// If extraction succeeds:
/// - `id` is the validated user id
/// - `token` is the raw token string from the request
/// - when RBAC is enabled, `roles` are also included
///
/// The token source is resolved via [`crate::extract_token_from_request`], which supports
/// configurable header/cookie names and priority.
///
/// ## 繁體中文
///
/// 由 actix-web 自動抽取的已驗證使用者上下文（Redis/Valkey 版本）。
///
/// Extractor 成功時：
/// - `id` 為驗證後的使用者 id
/// - `token` 為請求中帶來的 token 原文
/// - 啟用 RBAC 時也會包含 `roles`
///
/// token 來源會透過 [`crate::extract_token_from_request`] 解析，支援可設定的
/// header/cookie 名稱與優先順序。
pub struct RRedisUser {
    /// The validated user id.
    ///
    /// ## 繁體中文
    ///
    /// 驗證後的使用者 id。
    pub id: String,
    /// The raw token string from the request.
    ///
    /// ## 繁體中文
    ///
    /// 來自請求的 token 字串原文。
    pub token: String,
    #[cfg(feature = "rbac")]
    /// Roles associated with the token (RBAC enabled).
    ///
    /// ## 繁體中文
    ///
    /// 與 token 綁定的角色列表（啟用 RBAC 時）。
    pub roles: Vec<String>,
}

#[cfg(feature = "actix")]
impl actix_web::FromRequest for RRedisUser {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let manager = match req.app_data::<web::Data<RTokenRedisManager>>() {
            Some(manager) => manager.clone(),
            None => {
                return Box::pin(async {
                    Err(actix_web::error::ErrorInternalServerError(
                        "Token manager not found",
                    ))
                });
            }
        };

        let token = crate::extract_token_from_request(req);

        Box::pin(async move {
            let token = token.ok_or_else(|| actix_web::error::ErrorUnauthorized("Unauthorized"))?;

            #[cfg(feature = "rbac")]
            let user_info = manager
                .validate_with_roles(&token)
                .await
                .map_err(|_| actix_web::error::ErrorInternalServerError("Redis error"))?;

            #[cfg(not(feature = "rbac"))]
            let user_info = manager
                .validate(&token)
                .await
                .map_err(|_| actix_web::error::ErrorInternalServerError("Redis error"))?;

            #[cfg(feature = "rbac")]
            if let Some((user_id, roles)) = user_info {
                return Ok(Self {
                    id: user_id,
                    token,
                    roles,
                });
            }

            #[cfg(not(feature = "rbac"))]
            if let Some(user_id) = user_info {
                return Ok(Self { id: user_id, token });
            }

            Err(actix_web::error::ErrorUnauthorized("Invalid token"))
        })
    }
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

    #[cfg(feature = "rbac")]
    pub async fn login_with_roles(
        &self,
        user_id: &str,
        ttl_seconds: u64,
        roles: impl Into<Vec<String>>,
    ) -> Result<String, redis::RedisError> {
        let token = uuid::Uuid::new_v4().to_string();
        let key = self.key(&token);

        let mut connection = self.connection.lock().await;

        let expire_at = (chrono::Utc::now() + chrono::Duration::seconds(ttl_seconds as i64))
            .timestamp_millis() as u64;
        let info = RTokenInfo {
            user_id: user_id.to_string(),
            expire_at,
            roles: roles.into(),
        };
        let value = serde_json::to_string(&info).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::Client,
                "serialize token info",
                e.to_string(),
            ))
        })?;

        let _: () = connection.set_ex(key, value, ttl_seconds).await?;
        Ok(token)
    }

    #[cfg(feature = "rbac")]
    pub async fn get_roles(&self, token: &str) -> Result<Option<Vec<String>>, redis::RedisError> {
        Ok(self
            .validate_with_roles(token)
            .await?
            .map(|(_user_id, roles)| roles))
    }

    #[cfg(feature = "rbac")]
    pub async fn set_roles(
        &self,
        token: &str,
        roles: impl Into<Vec<String>>,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.connection.lock().await;

        let ttl_seconds: i64 = connection.ttl(&key).await?;
        if ttl_seconds == -2 {
            return Ok(());
        }

        let value: Option<String> = connection.get(&key).await?;
        let Some(value) = value else { return Ok(()) };

        let mut info = serde_json::from_str::<RTokenInfo>(&value).unwrap_or(RTokenInfo {
            user_id: value,
            expire_at: 0,
            roles: Vec::new(),
        });
        info.roles = roles.into();

        let new_value = serde_json::to_string(&info).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::Client,
                "serialize token info",
                e.to_string(),
            ))
        })?;

        if ttl_seconds > 0 {
            let _: () = connection
                .set_ex(key, new_value, ttl_seconds as u64)
                .await?;
        } else {
            let _: () = connection.set(key, new_value).await?;
        }

        Ok(())
    }

    #[cfg(feature = "rbac")]
    pub async fn validate_with_roles(
        &self,
        token: &str,
    ) -> Result<Option<(String, Vec<String>)>, redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.connection.lock().await;

        let value: Option<String> = connection.get(key).await?;
        let Some(value) = value else { return Ok(None) };

        let info = serde_json::from_str::<RTokenInfo>(&value).unwrap_or(RTokenInfo {
            user_id: value,
            expire_at: 0,
            roles: Vec::new(),
        });
        Ok(Some((info.user_id, info.roles)))
    }

    #[cfg(feature = "rbac")]
    pub async fn validate(&self, token: &str) -> Result<Option<String>, redis::RedisError> {
        Ok(self
            .validate_with_roles(token)
            .await?
            .map(|(user_id, _roles)| user_id))
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
        // redis_url 支持如：
        // - redis://127.0.0.1/
        // - redis://:password@127.0.0.1/0
        //
        // Valkey 也兼容 Redis 协议，因此同样可以使用 redis crate 连接。
        let client = redis::Client::open(redis_url)?;

        // ConnectionManager 会在底层连接断开后自动尝试重连（以 redis crate 的实现为准），
        // 对示例场景比较友好。
        let connection = client.get_connection_manager().await?;
        Ok(Self::new(prefix, connection))
    }

    pub async fn ttl_seconds(&self, token: &str) -> Result<Option<i64>, redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.connection.lock().await;
        let ttl: i64 = connection.ttl(key).await?;
        if ttl == -2 {
            return Ok(None);
        }
        Ok(Some(ttl))
    }

    pub async fn renew(&self, token: &str, ttl_seconds: u64) -> Result<bool, redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.connection.lock().await;
        let seconds = i64::try_from(ttl_seconds).unwrap_or(i64::MAX);
        let updated: bool = connection.expire(key, seconds).await?;
        Ok(updated)
    }

    pub async fn rotate(
        &self,
        token: &str,
        ttl_seconds: u64,
    ) -> Result<Option<String>, redis::RedisError> {
        let old_key = self.key(token);
        let mut connection = self.connection.lock().await;

        let value: Option<String> = connection.get(&old_key).await?;
        let Some(value) = value else {
            return Ok(None);
        };

        let new_token = uuid::Uuid::new_v4().to_string();
        let new_key = self.key(&new_token);

        #[cfg(feature = "rbac")]
        let value = {
            let expire_at = (chrono::Utc::now() + chrono::Duration::seconds(ttl_seconds as i64))
                .timestamp_millis() as u64;
            match serde_json::from_str::<RTokenInfo>(&value) {
                Ok(mut info) => {
                    info.expire_at = expire_at;
                    serde_json::to_string(&info).map_err(|e| {
                        redis::RedisError::from((
                            redis::ErrorKind::Client,
                            "serialize token info",
                            e.to_string(),
                        ))
                    })?
                }
                Err(_) => value,
            }
        };

        let _: () = connection.set_ex(&new_key, value, ttl_seconds).await?;
        let _: i64 = connection.del(old_key).await?;

        Ok(Some(new_token))
    }

    /// Builds the Redis key for a token.
    ///
    /// ## 繁體中文
    ///
    /// 依照 prefix 組合 token 的 Redis key。
    fn key(&self, token: &str) -> String {
        // 这里我们约定 prefix 总是以 ':' 结尾，因此直接拼接即可。
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
        // token 的生成策略与内存版一致：UUID v4 字符串。
        // 生产环境如果担心 Redis 泄露导致 token 可被直接利用，可以考虑存储 hash(token) 作为 key。
        let token = uuid::Uuid::new_v4().to_string();
        let key = self.key(&token);

        // 获取连接使用权（这里会 await，表示可能等待其他任务释放锁）。
        let mut connection = self.connection.lock().await;

        // SETEX 语义：SET key value 并设置 TTL（秒）。
        // 这里 value 只存 user_id，过期交给 Redis TTL 来处理，避免应用层自己算 expire_at。
        //
        // `let _: () = ...` 是为了让类型推导明确知道我们不关心返回值，只要命令成功即可。
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

        // DEL 返回实际删除的 key 数量：
        // - 1 表示删除成功
        // - 0 表示 key 不存在
        // 这里不关心这个数量，因为 logout 需要保持幂等。
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
    #[cfg(not(feature = "rbac"))]
    pub async fn validate(&self, token: &str) -> Result<Option<String>, redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.connection.lock().await;

        // GET key：
        // - Some(user_id) => token 有效
        // - None => token 不存在或已过期（TTL 到了被 Redis 自动删掉）
        let user_id: Option<String> = connection.get(key).await?;
        Ok(user_id)
    }
}
