//! ## 日本語
//!
//! Redis/Valkey をバックエンドにした token マネージャです。
//!
//! このモジュールは Redis 互換サーバ（Redis または Valkey）上に token を保存する
//! 最小構成の実装を提供します。インメモリ版と同じ振る舞いを目指しつつ、永続化と失効は
//! Redis の TTL（秒）に任せます。
//!
//! ## English
//!
//! Redis/Valkey-backed token manager.
//!
//! This module provides a minimal token store implementation backed by Redis-compatible
//! servers (Redis or Valkey). It mirrors the in-memory manager's behavior, but persists
//! tokens in Redis and relies on Redis TTL for expiration.

use redis::{AsyncCommands, Script};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Mutex;

#[cfg(feature = "rbac")]
use crate::models::RTokenInfo;

#[cfg(feature = "actix")]
use actix_web::web;

/// ## 日本語
///
/// 現在時刻の Unix epoch ミリ秒を返します。
///
/// ## English
///
/// Returns the current Unix epoch milliseconds.
fn now_ms_u64() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0)
}

/// ## 日本語
///
/// `now_ms + ttl_seconds` をミリ秒で安全に加算します（飽和演算）。
///
/// ## English
///
/// Computes `now_ms + ttl_seconds` in milliseconds with saturation.
fn add_ttl_ms(now_ms: u64, ttl_seconds: u64) -> u64 {
    let ttl_ms = (ttl_seconds as u128).saturating_mul(1000);
    (now_ms as u128)
        .saturating_add(ttl_ms)
        .min(u64::MAX as u128) as u64
}

/// ## 日本語
///
/// Redis/Valkey をバックエンドにした token マネージャです。
///
/// token は `prefix + token` を key、`user_id` を value として保存し、有効期限は
/// Redis の TTL（秒）で管理します。
///
/// ## English
///
/// A token manager backed by Redis/Valkey.
///
/// Tokens are stored as `prefix + token` keys with `user_id` as the value, and the
/// key expiration is controlled by Redis TTL (seconds).
#[derive(Clone)]
pub struct RTokenRedisManager {
    // 日本語: Redis の token key に付ける prefix。
    //        例: prefix="r_token:token:"、token="abc" のとき key は "r_token:token:abc"。
    // English: Prefix for token keys in Redis.
    //          Example: prefix="r_token:token:" and token="abc" => key "r_token:token:abc".
    prefix: String,

    // 日本語: 共有の非同期 ConnectionManager（Redis/Valkey 互換）。
    //        Arc: clone 時に接続を複製せず参照を共有するため。
    //        tokio::Mutex: 同時に 1 タスクだけが接続を使うようにするため。
    // English: Shared async ConnectionManager (Redis/Valkey compatible).
    //          Arc shares the handle cheaply; tokio::Mutex serializes access to the connection.
    connections: Arc<Vec<Mutex<redis::aio::ConnectionManager>>>,
    next_index: Arc<AtomicUsize>,
}

#[cfg(any(feature = "actix", feature = "axum"))]
#[derive(Debug)]
/// ## 日本語
///
/// actix-web / axum から抽出される認証済みユーザーコンテキスト（Redis/Valkey バックエンド）です。
///
/// 抽出が成功した場合：
/// - `id` は検証済みのユーザー ID
/// - `token` はリクエストに含まれていた token の生文字列
/// - RBAC 有効時は `roles` も含まれます
///
/// token の取得元は [`crate::extract_token_from_request`] により解決され、header/cookie 名と
/// 優先順位を設定できます。
///
/// ## English
///
/// An authenticated request context extracted from actix-web / axum using Redis/Valkey backend.
///
/// If extraction succeeds:
/// - `id` is the validated user id
/// - `token` is the raw token string from the request
/// - when RBAC is enabled, `roles` are also included
///
/// The token source is resolved via [`crate::extract_token_from_request`], which supports
/// configurable header/cookie names and priority.
pub struct RRedisUser {
    /// ## 日本語
    ///
    /// 検証後のユーザー ID。
    ///
    /// ## English
    ///
    /// The validated user id.
    pub id: String,
    /// ## 日本語
    ///
    /// リクエストに含まれていた token の生文字列。
    ///
    /// ## English
    ///
    /// The raw token string from the request.
    pub token: String,
    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// token に紐づく roles（RBAC 有効時）。
    ///
    /// ## English
    ///
    /// Roles associated with the token (RBAC enabled).
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
        // 日本語: app_data から Redis マネージャを取得する（見つからなければ 500）。
        //        actix-web の extractor はリクエストごとに動くので、ここで clone して
        //        async ブロックに move できる形にする。
        // English: Fetch Redis manager from app_data (500 if missing).
        //          Extractors run per request; we clone here so we can move it into the async block.
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

        // 日本語: リクエストから token を抽出する（header/cookie の優先度は設定に従う）。
        //        ここではまだエラーにせず、async 側で 401 に変換する（`?` しやすい形にするため）。
        // English: Extract token from request (header/cookie priority is configurable).
        //          We keep it as Option here and turn it into 401 inside the async block.
        let token = crate::extract_token_from_request(req);

        Box::pin(async move {
            // 日本語: token が無ければ 401。
            //        ここでの Unauthorized は「未ログイン」相当（入力が足りない）を意味する。
            // English: 401 when token is missing.
            //          This Unauthorized maps to “not logged in / missing credential”.
            let token = token.ok_or_else(|| actix_web::error::ErrorUnauthorized("Unauthorized"))?;

            #[cfg(feature = "rbac")]
            // 日本語: RBAC 有効時は user_id と roles をまとめて検証する。
            //        - Redis GET が失敗 => 500（インフラ障害）
            //        - GET は成功したが値が無い => None（期限切れ/削除/不正 token）
            // English: With RBAC enabled, validate and fetch both user_id and roles.
            //          - Redis GET error => 500 (infra failure)
            //          - GET ok but value missing => None (expired/deleted/invalid token)
            let user_info = manager
                .validate_with_roles(&token)
                .await
                .map_err(|_| actix_web::error::ErrorInternalServerError("Redis error"))?;

            #[cfg(not(feature = "rbac"))]
            // 日本語: RBAC 無効時は user_id のみ検証する（Some/None の意味は上と同じ）。
            // English: Without RBAC, validate and fetch only user_id (same Some/None semantics).
            let user_info = manager
                .validate(&token)
                .await
                .map_err(|_| actix_web::error::ErrorInternalServerError("Redis error"))?;

            #[cfg(feature = "rbac")]
            if let Some((user_id, roles)) = user_info {
                // 日本語: 検証済みコンテキストを返す（以後 handler では id/roles を信頼できる）。
                // English: Return validated request context (handler can trust id/roles).
                return Ok(Self {
                    id: user_id,
                    token,
                    roles,
                });
            }

            #[cfg(not(feature = "rbac"))]
            if let Some(user_id) = user_info {
                // 日本語: 検証済みコンテキストを返す（以後 handler では id を信頼できる）。
                // English: Return validated request context (handler can trust id).
                return Ok(Self { id: user_id, token });
            }

            // 日本語: token は渡されたが、存在しない/期限切れ/不正だったので 401
            // English: Token was provided but is missing/expired/invalid => 401
            Err(actix_web::error::ErrorUnauthorized("Invalid token"))
        })
    }
}

impl RTokenRedisManager {
    /// ## 日本語
    ///
    /// 接続プールから次の接続をロックして取得します。
    ///
    /// ## English
    ///
    /// Locks and returns the next connection from the pool.
    async fn lock_connection(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, redis::aio::ConnectionManager>, redis::RedisError> {
        let len = self.connections.len();
        if len == 0 {
            return Err(redis::RedisError::from((
                redis::ErrorKind::Client,
                "no redis connections",
            )));
        }
        let index = self.next_index.fetch_add(1, Ordering::Relaxed) % len;
        match self.connections.get(index) {
            Some(conn) => Ok(conn.lock().await),
            None => Err(redis::RedisError::from((
                redis::ErrorKind::Client,
                "no redis connections",
            ))),
        }
    }

    /// ## 日本語
    ///
    /// 既存の非同期 Redis 接続マネージャから新しいマネージャを作成します。
    ///
    /// `prefix` は常に `:` で終わるように正規化されます。
    ///
    /// ## English
    ///
    /// Creates a new manager from an existing async Redis connection manager.
    ///
    /// The `prefix` is normalized to always end with `:`.
    pub fn new(prefix: impl Into<String>, connection: redis::aio::ConnectionManager) -> Self {
        // 日本語: prefix は常に ':' で終わるように正規化する（key を単純連結できるようにする）
        // English: Normalize prefix to always end with ':' (so key concatenation is trivial)
        let mut prefix = prefix.into();
        if !prefix.ends_with(':') {
            prefix.push(':');
        }

        Self {
            prefix,
            connections: Arc::new(vec![Mutex::new(connection)]),
            next_index: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// roles を紐づけた token を発行し、TTL 付きで Redis に保存します（RBAC 有効時）。
    ///
    /// token は UUID v4 文字列として生成されます。value は JSON エンコードされた
    /// `RTokenInfo` として保存され、`user_id`、`roles`、`expire_at` を含みます。
    ///
    /// ## English
    ///
    /// Issues a new token with associated roles and stores it in Redis with TTL.
    ///
    /// The token is generated as a UUID v4 string. The value is stored as a JSON-encoded
    /// `RTokenInfo` containing `user_id`, `roles`, and `expire_at`.
    pub async fn login_with_roles(
        &self,
        user_id: &str,
        ttl_seconds: u64,
        roles: impl Into<Vec<String>>,
    ) -> Result<String, redis::RedisError> {
        // 日本語: token は UUID v4 文字列で生成する
        // English: Tokens are generated as UUID v4 strings
        let token = uuid::Uuid::new_v4().to_string();
        let key = self.key(&token);

        // 日本語: 同一接続を直列化するためにロックする
        // English: Lock to serialize access to the shared connection
        let mut connection = self.lock_connection().await?;

        // 日本語: RBAC 情報は JSON として保存し、expire_at も併せて保持する
        // English: Store RBAC info as JSON and keep expire_at together with user_id/roles
        let expire_at = add_ttl_ms(now_ms_u64(), ttl_seconds);
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

        // 日本語: TTL 付きで保存する（期限切れの削除は Redis TTL に任せる）
        // English: Save with TTL (expiration is handled by Redis TTL)
        let _: () = connection.set_ex(key, value, ttl_seconds).await?;
        Ok(token)
    }

    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// token に紐づく roles を返します（RBAC 有効時）。
    ///
    /// token が存在しない、または期限切れの場合は `Ok(None)` を返します。
    ///
    /// ## English
    ///
    /// Returns the roles associated with a token.
    ///
    /// Returns `Ok(None)` if the token does not exist or has expired.
    pub async fn get_roles(&self, token: &str) -> Result<Option<Vec<String>>, redis::RedisError> {
        Ok(self
            .validate_with_roles(token)
            .await?
            .map(|(_user_id, roles)| roles))
    }

    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// 既存 token の roles を更新し、現在の TTL を保持します（RBAC 有効時）。
    ///
    /// この操作は冪等です。token が存在しない場合でも成功として扱います。
    ///
    /// ## English
    ///
    /// Updates roles for an existing token while preserving its current TTL.
    ///
    /// This operation is idempotent: if the token does not exist, it is treated as success.
    pub async fn set_roles(
        &self,
        token: &str,
        roles: impl Into<Vec<String>>,
    ) -> Result<(), redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.lock_connection().await?;

        // 日本語: 現在の TTL を取得して、書き戻すときに維持する
        // English: Fetch current TTL so we can preserve it on write-back
        let ttl_seconds: i64 = connection.ttl(&key).await?;
        if ttl_seconds == -2 {
            return Ok(());
        }

        // 日本語: 現在の value を読み出す（並行削除などで None になり得る）
        // English: Read current value (may become None due to concurrent deletion)
        let value: Option<String> = connection.get(&key).await?;
        let Some(value) = value else {
            return Ok(());
        };

        // 日本語: 新フォーマット(JSON の RTokenInfo)なら roles を更新し、旧フォーマット(生 user_id)ならそれを user_id として扱う
        // English: If value is JSON RTokenInfo, update roles; otherwise treat it as legacy plain user_id
        let mut info = serde_json::from_str::<RTokenInfo>(&value).unwrap_or(RTokenInfo {
            user_id: value,
            expire_at: 0,
            roles: Vec::new(),
        });
        info.roles = roles.into();

        // 日本語: JSON へ再シリアライズして書き戻す
        // English: Serialize back to JSON and store it
        let new_value = serde_json::to_string(&info).map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::Client,
                "serialize token info",
                e.to_string(),
            ))
        })?;

        match ttl_seconds {
            ttl if ttl >= 0 => {
                let _: () = connection.set_ex(key, new_value, ttl as u64).await?;
            }
            _ => {
                let _: () = connection.set(key, new_value).await?;
            }
        }

        Ok(())
    }

    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// token を検証し、ユーザー ID と roles を返します（RBAC 有効時）。
    ///
    /// token が存在しない、または期限切れの場合は `Ok(None)` を返します。
    ///
    /// ## English
    ///
    /// Validates a token and returns both user id and roles (RBAC enabled).
    ///
    /// Returns `Ok(None)` when the token does not exist or has expired.
    pub async fn validate_with_roles(
        &self,
        token: &str,
    ) -> Result<Option<(String, Vec<String>)>, redis::RedisError> {
        let key = self.key(token);
        // 日本語: 同一接続を直列化するためにロックする
        // English: Lock to serialize access to the shared connection
        let mut connection = self.lock_connection().await?;

        // 日本語: key が無い（期限切れで消えた等）場合は None
        // English: Return None when key is missing (e.g. expired and removed)
        let value: Option<String> = connection.get(key).await?;
        let Some(value) = value else {
            return Ok(None);
        };

        // 日本語: JSON (RTokenInfo) として読めない場合は旧形式（プレーン user_id）として扱う
        // English: If JSON parsing fails, treat it as legacy plain user_id
        let info = serde_json::from_str::<RTokenInfo>(&value).unwrap_or(RTokenInfo {
            user_id: value,
            expire_at: 0,
            roles: Vec::new(),
        });
        Ok(Some((info.user_id, info.roles)))
    }

    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// token を検証し、ユーザー ID を返します（RBAC 有効時）。
    ///
    /// token が存在しない、または期限切れの場合は `Ok(None)` を返します。
    ///
    /// ## English
    ///
    /// Validates a token and returns the associated user id (RBAC enabled).
    ///
    /// Returns `Ok(None)` when the token does not exist or has expired.
    pub async fn validate(&self, token: &str) -> Result<Option<String>, redis::RedisError> {
        Ok(self
            .validate_with_roles(token)
            .await?
            .map(|(user_id, _roles)| user_id))
    }

    /// ## 日本語
    ///
    /// Redis/Valkey に接続してマネージャを作成します。
    ///
    /// 内部で複数の接続を確保し、簡易的なラウンドロビンで利用します。
    ///
    /// ## English
    ///
    /// Connects to Redis/Valkey and creates a manager.
    ///
    /// The manager allocates a small connection pool and uses round-robin selection.
    pub async fn connect(
        redis_url: &str,
        prefix: impl Into<String>,
    ) -> Result<Self, redis::RedisError> {
        // 日本語: redis_url の例：
        // - redis://127.0.0.1/
        // - redis://:password@127.0.0.1/0
        // English: Examples for redis_url:
        // - redis://127.0.0.1/
        // - redis://:password@127.0.0.1/0
        let client = redis::Client::open(redis_url)?;

        // 日本語: ConnectionManager は切断時に再接続を試みる（挙動は redis crate に依存）。
        // English: ConnectionManager attempts reconnection on disconnect (behavior depends on redis crate).
        let mut connections = Vec::with_capacity(4);
        for _ in 0..4 {
            connections.push(Mutex::new(client.get_connection_manager().await?));
        }
        Ok(Self {
            prefix: {
                let mut prefix = prefix.into();
                if !prefix.ends_with(':') {
                    prefix.push(':');
                }
                prefix
            },
            connections: Arc::new(connections),
            next_index: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// ## 日本語
    ///
    /// token key の残り TTL（秒）を返します。
    ///
    /// 本メソッドは Redis の TTL の意味をそのまま返します：
    /// - key が存在しない：`Ok(None)`
    /// - key は存在するが期限がない：`Ok(Some(-1))`
    /// - 残り TTL（秒）：`Ok(Some(n))`（n >= 0）
    ///
    /// ## English
    ///
    /// Returns the remaining TTL in seconds for a token key.
    ///
    /// This method follows Redis TTL semantics:
    /// - `Ok(None)` when the key does not exist
    /// - `Ok(Some(-1))` when the key exists but has no expiration
    /// - `Ok(Some(n))` (n >= 0) for the remaining TTL in seconds
    pub async fn ttl_seconds(&self, token: &str) -> Result<Option<i64>, redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.lock_connection().await?;
        let ttl: i64 = connection.ttl(key).await?;
        if ttl == -2 {
            return Ok(None);
        }
        Ok(Some(ttl))
    }

    /// ## 日本語
    ///
    /// token key の期限を「現在から `ttl_seconds`」に更新します。
    ///
    /// 返り値：
    /// - key が存在し、更新に成功：`Ok(true)`
    /// - key が存在しない：`Ok(false)`
    ///
    /// ## English
    ///
    /// Updates the token key expiration to `ttl_seconds` from now.
    ///
    /// Returns:
    /// - `Ok(true)` if the key exists and the expiration was updated
    /// - `Ok(false)` if the key does not exist
    pub async fn renew(&self, token: &str, ttl_seconds: u64) -> Result<bool, redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.lock_connection().await?;
        // 日本語: redis crate の API が i64 を要求するため、変換できない場合は上限に丸める
        // English: redis crate API expects i64; saturate to i64::MAX if conversion fails
        let seconds = i64::try_from(ttl_seconds).unwrap_or(i64::MAX);
        let updated: bool = connection.expire(key, seconds).await?;
        Ok(updated)
    }

    /// ## 日本語
    ///
    /// 新しい token を発行し、古い token key を削除します。
    ///
    /// 新 token は `ttl_seconds` で保存されます。古い token が存在しない場合は `Ok(None)` を
    /// 返します。
    ///
    /// RBAC 有効時に value が JSON エンコードされた `RTokenInfo` であれば `expire_at` を
    /// 新しい TTL に合わせて更新します。旧形式/プレーンな value はそのままコピーします。
    ///
    /// ## English
    ///
    /// Issues a new token and deletes the old token key.
    ///
    /// The new token will be stored with `ttl_seconds`. If the old token does not exist,
    /// returns `Ok(None)`.
    ///
    /// When RBAC is enabled and the stored value is a JSON-encoded `RTokenInfo`, the
    /// `expire_at` field is updated to match the new TTL. For legacy/plain values, the
    /// raw value is copied as-is.
    pub async fn rotate(
        &self,
        token: &str,
        ttl_seconds: u64,
    ) -> Result<Option<String>, redis::RedisError> {
        // 日本語: 旧 token の key を組み立てて、value を読み出す（無ければ None）。
        //        ここで None になるのは「すでに期限切れで消えた」か「最初から存在しない」ケース。
        // English: Build old key and fetch its value (None if missing).
        //          None means either “already expired and removed” or “never existed”.
        let old_key = self.key(token);
        let mut connection = self.lock_connection().await?;

        let mut raw_value: Option<String> = connection.get(&old_key).await?;
        if raw_value.is_none() {
            return Ok(None);
        }

        let new_token = uuid::Uuid::new_v4().to_string();
        let new_key = self.key(&new_token);

        let script = Script::new(
            r#"
local old_key = KEYS[1]
local new_key = KEYS[2]
local ttl = tonumber(ARGV[1])
local expected = ARGV[2]
local new_value = ARGV[3]

local cur = redis.call('GET', old_key)
if (not cur) or (cur ~= expected) then
  return 0
end

redis.call('SETEX', new_key, ttl, new_value)
redis.call('DEL', old_key)
return 1
"#,
        );
        for _ in 0..2 {
            let Some(current_value) = raw_value.as_ref() else {
                return Ok(None);
            };

            #[cfg(feature = "rbac")]
            let new_value = {
                let expire_at = add_ttl_ms(now_ms_u64(), ttl_seconds);
                match serde_json::from_str::<RTokenInfo>(current_value) {
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
                    Err(_) => current_value.clone(),
                }
            };

            #[cfg(not(feature = "rbac"))]
            let new_value = current_value.clone();

            let ok: i32 = script
                .key(&old_key)
                .key(&new_key)
                .arg(ttl_seconds)
                .arg(current_value)
                .arg(&new_value)
                .invoke_async(&mut *connection)
                .await?;
            if ok == 1 {
                return Ok(Some(new_token));
            }

            raw_value = connection.get(&old_key).await?;
        }

        Ok(None)
    }

    /// ## 日本語
    ///
    /// token から Redis key を組み立てます（prefix 付き）。
    ///
    /// ## English
    ///
    /// Builds the Redis key for a token.
    fn key(&self, token: &str) -> String {
        // 日本語: prefix は常に ':' で終わるよう正規化されているため、そのまま連結する。
        // English: The prefix is normalized to always end with ':', so we can concatenate directly.
        format!("{}{}", self.prefix, token)
    }

    /// ## 日本語
    ///
    /// `user_id` に対して新しい token を発行し、TTL 付きで Redis に保存します。
    ///
    /// `ttl_seconds` は秒として扱います。期限切れ token は Redis により自動的に削除されます。
    ///
    /// ## English
    ///
    /// Issues a new token for `user_id` and stores it in Redis with TTL.
    ///
    /// `ttl_seconds` is interpreted as seconds. Expired tokens are removed automatically
    /// by Redis.
    pub async fn login(
        &self,
        user_id: &str,
        ttl_seconds: u64,
    ) -> Result<String, redis::RedisError> {
        // 日本語: token の生成戦略はインメモリ版と同じ（UUID v4 文字列）。
        // English: Token generation matches the in-memory manager (UUID v4 string).
        let token = uuid::Uuid::new_v4().to_string();
        let key = self.key(&token);

        // 日本語: 接続のロックを取得する（await するため、他タスクの解放待ちになることがある）。
        // English: Acquire the connection lock (awaits if another task is holding it).
        let mut connection = self.lock_connection().await?;

        // 日本語: SETEX 相当（key に value を保存し TTL(秒) を設定する）。
        // English: SETEX semantics: set key/value and configure TTL (seconds).
        let _: () = connection.set_ex(key, user_id, ttl_seconds).await?;
        Ok(token)
    }

    /// ## 日本語
    ///
    /// Redis から key を削除して token を失効させます。
    ///
    /// この操作は冪等です。存在しない token を削除しても成功として扱います。
    ///
    /// ## English
    ///
    /// Revokes a token by deleting it from Redis.
    ///
    /// This operation is idempotent: deleting a non-existing token is treated as success.
    pub async fn logout(&self, token: &str) -> Result<(), redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.lock_connection().await?;

        // 日本語: DEL は削除件数を返すが、logout は冪等なので件数は無視する。
        // English: DEL returns how many keys were removed; logout is idempotent so we ignore it.
        let _: i64 = connection.del(key).await?;
        Ok(())
    }

    /// ## 日本語
    ///
    /// token を検証し、有効であれば紐づく `user_id` を返します。
    ///
    /// token が存在しない、または期限切れの場合は `Ok(None)` を返します。
    ///
    /// ## English
    ///
    /// Validates a token and returns the associated `user_id` if present.
    ///
    /// Returns `Ok(None)` when the token does not exist or has expired.
    #[cfg(not(feature = "rbac"))]
    pub async fn validate(&self, token: &str) -> Result<Option<String>, redis::RedisError> {
        let key = self.key(token);
        let mut connection = self.lock_connection().await?;

        // 日本語: GET の結果：
        // - Some(user_id) => token は有効（user_id が見つかった）
        // - None => token が存在しない/期限切れ（TTL により Redis が削除済み）
        // English: GET result:
        // - Some(user_id) => token is valid (user_id found)
        // - None => missing/expired (removed by Redis TTL)
        let user_id: Option<String> = connection.get(key).await?;
        Ok(user_id)
    }
}
