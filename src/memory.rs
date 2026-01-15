use crate::RTokenError;
use crate::models::RTokenInfo;
use chrono::Utc;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// ## 日本語
///
/// 認証 token の発行・保存・失効を行うマネージャです。
///
/// actix-web のアプリケーション state（例：`web::Data<RTokenManager>`）に保持する想定で、
/// 内部では `Arc<Mutex<...>>` を使って状態を共有します。そのため `Clone` は同じストアへの
/// ハンドルを増やすだけです。
///
/// token は UUID v4 文字列として生成され、次と紐づきます：
/// - ユーザー ID（`String`）
/// - 有効期限（Unix epoch ミリ秒）
///
/// ## English
///
/// Issues, stores, and revokes authentication tokens.
///
/// This type is designed to be stored in actix-web application state
/// (e.g. `web::Data<RTokenManager>`). Internally it uses an `Arc<Mutex<...>>`,
/// so `Clone` creates another handle to the same shared store.
///
/// Tokens are generated as UUID v4 strings. Each token is associated with:
/// - a user id (`String`)
/// - an expiration timestamp (Unix epoch milliseconds)
#[derive(Clone, Default)]
pub struct RTokenManager {
    /// ## 日本語
    ///
    /// インメモリの token ストア。
    ///
    /// ## English
    ///
    /// In-memory token store.
    // store: Arc<Mutex<HashMap<String, String>>>,
    store: Arc<Mutex<HashMap<String, RTokenInfo>>>,
}

impl RTokenManager {
    /// ## 日本語
    ///
    /// 空のマネージャを作成します。
    ///
    /// ## English
    ///
    /// Creates an empty manager.
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// ## 日本語
    ///
    /// 指定ユーザー ID の新しい token を発行します。
    ///
    /// `expire_time` は TTL（秒）として扱います。保存された有効期限が現在時刻より過去であれば、
    /// token は無効とみなされます。
    ///
    /// 内部 mutex が poisoned の場合は [`RTokenError::MutexPoisoned`] を返します。
    ///
    /// ## English
    ///
    /// Issues a new token for the given user id.
    ///
    /// `expire_time` is treated as TTL in seconds. The token will be considered invalid
    /// once the stored expiration timestamp is earlier than the current time.
    ///
    /// Returns [`RTokenError::MutexPoisoned`] if the internal mutex is poisoned.
    pub fn login(&self, id: &str, expire_time: u64) -> Result<String, RTokenError> {
        let token = uuid::Uuid::new_v4().to_string();
        // Acquire the write lock and insert the token-user mapping into the store
        // 获取写锁并将 Token-用户映射关系插入到存储中
        // #[allow(clippy::unwrap_used)]
        // self.store.lock().unwrap().insert(token.clone(), id.to_string());
        let now = Utc::now();
        let ttl = chrono::Duration::seconds(expire_time as i64);
        let deadline = now + ttl;
        let expire_time = deadline.timestamp_millis() as u64;
        let info = RTokenInfo {
            user_id: id.to_string(),
            expire_at: expire_time,
            roles: Vec::new(),
        };
        self.store
            .lock()
            .map_err(|_| RTokenError::MutexPoisoned)?
            .insert(token.clone(), info);
        Ok(token)
    }

    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// 指定ユーザー ID と役割（roles）を紐づけた新しい token を発行します（RBAC 有効時）。
    ///
    /// `expire_time` は TTL（秒）として扱います。
    ///
    /// ## English
    ///
    /// Issues a new token for the given user id and roles (RBAC enabled).
    ///
    /// `expire_time` is treated as TTL in seconds.
    pub fn login_with_roles(
        &self,
        id: &str,
        expire_time: u64,
        role: impl Into<Vec<String>>,
    ) -> Result<String, RTokenError> {
        let token = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let ttl = chrono::Duration::seconds(expire_time as i64);
        let deadline = now + ttl;
        let expire_time = deadline.timestamp_millis() as u64;
        let info = RTokenInfo {
            user_id: id.to_string(),
            expire_at: expire_time,
            roles: role.into(),
        };
        self.store
            .lock()
            .map_err(|_| RTokenError::MutexPoisoned)?
            .insert(token.clone(), info);
        Ok(token)
    }

    // pub fn set_role(&self, token: &str, role: impl Into<Vec<String>>) -> Result<(), RTokenError> {
    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// 既存 token の roles を更新します（RBAC 有効時）。
    ///
    /// token が存在しない場合でも成功として扱います（冪等）。
    ///
    /// ## English
    ///
    /// Updates roles for an existing token (RBAC enabled).
    ///
    /// This operation is idempotent: if the token does not exist, it is treated as success.
    pub fn set_roles(&self, token: &str, roles: impl Into<Vec<String>>) -> Result<(), RTokenError> {
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        if let Some(info) = store.get_mut(token) {
            info.roles = roles.into();
        }
        Ok(())
    }

    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// token に紐づく roles を返します（RBAC 有効時）。
    ///
    /// token が存在しない場合は `Ok(None)` を返します。
    ///
    /// ## English
    ///
    /// Returns roles associated with a token (RBAC enabled).
    ///
    /// Returns `Ok(None)` if the token does not exist.
    pub fn get_roles(&self, token: &str) -> Result<Option<Vec<String>>, RTokenError> {
        let store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        Ok(store.get(token).map(|info| info.roles.clone()))
    }

    /// ## 日本語
    ///
    /// token をインメモリストアから削除して失効させます。
    ///
    /// この操作は冪等です。存在しない token を削除しても成功として扱います。
    /// 内部 mutex が poisoned の場合は [`RTokenError::MutexPoisoned`] を返します。
    ///
    /// ## English
    ///
    /// Revokes a token by removing it from the in-memory store.
    ///
    /// This operation is idempotent: removing a non-existing token is treated as success.
    /// Returns [`RTokenError::MutexPoisoned`] if the internal mutex is poisoned.
    pub fn logout(&self, token: &str) -> Result<(), RTokenError> {
        // self.store.lock().unwrap().remove(token);
        self.store
            .lock()
            .map_err(|_| RTokenError::MutexPoisoned)?
            .remove(token);
        Ok(())
    }

    /// ## 日本語
    ///
    /// token に保存されている有効期限（Unix epoch ミリ秒）を返します。
    ///
    /// token が存在しない場合は `Ok(None)` を返します。本メソッドは token の期限切れ判定は
    /// 行いません。
    ///
    /// ## English
    ///
    /// Returns the stored expiration timestamp for a token (milliseconds since Unix epoch).
    ///
    /// Returns `Ok(None)` if the token does not exist. This method does not validate
    /// whether the token has already expired.
    pub fn expires_at(&self, token: &str) -> Result<Option<u64>, RTokenError> {
        let store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        Ok(store.get(token).map(|info| info.expire_at))
    }

    /// ## 日本語
    ///
    /// token の残り TTL（秒）を返します。
    ///
    /// 返り値：
    /// - token が存在しない：`Ok(None)`
    /// - token がすでに期限切れ：`Ok(Some(0))`（本メソッドでは削除しません）
    ///
    /// ## English
    ///
    /// Returns the remaining TTL in seconds for a token.
    ///
    /// Returns:
    /// - `Ok(None)` when the token does not exist
    /// - `Ok(Some(0))` when the token is already expired (it is not removed here)
    pub fn ttl_seconds(&self, token: &str) -> Result<Option<i64>, RTokenError> {
        let now_ms = Utc::now().timestamp_millis() as u64;
        let store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        let Some(expire_at) = store.get(token).map(|info| info.expire_at) else {
            return Ok(None);
        };

        if expire_at <= now_ms {
            return Ok(Some(0));
        }

        let remaining_ms = expire_at - now_ms;
        let remaining_seconds = remaining_ms.div_ceil(1000) as i64;
        Ok(Some(remaining_seconds))
    }

    /// ## 日本語
    ///
    /// token の有効期限を `now + ttl_seconds` に延長します。
    ///
    /// 返り値：
    /// - token が存在し、期限切れでない：`Ok(true)`
    /// - token が存在しない、または期限切れ：`Ok(false)`（期限切れの場合は削除します）
    ///
    /// ## English
    ///
    /// Extends a token's lifetime to `now + ttl_seconds`.
    ///
    /// Returns:
    /// - `Ok(true)` if the token exists and is not expired
    /// - `Ok(false)` if the token does not exist or is expired (expired tokens are removed)
    pub fn renew(&self, token: &str, ttl_seconds: u64) -> Result<bool, RTokenError> {
        let now = Utc::now();
        let ttl = chrono::Duration::seconds(ttl_seconds as i64);
        let expire_at = (now + ttl).timestamp_millis() as u64;

        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        let Some(info) = store.get_mut(token) else {
            return Ok(false);
        };

        if info.expire_at < Utc::now().timestamp_millis() as u64 {
            store.remove(token);
            return Ok(false);
        }

        info.expire_at = expire_at;
        Ok(true)
    }

    /// ## 日本語
    ///
    /// 同じユーザー（および roles）に対して新しい token を発行し、古い token を失効させます。
    ///
    /// 新しい token の TTL は「現在から `ttl_seconds`」になります。
    ///
    /// 古い token が存在しない、または期限切れの場合は `Ok(None)` を返します（期限切れの場合は
    /// 削除します）。
    ///
    /// ## English
    ///
    /// Issues a new token for the same user (and roles) and revokes the old token.
    ///
    /// The new token will have a lifetime of `ttl_seconds` from now.
    ///
    /// Returns `Ok(None)` if the old token does not exist or is expired (expired tokens
    /// are removed).
    pub fn rotate(&self, token: &str, ttl_seconds: u64) -> Result<Option<String>, RTokenError> {
        let now = Utc::now();
        let ttl = chrono::Duration::seconds(ttl_seconds as i64);
        let expire_at = (now + ttl).timestamp_millis() as u64;

        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        let Some(info) = store.get(token).cloned() else {
            return Ok(None);
        };

        if info.expire_at < Utc::now().timestamp_millis() as u64 {
            store.remove(token);
            return Ok(None);
        }

        let new_token = uuid::Uuid::new_v4().to_string();
        let new_info = RTokenInfo {
            user_id: info.user_id,
            expire_at,
            roles: info.roles,
        };

        store.remove(token);
        store.insert(new_token.clone(), new_info);
        Ok(Some(new_token))
    }

    /// ## 日本語
    ///
    /// インメモリストアから期限切れの token を削除し、削除した件数を返します。
    ///
    /// ## English
    ///
    /// Removes expired tokens from the in-memory store and returns how many were removed.
    pub fn prune_expired(&self) -> Result<usize, RTokenError> {
        let now = Utc::now().timestamp_millis() as u64;
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;

        let original_len = store.len();
        store.retain(|_token, info| info.expire_at >= now);
        Ok(original_len - store.len())
    }

    /// ## 日本語
    ///
    /// token を検証し、有効であれば紐づくユーザー ID を返します。
    ///
    /// 振る舞い：
    /// - token が存在し、期限切れでない：`Ok(Some(user_id))`
    /// - token が存在しない、または期限切れ：`Ok(None)`
    /// - 期限切れ token は検証時にストアから削除されます
    ///
    /// ## English
    ///
    /// Validates a token and returns the associated user id if present.
    ///
    /// Behavior:
    /// - Returns `Ok(Some(user_id))` when the token exists and is not expired.
    /// - Returns `Ok(None)` when the token does not exist or is expired.
    /// - Expired tokens are removed from the in-memory store during validation.
    pub fn validate(&self, token: &str) -> Result<Option<String>, RTokenError> {
        #[cfg(feature = "rbac")]
        {
            Ok(self
                .validate_with_roles(token)?
                .map(|(user_id, _roles)| user_id))
        }

        #[cfg(not(feature = "rbac"))]
        {
            let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
            let Some(info) = store.get(token) else {
                return Ok(None);
            };

            if info.expire_at < Utc::now().timestamp_millis() as u64 {
                store.remove(token);
                return Ok(None);
            }

            Ok(Some(info.user_id.clone()))
        }
    }

    #[cfg(feature = "rbac")]
    /// ## 日本語
    ///
    /// token を検証し、ユーザー ID と roles を返します（RBAC 有効時）。
    ///
    /// 期限切れの扱いは [`RTokenManager::validate`] と同じです。
    ///
    /// ## English
    ///
    /// Validates a token and returns both user id and roles (RBAC enabled).
    ///
    /// This has the same expiration behavior as [`RTokenManager::validate`].
    pub fn validate_with_roles(
        &self,
        token: &str,
    ) -> Result<Option<(String, Vec<String>)>, RTokenError> {
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        let Some(info) = store.get(token) else {
            return Ok(None);
        };

        if info.expire_at < Utc::now().timestamp_millis() as u64 {
            store.remove(token);
            return Ok(None);
        }

        Ok(Some((info.user_id.clone(), info.roles.clone())))
    }
}

/// ## 日本語
///
/// actix-web から抽出される認証済みユーザーコンテキストです。
///
/// 抽出が成功した場合：
/// - `id` は [`RTokenManager::login`] に渡したユーザー ID
/// - `token` はリクエストに含まれていた token の生文字列
///
/// token は `Authorization` header から読み取ります。次の形式に対応します：
/// - `Authorization: <token>`
/// - `Authorization: Bearer <token>`
///
/// ## English
///
/// An authenticated request context extracted from actix-web.
///
/// If extraction succeeds, `id` is the user id previously passed to
/// [`RTokenManager::login`], and `token` is the original token from the request.
///
/// The token is read from `Authorization` header. Both of the following formats
/// are accepted:
/// - `Authorization: <token>`
/// - `Authorization: Bearer <token>`
#[cfg(feature = "actix")]
#[derive(Debug)]
pub struct RUser {
    /// ## 日本語
    ///
    /// token に紐づくユーザー ID。
    ///
    /// ## English
    ///
    /// The user id associated with the token.
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

#[cfg(feature = "rbac")]
impl RUser {
    /// ## 日本語
    ///
    /// 指定した role を持つかどうかを返します。
    ///
    /// ## English
    ///
    /// Returns whether the user has the given role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// ## 日本語
///
/// actix-web のリクエストから [`RUser`] を抽出します。
///
/// 失敗時：
/// - 500：`app_data` にマネージャが無い、または mutex が poisoned
/// - 401：token が無い／無効／期限切れ
///
/// ## English
///
/// Extracts [`RUser`] from an actix-web request.
///
/// Failure modes:
/// - 500: manager is missing from `app_data`, or mutex is poisoned
/// - 401: token is missing, invalid, or expired
#[cfg(feature = "actix")]
impl actix_web::FromRequest for RUser {
    type Error = actix_web::Error;
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        use actix_web::web;

        // 獲取管理器
        let manager = match req.app_data::<web::Data<RTokenManager>>() {
            Some(m) => m,
            None => {
                return std::future::ready(Err(actix_web::error::ErrorInternalServerError(
                    "Token manager not found",
                )));
            }
        };
        let token = match crate::extract_token_from_request(req) {
            Some(token) => token,
            None => {
                return std::future::ready(Err(actix_web::error::ErrorUnauthorized(
                    "Unauthorized",
                )));
            }
        };

        #[cfg(feature = "rbac")]
        {
            let user_info = match manager.validate_with_roles(&token) {
                Ok(user_info) => user_info,
                Err(_) => {
                    return std::future::ready(Err(actix_web::error::ErrorInternalServerError(
                        "Mutex poisoned",
                    )));
                }
            };

            if let Some((user_id, roles)) = user_info {
                return std::future::ready(Ok(RUser {
                    id: user_id,
                    token,
                    roles,
                }));
            }

            std::future::ready(Err(actix_web::error::ErrorUnauthorized("Invalid token")))
        }

        #[cfg(not(feature = "rbac"))]
        {
            let user_id = match manager.validate(&token) {
                Ok(user_id) => user_id,
                Err(_) => {
                    return std::future::ready(Err(actix_web::error::ErrorInternalServerError(
                        "Mutex poisoned",
                    )));
                }
            };

            if let Some(user_id) = user_id {
                return std::future::ready(Ok(RUser { id: user_id, token }));
            }

            std::future::ready(Err(actix_web::error::ErrorUnauthorized("Invalid token")))
        }
    }
}
