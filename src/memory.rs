use crate::RTokenError;
use crate::models::RTokenInfo;
use chrono::Utc;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// Issues, stores, and revokes authentication tokens.
///
/// This type is designed to be stored in actix-web application state
/// (e.g. `web::Data<RTokenManager>`). Internally it uses an `Arc<Mutex<...>>`,
/// so `Clone` creates another handle to the same shared store.
///
/// Tokens are generated as UUID v4 strings. Each token is associated with:
/// - a user id (`String`)
/// - an expiration timestamp (Unix epoch milliseconds)
///
/// ## 繁體中文
///
/// 負責簽發、儲存與註銷 token 的管理器。
///
/// 一般會放在 actix-web 的 application state 中（例如 `web::Data<RTokenManager>`）。
/// 內部以 `Arc<Mutex<...>>` 共享狀態，因此 `Clone` 只是在同一份映射表上增加一個引用。
///
/// token 以 UUID v4 字串產生，並會綁定：
/// - 使用者 id（`String`）
/// - 到期時間（Unix epoch 毫秒）
#[derive(Clone, Default)]
pub struct RTokenManager {
    /// In-memory token store.
    ///
    /// ## 繁體中文
    ///
    /// 記憶體中的 token 儲存表。
    // store: Arc<Mutex<HashMap<String, String>>>,
    store: Arc<Mutex<HashMap<String, RTokenInfo>>>,
}

impl RTokenManager {
    /// Creates an empty manager.
    ///
    /// ## 繁體中文
    ///
    /// 建立一個空的管理器。
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Issues a new token for the given user id.
    ///
    /// `expire_time` is treated as TTL in seconds. The token will be considered invalid
    /// once the stored expiration timestamp is earlier than the current time.
    ///
    /// Returns [`RTokenError::MutexPoisoned`] if the internal mutex is poisoned.
    ///
    /// ## 繁體中文
    ///
    /// 為指定使用者 id 簽發新 token。
    ///
    /// `expire_time` 會被視為 TTL（秒）。當儲存的到期時間早於目前時間時，token 會被視為無效。
    ///
    /// 若內部 mutex 發生 poisoned，會回傳 [`RTokenError::MutexPoisoned`]。
    // pub fn login(&self, id: &str, expire_time: u64,role:impl Into<Vec<String>>) -> Result<String, RTokenError> {
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
    pub fn set_roles(&self, token: &str, roles: impl Into<Vec<String>>) -> Result<(), RTokenError> {
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        if let Some(info) = store.get_mut(token) {
            info.roles = roles.into();
        }
        Ok(())
    }

    #[cfg(feature = "rbac")]
    pub fn get_roles(&self, token: &str) -> Result<Option<Vec<String>>, RTokenError> {
        let store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        Ok(store.get(token).map(|info| info.roles.clone()))
    }

    /// Revokes a token by removing it from the in-memory store.
    ///
    /// This operation is idempotent: removing a non-existing token is treated as success.
    /// Returns [`RTokenError::MutexPoisoned`] if the internal mutex is poisoned.
    ///
    /// ## 繁體中文
    ///
    /// 從記憶體儲存表中移除 token，以達到註銷效果。
    ///
    /// 此操作具冪等性：移除不存在的 token 也視為成功。
    /// 若內部 mutex 發生 poisoned，會回傳 [`RTokenError::MutexPoisoned`]。
    pub fn logout(&self, token: &str) -> Result<(), RTokenError> {
        // self.store.lock().unwrap().remove(token);
        self.store
            .lock()
            .map_err(|_| RTokenError::MutexPoisoned)?
            .remove(token);
        Ok(())
    }

    /// Returns the stored expiration timestamp for a token (milliseconds since Unix epoch).
    ///
    /// Returns `Ok(None)` if the token does not exist. This method does not validate
    /// whether the token has already expired.
    ///
    /// ## 繁體中文
    ///
    /// 回傳 token 的到期時間戳（Unix epoch 毫秒）。
    ///
    /// 若 token 不存在，回傳 `Ok(None)`。本方法不會檢查 token 是否已過期。
    pub fn expires_at(&self, token: &str) -> Result<Option<u64>, RTokenError> {
        let store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        Ok(store.get(token).map(|info| info.expire_at))
    }

    /// Returns the remaining TTL in seconds for a token.
    ///
    /// Returns:
    /// - `Ok(None)` when the token does not exist
    /// - `Ok(Some(0))` when the token is already expired (it is not removed here)
    ///
    /// ## 繁體中文
    ///
    /// 回傳 token 剩餘 TTL（秒）。
    ///
    /// 回傳：
    /// - token 不存在：`Ok(None)`
    /// - token 已過期：`Ok(Some(0))`（本方法不會在此移除它）
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

    /// Extends a token's lifetime to `now + ttl_seconds`.
    ///
    /// Returns:
    /// - `Ok(true)` if the token exists and is not expired
    /// - `Ok(false)` if the token does not exist or is expired (expired tokens are removed)
    ///
    /// ## 繁體中文
    ///
    /// 將 token 續期為 `now + ttl_seconds`。
    ///
    /// 回傳：
    /// - token 存在且未過期：`Ok(true)`
    /// - token 不存在或已過期：`Ok(false)`（若已過期會順便移除）
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

    /// Issues a new token for the same user (and roles) and revokes the old token.
    ///
    /// The new token will have a lifetime of `ttl_seconds` from now.
    ///
    /// Returns `Ok(None)` if the old token does not exist or is expired (expired tokens
    /// are removed).
    ///
    /// ## 繁體中文
    ///
    /// 為同一位使用者（以及角色）換發新 token，並註銷舊 token。
    ///
    /// 新 token 的 TTL 會以現在起算 `ttl_seconds`。
    ///
    /// 若舊 token 不存在或已過期，回傳 `Ok(None)`（若已過期會順便移除）。
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

    /// Removes expired tokens from the in-memory store and returns how many were removed.
    ///
    /// ## 繁體中文
    ///
    /// 從記憶體儲存表中移除已過期的 token，並回傳移除數量。
    pub fn prune_expired(&self) -> Result<usize, RTokenError> {
        let now = Utc::now().timestamp_millis() as u64;
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;

        let original_len = store.len();
        store.retain(|_token, info| info.expire_at >= now);
        Ok(original_len - store.len())
    }

    /// Validates a token and returns the associated user id if present.
    ///
    /// Behavior:
    /// - Returns `Ok(Some(user_id))` when the token exists and is not expired.
    /// - Returns `Ok(None)` when the token does not exist or is expired.
    /// - Expired tokens are removed from the in-memory store during validation.
    ///
    /// ## 繁體中文
    ///
    /// 驗證 token，若有效則回傳對應的使用者 id。
    ///
    /// 行為：
    /// - token 存在且未過期：回傳 `Ok(Some(user_id))`
    /// - token 不存在或已過期：回傳 `Ok(None)`
    /// - 若 token 已過期，會在驗證時從記憶體儲存表中移除
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
    /// Validates a token and returns both user id and roles (RBAC enabled).
    ///
    /// This has the same expiration behavior as [`RTokenManager::validate`].
    ///
    /// ## 繁體中文
    ///
    /// 驗證 token，並在 RBAC 啟用時同時回傳使用者 id 與角色列表。
    ///
    /// 到期行為與 [`RTokenManager::validate`] 相同。
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

/// An authenticated request context extracted from actix-web.
///
/// If extraction succeeds, `id` is the user id previously passed to
/// [`RTokenManager::login`], and `token` is the original token from the request.
///
/// The token is read from `Authorization` header. Both of the following formats
/// are accepted:
/// - `Authorization: <token>`
/// - `Authorization: Bearer <token>`
///
/// ## 繁體中文
///
/// 由 actix-web 自動抽取的已驗證使用者上下文。
///
/// Extractor 成功時：
/// - `id` 會是先前傳給 [`RTokenManager::login`] 的使用者 id
/// - `token` 會是請求中帶來的 token 原文
///
/// token 會從 `Authorization` header 讀取，支援以下格式：
/// - `Authorization: <token>`
/// - `Authorization: Bearer <token>`
#[cfg(feature = "actix")]
#[derive(Debug)]
pub struct RUser {
    /// The user id associated with the token.
    ///
    /// ## 繁體中文
    ///
    /// 與 token 綁定的使用者 id。
    pub id: String,

    /// The raw token string from the request.
    ///
    /// ## 繁體中文
    ///
    /// 來自請求的 token 字串原文。
    pub token: String,
    #[cfg(feature = "rbac")]
    pub roles: Vec<String>,
}

#[cfg(feature = "rbac")]
impl RUser {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

/// Extracts [`RUser`] from an actix-web request.
///
/// Failure modes:
/// - 500: manager is missing from `app_data`, or mutex is poisoned
/// - 401: token is missing, invalid, or expired
///
/// ## 繁體中文
///
/// 從 actix-web 請求中抽取 [`RUser`]。
///
/// 失敗情況：
/// - 500：`app_data` 中找不到管理器，或 mutex poisoned
/// - 401：token 缺失、無效、或已過期
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
