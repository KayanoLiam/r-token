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
            let Some(info) = store.get(token) else { return Ok(None) };

            if info.expire_at < Utc::now().timestamp_millis() as u64 {
                store.remove(token);
                return Ok(None);
            }

            Ok(Some(info.user_id.clone()))
        }
    }

    #[cfg(feature = "rbac")]
    pub fn validate_with_roles(
        &self,
        token: &str,
    ) -> Result<Option<(String, Vec<String>)>, RTokenError> {
        let mut store = self.store.lock().map_err(|_| RTokenError::MutexPoisoned)?;
        let Some(info) = store.get(token) else { return Ok(None) };

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
