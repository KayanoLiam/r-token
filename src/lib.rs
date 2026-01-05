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

pub use crate::models::RTokenError;
use crate::models::RTokenInfo;
use actix_web::{FromRequest, HttpRequest, web};
use chrono::Utc;
use std::future::{Ready, ready};
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
        };
        self.store
            .lock()
            .map_err(|_| RTokenError::MutexPoisoned)?
            .insert(token.clone(), info);
        Ok(token)
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
impl FromRequest for RUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut actix_web::dev::Payload) -> Self::Future {
        // 獲取管理器
        let manager = match req.app_data::<web::Data<RTokenManager>>() {
            Some(m) => m,
            None => {
                return ready(Err(actix_web::error::ErrorInternalServerError(
                    "Token manager not found",
                )));
            }
        };
        // 獲取Token（優先看header中的Authorization）
        let token = match req
            .headers()
            .get("Authorization")
            .and_then(|h| h.to_str().ok())
        {
            Some(token_str) => token_str
                .strip_prefix("Bearer ")
                .unwrap_or(token_str)
                .to_string(),
            None => return ready(Err(actix_web::error::ErrorUnauthorized("Unauthorized"))),
        };

        // 驗證token
        let store = match manager.store.lock() {
            Ok(s) => s,
            Err(_) => {
                return ready(Err(actix_web::error::ErrorInternalServerError(
                    "Mutex poisoned",
                )));
            }
        };

        match store.get(&token) {
            Some(id) => {
                // 檢查token是否過期
                if id.expire_at < Utc::now().timestamp_millis() as u64 {
                    return ready(Err(actix_web::error::ErrorUnauthorized("Token expired")));
                }
                ready(Ok(RUser {
                    id: id.user_id.clone(),
                    token: token.clone(),
                }))
                // return ready(Ok(RUser {
                //     // id: id.clone(),
                //     id: id.user_id.clone(),
                //     token: token.clone(),
                // }));
            }
            None => ready(Err(actix_web::error::ErrorUnauthorized("Invalid token"))),
        }
    }
}
