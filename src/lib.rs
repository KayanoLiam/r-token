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

mod memory;
mod models;
#[cfg(feature = "redis")]
mod redis;

/// Default cookie name used for token transport.
///
/// This name is used by:
/// - the example servers when setting cookies on `/login`
/// - the actix extractors when reading the token from cookies
///
/// ## 繁體中文
///
/// 預設的 token Cookie 名稱。
///
/// 這個名稱會被用在：
/// - 範例伺服器的 `/login` 回應中設定 Cookie
/// - actix Extractor 從 Cookie 讀取 token
pub const TOKEN_COOKIE_NAME: &str = "r_token";

#[cfg(feature = "actix")]
#[derive(Clone, Debug)]
/// Priority for selecting which token source to use when multiple are present.
///
/// ## 繁體中文
///
/// 當同時存在多種 token 來源時，選擇使用哪一種的優先順序。
pub enum TokenSourcePriority {
    /// Prefer headers (e.g. `Authorization`) over cookies.
    ///
    /// ## 繁體中文
    ///
    /// Header（例如 `Authorization`）優先於 Cookie。
    HeaderFirst,
    /// Prefer cookies over headers.
    ///
    /// ## 繁體中文
    ///
    /// Cookie 優先於 Header。
    CookieFirst,
}

#[cfg(feature = "actix")]
#[derive(Clone, Debug)]
/// Token source configuration for actix extractors.
///
/// You can register this as `app_data(web::Data<TokenSourceConfig>)` to customize:
/// - which header names are scanned for a token
/// - which cookie names are scanned for a token
/// - the priority order between header/cookie
///
/// ## 繁體中文
///
/// actix Extractor 的 token 來源設定。
///
/// 你可以把它以 `app_data(web::Data<TokenSourceConfig>)` 的形式注入到 App，
/// 用來自訂：
/// - 會掃描哪些 header 名稱來取得 token
/// - 會掃描哪些 cookie 名稱來取得 token
/// - header/cookie 之間的優先順序
pub struct TokenSourceConfig {
    /// Priority of token sources.
    ///
    /// ## 繁體中文
    ///
    /// token 來源優先順序。
    pub priority: TokenSourcePriority,
    /// Header names that will be checked in order.
    ///
    /// ## 繁體中文
    ///
    /// 會依序檢查的 header 名稱列表。
    pub header_names: Vec<String>,
    /// Cookie names that will be checked in order.
    ///
    /// ## 繁體中文
    ///
    /// 會依序檢查的 cookie 名稱列表。
    pub cookie_names: Vec<String>,
}

#[cfg(feature = "actix")]
impl Default for TokenSourceConfig {
    fn default() -> Self {
        Self {
            priority: TokenSourcePriority::HeaderFirst,
            header_names: vec!["Authorization".to_string()],
            cookie_names: vec![TOKEN_COOKIE_NAME.to_string(), "token".to_string()],
        }
    }
}

#[cfg(feature = "actix")]
/// Extracts a token from an actix-web request.
///
/// The function reads configuration from `app_data(web::Data<TokenSourceConfig>)` if present;
/// otherwise it falls back to `TokenSourceConfig::default()`.
///
/// ## 繁體中文
///
/// 從 actix-web 請求中抽取 token。
///
/// 若 App 有注入 `app_data(web::Data<TokenSourceConfig>)` 則會使用該設定；
/// 否則使用 `TokenSourceConfig::default()`。
pub fn extract_token_from_request(req: &actix_web::HttpRequest) -> Option<String> {
    use actix_web::web;

    if let Some(cfg) = req.app_data::<web::Data<TokenSourceConfig>>() {
        extract_token_from_request_with_config(req, cfg.as_ref())
    } else {
        let default_cfg = TokenSourceConfig::default();
        extract_token_from_request_with_config(req, &default_cfg)
    }
}

#[cfg(feature = "actix")]
/// Extracts a token from an actix-web request using an explicit config.
///
/// Token parsing behavior:
/// - Header values support both `Bearer <token>` and raw `<token>` formats.
/// - Cookie values use the raw cookie value as the token.
///
/// ## 繁體中文
///
/// 使用指定設定，從 actix-web 請求中抽取 token。
///
/// 解析行為：
/// - Header 支援 `Bearer <token>` 與純 `<token>` 兩種格式。
/// - Cookie 直接使用 cookie value 作為 token。
pub fn extract_token_from_request_with_config(
    req: &actix_web::HttpRequest,
    cfg: &TokenSourceConfig,
) -> Option<String> {
    let from_headers = || {
        cfg.header_names.iter().find_map(|name| {
            req.headers()
                .get(name)
                .and_then(|h| h.to_str().ok())
                .map(|token_str| {
                    token_str
                        .strip_prefix("Bearer ")
                        .unwrap_or(token_str)
                        .to_string()
                })
        })
    };

    let from_cookies = || {
        cfg.cookie_names
            .iter()
            .find_map(|name| req.cookie(name).map(|cookie| cookie.value().to_string()))
    };

    match cfg.priority {
        TokenSourcePriority::HeaderFirst => from_headers().or_else(from_cookies),
        TokenSourcePriority::CookieFirst => from_cookies().or_else(from_headers),
    }
}

pub use crate::memory::RTokenManager;
#[cfg(feature = "actix")]
pub use crate::memory::RUser;
pub use crate::models::RTokenError;
#[cfg(all(feature = "redis", feature = "actix"))]
pub use crate::redis::RRedisUser;
#[cfg(feature = "redis")]
pub use crate::redis::RTokenRedisManager;
