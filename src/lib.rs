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
//! ## 日本語
//!
//! actix-web 向けの軽量なインメモリ token 認証ヘルパーです。
//!
//! このライブラリは主に次の 2 つを提供します：
//! - [`RTokenManager`]: token（UUID v4）の発行/失効と、インメモリストアの管理
//! - [`RUser`]: `Authorization` を自動検証する actix-web extractor
//!
//! ## 認証の流れ
//!
//! 1. ログイン処理で [`RTokenManager::login`] を呼び、ユーザー ID と TTL（秒）を渡します。
//! 2. token をクライアントへ返します（多くはプレーンテキストまたは JSON）。
//! 3. クライアントは `Authorization` header で token を送ります：
//!    - `Authorization: <token>`
//!    - `Authorization: Bearer <token>`
//! 4. handler が [`RUser`] を引数に持つと保護されたエンドポイントになります。抽出が成功すれば認証済みとして扱われ、失敗すれば actix-web がエラーを返します。
//!
//! ## English
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

mod memory;
mod models;
#[cfg(feature = "redis")]
mod redis;

/// ## 日本語
///
/// token 送受信に使うデフォルトの Cookie 名です。
///
/// この名前は次で使用されます：
/// - 例のサーバーが `/login` で Cookie をセットするとき
/// - actix extractor が Cookie から token を読むとき
///
/// ## English
///
/// Default cookie name used for token transport.
///
/// This name is used by:
/// - the example servers when setting cookies on `/login`
/// - the actix extractors when reading the token from cookies
pub const TOKEN_COOKIE_NAME: &str = "r_token";

#[cfg(feature = "actix")]
#[derive(Clone, Debug)]
/// ## 日本語
///
/// 複数の token 供給元がある場合に、どちらを優先するかの設定です。
///
/// ## English
///
/// Priority for selecting which token source to use when multiple are present.
pub enum TokenSourcePriority {
    /// ## 日本語
    ///
    /// Header（例：`Authorization`）を Cookie より優先します。
    ///
    /// ## English
    ///
    /// Prefer headers (e.g. `Authorization`) over cookies.
    HeaderFirst,
    /// ## 日本語
    ///
    /// Cookie を header より優先します。
    ///
    /// ## English
    ///
    /// Prefer cookies over headers.
    CookieFirst,
}

#[cfg(feature = "actix")]
#[derive(Clone, Debug)]
/// ## 日本語
///
/// actix extractor の token 取得元を設定します。
///
/// `app_data(web::Data<TokenSourceConfig>)` として登録すると、次をカスタマイズできます：
/// - どの header 名を順に探索するか
/// - どの cookie 名を順に探索するか
/// - header/cookie の優先順位
///
/// ## English
///
/// Token source configuration for actix extractors.
///
/// You can register this as `app_data(web::Data<TokenSourceConfig>)` to customize:
/// - which header names are scanned for a token
/// - which cookie names are scanned for a token
/// - the priority order between header/cookie
pub struct TokenSourceConfig {
    /// ## 日本語
    ///
    /// token 取得元の優先順位。
    ///
    /// ## English
    ///
    /// Priority of token sources.
    pub priority: TokenSourcePriority,
    /// ## 日本語
    ///
    /// 順にチェックする header 名の一覧。
    ///
    /// ## English
    ///
    /// Header names that will be checked in order.
    pub header_names: Vec<String>,
    /// ## 日本語
    ///
    /// 順にチェックする cookie 名の一覧。
    ///
    /// ## English
    ///
    /// Cookie names that will be checked in order.
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
/// ## 日本語
///
/// actix-web のリクエストから token を抽出します。
///
/// `app_data(web::Data<TokenSourceConfig>)` があればその設定を使い、なければ
/// `TokenSourceConfig::default()` にフォールバックします。
///
/// ## English
///
/// Extracts a token from an actix-web request.
///
/// The function reads configuration from `app_data(web::Data<TokenSourceConfig>)` if present;
/// otherwise it falls back to `TokenSourceConfig::default()`.
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
/// ## 日本語
///
/// 明示的な設定を使って actix-web のリクエストから token を抽出します。
///
/// 解析のルール：
/// - header は `Bearer <token>` と生の `<token>` の両方に対応します。
/// - cookie は cookie value をそのまま token として扱います。
///
/// ## English
///
/// Extracts a token from an actix-web request using an explicit config.
///
/// Token parsing behavior:
/// - Header values support both `Bearer <token>` and raw `<token>` formats.
/// - Cookie values use the raw cookie value as the token.
pub fn extract_token_from_request_with_config(
    req: &actix_web::HttpRequest,
    cfg: &TokenSourceConfig,
) -> Option<String> {
    // 日本語: header 名を順に見て、最初に見つかった token を返す。
    //        `Authorization: Bearer <token>` と `Authorization: <token>` の両方に対応する。
    //        - 値が UTF-8 でない header は無視する（to_str() が失敗するため）
    // English: Scan header names in order and return the first token found.
    //          Supports both `Authorization: Bearer <token>` and raw `Authorization: <token>`.
    //          - Non-UTF8 headers are ignored (to_str() fails)
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

    // 日本語: cookie 名を順に見て、最初に見つかった token を返す（cookie value をそのまま使う）。
    // English: Scan cookie names in order and return the first token found (uses cookie value as-is).
    let from_cookies = || {
        cfg.cookie_names
            .iter()
            .find_map(|name| req.cookie(name).map(|cookie| cookie.value().to_string()))
    };

    // 日本語: 設定された優先順位に従って header/cookie を選ぶ。
    //        両方に token がある場合でも「どちらを優先するか」をここで決める。
    // English: Choose header vs cookie by configured priority.
    //          This decides which source wins when both are present.
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
