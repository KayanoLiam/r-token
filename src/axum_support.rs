//! ## 日本語
//!
//! axum 向けの extractor 実装です。
//!
//! - `Extension<RTokenManager>` / `Extension<RTokenRedisManager>` を state から取得し
//! - Header/Cookie から token を抽出して検証し
//! - `RUser` / `RRedisUser` を handler 引数として利用できるようにします
//!
//! ## English
//!
//! Axum extractor implementations.
//!
//! - Fetches `Extension<RTokenManager>` / `Extension<RTokenRedisManager>` from request state
//! - Extracts a token from headers/cookies and validates it
//! - Enables `RUser` / `RRedisUser` as handler parameters

use crate::{TokenSourceConfig, extract_token_with_config};
use axum::{
    extract::{Extension, FromRequestParts},
    http::{StatusCode, header, request::Parts},
};

// 日本語: Axum extractor の失敗時に返す型。
//        ここでは「HTTP ステータス + 固定文字列ボディ」に絞って、依存と実装を最小にしている。
// English: Rejection type for axum extractors.
//          We intentionally keep it minimal: (HTTP status + static body string).
type AxumRejection = (StatusCode, &'static str);

// 日本語: 401 を返すためのヘルパー。
// English: Helper to build a 401 rejection.
fn unauthorized(body: &'static str) -> AxumRejection {
    (StatusCode::UNAUTHORIZED, body)
}

// 日本語: 500 を返すためのヘルパー。
// English: Helper to build a 500 rejection.
fn internal(body: &'static str) -> AxumRejection {
    (StatusCode::INTERNAL_SERVER_ERROR, body)
}

fn cookie_header_string(parts: &Parts) -> Option<String> {
    // 日本語: Cookie header は複数来る可能性があるため結合して扱う。
    // English: Cookie headers may appear multiple times; concatenate them.
    let mut out = String::new();
    for v in parts.headers.get_all(header::COOKIE).iter() {
        // 日本語: 無効なヘッダ値（非 ASCII 等）は無視する。
        // English: Ignore invalid header values (non-ASCII, etc.).
        let Ok(s) = v.to_str() else {
            continue;
        };
        if out.is_empty() {
            out.push_str(s);
        } else {
            // 日本語: cookie header の区切りに合わせて "; " で連結する。
            // English: Join with "; " to preserve cookie header semantics.
            out.push_str("; ");
            out.push_str(s);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

fn find_cookie_value(cookie_header: &str, target_name: &str) -> Option<String> {
    // 日本語: Cookie の最小パーサ（name=value; name2=value2 形式を想定）。
    // English: Minimal cookie parser for "name=value; name2=value2" format.
    //
    // 日本語: RFC 準拠の完全な cookie パース（URL デコード等）は行わない。
    //        本ライブラリの目的は「既知の cookie 名から token 文字列を取り出す」ことに絞る。
    // English: This is not a full RFC-compliant cookie parser (no decoding, etc.).
    //          It is sufficient for extracting a token from a known cookie name.
    for part in cookie_header.split(';') {
        let part = part.trim();
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        if name.trim() == target_name {
            return Some(value.trim().to_string());
        }
    }
    None
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for crate::memory::RUser
where
    S: Send + Sync,
{
    type Rejection = AxumRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // 日本語: 1) アプリ state から RTokenManager を取り出す。
        //        ルータに `.layer(Extension(RTokenManager::new()))` が必要。
        // English: 1) Fetch RTokenManager from request state.
        //          The router must install `.layer(Extension(RTokenManager::new()))`.
        let Extension(manager) =
            Extension::<crate::memory::RTokenManager>::from_request_parts(parts, state)
                .await
                .map_err(|_| internal("Token manager not found"))?;

        // 日本語: 2) TokenSourceConfig を任意で読む（無ければデフォルト）。
        //        `.layer(Extension(TokenSourceConfig{..}))` で優先順位や名前を上書きできる。
        // English: 2) Read TokenSourceConfig if provided; otherwise use defaults.
        //          Install via `.layer(Extension(TokenSourceConfig{..}))` to override behavior.
        let cfg = match Extension::<TokenSourceConfig>::from_request_parts(parts, state).await {
            Ok(Extension(cfg)) => cfg,
            Err(_) => TokenSourceConfig::default(),
        };

        // 日本語: 3) cookie を読む準備（複数 Cookie header を結合して 1 本にする）。
        // English: 3) Prepare cookie parsing (concatenate multiple Cookie headers).
        let cookie_header = cookie_header_string(parts);

        // 日本語: 4) header/cookie から token を抽出する（優先順位は cfg に従う）。
        //        header 文字列は "Bearer " を許容する。
        // English: 4) Extract token from header/cookie (priority controlled by cfg).
        //          Header values accept optional "Bearer " prefix.
        let token = extract_token_with_config(
            &cfg,
            |name| {
                // 日本語: header 名を渡すと、その header の値を文字列として返すクロージャ。
                //        値が UTF-8 でない場合は None。
                // English: Closure returning a header value as String (None if not valid UTF-8).
                parts
                    .headers
                    .get(name)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
            },
            |name| {
                // 日本語: cookie 名を渡すと、その cookie の値を返すクロージャ。
                //        Cookie header が無い場合は None。
                // English: Closure returning a cookie value by name (None if no Cookie header).
                cookie_header
                    .as_deref()
                    .and_then(|h| find_cookie_value(h, name))
            },
        )
        .ok_or_else(|| unauthorized("Unauthorized"))?;

        #[cfg(feature = "rbac")]
        {
            // 日本語: 5) RBAC 有効時は user_id + roles を検証で取得する。
            //        - Ok(Some(..)) => 有効 token
            //        - Ok(None) => 無効/期限切れ
            //        - Err => mutex poisoned（500 扱い）
            // English: 5) With RBAC enabled, validate and fetch user_id + roles.
            let user_info = manager
                .validate_with_roles(&token)
                .map_err(|_| internal("Mutex poisoned"))?;
            if let Some((user_id, roles)) = user_info {
                // 日本語: 6) extractor 成功。handler 側は `RUser` を引数で受け取れる。
                // English: 6) Extraction succeeded; handler can receive `RUser`.
                return Ok(Self {
                    id: user_id,
                    token,
                    roles,
                });
            }
            return Err(unauthorized("Invalid token"));
        }

        #[cfg(not(feature = "rbac"))]
        {
            // 日本語: 5) RBAC 無効時は user_id のみ検証で取得する。
            // English: 5) Without RBAC, validate and fetch only user_id.
            let user_id = manager
                .validate(&token)
                .map_err(|_| internal("Mutex poisoned"))?;
            if let Some(user_id) = user_id {
                // 日本語: 6) extractor 成功。
                // English: 6) Extraction succeeded.
                return Ok(Self { id: user_id, token });
            }
            Err(unauthorized("Invalid token"))
        }
    }
}

#[cfg(feature = "redis")]
#[axum::async_trait]
impl<S> FromRequestParts<S> for crate::redis::RRedisUser
where
    S: Send + Sync,
{
    type Rejection = AxumRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // 日本語: 1) アプリ state から Redis manager を取り出す。
        //        ルータに `.layer(Extension(RTokenRedisManager::connect(...).await?))` が必要。
        // English: 1) Fetch Redis-backed manager from request state.
        //          The router must install `.layer(Extension(RTokenRedisManager::connect(...).await?))`.
        let Extension(manager) =
            Extension::<crate::redis::RTokenRedisManager>::from_request_parts(parts, state)
                .await
                .map_err(|_| internal("Token manager not found"))?;

        // 日本語: 2) TokenSourceConfig を任意で読む（無ければデフォルト）。
        // English: 2) Read TokenSourceConfig if provided; otherwise use defaults.
        let cfg = match Extension::<TokenSourceConfig>::from_request_parts(parts, state).await {
            Ok(Extension(cfg)) => cfg,
            Err(_) => TokenSourceConfig::default(),
        };

        // 日本語: 3) Cookie header を結合し、cookie から token を引けるようにする。
        // English: 3) Concatenate Cookie headers so we can lookup token cookies.
        let cookie_header = cookie_header_string(parts);

        // 日本語: 4) header/cookie から token を抽出する（優先順位は cfg に従う）。
        // English: 4) Extract token from header/cookie (priority controlled by cfg).
        let token = extract_token_with_config(
            &cfg,
            |name| {
                // 日本語: header 名 -> header 値文字列。
                // English: Header name -> header value string.
                parts
                    .headers
                    .get(name)
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
            },
            |name| {
                // 日本語: cookie 名 -> cookie 値文字列。
                // English: Cookie name -> cookie value string.
                cookie_header
                    .as_deref()
                    .and_then(|h| find_cookie_value(h, name))
            },
        )
        .ok_or_else(|| unauthorized("Unauthorized"))?;

        #[cfg(feature = "rbac")]
        // 日本語: 5) RBAC 有効時は (user_id, roles) を取得する。
        // English: 5) With RBAC enabled, fetch (user_id, roles).
        let user_info = manager
            .validate_with_roles(&token)
            .await
            .map_err(|_| internal("Redis error"))?;

        #[cfg(not(feature = "rbac"))]
        // 日本語: 5) RBAC 無効時は user_id のみ取得する。
        // English: 5) Without RBAC, fetch only user_id.
        let user_info = manager
            .validate(&token)
            .await
            .map_err(|_| internal("Redis error"))?;

        #[cfg(feature = "rbac")]
        if let Some((user_id, roles)) = user_info {
            // 日本語: 6) extractor 成功。
            // English: 6) Extraction succeeded.
            return Ok(Self {
                id: user_id,
                token,
                roles,
            });
        }

        #[cfg(not(feature = "rbac"))]
        if let Some(user_id) = user_info {
            // 日本語: 6) extractor 成功。
            // English: 6) Extraction succeeded.
            return Ok(Self { id: user_id, token });
        }

        // 日本語: 期限切れ/存在しない/不正 token は 401。
        // English: Expired/missing/invalid tokens map to 401.
        Err(unauthorized("Invalid token"))
    }
}
