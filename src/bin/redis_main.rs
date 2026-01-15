//! # r-token Redis/Valkey example server
//!
//! ## 日本語
//!
//! `RTokenRedisManager` の使い方を示す最小構成の actix-web サンプルです：
//! - token を発行（login）し、TTL 付きで Redis/Valkey に保存
//! - Redis/Valkey 経由で `Authorization` を検証してエンドポイントを保護
//! - Redis key を削除して token を失効（logout）
//!
//! 環境変数：
//! - `REDIS_URL`（デフォルト：`redis://127.0.0.1/`）
//! - `R_TOKEN_PREFIX`（デフォルト：`r_token:token:`）
//!
//! ### 実行
//!
//! ```bash
//! REDIS_URL=redis://127.0.0.1/ cargo run --bin r-token-redis --features redis-actix
//! ```
//!
//! ### 試す（curl）
//!
//! ```bash
//! curl -X POST http://127.0.0.1:8081/login -d "alice"
//! curl -H "Authorization: <token>" http://127.0.0.1:8081/info
//! curl -X POST -H "Authorization: <token>" http://127.0.0.1:8081/logout
//! ```
//!
//! ## English
//!
//! A minimal actix-web application showcasing how to use `RTokenRedisManager`:
//! - issue a token (login) stored in Redis/Valkey with TTL
//! - protect endpoints by validating `Authorization` via Redis/Valkey
//! - revoke a token (logout) by deleting the Redis key
//!
//! Environment variables:
//! - `REDIS_URL` (default: `redis://127.0.0.1/`)
//! - `R_TOKEN_PREFIX` (default: `r_token:token:`)
//!
//! ## Run
//!
//! ```bash
//! REDIS_URL=redis://127.0.0.1/ cargo run --bin r-token-redis --features redis-actix
//! ```
//!
//! ## Try (curl)
//!
//! ```bash
//! curl -X POST http://127.0.0.1:8081/login -d "alice"
//! curl -H "Authorization: <token>" http://127.0.0.1:8081/info
//! curl -X POST -H "Authorization: <token>" http://127.0.0.1:8081/logout
//! ```

use actix_web::cookie::Cookie;
use actix_web::{HttpRequest, HttpResponse, HttpServer, get, post, web};
use r_token::RTokenRedisManager;

/// ## 日本語
///
/// `Authorization` header から token を抽出します。
///
/// 次の形式に対応します：
/// - `Authorization: <token>`
/// - `Authorization: Bearer <token>`
///
/// ## English
///
/// Extracts the token from `Authorization` header.
///
/// Accepts both formats:
/// - `Authorization: <token>`
/// - `Authorization: Bearer <token>`
fn extract_token(req: &HttpRequest) -> Result<String, actix_web::Error> {
    let header_token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .map(|token| token.strip_prefix("Bearer ").unwrap_or(token).to_string());

    if let Some(token) = header_token {
        return Ok(token);
    }

    if let Some(cookie) = req.cookie(r_token::TOKEN_COOKIE_NAME) {
        return Ok(cookie.value().to_string());
    }

    if let Some(cookie) = req.cookie("token") {
        return Ok(cookie.value().to_string());
    }

    Err(actix_web::error::ErrorUnauthorized("Unauthorized"))
}

/// ## 日本語
///
/// token を発行し、TTL 付きで Redis/Valkey に保存します。
///
/// リクエスト body は `user_id`（プレーンテキスト）として扱います。
///
/// ## English
///
/// Issues a token and stores it in Redis/Valkey with TTL.
///
/// The request body is treated as `user_id` (plain text).
#[post("/login")]
async fn do_login(
    manager: web::Data<RTokenRedisManager>,
    body: String,
) -> Result<HttpResponse, actix_web::Error> {
    let user_id = body.trim();
    if user_id.is_empty() {
        return Err(actix_web::error::ErrorBadRequest("Empty user id"));
    }

    let token = manager
        .login(user_id, 3600)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Redis error"))?;

    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build(r_token::TOKEN_COOKIE_NAME, token.clone())
                .path("/")
                .http_only(true)
                .finish(),
        )
        .body(token))
}

/// ## 日本語
///
/// Redis/Valkey 経由で `Authorization` を検証する保護されたエンドポイントです。
///
/// ## English
///
/// A protected endpoint that validates `Authorization` via Redis/Valkey.
#[get("/info")]
async fn do_info(
    manager: web::Data<RTokenRedisManager>,
    req: HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    // 日本語: まずはリクエストから token を取り出す（Authorization / Cookie）。
    //        ここで失敗するのは「token が無い」ケースで、その場合は 401 を返す。
    // English: Extract token from request (Authorization / Cookie).
    //          The failure case here is “missing token”, which maps to 401.
    let token = extract_token(&req)?;

    #[cfg(feature = "rbac")]
    // 日本語: RBAC 有効時は user_id と roles をまとめて取得する。
    //        - Some((user_id, roles)) => 有効 token
    //        - None => 無効/期限切れ/存在しない（Redis 側で TTL により消えている可能性もある）
    //        Redis の I/O エラーは 500 として扱う。
    // English: With RBAC enabled, fetch both user_id and roles.
    //          - Some((user_id, roles)) => valid token
    //          - None => invalid/expired/missing (may have been removed by Redis TTL)
    //          Redis I/O errors are treated as 500.
    let user_info = manager
        .validate_with_roles(&token)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Redis error"))?;

    #[cfg(not(feature = "rbac"))]
    // 日本語: RBAC 無効時は user_id のみ取得する（戻りの Some/None の意味は同じ）。
    // English: Without RBAC, fetch only user_id (same Some/None semantics).
    let user_info = manager
        .validate(&token)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Redis error"))?;

    #[cfg(feature = "rbac")]
    match user_info {
        Some((user_id, roles)) => {
            Ok(HttpResponse::Ok().body(format!("info: user_id={}, roles={:?}", user_id, roles)))
        }
        None => Err(actix_web::error::ErrorUnauthorized("Invalid token")),
    }

    #[cfg(not(feature = "rbac"))]
    match user_info {
        Some(user_id) => Ok(HttpResponse::Ok().body(format!("info: {}", user_id))),
        None => Err(actix_web::error::ErrorUnauthorized("Invalid token")),
    }
}

/// ## 日本語
///
/// Redis/Valkey から削除して現在の token を失効させます。
///
/// ## English
///
/// Revokes the current token by deleting it from Redis/Valkey.
#[post("/logout")]
async fn do_logout(
    manager: web::Data<RTokenRedisManager>,
    req: HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    let token = extract_token(&req)?;
    manager
        .logout(&token)
        .await
        .map_err(|_| actix_web::error::ErrorInternalServerError("Redis error"))?;

    Ok(HttpResponse::Ok().body("logout success"))
}

/// ## 日本語
///
/// Redis/Valkey バックエンドのサンプルサーバーを起動します。
///
/// ## English
///
/// Starts the Redis/Valkey-backed example server.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 讀取 Redis/Valkey 連線字串：允許透過環境變數覆蓋，否則使用本機預設。
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    // 讀取 Redis key 前綴：用來隔離不同應用/環境的 token key（避免互相覆蓋）。
    let prefix = std::env::var("R_TOKEN_PREFIX").unwrap_or_else(|_| "r_token:token:".to_string());

    // 建立 Redis/Valkey 管理器：內部會建立連線管理器並保存 prefix。
    let manager = RTokenRedisManager::connect(&redis_url, prefix)
        .await
        // 把 Redis 連線錯誤轉成 std::io::Error，讓 main 的返回型別保持簡單（方便示例）。
        .map_err(|_| std::io::Error::other("Redis connect failed"))?;

    // 提示啟動成功，方便用 curl 直接測試。
    println!("r-token (redis) server started at http://127.0.0.1:8081");

    // 啟動 Actix HTTP 伺服器：用 move 把 manager 捕獲進工廠閉包（每個 worker 都能 clone 使用）。
    HttpServer::new(move || {
        actix_web::App::new()
            // 把 manager 放到 app state，handler 才能用 web::Data<RTokenRedisManager> 取到它。
            .app_data(web::Data::new(manager.clone()))
            // 註冊路由：/login（簽發 token）、/info（驗證 token）、/logout（註銷 token）。
            .service(do_login)
            .service(do_info)
            .service(do_logout)
    })
    // 綁定監聽地址：示例固定在本機 8081。
    .bind("127.0.0.1:8081")?
    // 開始跑 event loop；await 直到伺服器停止（或發生錯誤）。
    .run()
    .await
}
