//! # r-token Redis/Valkey example server
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
//!
//! ## 繁體中文
//!
//! 這是一個最小化的 actix-web 範例，用來示範 `RTokenRedisManager` 的使用方式：
//! - 簽發 token（login），並以 TTL 寫入 Redis/Valkey
//! - 透過 Redis/Valkey 驗證 `Authorization` 以保護端點
//! - 註銷 token（logout），透過刪除 Redis key 完成
//!
//! 環境變數：
//! - `REDIS_URL`（預設：`redis://127.0.0.1/`）
//! - `R_TOKEN_PREFIX`（預設：`r_token:token:`）
//!
//! ## 執行
//!
//! ```bash
//! REDIS_URL=redis://127.0.0.1/ cargo run --bin r-token-redis --features redis-actix
//! ```
//!
//! ## 測試（curl）
//!
//! ```bash
//! curl -X POST http://127.0.0.1:8081/login -d "alice"
//! curl -H "Authorization: <token>" http://127.0.0.1:8081/info
//! curl -X POST -H "Authorization: <token>" http://127.0.0.1:8081/logout
//! ```

use actix_web::cookie::Cookie;
use actix_web::{HttpRequest, HttpResponse, HttpServer, get, post, web};
use r_token::RTokenRedisManager;

/// Extracts the token from `Authorization` header.
///
/// Accepts both formats:
/// - `Authorization: <token>`
/// - `Authorization: Bearer <token>`
///
/// ## 繁體中文
///
/// 從 `Authorization` header 解析 token。
///
/// 支援以下格式：
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

/// Issues a token and stores it in Redis/Valkey with TTL.
///
/// The request body is treated as `user_id` (plain text).
///
/// ## 繁體中文
///
/// 簽發 token，並以 TTL 方式寫入 Redis/Valkey。
///
/// request body 會被視為 `user_id`（純文字）。
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

/// A protected endpoint that validates `Authorization` via Redis/Valkey.
///
/// ## 繁體中文
///
/// 受保護端點，會透過 Redis/Valkey 驗證 `Authorization`。
#[get("/info")]
async fn do_info(
    manager: web::Data<RTokenRedisManager>,
    req: HttpRequest,
) -> Result<HttpResponse, actix_web::Error> {
    let token = extract_token(&req)?;
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

/// Revokes the current token by deleting it from Redis/Valkey.
///
/// ## 繁體中文
///
/// 透過從 Redis/Valkey 刪除 key 來註銷當前 token。
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

/// Starts the Redis/Valkey-backed example server.
///
/// ## 繁體中文
///
/// 啟動 Redis/Valkey 版本的範例伺服器。
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
