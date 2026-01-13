//! # r-token example server
//!
//! A minimal actix-web application showcasing how to use `r_token`:
//! - issue a token (login)
//! - protect endpoints via the `RUser` extractor
//! - revoke a token (logout)
//!
//! ## Run
//!
//! ```bash
//! cargo run
//! ```
//!
//! ## Try (curl)
//!
//! ```bash
//! curl -X POST http://127.0.0.1:8080/login
//! curl -H "Authorization: <token>" http://127.0.0.1:8080/info
//! curl -X POST -H "Authorization: <token>" http://127.0.0.1:8080/logout
//! ```
//!
//! ## 繁體中文
//!
//! 這是一個最小化的 actix-web 範例，用來示範 `r_token` 的使用方式：
//! - 簽發 token（login）
//! - 透過 `RUser` Extractor 保護端點
//! - 註銷 token（logout）
//!
//! ## 執行
//!
//! ```bash
//! cargo run
//! ```
//!
//! ## 測試（curl）
//!
//! ```bash
//! curl -X POST http://127.0.0.1:8080/login
//! curl -H "Authorization: <token>" http://127.0.0.1:8080/info
//! curl -X POST -H "Authorization: <token>" http://127.0.0.1:8080/logout
//! ```

use actix_web::cookie::Cookie;
use actix_web::{HttpResponse, HttpServer, get, post, web};
use r_token::{RTokenManager, RUser};

/// Issues a token and returns it as the response body.
///
/// The example uses a fixed user id and TTL for simplicity.
///
/// ## 繁體中文
///
/// 簽發 token 並以 response body 回傳。
///
/// 為了簡化示範，此範例使用固定的使用者 id 與 TTL。
#[post("/login")]
async fn do_login(
    manager: web::Data<RTokenManager>,
    _body: String,
) -> Result<HttpResponse, r_token::RTokenError> {
    // let token = manager.login("123456");
    // let token = manager.login(&body)?;
    let token = manager.login("121381", 3600)?; // 1 hour expiration
    Ok(HttpResponse::Ok()
        .cookie(
            Cookie::build(r_token::TOKEN_COOKIE_NAME, token.clone())
                .path("/")
                .http_only(true)
                .finish(),
        )
        .body(token))
}

/// A protected endpoint.
///
/// Access requires a valid `Authorization` header; if extraction succeeds,
/// `user.id` is available.
///
/// ## 繁體中文
///
/// 受保護端點。
///
/// 需要有效的 `Authorization` header；Extractor 成功後即可使用 `user.id`。
#[get("/info")]
async fn do_info(user: RUser) -> impl actix_web::Responder {
    format!("info: {}", user.id)
}

/// Revokes the current token.
///
/// This endpoint is protected; on success, the token is removed from the store.
///
/// ## 繁體中文
///
/// 註銷當前 token。
///
/// 此端點本身也受保護；成功後 token 會從儲存表中移除。
#[post("/logout")]
async fn do_logout(
    manager: web::Data<crate::RTokenManager>,
    user: RUser,
) -> Result<HttpResponse, r_token::RTokenError> {
    manager.logout(&user.token)?;
    Ok(HttpResponse::Ok().body("logout success"))
}

/// Starts the example server.
///
/// ## 繁體中文
///
/// 啟動範例伺服器。
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 1. Initialize r-token manager (global singleton) | 初始化 r-token 管理器（全局单例）
    let r_manager = r_token::RTokenManager::new();

    println!("🚀 r-token server started at http://127.0.0.1:8080");
    println!("📖 Try:");
    println!("   POST http://127.0.0.1:8080/login");
    println!("   GET  http://127.0.0.1:8080/info  (with Authorization header)");
    println!("   POST http://127.0.0.1:8080/logout (with Authorization header)");

    HttpServer::new(move || {
        actix_web::App::new()
            // 2. Inject global state (required!) | 注入全局状态（必须步骤！）
            // This allows all handlers to access via web::Data<RTokenManager>
            // 这样所有 Handler 都可以通过 web::Data<RTokenManager> 访问
            .app_data(web::Data::new(r_manager.clone()))
            // 3. Register route services | 注册路由服务
            .service(do_login) // Public endpoint | 公开接口
            .service(do_info) // Protected endpoint | 受保护接口
            .service(do_logout) // Protected endpoint | 受保护接口
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
