//! # r-token Example Application
//!
//! A complete demonstration of r-token authentication in an actix-web application.
//!
//! This example shows how to:
//! - Set up token-based authentication
//! - Create login/logout endpoints
//! - Protect routes using the `RUser` extractor
//!
//! ## Quick Start
//!
//! 1. **Start the server**:
//!    ```bash
//!    cargo run
//!    ```
//!
//! 2. **Login to get a token**:
//!    ```bash
//!    curl -X POST http://127.0.0.1:8080/login \
//!      -H "Content-Type: text/plain" \
//!      -d "user_12345"
//!    ```
//!
//! 3. **Access protected endpoint**:
//!    ```bash
//!    curl -H "Authorization: <your-token>" \
//!      http://127.0.0.1:8080/info
//!    ```
//!
//! 4. **Logout to invalidate token**:
//!    ```bash
//!    curl -X POST \
//!      -H "Authorization: <your-token>" \
//!      http://127.0.0.1:8080/logout
//!    ```

use actix_web::{HttpResponse, HttpServer, get, post, web};
use r_token::{RTokenManager, RUser};

/// Login endpoint - generates a new authentication token.
///
/// Accepts a user ID in the request body and returns a UUID v4 token.
///
/// # Request
///
/// - **Method**: `POST`
/// - **Path**: `/login`
/// - **Body**: Plain text user ID
///
/// # Response
///
/// - **200 OK**: Returns the generated token (UUID v4 format)
/// - **500 Internal Server Error**: Failed to generate token
///
/// # Example
///
/// ```bash
/// curl -X POST http://127.0.0.1:8080/login \
///   -H "Content-Type: text/plain" \
///   -d "user_12345"
/// # Response: 550e8400-e29b-41d4-a716-446655440000
/// ```
#[post("/login")]
async fn do_login(manager: web::Data<RTokenManager>,body:String) -> Result<HttpResponse, r_token::RTokenError> {
    // let token = manager.login("123456");
    let token = manager.login(&body)?;
    Ok(HttpResponse::Ok().body(token))
}

/// Protected endpoint - returns user information.
///
/// Demonstrates r-token's core feature: **declaring `RUser` as a parameter
/// automatically blocks unauthenticated requests!**
///
/// # Request
///
/// - **Method**: `GET`
/// - **Path**: `/info`
/// - **Headers**: `Authorization: <token>` or `Authorization: Bearer <token>`
///
/// # Response
///
/// - **200 OK**: Returns user information
/// - **401 Unauthorized**: Token missing or invalid
///
/// # Example
///
/// ```bash
/// # ❌ Without token -> 401 Unauthorized
/// curl http://127.0.0.1:8080/info
///
/// # ✅ With token -> 200 OK
/// curl -H "Authorization: <your-token>" http://127.0.0.1:8080/info
/// # Response: info: user_12345
/// ```
#[get("/info")]
async fn do_info(user: RUser) -> impl actix_web::Responder {
    format!("info: {}", user.id)
}

/// Protected logout endpoint - invalidates the user's token.
///
/// Requires authentication via `RUser` and access to `RTokenManager`.
///
/// # Request
///
/// - **Method**: `POST`
/// - **Path**: `/logout`
/// - **Headers**: `Authorization: <token>` or `Authorization: Bearer <token>`
///
/// # Response
///
/// - **200 OK**: Token successfully invalidated
/// - **401 Unauthorized**: Token missing or invalid
/// - **500 Internal Server Error**: Failed to invalidate token
///
/// # Example
///
/// ```bash
/// curl -X POST -H "Authorization: <your-token>" \
///   http://127.0.0.1:8080/logout
/// # Response: logout success
/// # Note: Token is now invalid and cannot access protected endpoints
/// ```
#[post("/logout")]
async fn do_logout(
    manager: web::Data<crate::RTokenManager>,
    user: RUser,
) -> Result<HttpResponse, r_token::RTokenError> {
    manager.logout(&user.token)?;
    Ok(HttpResponse::Ok().body("logout success"))
}

/// Application entry point.
///
/// # Initialization Steps
///
/// 1. Create a `RTokenManager` instance (shared across workers)
/// 2. Inject it into the actix-web app via `.app_data()`
/// 3. Register all route handlers
/// 4. Bind to address and start the server
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
            .service(do_login)   // Public endpoint | 公开接口
            .service(do_info)    // Protected endpoint | 受保护接口
            .service(do_logout)  // Protected endpoint | 受保护接口
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
