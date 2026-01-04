//! # r-token Example Application | r-token 示例应用
//!
//! This is a complete r-token usage example, demonstrating how to integrate authentication in actix-web.
//!
//! 这是一个完整的 r-token 使用示例，展示了如何在 actix-web 中集成鉴权功能。
//!
//! ## Testing Steps | 测试步骤
//!
//! 1. Start server | 启动服务器: `cargo run`
//! 2. Login to get Token | 登录获取 Token:
//!    ```bash
//!    curl -X POST http://127.0.0.1:8080/login
//!    ```
//! 3. Access protected resource with Token | 使用 Token 访问受保护资源:
//!    ```bash
//!    curl -H "Authorization: <your-token>" http://127.0.0.1:8080/info
//!    ```
//! 4. Logout to invalidate Token | 登出使 Token 失效:
//!    ```bash
//!    curl -X POST -H "Authorization: <your-token>" http://127.0.0.1:8080/logout
//!    ```

use actix_web::{HttpResponse, HttpServer, get, post, web};
use r_token::{RTokenManager, RUser};

/// Login Endpoint | 登录接口
///
/// Generates a new Token for the user and returns it.
///
/// 为用户生成一个新的 Token 并返回。
///
/// ## Request | 请求
///
/// - **Method | 方法**: POST
/// - **Path | 路径**: `/login`
/// - **Parameters | 参数**: None (uses fixed user ID "123456" in this example) | 无（示例中使用固定用户 ID "123456")
///
/// ## Response | 响应
///
/// - **Success | 成功**: Returns the generated Token string (UUID v4 format) | 返回生成的 Token 字符串（UUID v4 格式）
///
/// ## Example | 示例
///
/// ```bash
/// curl -X POST http://127.0.0.1:8080/login
/// # Response | 响应: 550e8400-e29b-41d4-a716-446655440000
/// ```
#[post("/login")]
async fn do_login(manager: web::Data<RTokenManager>) -> impl actix_web::Responder {
    let token = manager.login("123456");
    HttpResponse::Ok().body(token)
}

/// Get User Info (Protected Endpoint) | 获取用户信息（受保护接口）
///
/// This is a protected endpoint demonstrating r-token's core feature:
/// **With `RUser` declared in parameters, requests without valid tokens cannot access!**
///
/// 这是一个受保护的接口，展示了 r-token 的核心特性：
/// **参数里声明了 `RUser`，没有有效 Token 的请求绝对进不来！**
///
/// ## Request | 请求
///
/// - **Method | 方法**: GET
/// - **Path | 路径**: `/info`
/// - **Headers**: `Authorization: <token>` or | 或 `Authorization: Bearer <token>`
///
/// ## Response | 响应
///
/// - **Success (200) | 成功**: Returns user information | 返回用户信息
/// - **Failure (401) | 失败**: Token missing or invalid | Token 缺失或无效
///
/// ## Example | 示例
///
/// ```bash
/// # ❌ Without Token -> 401 Unauthorized | 不带 Token -> 401 Unauthorized
/// curl http://127.0.0.1:8080/info
///
/// # ✅ With Token -> 200 OK | 带 Token -> 200 OK
/// curl -H "Authorization: <your-token>" http://127.0.0.1:8080/info
/// # Response | 响应: info: 123456
/// ```
#[get("/info")]
async fn do_info(user: RUser) -> impl actix_web::Responder {
    format!("info: {}", user.id)
}

/// Logout Endpoint (Protected) | 登出接口（受保护接口）
///
/// Invalidates the user's Token. Requires both `RTokenManager` and `RUser` injection.
///
/// 注销用户的 Token，使其失效。需要同时注入 `RTokenManager` 和 `RUser`。
///
/// ## Request | 请求
///
/// - **Method | 方法**: POST
/// - **Path | 路径**: `/logout`
/// - **Headers**: `Authorization: <token>` or | 或 `Authorization: Bearer <token>`
///
/// ## Response | 响应
///
/// - **Success (200) | 成功**: Token has been invalidated | Token 已被注销
/// - **Failure (401) | 失败**: Token missing or invalid | Token 缺失或无效
///
/// ## Example | 示例
///
/// ```bash
/// curl -X POST -H "Authorization: <your-token>" http://127.0.0.1:8080/logout
/// # Response | 响应: logout success
/// # Note: This Token can no longer access any protected endpoints | 注意：此后该 Token 将无法再访问任何受保护接口
/// ```
#[post("/logout")]
async fn do_logout(
    manager: web::Data<crate::RTokenManager>,
    user: RUser,
) -> impl actix_web::Responder {
    manager.logout(&user.token);
    HttpResponse::Ok().body("logout success")
}

/// Application Entry Point | 应用程序入口
///
/// ## Initialization Steps | 初始化步骤
///
/// 1. Create `RTokenManager` instance (global singleton) | 创建 `RTokenManager` 实例（全局单例）
/// 2. Inject via `app_data` into actix-web app | 通过 `app_data` 注入到 actix-web 应用中
/// 3. Register all routes (login, protected endpoints, logout) | 注册所有路由（登录、受保护接口、登出）
/// 4. Bind address and start server | 绑定地址并启动服务器
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
