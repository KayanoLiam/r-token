//! # r-token 🦀
//!
//! **r-token** is a lightweight, non-invasive authentication library designed for Rust (`actix-web`).
//!
//! **r-token** 是一个专为 Rust (`actix-web`) 设计的轻量级、无侵入式鉴权库。
//!
//! ## Design Philosophy | 设计理念
//!
//! Inspired by Java's [Sa-Token](https://sa-token.cc/), r-token provides an "out-of-the-box",
//! "parameter-as-authentication" minimalist experience.
//!
//! 设计灵感来源于 Java 的 [Sa-Token](https://sa-token.cc/)，旨在提供一种"开箱即用"、"参数即鉴权"的极简体验。
//!
//! ## Features | 特性
//!
//! - **Minimal Integration | 极简集成**: Initialize with just a few lines of code | 只需几行代码即可初始化
//! - **Idiomatic Rust | Rust 风格**: Leverages Actix's `Extractor` mechanism, eliminating cumbersome `if/else` checks | 利用 Actix 的 `Extractor` 机制，摆脱繁琐的 `if/else` 检查
//! - **Non-invasive | 零侵入**: Automatic authentication by declaring `RUser` in handler parameters | 在 Handler 参数中声明 `RUser` 即可自动完成鉴权
//! - **State Sharing | 状态共享**: Thread-safe token management with `Arc` and `Mutex` | 基于 `Arc` 和 `Mutex` 实现线程安全的 Token 管理
//!
//! ## Quick Start | 快速开始
//!
//! ```rust,no_run
//! use actix_web::{get, post, web, HttpResponse, HttpServer, App};
//! use r_token::{RTokenManager, RUser};
//!
//! // Login endpoint | 登录接口
//! #[post("/login")]
//! async fn login(manager: web::Data<RTokenManager>) -> impl actix_web::Responder {
//!     let user_id = "10086";
//!     let token = manager.login(user_id);
//!     HttpResponse::Ok().body(format!("Login Success, Token: {}", token))
//! }
//!
//! // Protected endpoint - Users without valid tokens can't access! | 受保护接口 - 没有有效 Token 的用户无法访问！
//! #[get("/info")]
//! async fn user_info(user: RUser) -> impl actix_web::Responder {
//!     format!("Hello, User ID: {}", user.id)
//! }
//!
//! // Logout endpoint | 注销接口
//! #[post("/logout")]
//! async fn logout(manager: web::Data<RTokenManager>, user: RUser) -> impl actix_web::Responder {
//!     manager.logout(&user.token);
//!     HttpResponse::Ok().body("Logout Success")
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     let manager = RTokenManager::new();
//!     
//!     HttpServer::new(move || {
//!         App::new()
//!             .app_data(web::Data::new(manager.clone()))
//!             .service(login)
//!             .service(user_info)
//!             .service(logout)
//!     })
//!     .bind(("127.0.0.1", 8080))?
//!     .run()
//!     .await
//! }
//! ```

use std::{collections::HashMap, sync::{Arc,Mutex}};
use actix_web::{FromRequest, HttpRequest, web};
use std::future::{ready, Ready};

/// Token Manager | Token 管理器
///
/// `RTokenManager` is the core component of r-token library, responsible for managing user token lifecycle.
///
/// `RTokenManager` 是 r-token 库的核心组件，负责管理用户的 Token 生命周期。
///
/// ## Features | 特点
///
/// - **Thread-safe | 线程安全**: Safe multi-threaded access with `Arc<Mutex<HashMap>>` | 使用 `Arc<Mutex<HashMap>>` 实现多线程环境下的安全访问
/// - **Cloneable | 可克隆**: Implements `Clone` trait for sharing across `actix-web` workers | 实现了 `Clone` trait，可以在多个 `actix-web` worker 之间共享
/// - **Simple | 简单易用**: Provides two core methods: `login` and `logout` | 提供 `login` 和 `logout` 两个核心方法
///
/// ## Example | 示例
///
/// ```rust
/// use r_token::RTokenManager;
///
/// let manager = RTokenManager::new();
/// let token = manager.login("user123");
/// println!("Generated token: {}", token);
///
/// // Later... | 稍后...
/// manager.logout(&token);
/// ```
#[derive(Clone)]
pub struct RTokenManager {
    /// Internal storage: Key = Token, Value = User ID | 内部存储：Key = Token, Value = User ID
    ///
    /// Uses `Arc<Mutex<HashMap>>` to ensure thread-safety and shared ownership.
    ///
    /// 使用 `Arc<Mutex<HashMap>>` 确保线程安全和多所有权。
    store: Arc<Mutex<HashMap<String, String>>>,
}

impl RTokenManager {
    /// Create a new Token Manager instance | 创建一个新的 Token 管理器实例
    ///
    /// This method initializes an empty token storage. In an `actix-web` application,
    /// it's typically called once in the `main` function, then injected into the app via `app_data`.
    ///
    /// 这个方法会初始化一个空的 Token 存储。在 `actix-web` 应用中，
    /// 通常在 `main` 函数中调用一次，然后通过 `app_data` 注入到应用中。
    ///
    /// # Example | 示例
    ///
    /// ```rust
    /// use r_token::RTokenManager;
    /// use actix_web::{web, App};
    ///
    /// let manager = RTokenManager::new();
    /// // Usage in actix-web | 在 actix-web 中使用
    /// // App::new().app_data(web::Data::new(manager.clone()))
    /// ```
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// User login: Generate and store Token | 用户登录：生成 Token 并存储
    ///
    /// This method will: | 此方法会：
    /// 1. Generate a new UUID v4 as Token | 生成一个新的 UUID v4 作为 Token
    /// 2. Store the mapping between Token and User ID in memory | 将 Token 和用户 ID 的映射关系存入内存
    /// 3. Return the generated Token string | 返回生成的 Token 字符串
    ///
    /// # Parameters | 参数
    ///
    /// - `id`: User's unique identifier (usually user ID) | 用户的唯一标识符（通常是用户 ID）
    ///
    /// # Returns | 返回值
    ///
    /// Returns a newly generated Token string (UUID v4 format) | 返回一个新生成的 Token 字符串（UUID v4 格式）
    ///
    /// # Example | 示例
    ///
    /// ```rust
    /// use r_token::RTokenManager;
    ///
    /// let manager = RTokenManager::new();
    /// let token = manager.login("user123");
    /// assert!(!token.is_empty());
    /// ```
    pub fn login(&self,id:&str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        self.store.lock().unwrap().insert(token.clone(), id.to_string());
        token
    }

    /// User logout: Remove Token | 用户登出：移除 Token
    ///
    /// This method removes the specified Token from memory, invalidating it.
    /// Invalidated tokens will fail validation through the `RUser` extractor.
    ///
    /// 此方法会从内存中删除指定的 Token，使其失效。
    /// 失效后的 Token 将无法通过 `RUser` extractor 的验证。
    ///
    /// # Parameters | 参数
    ///
    /// - `token`: The Token string to invalidate | 要注销的 Token 字符串
    ///
    /// # Example | 示例
    ///
    /// ```rust
    /// use r_token::RTokenManager;
    ///
    /// let manager = RTokenManager::new();
    /// let token = manager.login("user123");
    ///
    /// // User logout | 用户登出
    /// manager.logout(&token);
    /// // Token is now invalid | 此时 token 已失效
    /// ```
    pub fn logout(&self, token: &str) {
        self.store.lock().unwrap().remove(token);
    }

}

/// Authenticated User Information | 已认证用户信息
///
/// `RUser` is the core concept of r-token. It implements `actix-web`'s `FromRequest` trait,
/// enabling "parameter-as-authentication" by using it directly as a handler parameter.
///
/// `RUser` 是 r-token 最核心的概念，它实现了 `actix-web` 的 `FromRequest` trait，
/// 可以作为 Handler 的参数直接使用，实现"参数即鉴权"的效果。
///
/// ## How It Works | 工作原理
///
/// When you declare `RUser` as a handler parameter, `actix-web` automatically:
///
/// 当你在 Handler 参数中声明 `RUser` 时，`actix-web` 会自动：
///
/// 1. Extracts the Token from the `Authorization` header | 从请求的 `Authorization` header 中提取 Token
/// 2. Validates the Token through `RTokenManager` | 通过 `RTokenManager` 验证 Token 的有效性
/// 3. If valid, creates an `RUser` instance and passes it to your handler | 如果验证通过，创建 `RUser` 实例并传递给你的 Handler
/// 4. If invalid, returns 401 Unauthorized without calling the handler | 如果验证失败，直接返回 401 Unauthorized，Handler 不会被调用
///
/// ## Zero-Intrusion Design | 零侵入式设计
///
/// You don't need any `if/else` checks in your business code to verify if a user is logged in.
/// If a parameter has `RUser`, the user is guaranteed to be authenticated!
///
/// 你不需要在业务代码中写任何 `if/else` 来检查用户是否登录，
/// 只要参数里有 `RUser`，就保证用户一定是已登录的！
///
/// ## Example | 示例
///
/// ```rust,no_run
/// use actix_web::{get, HttpResponse};
/// use r_token::RUser;
///
/// #[get("/protected")]
/// async fn protected_route(user: RUser) -> impl actix_web::Responder {
///     // If we get here, user is guaranteed to be valid! | 能进到这里，user 一定是合法的！
///     HttpResponse::Ok().body(format!("Welcome, user {}", user.id))
/// }
/// ```
#[derive(Debug)]
pub struct RUser {
    /// User ID | 用户 ID
    ///
    /// Corresponds to the user identifier passed during login | 对应登录时传入的用户标识符
    pub id: String,
    
    /// User's Token | 用户的 Token
    ///
    /// The Token string extracted from the `Authorization` header | 从 `Authorization` header 中提取的 Token 字符串
    pub token: String,
}

/// `FromRequest` Trait Implementation | `FromRequest` trait 实现
///
/// This is the key to r-token's "parameter-as-authentication" feature.
///
/// 这是 r-token 实现"参数即鉴权"的关键。
///
/// ## Execution Flow | 执行流程
///
/// When `actix-web` receives a request and finds a handler needs an `RUser` parameter,
/// it automatically executes this logic:
///
/// 当 `actix-web` 收到请求并发现 Handler 需要 `RUser` 参数时，会自动执行这里的逻辑：
///
/// 1. **Get Token Manager | 获取 Token 管理器**: Extract `RTokenManager` from `app_data` | 从 `app_data` 中提取 `RTokenManager`
/// 2. **Extract Token | 提取 Token**: Get Token from `Authorization` header (supports `Bearer` prefix) | 从 `Authorization` header 中获取 Token（支持 `Bearer` 前缀）
/// 3. **Validate Token | 验证 Token**: Check if Token exists in manager's storage | 检查 Token 是否存在于管理器的存储中
/// 4. **Return Result | 返回结果**:
///    - Success → Create `RUser` instance, handler executes normally | 成功 → 创建 `RUser` 实例，Handler 正常执行
///    - Failure → Return 401 Unauthorized, handler is not called | 失败 → 返回 401 Unauthorized，Handler 不会被调用
///
/// ## Error Handling | 错误处理
///
/// - `500 Internal Server Error`: Token manager not injected into `app_data` | Token 管理器未注入到 `app_data`
/// - `401 Unauthorized`: Token missing or invalid | Token 缺失或无效
impl FromRequest for RUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest,_payload: &mut actix_web::dev::Payload) -> Self::Future {

        // 獲取管理器
        let manager = match req.app_data::<web::Data<RTokenManager>>() {
            Some(m) => m,
            None => return ready(Err(actix_web::error::ErrorInternalServerError("Token manager not found"))),
        };
        // 獲取Token（優先看header中的Authorization）
        let token = match req.headers().get("Authorization").and_then(|h| h.to_str().ok()) {
            Some(token_str) => token_str.strip_prefix("Bearer ").unwrap_or(token_str).to_string(),
            None => return ready(Err(actix_web::error::ErrorUnauthorized("Unauthorized"))),
        };

        // 驗證token
        let store = manager.store.lock().unwrap();
        match store.get(&token) {
            Some(id) => {
                return ready(Ok(RUser { id: id.clone(), token: token.clone() }));
            }
            None => {
                return ready(Err(actix_web::error::ErrorUnauthorized("Invalid token")));
            }
        }
    }

    
}

// ============ 单元测试 ============
#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_login() {
        let manager = RTokenManager::new();
        let token = manager.login("user123");
        
        // 验证 token 不为空
        assert!(!token.is_empty());
        
        // 验证 token 是有效的 UUID 格式
        assert!(uuid::Uuid::parse_str(&token).is_ok());
    }

    #[test]
    fn test_logout() {
        let manager = RTokenManager::new();
        let token = manager.login("user456");
        
        // 登出前，token 应该存在
        assert!(manager.store.lock().unwrap().contains_key(&token));
        
        // 登出
        manager.logout(&token);
        
        // 登出后，token 应该被移除
        assert!(!manager.store.lock().unwrap().contains_key(&token));
    }

    #[test]
    fn test_multiple_users() {
        let manager = RTokenManager::new();
        
        let token1 = manager.login("user1");
        let token2 = manager.login("user2");
        let token3 = manager.login("user3");
        
        // 验证三个 token 都不同
        assert_ne!(token1, token2);
        assert_ne!(token2, token3);
        assert_ne!(token1, token3);
        
        // 验证所有 token 都存在
        let store = manager.store.lock().unwrap();
        assert_eq!(store.len(), 3);
        assert_eq!(store.get(&token1), Some(&"user1".to_string()));
        assert_eq!(store.get(&token2), Some(&"user2".to_string()));
        assert_eq!(store.get(&token3), Some(&"user3".to_string()));
    }
}

// ============ 集成测试 ============
#[cfg(test)]
mod integration_tests {
    use super::*;
    use actix_web::{test, web, App, http::header, HttpResponse};

    #[actix_web::test]
    async fn test_from_request_valid_token() {
        let manager = RTokenManager::new();
        let token = manager.login("test_user");
        
        // 创建测试 app
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(manager.clone()))
                .route("/test", web::get().to(|user: RUser| async move {
                    HttpResponse::Ok().body(format!("User ID: {}", user.id))
                }))
        ).await;
        
        // 发送带有 Authorization header 的请求
        let req = test::TestRequest::get()
            .uri("/test")
            .insert_header((header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_from_request_missing_token() {
        let manager = RTokenManager::new();
        
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(manager.clone()))
                .route("/test", web::get().to(|user: RUser| async move {
                    HttpResponse::Ok().body(format!("User ID: {}", user.id))
                }))
        ).await;
        
        // 发送没有 Authorization header 的请求
        let req = test::TestRequest::get()
            .uri("/test")
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401); // Unauthorized
    }

    #[actix_web::test]
    async fn test_from_request_invalid_token() {
        let manager = RTokenManager::new();
        
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(manager.clone()))
                .route("/test", web::get().to(|user: RUser| async move {
                    HttpResponse::Ok().body(format!("User ID: {}", user.id))
                }))
        ).await;
        
        // 发送带有无效 token 的请求
        let req = test::TestRequest::get()
            .uri("/test")
            .insert_header((header::AUTHORIZATION, "Bearer invalid-token-12345"))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401); // Unauthorized
    }

    #[actix_web::test]
    async fn test_logout_invalidates_token() {
        let manager = RTokenManager::new();
        let token = manager.login("test_user");
        
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(manager.clone()))
                .route("/test", web::get().to(|user: RUser| async move {
                    HttpResponse::Ok().body(format!("User ID: {}", user.id))
                }))
        ).await;
        
        // 第一次请求应该成功
        let req = test::TestRequest::get()
            .uri("/test")
            .insert_header((header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
        
        // 登出
        manager.logout(&token);
        
        // 第二次请求应该失败（token 已失效）
        let req = test::TestRequest::get()
            .uri("/test")
            .insert_header((header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();
        
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 401); // Unauthorized
    }
}
