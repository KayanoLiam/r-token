#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::empty_loop)]
#![deny(clippy::indexing_slicing)]
#![deny(unused)]
//! # r-token 🦀
//!
//! A lightweight, zero-boilerplate authentication library for actix-web applications.
//!
//! ## Overview
//!
//! r-token provides a minimalist approach to HTTP authentication in Rust web applications.
//! Inspired by Java's [Sa-Token](https://sa-token.cc/), it leverages actix-web's extractor
//! pattern to enable "parameter-as-authentication" - simply declare [`RUser`] in your handler
//! parameters, and authentication is handled automatically.
//!
//! ## Key Features
//!
//! - **Zero Boilerplate**: No manual token validation or middleware setup required
//! - **Type-Safe**: Leverages Rust's type system - if your handler receives [`RUser`], the user is authenticated
//! - **Non-Invasive**: Uses actix-web's [`FromRequest`] trait for seamless integration
//! - **Thread-Safe**: Built on `Arc<Mutex<HashMap>>` for safe concurrent access
//! - **Minimalist API**: Only two core methods - [`login`](RTokenManager::login) and [`logout`](RTokenManager::logout)
//!
//! ## Quick Start
//!
//! Add r-token to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! r-token = "0.1"
//! actix-web = "4"
//! ```
//!
//! Then create your authentication endpoints:
//!
//! ```rust,no_run
//! use actix_web::{get, post, web, HttpResponse, HttpServer, App};
//! use r_token::{RTokenManager, RUser, RTokenError};
//!
//! #[post("/login")]
//! async fn login(
//!     manager: web::Data<RTokenManager>
//! ) -> Result<HttpResponse, RTokenError> {
//!     let token = manager.login("user_10086")?;
//!     Ok(HttpResponse::Ok().body(token))
//! }
//!
//! #[get("/profile")]
//! async fn profile(user: RUser) -> impl actix_web::Responder {
//!     // If we reach here, the user is guaranteed to be authenticated
//!     format!("Welcome, user: {}", user.id)
//! }
//!
//! #[post("/logout")]
//! async fn logout(
//!     manager: web::Data<RTokenManager>,
//!     user: RUser,
//! ) -> Result<HttpResponse, RTokenError> {
//!     manager.logout(&user.token)?;
//!     Ok(HttpResponse::Ok().body("Logged out successfully"))
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
//!             .service(profile)
//!             .service(logout)
//!     })
//!     .bind(("127.0.0.1", 8080))?
//!     .run()
//!     .await
//! }
//! ```
//!
//! ## How It Works
//!
//! 1. **Login**: Call [`RTokenManager::login()`] with a user ID to generate a UUID token
//! 2. **Authenticate**: Add [`RUser`] to any handler that requires authentication
//! 3. **Automatic Validation**: actix-web verifies the `Authorization` header before calling your handler
//! 4. **Logout**: Call [`RTokenManager::logout()`] to invalidate a token
//!
//! ## Authorization Header Format
//!
//! Clients should include the token in the `Authorization` header:
//!
//! ```text
//! Authorization: <token>
//! ```
//!
//! Or with the `Bearer` prefix:
//!
//! ```text
//! Authorization: Bearer <token>
//! ```
//!
//! ## Error Handling
//!
//! - **401 Unauthorized**: Returned when token is missing or invalid
//! - **500 Internal Server Error**: Returned when [`RTokenManager`] is not registered in `app_data`
//! - **[`RTokenError::MutexPoisoned`]**: Returned when the internal lock is poisoned (rare)
//!
//! [`FromRequest`]: actix_web::FromRequest

mod models;

pub use crate::models::RTokenError;
use actix_web::{FromRequest, HttpRequest, web};
use std::future::{Ready, ready};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

/// The core token management component.
///
/// `RTokenManager` maintains an in-memory mapping of tokens to user IDs,
/// providing thread-safe token generation, validation, and invalidation.
///
/// # Thread Safety
///
/// This type uses `Arc<Mutex<HashMap>>` internally, making it safe to clone
/// and share across multiple actix-web worker threads. Each clone shares the
/// same underlying token storage.
///
/// # Usage
///
/// In a typical actix-web application:
///
/// 1. Create a single instance in your `main()` function
/// 2. Register it with `.app_data(web::Data::new(manager.clone()))`
/// 3. Inject it into handlers via `web::Data<RTokenManager>`
///
/// # Example
///
/// ```rust
/// use r_token::RTokenManager;
/// use actix_web::{web, App};
///
/// let manager = RTokenManager::new();
///
/// // In your actix-web app:
/// // App::new().app_data(web::Data::new(manager.clone()))
///
/// // Generate a token
/// let token = manager.login("user_12345").unwrap();
/// println!("Generated token: {}", token);
///
/// // Later, invalidate it
/// manager.logout(&token).unwrap();
/// ```
#[derive(Clone,Default)]
pub struct RTokenManager {
    /// Internal token storage mapping tokens to user IDs.
    ///
    /// Uses `Arc<Mutex<HashMap>>` for thread-safe shared ownership across workers.
    store: Arc<Mutex<HashMap<String, String>>>,
}

impl RTokenManager {
    /// Creates a new token manager with empty storage.
    ///
    /// In a typical actix-web application, call this once in `main()` and
    /// register the instance using `.app_data(web::Data::new(manager.clone()))`.
    ///
    /// # Example
    ///
    /// ```rust
    /// use r_token::RTokenManager;
    ///
    /// let manager = RTokenManager::new();
    /// ```
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generates a new authentication token for the given user ID.
    ///
    /// This method creates a UUID v4 token, stores the token-to-user-ID mapping
    /// in memory, and returns the token string.
    ///
    /// # Arguments
    ///
    /// * `id` - The unique identifier for the user (typically a user ID from your database)
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the generated UUID v4 token on success,
    /// or `Err(RTokenError::MutexPoisoned)` if the internal lock is poisoned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use r_token::RTokenManager;
    ///
    /// let manager = RTokenManager::new();
    /// let token = manager.login("user_12345").expect("Failed to generate token");
    /// assert_eq!(token.len(), 36); // UUID v4 length
    /// ```
    pub fn login(&self, id: &str) -> Result<String, RTokenError> {
        let token = uuid::Uuid::new_v4().to_string();
        // Acquire the write lock and insert the token-user mapping into the store
        // 获取写锁并将 Token-用户映射关系插入到存储中
        // #[allow(clippy::unwrap_used)]
        // self.store.lock().unwrap().insert(token.clone(), id.to_string());
        self.store
            .lock()
            .map_err(|_| RTokenError::MutexPoisoned)?
            .insert(token.clone(), id.to_string());
        Ok(token)
    }

    /// Invalidates a token by removing it from storage.
    ///
    /// After calling this method, the specified token will no longer be valid,
    /// and any requests using it will receive a 401 Unauthorized response.
    ///
    /// # Arguments
    ///
    /// * `token` - The token string to invalidate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success, or `Err(RTokenError::MutexPoisoned)`
    /// if the internal lock is poisoned.
    ///
    /// # Example
    ///
    /// ```rust
    /// use r_token::RTokenManager;
    ///
    /// let manager = RTokenManager::new();
    /// let token = manager.login("user_12345").unwrap();
    ///
    /// // Later, invalidate the token
    /// manager.logout(&token).expect("Failed to logout");
    /// ```
    pub fn logout(&self, token: &str) -> Result<(), RTokenError> {
        // self.store.lock().unwrap().remove(token);
        self.store
            .lock()
            .map_err(|_| RTokenError::MutexPoisoned)?
            .remove(token);
        Ok(())
    }
}

/// Represents an authenticated user.
///
/// `RUser` is the key to r-token's "parameter-as-authentication" pattern.
/// By implementing actix-web's [`FromRequest`] trait, it enables automatic
/// authentication validation before your handler is called.
///
/// # How It Works
///
/// When you declare `RUser` as a handler parameter:
///
/// 1. actix-web extracts the token from the `Authorization` header
/// 2. Validates the token using [`RTokenManager`]
/// 3. If valid: creates an `RUser` instance and calls your handler
/// 4. If invalid: returns 401 Unauthorized without calling your handler
///
/// # Type Safety Guarantee
///
/// If your handler receives an `RUser` parameter, the user is **guaranteed**
/// to be authenticated. No manual validation needed!
///
/// # Example
///
/// ```rust,no_run
/// use actix_web::{get, HttpResponse};
/// use r_token::RUser;
///
/// #[get("/profile")]
/// async fn profile(user: RUser) -> impl actix_web::Responder {
///     // If we reach here, authentication succeeded
///     HttpResponse::Ok().body(format!("User ID: {}", user.id))
/// }
/// ```
///
/// # Error Responses
///
/// - **401 Unauthorized**: Token missing, invalid, or expired
/// - **500 Internal Server Error**: [`RTokenManager`] not registered in app_data
///
/// [`FromRequest`]: actix_web::FromRequest
#[derive(Debug)]
pub struct RUser {
    /// The user's unique identifier.
    ///
    /// This corresponds to the ID passed to [`RTokenManager::login()`].
    pub id: String,

    /// The authentication token.
    ///
    /// Extracted from the `Authorization` request header.
    pub token: String,
}

/// Implementation of actix-web's `FromRequest` trait for automatic authentication.
///
/// This implementation enables the "parameter-as-authentication" pattern.
///
/// # Validation Flow
///
/// When actix-web processes a request with an `RUser` parameter:
///
/// 1. **Retrieve Manager**: Extracts `RTokenManager` from app_data
/// 2. **Extract Token**: Reads the `Authorization` header (supports `Bearer` prefix)
/// 3. **Validate Token**: Checks if the token exists in the manager's storage
/// 4. **Return Result**:
///    - **Success**: Creates `RUser` and calls the handler
///    - **Failure**: Returns error response without calling the handler
///
/// # Error Responses
///
/// - `500 Internal Server Error`: `RTokenManager` not found in app_data or mutex poisoned
/// - `401 Unauthorized`: Token missing or invalid
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
                return ready(Ok(RUser {
                    id: id.clone(),
                    token: token.clone(),
                }));
            }
            None => {
                return ready(Err(actix_web::error::ErrorUnauthorized("Invalid token")));
            }
        }
    }
}

