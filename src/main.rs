//! # r-token example server
//!
//! ## 日本語
//!
//! `r_token` の使い方を示す最小構成の actix-web サンプルです：
//! - token を発行（login）
//! - `RUser` extractor でエンドポイントを保護
//! - token を失効（logout）
//!
//! ### 実行
//!
//! ```bash
//! cargo run
//! ```
//!
//! ### 試す（curl）
//!
//! ```bash
//! curl -X POST http://127.0.0.1:8080/login
//! curl -H "Authorization: <token>" http://127.0.0.1:8080/info
//! curl -X POST -H "Authorization: <token>" http://127.0.0.1:8080/logout
//! ```
//!
//! ## English
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

use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpResponse, HttpServer, get, post, web};
use r_token::{RTokenManager, RUser};

/// ## 日本語
///
/// token を発行し、レスポンス body として返します。
///
/// 簡単のため、このサンプルでは固定のユーザー ID と TTL を使用します。
///
/// ## English
///
/// Issues a token and returns it as the response body.
///
/// The example uses a fixed user id and TTL for simplicity.
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
                .secure(true)
                .same_site(SameSite::Lax)
                .finish(),
        )
        .body(token))
}

/// ## 日本語
///
/// 保護されたエンドポイントです。
///
/// 有効な `Authorization` header が必要です。抽出が成功すると `user.id` を利用できます。
///
/// ## English
///
/// A protected endpoint.
///
/// Access requires a valid `Authorization` header; if extraction succeeds,
/// `user.id` is available.
#[get("/info")]
async fn do_info(user: RUser) -> impl actix_web::Responder {
    format!("info: {}", user.id)
}

/// ## 日本語
///
/// 現在の token を失効させます。
///
/// このエンドポイント自体も保護されています。成功すると token はストアから削除されます。
///
/// ## English
///
/// Revokes the current token.
///
/// This endpoint is protected; on success, the token is removed from the store.
#[post("/logout")]
async fn do_logout(
    manager: web::Data<crate::RTokenManager>,
    user: RUser,
) -> Result<HttpResponse, r_token::RTokenError> {
    manager.logout(&user.token)?;
    Ok(HttpResponse::Ok().body("logout success"))
}

/// ## 日本語
///
/// サンプルサーバーを起動します。
///
/// ## English
///
/// Starts the example server.
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 日本語: r-token マネージャを初期化する（アプリ全体で共有する想定）
    // English: Initialize the r-token manager (shared application state)
    let r_manager = r_token::RTokenManager::new();

    println!("🚀 r-token server started at http://127.0.0.1:8080");
    println!("📖 Try:");
    println!("   POST http://127.0.0.1:8080/login");
    println!("   GET  http://127.0.0.1:8080/info  (with Authorization header)");
    println!("   POST http://127.0.0.1:8080/logout (with Authorization header)");

    HttpServer::new(move || {
        actix_web::App::new()
            // 日本語: マネージャを app state に注入する（handler は web::Data<RTokenManager> 経由で参照）
            // English: Inject the manager into app state (handlers access via web::Data<RTokenManager>)
            .app_data(web::Data::new(r_manager.clone()))
            // 日本語: ルート登録
            // English: Register routes
            .service(do_login)
            .service(do_info)
            .service(do_logout)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
