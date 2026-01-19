//! ## 日本語
//!
//! r-token の Redis/Valkey 版を axum で使う最小サンプルです。
//!
//! 環境変数：
//! - `REDIS_URL`（デフォルト：`redis://127.0.0.1/`）
//! - `R_TOKEN_PREFIX`（デフォルト：`r_token:token:`）
//!
//! ## English
//!
//! Minimal axum example for the Redis/Valkey-backed r-token manager.
//!
//! Environment variables:
//! - `REDIS_URL` (default: `redis://127.0.0.1/`)
//! - `R_TOKEN_PREFIX` (default: `r_token:token:`)

use axum::{
    Router,
    extract::Extension,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use cookie::{Cookie, SameSite};
use r_token::{RRedisUser, RTokenRedisManager, TOKEN_COOKIE_NAME};

async fn login(
    Extension(manager): Extension<RTokenRedisManager>,
    body: String,
) -> Result<Response, Response> {
    let user_id = body.trim();
    if user_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty user id").into_response());
    }

    let token = manager
        .login(user_id, 3600)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Redis error").into_response())?;

    let mut resp = token.clone().into_response();
    let cookie = Cookie::build((TOKEN_COOKIE_NAME, token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();
    let cookie = HeaderValue::from_str(cookie.to_string().as_str())
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid cookie").into_response())?;
    resp.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(resp)
}

async fn info(user: RRedisUser) -> impl IntoResponse {
    #[cfg(feature = "rbac")]
    {
        format!("info: user_id={}, roles={:?}", user.id, user.roles)
    }
    #[cfg(not(feature = "rbac"))]
    {
        format!("info: {}", user.id)
    }
}

async fn logout(
    Extension(manager): Extension<RTokenRedisManager>,
    user: RRedisUser,
) -> Result<&'static str, Response> {
    manager
        .logout(&user.token)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Redis error").into_response())?;
    Ok("Logged out")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string());
    let prefix = std::env::var("R_TOKEN_PREFIX").unwrap_or_else(|_| "r_token:token:".to_string());

    let manager = RTokenRedisManager::connect(&redis_url, prefix)
        .await
        .map_err(|_| std::io::Error::other("Redis connect failed"))?;

    let app = Router::new()
        .route("/login", post(login))
        .route("/info", get(info))
        .route("/logout", post(logout))
        .layer(Extension(manager));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8083").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
