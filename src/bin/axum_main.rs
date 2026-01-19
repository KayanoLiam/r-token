//! ## 日本語
//!
//! r-token の in-memory 版を axum で使う最小サンプルです。
//!
//! - `/login`: token 発行（Cookie もセット）
//! - `/profile`: `RUser` extractor による保護
//! - `/logout`: token 失効
//!
//! ## English
//!
//! Minimal axum example for the in-memory r-token manager.
//!
//! - `/login`: issues a token (also sets a cookie)
//! - `/profile`: protected via the `RUser` extractor
//! - `/logout`: revokes the token

use axum::{
    Router,
    extract::Extension,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use cookie::{Cookie, SameSite};
use r_token::{RTokenError, RTokenManager, RUser, TOKEN_COOKIE_NAME};

async fn login(
    Extension(manager): Extension<RTokenManager>,
    body: String,
) -> Result<Response, Response> {
    let user_id = body.trim();
    if user_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty user id").into_response());
    }

    let token = manager
        .login(user_id, 3600)
        .map_err(|e: RTokenError| e.into_response())?;

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

async fn profile(user: RUser) -> impl IntoResponse {
    format!("Profile: {}", user.id)
}

async fn logout(
    Extension(manager): Extension<RTokenManager>,
    user: RUser,
) -> Result<&'static str, RTokenError> {
    manager.logout(&user.token)?;
    Ok("Logged out")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let manager = RTokenManager::new();
    let app = Router::new()
        .route("/login", post(login))
        .route("/profile", get(profile))
        .route("/logout", post(logout))
        .layer(Extension(manager));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8082").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
