#![cfg(feature = "axum")]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use http_body_util::BodyExt;
use r_token::{RTokenManager, RUser, TOKEN_COOKIE_NAME, TokenSourceConfig, TokenSourcePriority};
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[tokio::test]
async fn protected_route_without_token() -> TestResult {
    async fn protected(user: RUser) -> impl IntoResponse {
        format!("User: {}", user.id)
    }

    let manager = RTokenManager::new();
    let app = Router::new()
        .route("/protected", get(protected))
        .layer(axum::extract::Extension(manager));

    let req = Request::builder().uri("/protected").body(Body::empty())?;

    let resp = app.oneshot(req).await.map_err(|e| match e {})?;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn protected_route_with_invalid_token() -> TestResult {
    async fn protected(user: RUser) -> impl IntoResponse {
        format!("User: {}", user.id)
    }

    let manager = RTokenManager::new();
    let app = Router::new()
        .route("/protected", get(protected))
        .layer(axum::extract::Extension(manager));

    let req = Request::builder()
        .uri("/protected")
        .header("Authorization", "invalid-token-xyz")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await.map_err(|e| match e {})?;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn protected_route_with_valid_token() -> TestResult {
    async fn protected(user: RUser) -> impl IntoResponse {
        format!("User: {}", user.id)
    }

    let manager = RTokenManager::new();
    let token = manager.login("test_user", 3600)?;
    let app = Router::new()
        .route("/protected", get(protected))
        .layer(axum::extract::Extension(manager));

    let req = Request::builder()
        .uri("/protected")
        .header("Authorization", token.as_str())
        .body(Body::empty())?;

    let resp = app.oneshot(req).await.map_err(|e| match e {})?;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
        .to_bytes();
    let body = std::str::from_utf8(body.as_ref())?;
    assert_eq!(body, "User: test_user");
    Ok(())
}

#[tokio::test]
async fn protected_route_with_bearer_token() -> TestResult {
    async fn protected(user: RUser) -> impl IntoResponse {
        format!("User: {}", user.id)
    }

    let manager = RTokenManager::new();
    let token = manager.login("bearer_user", 3600)?;
    let app = Router::new()
        .route("/protected", get(protected))
        .layer(axum::extract::Extension(manager));

    let req = Request::builder()
        .uri("/protected")
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())?;

    let resp = app.oneshot(req).await.map_err(|e| match e {})?;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
        .to_bytes();
    let body = std::str::from_utf8(body.as_ref())?;
    assert_eq!(body, "User: bearer_user");
    Ok(())
}

#[tokio::test]
async fn protected_route_with_cookie_token() -> TestResult {
    async fn protected(user: RUser) -> impl IntoResponse {
        format!("User: {}", user.id)
    }

    let manager = RTokenManager::new();
    let token = manager.login("cookie_user", 3600)?;
    let app = Router::new()
        .route("/protected", get(protected))
        .layer(axum::extract::Extension(manager));

    let req = Request::builder()
        .uri("/protected")
        .header(header::COOKIE, format!("{}={}", TOKEN_COOKIE_NAME, token))
        .body(Body::empty())?;

    let resp = app.oneshot(req).await.map_err(|e| match e {})?;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
        .to_bytes();
    let body = std::str::from_utf8(body.as_ref())?;
    assert_eq!(body, "User: cookie_user");
    Ok(())
}

#[tokio::test]
async fn authorization_header_takes_precedence_over_cookie() -> TestResult {
    async fn protected(user: RUser) -> impl IntoResponse {
        format!("User: {}", user.id)
    }

    let manager = RTokenManager::new();
    let token = manager.login("cookie_user_2", 3600)?;
    let app = Router::new()
        .route("/protected", get(protected))
        .layer(axum::extract::Extension(manager));

    let req = Request::builder()
        .uri("/protected")
        .header("Authorization", "invalid-token-xyz")
        .header(header::COOKIE, format!("{}={}", TOKEN_COOKIE_NAME, token))
        .body(Body::empty())?;

    let resp = app.oneshot(req).await.map_err(|e| match e {})?;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn token_source_config_cookie_first_can_override_header() -> TestResult {
    async fn protected(user: RUser) -> impl IntoResponse {
        format!("User: {}", user.id)
    }

    let manager = RTokenManager::new();
    let token = manager.login("cookie_first_user", 3600)?;
    let cfg = TokenSourceConfig {
        priority: TokenSourcePriority::CookieFirst,
        header_names: vec!["Authorization".to_string()],
        cookie_names: vec![TOKEN_COOKIE_NAME.to_string()],
    };

    let app = Router::new()
        .route("/protected", get(protected))
        .layer(axum::extract::Extension(cfg))
        .layer(axum::extract::Extension(manager));

    let req = Request::builder()
        .uri("/protected")
        .header("Authorization", "invalid-token-xyz")
        .header(header::COOKIE, format!("{}={}", TOKEN_COOKIE_NAME, token))
        .body(Body::empty())?;

    let resp = app.oneshot(req).await.map_err(|e| match e {})?;
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
        .to_bytes();
    let body = std::str::from_utf8(body.as_ref())?;
    assert_eq!(body, "User: cookie_first_user");
    Ok(())
}

#[tokio::test]
async fn missing_manager_returns_500() -> TestResult {
    async fn protected(user: RUser) -> impl IntoResponse {
        format!("User: {}", user.id)
    }

    let app = Router::new().route("/protected", get(protected));

    let req = Request::builder()
        .uri("/protected")
        .header("Authorization", "any")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await.map_err(|e| match e {})?;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}
