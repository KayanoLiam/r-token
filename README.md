# r-token

**r-token** is a lightweight, zero-boilerplate authentication library designed for Rust and `actix-web`.

Inspired by the "parameter-as-authentication" pattern, it enables secure authentication by simply adding typed extractors to your route handlers.

## Features

-   **Zero Boilerplate**: No manual token validation or complex middleware configuration required.
-   **Type-Safe Authentication**: Leverages Actix's `Extractor` mechanism. If an `RUser` parameter is present, the request is guaranteed to be authenticated.
-   **Thread-Safe**: Built on `Arc` and `Mutex` for safe concurrent token management.
-   **Non-Invasive**: easily integrates into existing Actix applications.

## Installation

Add r-token to your `Cargo.toml`:

```toml
[dependencies]
r-token = "0.1"
actix-web = "4"
```

## Quick Start

### 1. Implement Authentication Logic

No manual parsing is needed. Simply inject `RUser` into your protected handlers.

```rust
use actix_web::{get, post, web, HttpResponse, Responder};
use r_token::{RTokenManager, RUser, RTokenError};

// --- Login Endpoint ---
// Injects the manager to generate and return a token
#[post("/login")]
async fn login(
    manager: web::Data<RTokenManager>
) -> Result<impl Responder, RTokenError> {
    let user_id = "user_123";
    let token = manager.login(user_id)?;
    Ok(HttpResponse::Ok().body(token))
}

// --- Protected Endpoint ---
// The presence of RUser guarantees authentication.
// Unauthenticated requests are automatically rejected with 401 Unauthorized.
#[get("/profile")]
async fn profile(user: RUser) -> impl Responder {
    format!("Welcome, User ID: {}", user.id)
}

// --- Logout Endpoint ---
// Requires both Manager (state) and RUser (auth context)
#[post("/logout")]
async fn logout(
    manager: web::Data<RTokenManager>,
    user: RUser,
) -> Result<impl Responder, RTokenError> {
    manager.logout(&user.token)?;
    Ok(HttpResponse::Ok().body("Logged out successfully"))
}
```

### 2. Register and Run

Initialize `RTokenManager` and register it with your Actix application.

```rust
use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let manager = RTokenManager::new();

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(manager.clone()))
            .service(login)
            .service(profile)
            .service(logout)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

## Usage Examples

### Login

```bash
curl -X POST http://127.0.0.1:8080/login
# Response: 550e8400-e29b-41d4-a716-446655440000
```

### Access Protected Resource

```bash
# Without Token -> 401 Unauthorized
curl http://127.0.0.1:8080/profile

# With Token -> 200 OK
curl -H "Authorization: <token>" http://127.0.0.1:8080/profile
```

## Roadmap

-   [x] Basic In-Memory Token Management
-   [x] `Authorization` Header Support
-   [ ] Token Expiration (TTL)
-   [ ] Persistent Storage (Redis)
-   [ ] Role-Based Access Control (RBAC)
-   [ ] Cookie Support

## License

MIT