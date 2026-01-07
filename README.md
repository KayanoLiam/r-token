# r-token

**r-token** is a small, in-memory token authentication helper for Rust + `actix-web`.

It follows a “parameter-as-authentication” style: add `RUser` to your handler parameters, and the request is authenticated automatically via Actix extractors.

## Features

- **Zero boilerplate**: no custom middleware required for basic header auth.
- **Extractor-first**: declaring `RUser` protects the route.
- **Thread-safe, shared state**: `RTokenManager` is `Clone` and shares an in-memory store.
- **TTL support**: tokens expire based on a per-login TTL (seconds).

> **⚠️ Production Warning**
>
> This project is currently in active development and is **not recommended for production use**. The API may change, and there may be security vulnerabilities that have not been discovered or addressed. Please use this library at your own risk.

> **📝 Documentation Notice**
>
> This project is in active development, and the documentation on [docs.rs](https://docs.rs/r-token/latest/r_token/) and this README may not always be up-to-date. Please refer to the source code for the most accurate and current information. This will be resolved when a stable release is published.

## Installation

Add r-token to your `Cargo.toml`:

```toml
[dependencies]
r-token = "0.1.4"
```

## Quick Start

### 1. Add endpoints

No manual header parsing is needed. Inject `RUser` into protected handlers.

```rust
use actix_web::{get, post, web, HttpResponse, Responder};
use r_token::{RTokenManager, RUser, RTokenError};

#[post("/login")]
async fn login(manager: web::Data<RTokenManager>) -> Result<impl Responder, RTokenError> {
    let user_id = "user_123";
    let token = manager.login(user_id, 3600)?;
    Ok(HttpResponse::Ok().body(token))
}

#[get("/profile")]
async fn profile(user: RUser) -> impl Responder {
    format!("Welcome, User ID: {}", user.id)
}

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
use r_token::RTokenManager;

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

## Authorization header

The extractor reads the token from `Authorization` and supports:

```text
Authorization: <token>
Authorization: Bearer <token>
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
-   [x] Token Expiration (TTL)
-   [ ] Persistent Storage (Redis)
-   [ ] Role-Based Access Control (RBAC)
-   [ ] Cookie Support

## License

MIT
