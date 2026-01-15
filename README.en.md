# r-token

README: [日本語](README.md) | English (this page)

**r-token** is a token authentication helper for Rust. It supports both `actix-web` and `axum`: declare an extractor (`RUser` / `RRedisUser`) as a handler parameter, and you get an authenticated request context without manual token parsing.

It provides two backends:

- **In-memory**: `RTokenManager` (expiration tracked as an absolute timestamp in Unix epoch milliseconds)
- **Redis/Valkey** (optional): `RTokenRedisManager` (expiration enforced by Redis TTL seconds)

## Highlights

- **Extractor-first**: protect routes by declaring `RUser` / `RRedisUser`
- **Low boilerplate**: no custom middleware needed for header/cookie auth
- **TTL support**: in-memory TTL and Redis TTL
- **Configurable token sources**: control header/cookie names and priority via `TokenSourceConfig`
- **RBAC (optional)**: assign and validate roles (`rbac` feature)

## Security notes

- This is bearer-token auth. Always use HTTPS in production.
- Token strings grant access. Treat them like passwords: do not log them, and do not store them in plaintext client storage without careful threat modeling.
- The Redis backend stores `user_id` as the Redis value (JSON when RBAC is enabled). If Redis data disclosure is a concern, consider storing a hashed token as the key (not implemented by this crate yet).

## Installation

```toml
[dependencies]
r-token = "1.1.0"
```

## Feature flags

r-token uses Cargo features to keep dependencies optional:

- `actix` (default): actix-web integration (extractors for actix)
- `axum`: axum integration (extractors for axum)
- `redis`: Redis/Valkey backend (requires Tokio runtime)
- `redis-actix`: convenience feature = `redis` + `actix`
- `redis-axum`: convenience feature = `redis` + `axum`
- `rbac`: role-based access control support (Serde)

Examples:

```toml
[dependencies]
r-token = { version = "1.1.0", default-features = false, features = ["axum"] }
```

```toml
[dependencies]
r-token = { version = "1.1.0", features = ["redis-actix"] }
```

```toml
[dependencies]
r-token = { version = "1.1.0", features = ["redis-axum", "rbac"] }
```

## Where tokens come from

By default, tokens are read from `Authorization` header and/or cookies.

Supported header formats:

```text
Authorization: <token>
Authorization: Bearer <token>
```

Cookies are searched by name (default includes `r_token` and `token`). You can control names and priority via `TokenSourceConfig`.

## Quickstart (actix-web / in-memory)

No manual parsing: declare `RUser` in protected handlers.

```rust
use actix_web::{get, post, web, HttpResponse, Responder};
use r_token::{RTokenError, RTokenManager, RUser};

#[post("/login")]
async fn login(manager: web::Data<RTokenManager>, body: String) -> Result<impl Responder, RTokenError> {
    let token = manager.login(body.trim(), 3600)?;
    Ok(HttpResponse::Ok().body(token))
}

#[get("/profile")]
async fn profile(user: RUser) -> impl Responder {
    format!("Profile: {}", user.id)
}

#[post("/logout")]
async fn logout(manager: web::Data<RTokenManager>, user: RUser) -> Result<impl Responder, RTokenError> {
    manager.logout(&user.token)?;
    Ok(HttpResponse::Ok().body("Logged out"))
}
```

Register the manager in Actix application state:

```rust
use actix_web::{web, App, HttpServer};
use r_token::RTokenManager;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let manager = RTokenManager::new();
    HttpServer::new(move || App::new().app_data(web::Data::new(manager.clone())))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
```

## Quickstart (axum / in-memory)

Inject the manager via `Extension`; `RUser` works as a handler parameter.

```rust
use axum::{Router, extract::Extension, routing::get};
use r_token::{RTokenManager, RUser};

async fn profile(user: RUser) -> String {
    format!("Profile: {}", user.id)
}

#[tokio::main]
async fn main() {
    let manager = RTokenManager::new();
    let app = Router::new().route("/profile", get(profile)).layer(Extension(manager));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8082").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## Redis/Valkey (token persistence)

`RTokenRedisManager` is async and requires a Tokio runtime. In both actix-web and axum, you can use the `RRedisUser` extractor when `redis` + (`actix` or `axum`) are enabled.

Minimal Tokio dependency if your application doesn’t already have it:

```toml
[dependencies]
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## TokenSourceConfig (header/cookie names and priority)

actix-web:

```rust
use actix_web::{web, App};
use r_token::{TokenSourceConfig, TokenSourcePriority};

let cfg = TokenSourceConfig {
    priority: TokenSourcePriority::CookieFirst,
    header_names: vec!["Authorization".to_string()],
    cookie_names: vec!["r_token".to_string()],
};

App::new().app_data(web::Data::new(cfg));
```

axum:

```rust
use axum::{Router, extract::Extension};
use r_token::{TokenSourceConfig, TokenSourcePriority};

let cfg = TokenSourceConfig {
    priority: TokenSourcePriority::CookieFirst,
    header_names: vec!["Authorization".to_string()],
    cookie_names: vec!["r_token".to_string()],
};

Router::new().layer(Extension(cfg));
```

## RBAC (roles)

Enable the `rbac` feature to attach roles to tokens.

- In-memory: `RTokenManager::login_with_roles` / `set_roles` / `get_roles`, plus `RUser.roles` and `RUser::has_role`
- Redis: `RTokenRedisManager::login_with_roles` / `set_roles` / `get_roles` / `validate_with_roles`, plus `RRedisUser.roles`

## Example servers in this repo

In-memory (actix-web, port 8080):

```bash
cargo run --bin r-token
```

Redis/Valkey (actix-web, port 8081):

```bash
REDIS_URL=redis://127.0.0.1/ R_TOKEN_PREFIX=r_token:token: \
  cargo run --bin r-token-redis --features redis-actix
```

In-memory (axum, port 8082):

```bash
cargo run --bin r-token-axum --features axum
```

Redis/Valkey (axum, port 8083):

```bash
REDIS_URL=redis://127.0.0.1/ R_TOKEN_PREFIX=r_token:token: \
  cargo run --bin r-token-redis-axum --features redis-axum
```

## License

MIT
