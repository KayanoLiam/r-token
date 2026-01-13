# r-token

**r-token** is a small token authentication helper for Rust and `actix-web`.

It provides two token managers:

- **In-memory**: `RTokenManager` stores tokens in memory with an expiration timestamp.
- **Redis/Valkey** (optional): `RTokenRedisManager` stores tokens in Redis with TTL.

For `actix-web`, r-token follows a “parameter-as-authentication” style: add `RUser` to handler parameters, and the request is authenticated automatically via the Actix extractor mechanism.

## Features

- **Zero boilerplate**: no custom middleware required for basic header auth.
- **Extractor-first**: declaring `RUser` protects the route.
- **Thread-safe, shared state**: `RTokenManager` is `Clone` and shares an in-memory store.
- **TTL support**:
  - In-memory: tokens expire based on a per-login TTL (seconds).
  - Redis/Valkey: expiration is enforced by Redis TTL (seconds).
- **Redis/Valkey backend (optional)**: `RTokenRedisManager` stores `user_id` by token key.

## Security notes

- This library implements bearer-token authentication. Always use HTTPS in production.
- Token strings grant access. Treat them like passwords: do not log them, do not store them in plaintext client storage without careful threat modeling.
- The Redis backend stores `user_id` as the Redis value. If you need stronger protection against Redis data disclosure, consider storing a hashed token (not currently implemented by this crate).

## Status

This project is in active development. Review the source code and tests before adopting it in security-sensitive environments.

This project has not yet released version 1.0.0 and is not recommended for use in any production-level projects. The current state should be considered experimental and potentially unstable.

Please note that this project has not been officially released. Both the documentation on docs.rs and this README file may not always reflect the latest changes in the source code. Always refer to the actual source code for the most accurate information. This documentation inconsistency will be resolved upon official release.

## Installation

Add r-token to your `Cargo.toml`:

```toml
[dependencies]
r-token = "0.1.5"
```

## Feature flags

r-token uses Cargo features to keep dependencies optional:

- `actix` (default): enables the `RUser` extractor and actix-web integration.
- `redis`: enables Redis/Valkey support via the `redis` crate.
- `redis-actix`: convenience feature = `redis` + `actix`.
- `rbac`: enables role-based access control (RBAC) support.

Examples:

```toml
[dependencies]
r-token = { version = "0.1.5", default-features = false }
```

```toml
[dependencies]
r-token = { version = "0.1.5", features = ["redis-actix"] }
```

```toml
[dependencies]
r-token = { version = "0.1.5", features = ["rbac"] }
```

```toml
[dependencies]
r-token = { version = "0.1.5", features = ["redis-actix", "rbac"] }
```

## Authorization header

The `RUser` extractor (and the Redis example server) reads the token from `Authorization` and supports:

```text
Authorization: <token>
Authorization: Bearer <token>
```

## API overview

Core types:

- `RTokenManager` (always available): issues and revokes tokens in memory.
- `RTokenError` (always available): error type used by in-memory manager.

Actix integration (requires `actix`, enabled by default):

- `RUser`: `actix_web::FromRequest` extractor that validates `Authorization`.

Redis backend (requires `redis`):

- `RTokenRedisManager`: issues, validates, and revokes tokens backed by Redis/Valkey.

RBAC support (requires `rbac`):

- `RTokenManager::login_with_roles()`: issues a token with associated roles.
- `RTokenManager::set_roles()`: updates roles for an existing token.
- `RTokenManager::get_roles()`: retrieves roles for a token.
- `RUser.roles`: vector of roles associated with the authenticated user.
- `RUser::has_role()`: checks if the user has a specific role.
- `RTokenRedisManager::login_with_roles()`: issues a token with roles in Redis.
- `RTokenRedisManager::set_roles()`: updates roles for a token in Redis.
- `RTokenRedisManager::get_roles()`: retrieves roles for a token in Redis.
- `RTokenRedisManager::validate()`: returns both `user_id` and `roles` when RBAC is enabled.

## In-memory usage (actix-web)

### 1. Add endpoints

No manual header parsing is needed. Inject `RUser` into protected handlers.

```rust
use actix_web::{get, post, web, HttpResponse, Responder};
use r_token::{RTokenManager, RUser, RTokenError};

#[post("/login")]
async fn login(
    manager: web::Data<RTokenManager>,
    body: String,
) -> Result<impl Responder, RTokenError> {
    let token = manager.login(&body, 3600)?;
    Ok(HttpResponse::Ok().body(token))
}

#[get("/info")]
async fn info(user: RUser) -> impl Responder {
    format!("info: {}", user.id)
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
            .service(info)
            .service(logout)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

## RBAC usage (role-based access control)

When the `rbac` feature is enabled, you can assign roles to tokens and perform role-based authorization.

### In-memory RBAC

```rust
use r_token::{RTokenManager, RUser, RTokenError};
use actix_web::{get, post, web, HttpResponse, Responder};

#[post("/login")]
async fn login(
    manager: web::Data<RTokenManager>,
    body: String,
) -> Result<impl Responder, RTokenError> {
    // Parse user_id and roles from request body
    let parts: Vec<&str> = body.split(':').collect();
    let user_id = parts[0];
    let roles: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

    let token = manager.login_with_roles(user_id, 3600, roles)?;
    Ok(HttpResponse::Ok().body(token))
}

#[get("/admin")]
async fn admin_only(user: RUser) -> impl Responder {
    if user.has_role("admin") {
        HttpResponse::Ok().body(format!("Welcome, admin {}", user.id))
    } else {
        HttpResponse::Forbidden().body("Access denied: admin role required")
    }
}

#[post("/promote")]
async fn promote(
    manager: web::Data<RTokenManager>,
    user: RUser,
) -> Result<impl Responder, RTokenError> {
    // Only admins can promote users
    if !user.has_role("admin") {
        return Ok(HttpResponse::Forbidden().body("Access denied"));
    }

    // Add 'moderator' role to the current user
    manager.set_roles(&user.token, vec!["admin".to_string(), "moderator".to_string()])?;
    Ok(HttpResponse::Ok().body("Promoted to moderator"))
}

#[get("/roles")]
async fn get_user_roles(user: RUser) -> impl Responder {
    HttpResponse::Ok().json(&user.roles)
}
```

### Redis RBAC

```rust
use r_token::RTokenRedisManager;

#[tokio::main]
async fn main() -> Result<(), redis::RedisError> {
    let manager = RTokenRedisManager::connect("redis://127.0.0.1/", "r_token:token:")
        .await?;

    // Create token with roles
    let roles = vec!["admin".to_string(), "editor".to_string()];
    let token = manager.login_with_roles("alice", 3600, roles).await?;

    // Validate and get user info with roles
    let user_info = manager.validate(&token).await?;
    if let Some((user_id, retrieved_roles)) = user_info {
        println!("User: {}, Roles: {:?}", user_id, retrieved_roles);
    }

    // Update roles
    manager.set_roles(&token, vec!["admin".to_string()]).await?;

    // Get roles only
    let roles = manager.get_roles(&token).await?;
    println!("Roles: {:?}", roles);

    manager.logout(&token).await?;
    Ok(())
}
```

## Behavioral details

In-memory manager:

- `RTokenManager::login(user_id, ttl_seconds)` returns a UUID v4 token string.
- Expiration is tracked by storing an absolute expiration timestamp (milliseconds since Unix epoch).
- `RTokenManager::logout(token)` is idempotent: revoking a non-existent token is treated as success.

Actix extractor:

- On success, `RUser` provides `id` and the raw `token`.
- When RBAC is enabled, `RUser` also provides `roles` (a vector of role strings).
- `RUser::has_role(role)` checks if the user has a specific role.
- Failure modes:
  - `401 Unauthorized`: missing token, invalid token, or expired token.
  - `500 Internal Server Error`: token manager missing from `app_data`, or internal mutex poisoned.

Redis manager:

- `RTokenRedisManager::login(user_id, ttl_seconds)` stores `prefix + token` as the key and `user_id` as the value, with Redis TTL set to `ttl_seconds`.
- `validate(token)` returns `Ok(None)` when the key is absent (revoked or expired).
- When RBAC is enabled, `validate(token)` returns `Ok(Some((user_id, roles)))` with both user ID and roles.
- `logout(token)` deletes the key and is idempotent.

RBAC behavior:

- Tokens can be created with roles via `login_with_roles()`.
- Roles can be updated on existing tokens via `set_roles()`.
- Roles can be retrieved via `get_roles()`.
- `RUser.roles` is always available (empty vector if no roles were assigned).
- `RUser::has_role()` performs a case-sensitive string comparison.

## Redis/Valkey usage

If you want token persistence and Redis-managed TTL expiration, enable `redis` (or `redis-actix`) and use `RTokenRedisManager`.

You also need a Tokio runtime in your application (do not rely on transitive dependencies):

```toml
[dependencies]
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use r_token::RTokenRedisManager;

#[tokio::main]
async fn main() -> Result<(), redis::RedisError> {
    let manager = RTokenRedisManager::connect("redis://127.0.0.1/", "r_token:token:")
        .await?;

    let token = manager.login("alice", 3600).await?;
    let user_id = manager.validate(&token).await?;
    assert_eq!(user_id.as_deref(), Some("alice"));

    manager.logout(&token).await?;
    Ok(())
}
```

## Usage examples (curl)

### Login

```bash
curl -X POST http://127.0.0.1:8080/login -d "alice"
# Response: 550e8400-e29b-41d4-a716-446655440000
```

### Access Protected Resource

```bash
# Without Token -> 401 Unauthorized
curl http://127.0.0.1:8080/info

# With Token -> 200 OK
curl -H "Authorization: <token>" http://127.0.0.1:8080/info
```

## Example servers in this repo

### In-memory (actix-web)

```bash
cargo run --bin r-token
```

### Redis/Valkey (actix-web)

Environment variables:

- `REDIS_URL` (default: `redis://127.0.0.1/`)
- `R_TOKEN_PREFIX` (default: `r_token:token:`)

```bash
REDIS_URL=redis://127.0.0.1/ cargo run --bin r-token-redis --features redis-actix
```

## Roadmap

- [x] In-memory token management + extractor
- [x] Token expiration (TTL)
- [x] Redis/Valkey backend token storage (optional)
- [x] Role-based access control (RBAC)
- [ ] Cookie support

## License

MIT
