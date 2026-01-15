# r-token

README: [日本語](README.md) | English (this page)

**r-token** is a token authentication helper for Rust. It supports both `actix-web` and `axum`: declare an extractor (`RUser` / `RRedisUser`) as a handler parameter, and you get an authenticated request context without manual token parsing.

This crate provides authentication primitives:

- issue tokens (login)
- validate tokens (extractors / validate)
- revoke tokens (logout)
- expire tokens automatically via TTL (in-memory / Redis)
- optionally attach roles (RBAC)

It provides two backends:

- **In-memory**: `RTokenManager` (expiration tracked as an absolute timestamp in Unix epoch milliseconds)
- **Redis/Valkey** (optional): `RTokenRedisManager` (expiration enforced by Redis TTL seconds)

## Table of contents

- [Highlights](#highlights)
- [Compatibility matrix](#compatibility-matrix)
- [Security notes](#security-notes)
- [Installation](#installation)
- [Feature flags](#feature-flags)
- [What should I pick? (cheat sheet)](#what-should-i-pick-cheat-sheet)
- [Authentication flow](#authentication-flow)
- [Where tokens come from (Header / Cookie)](#where-tokens-come-from-header--cookie)
- [Quickstart: actix-web (in-memory)](#quickstart-actix-web-in-memory)
- [Quickstart: axum (in-memory)](#quickstart-axum-in-memory)
- [Redis/Valkey backend](#redisvalkey-backend)
- [RBAC (roles)](#rbac-roles)
- [TTL operations (renew / rotate / ttl_seconds)](#ttl-operations-renew--rotate--ttl_seconds)
- [Errors and HTTP status codes](#errors-and-http-status-codes)
- [Example servers in this repo](#example-servers-in-this-repo)
- [Tests](#tests)
- [FAQ / troubleshooting](#faq--troubleshooting)
- [License](#license)

## Highlights

- **Extractor-first**: protect routes by declaring `RUser` / `RRedisUser`
- **Low boilerplate**: no custom middleware needed for header/cookie auth
- **TTL support**: in-memory TTL and Redis TTL
- **Configurable token sources**: control header/cookie names and priority via `TokenSourceConfig`
- **RBAC (optional)**: attach and validate roles (`rbac` feature)
- **Valkey compatible**: works with Redis-compatible protocol via the `redis` crate

## Compatibility matrix

| Goal | In-memory | Redis/Valkey |
|---|---:|---:|
| actix-web extractor | `RUser` | `RRedisUser` (`redis-actix`) |
| axum extractor | `RUser` | `RRedisUser` (`redis-axum`) |
| expiration model | app-side (deadline ms, cleaned on validate/prune) | server-side (Redis TTL seconds) |
| roles (RBAC) | `rbac` feature | `rbac` feature (value is JSON) |

## Security notes

- This is bearer-token auth. Always use HTTPS in production.
- Token strings grant access. Treat them like passwords: do not log them, and do not store them in plaintext client storage without careful threat modeling.
- If you transport tokens via cookies, consider `Secure` / `HttpOnly` / `SameSite` (examples keep cookies minimal and only set `HttpOnly`).
- The Redis backend stores `user_id` as the Redis value (JSON when RBAC is enabled). If Redis data disclosure is a concern, consider storing a hashed token as the key (not implemented by this crate yet).

## Installation

```toml
[dependencies]
r-token = "1.1.0"
```

For MSRV (minimum supported Rust version), see `rust-version` in `Cargo.toml`.

## Feature flags

r-token uses Cargo features to keep dependencies optional:

- `actix` (default): actix-web integration (extractors for actix)
- `axum`: axum integration (extractors for axum, requires Tokio)
- `redis`: Redis/Valkey backend (requires Tokio)
- `redis-actix`: convenience feature = `redis` + `actix`
- `redis-axum`: convenience feature = `redis` + `axum`
- `rbac`: role-based access control support (Serde)

Examples:

```toml
[dependencies]
r-token = { version = "1.1.0", default-features = false, features = ["actix"] }
```

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

## What should I pick? (cheat sheet)

- **actix-web + in-memory**: `r-token = "1.1.0"` (default `actix`)
- **axum + in-memory**: `default-features = false, features = ["axum"]`
- **actix-web + Redis/Valkey**: `features = ["redis-actix"]`
- **axum + Redis/Valkey**: `features = ["redis-axum"]`
- **Need roles**: add `rbac` on top

## Authentication flow

Typical API flow:

1. `/login` (public) calls `login(..)` and returns the token (optionally sets a cookie).
2. The client attaches the token to subsequent requests:
   - `Authorization: <token>`
   - `Authorization: Bearer <token>`
   - or cookies (default name is `r_token`)
3. Protected handlers declare `RUser` / `RRedisUser`.
4. If extraction succeeds, the handler can use `user.id` (and `user.roles` if RBAC is enabled).

## Where tokens come from (Header / Cookie)

By default, tokens are read from `Authorization` header and/or cookies.

Supported header formats:

```text
Authorization: <token>
Authorization: Bearer <token>
```

Cookies are searched by name (default includes `r_token` and `token`). You can override the lookup rules via `TokenSourceConfig`:

- `header_names`: header names to check in order (e.g. `Authorization`, `X-Api-Token`)
- `cookie_names`: cookie names to check in order (e.g. `r_token`, `token`)
- `priority`: HeaderFirst / CookieFirst

Inject configuration via:

- actix-web: `app_data(web::Data<TokenSourceConfig>)`
- axum: `Extension(TokenSourceConfig)`

## Quickstart: actix-web (in-memory)

### 1) Dependency

```toml
[dependencies]
r-token = "1.1.0"
```

### 2) Routes (login / profile / logout)

No manual parsing: declare `RUser` in protected handlers.

```rust
use actix_web::{get, post, web, HttpResponse, Responder};
use r_token::{RTokenError, RTokenManager, RUser};

#[post("/login")]
async fn login(
    manager: web::Data<RTokenManager>,
    body: String,
) -> Result<impl Responder, RTokenError> {
    let user_id = body.trim();
    let token = manager.login(user_id, 3600)?;
    Ok(HttpResponse::Ok().body(token))
}

#[get("/profile")]
async fn profile(user: RUser) -> impl Responder {
    format!("Profile: {}", user.id)
}

#[post("/logout")]
async fn logout(
    manager: web::Data<RTokenManager>,
    user: RUser,
) -> Result<impl Responder, RTokenError> {
    manager.logout(&user.token)?;
    Ok(HttpResponse::Ok().body("Logged out"))
}
```

### 3) Register the manager in Actix application state (required)

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

### 4) Try it (curl)

```bash
token=$(curl -s -X POST http://127.0.0.1:8080/login -d "alice")
curl -s -H "Authorization: $token" http://127.0.0.1:8080/profile
curl -s -X POST -H "Authorization: $token" http://127.0.0.1:8080/logout
```

## Quickstart: axum (in-memory)

### 1) Dependency

```toml
[dependencies]
r-token = { version = "1.1.0", default-features = false, features = ["axum"] }
tokio = { version = "1", features = ["macros", "net", "rt-multi-thread"] }
```

### 2) Routes (login / profile / logout)

Inject the manager via `Extension`; `RUser` works as a handler parameter.

```rust
use axum::{
    Router,
    extract::Extension,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use r_token::{RTokenError, RTokenManager, RUser, TOKEN_COOKIE_NAME};

async fn login(Extension(manager): Extension<RTokenManager>, body: String) -> Result<Response, Response> {
    let user_id = body.trim();
    if user_id.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Empty user id").into_response());
    }

    let token = manager.login(user_id, 3600).map_err(|e: RTokenError| e.into_response())?;

    let mut resp = token.clone().into_response();
    let cookie = format!("{}={}; Path=/; HttpOnly", TOKEN_COOKIE_NAME, token);
    let cookie = HeaderValue::from_str(&cookie)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid cookie").into_response())?;
    resp.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(resp)
}

async fn profile(user: RUser) -> impl IntoResponse {
    format!("Profile: {}", user.id)
}

async fn logout(Extension(manager): Extension<RTokenManager>, user: RUser) -> Result<&'static str, RTokenError> {
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
```

### 3) Try it (curl)

```bash
token=$(curl -s -X POST http://127.0.0.1:8082/login -d "alice")
curl -s -H "Authorization: $token" http://127.0.0.1:8082/profile
curl -s -X POST -H "Authorization: $token" http://127.0.0.1:8082/logout
```

## Redis/Valkey backend

`RTokenRedisManager` is async and requires a Tokio runtime. In both actix-web and axum, you can use the `RRedisUser` extractor when `redis` + (`actix` or `axum`) are enabled.

### Connect

```rust
use r_token::RTokenRedisManager;

let redis_url = "redis://127.0.0.1/";
let prefix = "r_token:token:";
let manager = RTokenRedisManager::connect(redis_url, prefix).await?;
```

The `prefix` is meant to isolate tokens across apps/environments. A trailing `:` is automatically added if missing.

### Use with actix-web

- inject as `web::Data<RTokenRedisManager>`
- protected routes declare `RRedisUser`

See [redis_main.rs](file:///Volumes/P600/r-token/src/bin/redis_main.rs).

### Use with axum

- inject as `Extension(RTokenRedisManager)`
- protected routes declare `RRedisUser`

See [redis_axum_main.rs](file:///Volumes/P600/r-token/src/bin/redis_axum_main.rs).

## RBAC (roles)

Enable the `rbac` feature to attach roles to tokens.

Main APIs:

- In-memory:
  - `RTokenManager::login_with_roles(user_id, ttl, roles)`
  - `RTokenManager::set_roles(token, roles)` (idempotent)
  - `RTokenManager::get_roles(token)`
  - `RUser.roles` / `RUser::has_role(..)`
- Redis:
  - `RTokenRedisManager::login_with_roles(user_id, ttl, roles)`
  - `RTokenRedisManager::set_roles(token, roles)` (idempotent, preserves TTL)
  - `RTokenRedisManager::get_roles(token)`
  - `RTokenRedisManager::validate_with_roles(token)`
  - `RRedisUser.roles`

### Typical authorization pattern

r-token handles authentication. Authorization (e.g. “must have admin role”) is implemented in your app:

```rust
use actix_web::{get, HttpResponse};
use r_token::RUser;

#[get("/admin")]
async fn admin(user: RUser) -> HttpResponse {
    if !user.has_role("admin") {
        return HttpResponse::Forbidden().body("forbidden");
    }
    HttpResponse::Ok().body("ok")
}
```

## TTL operations (renew / rotate / ttl_seconds)

### In-memory (RTokenManager)

- `expires_at(token) -> Option<u64>`: stored deadline (ms); does not validate expiration
- `ttl_seconds(token) -> Option<i64>`: remaining TTL; expired => `Some(0)`
- `renew(token, ttl) -> bool`: extend; expired => removed and returns `false`
- `rotate(token, ttl) -> Option<String>`: issue a new token and revoke the old one
- `prune_expired() -> usize`: remove expired tokens in bulk

### Redis/Valkey (RTokenRedisManager)

- `ttl_seconds(token) -> Option<i64>`: returns Redis TTL semantics
  - `None`: key does not exist
  - `Some(-1)`: key exists but has no expiration
  - `Some(n)` (n >= 0): remaining TTL seconds
- `renew(token, ttl) -> bool`: extend via `EXPIRE`
- `rotate(token, ttl) -> Option<String>`: issue new token then delete old key (not atomic, by design simplicity)

## Errors and HTTP status codes

### `RTokenError`

`RTokenManager` currently returns a single error: `MutexPoisoned`.

- actix-web: implements `actix_web::ResponseError`, so you can return it directly from handlers
- axum: implements `IntoResponse` and returns 500 by default

### extractor failures (401 / 500)

Common failure modes:

- **401 Unauthorized**: missing token / invalid token / expired token
- **500 Internal Server Error**: manager missing from request state (forgot to inject), or internal mutex poisoned

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

## Tests

Basic:

```bash
cargo test
```

All features:

```bash
cargo test --all-features
```

About Redis tests:

- If `REDIS_URL` is not set, tests will attempt to spawn a local `redis-server`.
- On environments without `redis-server`, set `REDIS_URL` to point to an existing Redis/Valkey instance.

## FAQ / troubleshooting

### I get 401 Unauthorized

- You did not send a token (no `Authorization` and no matching cookie).
- The header format is wrong (both `Bearer <token>` and raw `<token>` are accepted).
- Token expired (in-memory removes expired tokens during validation; Redis removes them via TTL).
- You customized `TokenSourceConfig` but your header/cookie names don’t match what the client sends.

### I get 500 (Token manager not found / Redis error)

- actix-web: you forgot to register `web::Data<RTokenManager>` / `web::Data<RTokenRedisManager>`
- axum: you forgot to install `.layer(Extension(RTokenManager))` / `.layer(Extension(RTokenRedisManager))`
- Redis: your connection URL is wrong, or the server is down

## License

MIT
