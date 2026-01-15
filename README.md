# r-token

README: 日本語（このページ） | [English](README.en.md)

**r-token** は Rust の token 認証ヘルパーです。`actix-web` と `axum` の両方で、handler の引数に extractor（`RUser` / `RRedisUser`）を書くだけで認証済みコンテキストを取得できます。

バックエンドは 2 種類です：

- **インメモリ**: `RTokenManager`（期限は「Unix epoch ミリ秒」の絶対時刻で追跡）
- **Redis/Valkey（任意）**: `RTokenRedisManager`（期限は Redis TTL（秒）で強制）

## 特長

- **Extractor-first**: `RUser` / `RRedisUser` を引数に書くだけでルートを保護
- **最小のボイラープレート**: header/cookie パース用の独自ミドルウェアが不要
- **TTL 対応**: インメモリ TTL と Redis TTL の両方をサポート
- **Token source 設定**: header/cookie 名と優先順位を `TokenSourceConfig` で制御
- **RBAC（任意）**: roles の付与と検証（`rbac` feature）

## セキュリティ注意

- bearer-token 認証です。本番では必ず HTTPS を使ってください。
- token 文字列はアクセス権そのものです。ログ出力しない／クライアントに平文保存しない（脅威モデルが無い場合）など、パスワード同様に扱ってください。
- Redis バックエンドは value として `user_id`（RBAC 有効時は JSON）を保存します。Redis の漏えいを前提にする場合は、token を hash 化して key として保存する方式を検討してください（現状この crate では未実装）。

## インストール

```toml
[dependencies]
r-token = "1.1.0"
```

## Feature flags

依存を任意化するため、機能は Cargo features で切り替えます：

- `actix`（デフォルト）: actix-web 連携（`RUser` / `RRedisUser` の actix extractor）
- `axum`: axum 連携（`RUser` / `RRedisUser` の axum extractor）
- `redis`: Redis/Valkey バックエンド（Tokio が必要）
- `redis-actix`: 便利 feature（`redis` + `actix`）
- `redis-axum`: 便利 feature（`redis` + `axum`）
- `rbac`: roles を含む RBAC サポート（Serde が必要）

例：

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

## Token の取得元

既定では `Authorization` header と cookie から token を探します。

対応する header 形式：

```text
Authorization: <token>
Authorization: Bearer <token>
```

cookie は `r_token`（既定）や `token` を順に探索します。header/cookie 名や優先順位は `TokenSourceConfig` で変更できます。

## Quickstart（actix-web / in-memory）

保護したい handler に `RUser` を引数として追加します（手動パース不要）。

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

アプリ state への登録：

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

## Quickstart（axum / in-memory）

axum では `Extension` を使って manager を注入します。`RUser` は handler 引数としてそのまま使えます。

```rust
use axum::{Router, extract::Extension, routing::{get, post}};
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

## Redis/Valkey（token 永続化）

`RTokenRedisManager` は非同期 API です（Tokio runtime が必要）。actix-web / axum のどちらでも、`RRedisUser` extractor が利用できます（`redis` + `actix` または `axum`）。

Tokio を自分のアプリに追加していない場合の最小例：

```toml
[dependencies]
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## TokenSourceConfig（header/cookie 名と優先順位）

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

## RBAC（roles）

`rbac` feature を有効にすると、token に roles を紐づけられます。

- in-memory: `RTokenManager::login_with_roles` / `set_roles` / `get_roles`、`RUser.roles`、`RUser::has_role`
- Redis: `RTokenRedisManager::login_with_roles` / `set_roles` / `get_roles` / `validate_with_roles`、`RRedisUser.roles`

## このリポジトリのサンプルサーバー

in-memory（actix-web、8080）:

```bash
cargo run --bin r-token
```

Redis/Valkey（actix-web、8081）:

```bash
REDIS_URL=redis://127.0.0.1/ R_TOKEN_PREFIX=r_token:token: \
  cargo run --bin r-token-redis --features redis-actix
```

in-memory（axum、8082）:

```bash
cargo run --bin r-token-axum --features axum
```

Redis/Valkey（axum、8083）:

```bash
REDIS_URL=redis://127.0.0.1/ R_TOKEN_PREFIX=r_token:token: \
  cargo run --bin r-token-redis-axum --features redis-axum
```

## ライセンス

MIT
