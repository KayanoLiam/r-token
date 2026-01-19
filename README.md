# r-token

README: 日本語（このページ） | [English](README.en.md)

**r-token** は Rust の token 認証ヘルパーです。`actix-web` と `axum` の両方で、handler の引数に extractor（`RUser` / `RRedisUser`）を書くだけで認証済みコンテキストを取得できます。

この crate が提供するのは「認証（authentication）」のための primitives です：

- token の発行（login）
- token の検証（extractor / validate）
- token の失効（logout）
- TTL による自動失効（in-memory / Redis）
- 任意で roles を付与（RBAC）

バックエンドは 2 種類です：

- **インメモリ**: `RTokenManager`（期限は「Unix epoch ミリ秒」の絶対時刻で追跡）
- **Redis/Valkey（任意）**: `RTokenRedisManager`（期限は Redis TTL（秒）で強制）

## 目次

- [特長](#特長)
- [対応マトリクス](#対応マトリクス)
- [セキュリティ注意](#セキュリティ注意)
- [インストール](#インストール)
- [Feature flags](#feature-flags)
- [まず何を選べばいい？（早見表）](#まず何を選べばいい早見表)
- [認証の基本フロー](#認証の基本フロー)
- [Token の取得元（Header / Cookie）](#token-の取得元header--cookie)
- [Quickstart：actix-web（in-memory）](#quickstartactix-webin-memory)
- [Quickstart：axum（in-memory）](#quickstartaxumin-memory)
- [Redis/Valkey バックエンド](#redisvalkey-バックエンド)
- [RBAC（roles）](#rbacroles)
- [TTL 操作（renew / rotate / ttl_seconds など）](#ttl-操作renew--rotate--ttl_seconds-など)
- [エラーとステータスコード](#エラーとステータスコード)
- [例：このリポジトリのサンプルサーバー](#例このリポジトリのサンプルサーバー)
- [テスト](#テスト)
- [FAQ / トラブルシュート](#faq--トラブルシュート)
- [ライセンス](#ライセンス)

## 特長

- **Extractor-first**: `RUser` / `RRedisUser` を引数に書くだけでルートを保護
- **最小のボイラープレート**: header/cookie パース用の独自ミドルウェアが不要
- **TTL 対応**: インメモリ TTL と Redis TTL の両方をサポート
- **Token source 設定**: header/cookie 名と優先順位を `TokenSourceConfig` で制御
- **RBAC（任意）**: roles の付与と検証（`rbac` feature）
- **Valkey 対応**: Redis 互換プロトコルなら同様に利用可能（接続は `redis` crate）

## 対応マトリクス

| 目的 | in-memory | Redis/Valkey |
|---|---:|---:|
| actix-web extractor | `RUser` | `RRedisUser`（`redis-actix`） |
| axum extractor | `RUser` | `RRedisUser`（`redis-axum`） |
| TTL / 期限切れ | アプリ側（期限 ms を検証時に掃除） | Redis 側（TTL 秒で削除） |
| roles（RBAC） | `rbac` feature | `rbac` feature（value は JSON） |

## セキュリティ注意

- bearer-token 認証です。本番では必ず HTTPS を使ってください。
- token 文字列はアクセス権そのものです。ログ出力しない／クライアントに平文保存しないなど、パスワード同様に扱ってください。
- cookie で運ぶ場合は、基本的に `Secure` / `HttpOnly` / `SameSite` を検討してください（サンプルは簡潔さ優先で `HttpOnly` のみ）。
- Redis バックエンドは value として `user_id`（RBAC 有効時は JSON）を保存します。Redis の漏えいを前提にする場合は、token を hash 化して key として保存する方式を検討してください（現状この crate では未実装）。

## インストール

```toml
[dependencies]
r-token = "1.2.0"
```

MSRV（最小 Rust バージョン）は `Cargo.toml` の `rust-version` を参照してください。

## Feature flags

依存を任意化するため、機能は Cargo features で切り替えます：

- `actix`（デフォルト）: actix-web 連携（`RUser` / `RRedisUser` の actix extractor）
- `axum`: axum 連携（`RUser` / `RRedisUser` の axum extractor、Tokio が必要）
- `redis`: Redis/Valkey バックエンド（Tokio が必要）
- `redis-actix`: 便利 feature（`redis` + `actix`）
- `redis-axum`: 便利 feature（`redis` + `axum`）
- `rbac`: roles を含む RBAC サポート（Serde が必要）

例：

```toml
[dependencies]
r-token = { version = "1.2.0", default-features = false, features = ["actix"] }
```

```toml
[dependencies]
r-token = { version = "1.2.0", default-features = false, features = ["axum"] }
```

```toml
[dependencies]
r-token = { version = "1.2.0", features = ["redis-actix"] }
```

```toml
[dependencies]
r-token = { version = "1.2.0", features = ["redis-axum", "rbac"] }
```

## まず何を選べばいい？（早見表）

- **actix-web + in-memory**: `r-token = "1.2.0"`（デフォルト `actix`）
- **axum + in-memory**: `default-features = false, features = ["axum"]`
- **actix-web + Redis/Valkey**: `features = ["redis-actix"]`
- **axum + Redis/Valkey**: `features = ["redis-axum"]`
- **roles も必要**: 上記に `rbac` を追加

## 認証の基本フロー

一般的な API の流れは次の通りです：

1. `/login`（公開）で `login(..)` を呼び、token を返す（必要なら cookie もセット）
2. クライアントは token を以後のリクエストに付与する
   - `Authorization: <token>`
   - `Authorization: Bearer <token>`
   - または cookie（既定は `r_token`）
3. 保護したい handler に `RUser` / `RRedisUser` を引数として書く
4. extractor が成功すれば、handler 内で `user.id`（RBAC 有効なら `user.roles`）が使える

## Token の取得元（Header / Cookie）

既定では `Authorization` header と cookie から token を探します。

対応する header 形式：

```text
Authorization: <token>
Authorization: Bearer <token>
```

cookie は `r_token`（既定）を探索します。探索ルールは `TokenSourceConfig` で変更できます：

- `header_names`: 順に探す header 名（例：`Authorization`、`X-Api-Token`）
- `cookie_names`: 順に探す cookie 名（例：`r_token`）
- `priority`: HeaderFirst / CookieFirst

actix-web では `app_data(web::Data<TokenSourceConfig>)`、axum では `Extension(TokenSourceConfig)` で注入します。

## Quickstart：actix-web（in-memory）

### 1) 依存

```toml
[dependencies]
r-token = "1.2.0"
```

### 2) ルート（login / profile / logout）

保護したい handler に `RUser` を引数として追加します（手動パース不要）。

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

### 3) アプリ state（必須）

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

### 4) 試す（curl）

```bash
token=$(curl -s -X POST http://127.0.0.1:8080/login -d "alice")
curl -s -H "Authorization: $token" http://127.0.0.1:8080/profile
curl -s -X POST -H "Authorization: $token" http://127.0.0.1:8080/logout
```

## Quickstart：axum（in-memory）

### 1) 依存

```toml
[dependencies]
r-token = { version = "1.2.0", default-features = false, features = ["axum"] }
tokio = { version = "1", features = ["macros", "net", "rt-multi-thread"] }
```

### 2) ルート（login / profile / logout）

`Extension` で manager を注入します。`RUser` は handler 引数としてそのまま使えます。

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

### 3) 試す（curl）

```bash
token=$(curl -s -X POST http://127.0.0.1:8082/login -d "alice")
curl -s -H "Authorization: $token" http://127.0.0.1:8082/profile
curl -s -X POST -H "Authorization: $token" http://127.0.0.1:8082/logout
```

## Redis/Valkey バックエンド

`RTokenRedisManager` は非同期 API です（Tokio runtime が必要）。actix-web / axum のどちらでも、`RRedisUser` extractor が利用できます（`redis` + `actix` または `axum`）。

### 接続

```rust
use r_token::RTokenRedisManager;

let redis_url = "redis://127.0.0.1/";
let prefix = "r_token:token:";
let manager = RTokenRedisManager::connect(redis_url, prefix).await?;
```

`prefix` は環境ごと・アプリごとの分離に使います。末尾の `:` は自動で補われます。

### actix-web で使う

- manager は `web::Data<RTokenRedisManager>` として注入します
- 保護ルートは `RRedisUser` を引数に持ちます

サンプル実装は [redis_main.rs](file:///Volumes/P600/r-token/src/bin/redis_main.rs) を参照してください。

### axum で使う

- manager は `Extension(RTokenRedisManager)` として注入します
- 保護ルートは `RRedisUser` を引数に持ちます

サンプル実装は [redis_axum_main.rs](file:///Volumes/P600/r-token/src/bin/redis_axum_main.rs) を参照してください。

## RBAC（roles）

`rbac` feature を有効にすると、token に roles を紐づけられます。

利用できる主な API：

- in-memory:
  - `RTokenManager::login_with_roles(user_id, ttl, roles)`
  - `RTokenManager::set_roles(token, roles)`（冪等）
  - `RTokenManager::get_roles(token)`
  - `RUser.roles` / `RUser::has_role(..)`
- Redis:
  - `RTokenRedisManager::login_with_roles(user_id, ttl, roles)`
  - `RTokenRedisManager::set_roles(token, roles)`（冪等、TTL を保持）
  - `RTokenRedisManager::get_roles(token)`
  - `RTokenRedisManager::validate_with_roles(token)`
  - `RRedisUser.roles`

### 典型的な「認可」パターン

r-token は「認証」までを担当します。認可（特定の role が必要、など）はアプリ側で実装します。

actix-web:

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

## TTL 操作（renew / rotate / ttl_seconds など）

### in-memory（RTokenManager）

- `expires_at(token) -> Option<u64>`: 保存されている期限（ms）。期限切れ判定はしない
- `ttl_seconds(token) -> Option<i64>`: 残り TTL（秒）。期限切れは `Some(0)`
- `renew(token, ttl) -> bool`: 期限を延長（期限切れは削除して `false`）
- `rotate(token, ttl) -> Option<String>`: 新 token を発行し old token を失効
- `prune_expired() -> usize`: 期限切れ token を掃除（件数を返す）

### Redis/Valkey（RTokenRedisManager）

- `ttl_seconds(token) -> Option<i64>`: Redis TTL の意味をそのまま返す
  - `None`: key が存在しない
  - `Some(-1)`: key は存在するが期限がない
  - `Some(n)`（n >= 0）: 残り TTL（秒）
- `renew(token, ttl) -> bool`: `EXPIRE` による延長
- `rotate(token, ttl) -> Option<String>`: 新 token を発行して old key を削除（簡潔さ優先のため原子的ではない）

## エラーとステータスコード

### `RTokenError`

`RTokenManager` が返すエラーは現在 `MutexPoisoned` のみです。

- actix-web: `actix_web::ResponseError` を実装しているため handler からそのまま返せます
- axum: `IntoResponse` を実装しており、既定では 500 を返します（詳細は `Display` の文字列）

### extractor の 401 / 500

共通の失敗パターン：

- **401 Unauthorized**: token が無い / 無効 / 期限切れ
- **500 Internal Server Error**: manager が state に注入されていない（設定忘れ）、または内部の mutex が poisoned

## 例：このリポジトリのサンプルサーバー

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

## テスト

基本：

```bash
cargo test
```

全 feature：

```bash
cargo test --all-features
```

Redis テストについて：

- `REDIS_URL` が指定されていない場合、テストは `redis-server` をローカルで起動しようとします。
- `redis-server` が利用できない環境では、`REDIS_URL` を設定して既存の Redis/Valkey を使ってください。

## FAQ / トラブルシュート

### 401 になる

- token を送っていない（`Authorization` / cookie のどちらも無い）
- `Authorization` の形式が違う（`Bearer ` を付ける／付けないはどちらも可）
- token が期限切れ（in-memory では検証時に削除されます。Redis では TTL で消えます）
- `TokenSourceConfig` を変更していて header/cookie 名が一致していない

### 500 になる（Token manager not found / Redis error）

- actix-web: `web::Data<RTokenManager>` / `web::Data<RTokenRedisManager>` を `app_data` に入れ忘れている
- axum: `Extension(RTokenManager)` / `Extension(RTokenRedisManager)` を `.layer(..)` していない
- Redis: 接続先が落ちている、URL が間違っている

## ライセンス

MIT
