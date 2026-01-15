# r-token

README: 日本語（このページ） | [English](README.en.md)

**r-token** は Rust と `actix-web` 向けの小さな token 認証ヘルパーです。

token マネージャは 2 種類あります：

- **インメモリ**: `RTokenManager` が token をメモリ上に保持し、期限は絶対時刻（ミリ秒）で管理します。
- **Redis/Valkey（任意）**: `RTokenRedisManager` が token を Redis に保存し、期限は Redis の TTL（秒）に任せます。

`actix-web` では “parameter-as-authentication” スタイルを採用しています。handler の引数に `RUser` を追加するだけで、Actix の extractor が `Authorization`（または cookie）を自動検証し、リクエストを認証済みにします。

## 特長

- **ボイラープレート最小**: 基本的な header 認証に独自ミドルウェア不要。
- **Extractor-first**: `RUser` を引数に書くだけでルートを保護。
- **スレッドセーフな共有状態**: `RTokenManager` は `Clone` でき、同じインメモリストアを共有。
- **TTL 対応**:
  - インメモリ: login 時の TTL（秒）から期限を計算。
  - Redis/Valkey: Redis の TTL（秒）が期限を強制。
- **Redis/Valkey バックエンド（任意）**: `RTokenRedisManager` が `prefix + token` を key として保存。

## セキュリティ注意

- 本ライブラリは bearer-token 認証です。本番では必ず HTTPS を使ってください。
- token 文字列はアクセス権そのものです。パスワード同様に扱い、ログに出さない／脅威モデル無しでクライアント側に平文保存しないでください。
- Redis バックエンドは value として `user_id`（または RBAC 時は JSON）を保存します。Redis のデータ漏えいが懸念される場合は、token を hash 化して key として保存する方式を検討してください（現状この crate では未実装）。

## ステータス

本プロジェクトは活発に開発中です。セキュリティ要件が厳しい環境では、導入前にソースとテストを確認してください。

安定版はリリースしていますが、API はまだ完全固定ではありません。後方互換性を維持し、破壊的変更は導入しない方針です。

## インストール

`Cargo.toml` に追加します：

```toml
[dependencies]
r-token = "1.0.2"
```

## Cargo features

r-token は Cargo features で依存を任意化しています：

- `actix`（デフォルト）: `RUser` extractor と actix-web 連携を有効化します。
- `redis`: `redis` crate を使った Redis/Valkey バックエンドを有効化します。
- `redis-actix`: 便利 feature（`redis` + `actix`）。
- `rbac`: ロールベースアクセス制御（RBAC）を有効化します。

例：

```toml
[dependencies]
r-token = { version = "1.0.2", default-features = false }
```

```toml
[dependencies]
r-token = { version = "1.0.2", features = ["redis-actix"] }
```

```toml
[dependencies]
r-token = { version = "1.0.2", features = ["rbac"] }
```

```toml
[dependencies]
r-token = { version = "1.0.2", features = ["redis-actix", "rbac"] }
```

## Authorization header

`RUser` extractor（および Redis サンプルサーバー）は `Authorization` から token を読み取り、次の形式に対応します：

```text
Authorization: <token>
Authorization: Bearer <token>
```

## API 概要

コア型：

- `RTokenManager`（常に利用可）: インメモリで token を発行・失効します。
- `RTokenError`（常に利用可）: インメモリマネージャが使うエラー型です。

Actix 連携（`actix` が必要、デフォルトで有効）：

- `RUser`: `Authorization`（または cookie）を検証する `actix_web::FromRequest` extractor。

Redis バックエンド（`redis` が必要）：

- `RTokenRedisManager`: Redis/Valkey をバックエンドに token を発行・検証・失効します。

RBAC（`rbac` が必要）：

- `RTokenManager::login_with_roles()`: roles を紐づけた token を発行します。
- `RTokenManager::set_roles()`: 既存 token の roles を更新します。
- `RTokenManager::get_roles()`: token の roles を取得します。
- `RUser.roles`: 認証済みユーザーに紐づく roles（`Vec<String>`）。
- `RUser::has_role()`: 指定 role を持つか判定します。
- `RTokenRedisManager::login_with_roles()`: Redis に roles 付き token を発行します。
- `RTokenRedisManager::set_roles()`: Redis 上の token の roles を更新します。
- `RTokenRedisManager::get_roles()`: Redis 上の token の roles を取得します。
- `RTokenRedisManager::validate()`: RBAC 有効時は `user_id` と `roles` を返します。

## インメモリ利用例（actix-web）

### 1. エンドポイントを追加

手動で header を解析する必要はありません。保護したい handler に `RUser` を引数として追加します。

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

### 2. 登録して起動

`RTokenManager` を初期化し、Actix の app state に登録します。

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

## RBAC 利用例（role-based access control）

`rbac` feature を有効にすると、token に roles を紐づけてロールベースの認可を行えます。

### インメモリ RBAC

```rust
use r_token::{RTokenManager, RUser, RTokenError};
use actix_web::{get, post, web, HttpResponse, Responder};

#[post("/login")]
async fn login(
    manager: web::Data<RTokenManager>,
    body: String,
) -> Result<impl Responder, RTokenError> {
    // Example: Parse user_id and roles from request body
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
    // Example: Only admins can promote users
    if !user.has_role("admin") {
        return Ok(HttpResponse::Forbidden().body("Access denied"));
    }

    // Example: Add 'moderator' role to the current user
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
    let user_info = manager.validate_with_roles(&token).await?;
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

## 振る舞いの詳細

インメモリマネージャ：

- `RTokenManager::login(user_id, ttl_seconds)` は UUID v4 の token 文字列を返します。
- `RTokenManager::renew(token, ttl_seconds)` は既存 token の期限を延長します。
- `RTokenManager::rotate(token, ttl_seconds)` は新 token を発行し、旧 token を失効させます。
- `RTokenManager::ttl_seconds(token)` は残り TTL（秒）を返します。
- 期限は「Unix epoch ミリ秒の絶対時刻」として保存して追跡します。
- 期限切れ token は `validate()` 呼び出し時に削除されます（それ以外のタイミングでは残り続けます）。
- `RTokenManager::prune_expired()` で期限切れ token を能動的に掃除できます。
- `RTokenManager::logout(token)` は冪等です。存在しない token を失効しても成功扱いです。

Actix extractor：

- 成功時、`RUser` は `id` と生の `token` を提供します。
- RBAC 有効時は `RUser.roles` も提供されます（role 文字列の `Vec<String>`）。
- `RUser::has_role(role)` は指定 role を持つか判定します。
- 失敗時：
  - `401 Unauthorized`: token が無い／不正／期限切れ。
  - `500 Internal Server Error`: `app_data` にマネージャが無い／内部 mutex が poisoned。

Redis マネージャ：

- `RTokenRedisManager::login(user_id, ttl_seconds)` は `prefix + token` を key、`user_id` を value として保存し、TTL を `ttl_seconds`（秒）に設定します。
- `RTokenRedisManager::renew(token, ttl_seconds)` は token key の Redis TTL を更新します。
- `RTokenRedisManager::rotate(token, ttl_seconds)` は新 token を発行し、旧 key を削除します。
- `RTokenRedisManager::ttl_seconds(token)` は token key の Redis TTL（Redis の意味論）を返します。
- `validate(token)` は key が無い（失効済み/期限切れ）とき `Ok(None)` を返します。
- RBAC 有効時、`validate(token)` は `Ok(Some(user_id))` を返します（roles が必要なら `validate_with_roles(token)`）。
- RBAC 有効時、`validate_with_roles(token)` は `Ok(Some((user_id, roles)))` を返します。
- `logout(token)` は key を削除し、冪等です。

RBAC の挙動：

- `login_with_roles()` で roles 付き token を作れます。
- `set_roles()` で既存 token の roles を更新できます。
- `get_roles()` で roles を取得できます。
- RBAC 有効時は `RUser.roles` が利用できます（roles 未設定なら空ベクタ）。
- `RUser::has_role()` は大文字小文字を区別して比較します。

## Redis/Valkey 利用例

token を永続化し、期限切れを Redis の TTL で管理したい場合は `redis`（または `redis-actix`）を有効にし、`RTokenRedisManager` を使います。

アプリ側で Tokio runtime も必要です（推移的依存に頼らないでください）：

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

## 利用例（curl）

### Login

```bash
curl -X POST http://127.0.0.1:8080/login -d "alice"
# レスポンス例: 550e8400-e29b-41d4-a716-446655440000
```

### 保護されたリソースにアクセス

```bash
# token 無し -> 401 Unauthorized
curl http://127.0.0.1:8080/info

# token あり -> 200 OK
curl -H "Authorization: <token>" http://127.0.0.1:8080/info
```

## このリポジトリのサンプルサーバー

### インメモリ（actix-web）

```bash
cargo run --bin r-token
```

### Redis/Valkey（actix-web）

環境変数：

- `REDIS_URL`（デフォルト：`redis://127.0.0.1/`）
- `R_TOKEN_PREFIX`（デフォルト：`r_token:token:`）

```bash
REDIS_URL=redis://127.0.0.1/ cargo run --bin r-token-redis --features redis-actix
```

## ロードマップ

- [x] インメモリ token 管理 + extractor
- [x] token 期限（TTL）
- [x] Redis/Valkey バックエンド（任意）
- [x] ロールベースアクセス制御（RBAC）
- [x] Cookie 対応
- [x] インメモリ token 検証 API（non-actix）
- [x] Redis actix-web extractor（parameter-as-authentication）
- [x] token 取得元の設定（header/cookie 名、優先順位）

## ライセンス

MIT
