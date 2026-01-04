# r-token 🦀

**r-token** 是一个专为 Rust (`actix-web`) 设计的轻量级、无侵入式鉴权库。

> 💡 设计灵感来源于 Java 的 [Sa-Token](https://sa-token.cc/)，旨在提供一种“开箱即用”、“参数即鉴权”的极简体验。

## ✨ 特性 (Features)

*   **极简集成**：只需几行代码即可初始化。
*   **Rust 风格 (Idiomatic)**：利用 Actix 的 `Extractor` 机制，摆脱繁琐的 `if/else` 检查。
*   **零侵入 (Non-invasive)**：在 Handler 参数中声明 `RUser` 即可自动完成鉴权。
*   **状态共享**：基于 `Arc` 和 `Mutex` 实现线程安全的 Token 管理。

## 📦 安装 (Installation)

在你的 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
# Web 框架
actix-web = "4"
# 本库
r-token = { path = "./" } # 如果是本地开发
# r-token = "0.1.0"       # 如果发布到了 crates.io
```

## 🚀 快速开始 (Quick Start)

### 1. 编写业务逻辑

你不需要在代码里写任何 Token 解析逻辑，只需要在参数里要求 `RUser`：

```rust
use actix_web::{get, post, web, HttpResponse, Responder};
use r_token::{RTokenManager, RUser};

// --- 登录接口 ---
// 注入 Manager，生成并返回 Token
#[post("/login")]
async fn login(manager: web::Data<RTokenManager>) -> impl Responder {
    let user_id = "10086";
    let token = manager.login(user_id);
    HttpResponse::Ok().body(format!("Login Success, Token: {}", token))
}

// --- 受保护接口 ---
// 核心魔法：参数里写了 RUser，没登录的用户绝对进不来！
// Actix 会自动拦截无效请求，返回 401 Unauthorized
#[get("/info")]
async fn user_info(user: RUser) -> impl Responder {
    format!("Hello, User ID: {}", user.id)
}

// --- 注销接口 ---
// 同时需要 Manager (操作数据) 和 RUser (验证身份)
#[post("/logout")]
async fn logout(manager: web::Data<RTokenManager>, user: RUser) -> impl Responder {
    manager.logout(&user.token);
    HttpResponse::Ok().body("Logout Success")
}
```

### 2. 注册并启动

在 `main.rs` 中初始化并注入 `RTokenManager`：

```rust
use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 1. 初始化管理器 (全局单例)
    let manager = RTokenManager::new();

    println!("Server running at http://127.0.0.1:8080");

    HttpServer::new(move || {
        App::new()
            // 2. 注入全局状态 (必须步骤)
            .app_data(web::Data::new(manager.clone()))
            // 3. 注册服务
            .service(login)
            .service(user_info)
            .service(logout)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

## 🧪 测试 (Testing)

### 登录
```bash
curl -X POST http://127.0.0.1:8080/login
# 返回: Login Success, Token: 550e8400-e29b...
```

### 访问受保护资源
```bash
# ❌ 不带 Token -> 401 Unauthorized
curl http://127.0.0.1:8080/info

# ✅ 带 Token -> 200 OK
curl -H "Authorization: <你的Token>" http://127.0.0.1:8080/info
```

## 🗓️ 开发计划 (Roadmap)

*   [x] 基础 Token 生成与存储 (MVP)
*   [x] 基于 `Header: Authorization` 的自动鉴权
*   [ ] **Token 过期时间 (TTL) 支持**
*   [ ] **Redis 存储支持** (持久化)
*   [ ] **角色/权限控制** (RBAC)
*   [ ] 支持 Cookie 模式读取 Token

## 📄 License

MIT

---

### 这份 README 的优点：
1.  **清晰**：告诉别人这是干嘛的（Rust 版 Sa-Token）。
2.  **简单**：代码示例直接复制就能跑。
3.  **专业**：包含了 Installation, Usage, Features, Roadmap 几个标准板块。

你可以把它保存为 `README.md` 文件放在你的项目根目录下。