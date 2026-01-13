//! RBAC (Role-Based Access Control) tests for the r-token library.
//!
//! These tests verify the role-based access control functionality.

#[cfg(feature = "rbac")]
mod rbac_tests {
    use r_token::RTokenManager;

    // ============ In-Memory RBAC Tests ============

    #[test]
    fn login_with_roles_creates_token() {
        let manager = RTokenManager::new();
        let roles = vec!["admin".to_string(), "user".to_string()];
        let result = manager.login_with_roles("user_123", 3600, roles.clone());

        assert!(result.is_ok());
        let token = result.unwrap();

        // UUID v4 should be 36 characters (including hyphens)
        assert_eq!(token.len(), 36);
        assert!(token.contains('-'));
    }

    #[test]
    fn get_roles_returns_correct_roles() {
        let manager = RTokenManager::new();
        let roles = vec!["admin".to_string(), "editor".to_string()];
        let token = manager
            .login_with_roles("user_456", 3600, roles.clone())
            .unwrap();

        let result = manager.get_roles(&token);
        assert!(result.is_ok());

        let retrieved_roles = result.unwrap();
        assert!(retrieved_roles.is_some());
        assert_eq!(retrieved_roles.unwrap(), roles);
    }

    #[test]
    fn get_roles_for_nonexistent_token() {
        let manager = RTokenManager::new();

        let result = manager.get_roles("nonexistent-token");
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn set_roles_updates_roles() {
        let manager = RTokenManager::new();
        let initial_roles = vec!["user".to_string()];
        let token = manager
            .login_with_roles("user_789", 3600, initial_roles)
            .unwrap();

        let new_roles = vec!["admin".to_string(), "moderator".to_string()];
        let result = manager.set_roles(&token, new_roles.clone());
        assert!(result.is_ok());

        let retrieved_roles = manager.get_roles(&token).unwrap().unwrap();
        assert_eq!(retrieved_roles, new_roles);
    }

    #[test]
    fn set_roles_for_nonexistent_token() {
        let manager = RTokenManager::new();
        let roles = vec!["admin".to_string()];

        // Setting roles on a non-existent token should not fail
        let result = manager.set_roles("nonexistent-token", roles);
        assert!(result.is_ok());
    }

    #[test]
    fn login_without_roles_has_empty_roles() {
        let manager = RTokenManager::new();
        let token = manager.login("user_abc", 3600).unwrap();

        let result = manager.get_roles(&token);
        assert!(result.is_ok());

        let retrieved_roles = result.unwrap();
        assert!(retrieved_roles.is_some());
        assert!(retrieved_roles.unwrap().is_empty());
    }

    #[test]
    fn login_with_empty_roles() {
        let manager = RTokenManager::new();
        let roles: Vec<String> = vec![];
        let token = manager.login_with_roles("user_def", 3600, roles).unwrap();

        let result = manager.get_roles(&token);
        assert!(result.is_ok());

        let retrieved_roles = result.unwrap();
        assert!(retrieved_roles.is_some());
        assert!(retrieved_roles.unwrap().is_empty());
    }

    #[test]
    fn multiple_users_with_different_roles() {
        let manager = RTokenManager::new();

        let token1 = manager
            .login_with_roles("alice", 3600, vec!["admin".to_string()])
            .unwrap();
        let token2 = manager
            .login_with_roles("bob", 3600, vec!["user".to_string()])
            .unwrap();
        let token3 = manager
            .login_with_roles(
                "charlie",
                3600,
                vec!["moderator".to_string(), "user".to_string()],
            )
            .unwrap();

        let roles1 = manager.get_roles(&token1).unwrap().unwrap();
        let roles2 = manager.get_roles(&token2).unwrap().unwrap();
        let roles3 = manager.get_roles(&token3).unwrap().unwrap();

        assert_eq!(roles1, vec!["admin"]);
        assert_eq!(roles2, vec!["user"]);
        assert_eq!(roles3, vec!["moderator", "user"]);
    }

    // ============ Actix Integration RBAC Tests ============

    #[cfg(feature = "actix")]
    mod actix_rbac_tests {
        use super::*;
        use actix_web::{App, HttpResponse, get, post, test as actix_test, web};
        use r_token::{RTokenError, RUser};

        #[actix_web::test]
        async fn ruser_contains_correct_roles() {
            let manager = RTokenManager::new();
            let roles = vec!["admin".to_string(), "editor".to_string()];
            let token = manager.login_with_roles("test_user", 3600, roles).unwrap();

            #[get("/protected")]
            async fn protected(user: RUser) -> impl actix_web::Responder {
                HttpResponse::Ok().json(&user.roles)
            }

            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(manager))
                    .service(protected),
            )
            .await;

            let req = actix_test::TestRequest::get()
                .uri("/protected")
                .insert_header(("Authorization", token.as_str()))
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);

            let body_bytes = actix_test::read_body(resp).await;
            let body: Vec<String> = serde_json::from_slice(body_bytes.as_ref()).unwrap();
            assert_eq!(body, vec!["admin", "editor"]);
        }

        #[actix_web::test]
        async fn ruser_has_role_returns_true_for_existing_role() {
            let manager = RTokenManager::new();
            let roles = vec!["admin".to_string(), "user".to_string()];
            let token = manager.login_with_roles("role_user", 3600, roles).unwrap();

            #[get("/check")]
            async fn check(user: RUser) -> impl actix_web::Responder {
                let has_admin = user.has_role("admin");
                let has_moderator = user.has_role("moderator");
                HttpResponse::Ok().body(format!(
                    "admin: {}, moderator: {}",
                    has_admin, has_moderator
                ))
            }

            let app = actix_test::init_service(
                App::new().app_data(web::Data::new(manager)).service(check),
            )
            .await;

            let req = actix_test::TestRequest::get()
                .uri("/check")
                .insert_header(("Authorization", token.as_str()))
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);

            let body = actix_test::read_body(resp).await;
            assert_eq!(body, "admin: true, moderator: false");
        }

        #[actix_web::test]
        async fn ruser_with_empty_roles() {
            let manager = RTokenManager::new();
            let token = manager.login("no_role_user", 3600).unwrap();

            #[get("/roles")]
            async fn roles(user: RUser) -> impl actix_web::Responder {
                HttpResponse::Ok().json(&user.roles)
            }

            let app = actix_test::init_service(
                App::new().app_data(web::Data::new(manager)).service(roles),
            )
            .await;

            let req = actix_test::TestRequest::get()
                .uri("/roles")
                .insert_header(("Authorization", token.as_str()))
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);

            let body_bytes = actix_test::read_body(resp).await;
            let body: Vec<String> = serde_json::from_slice(body_bytes.as_ref()).unwrap();
            assert!(body.is_empty());
        }

        #[actix_web::test]
        async fn role_based_access_control() {
            let manager = RTokenManager::new();

            #[post("/login")]
            async fn login(
                manager: web::Data<RTokenManager>,
                body: String,
            ) -> Result<HttpResponse, RTokenError> {
                let parts: Vec<&str> = body.split(':').collect();
                let user_id = parts[0];
                let roles: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
                let token = manager.login_with_roles(user_id, 3600, roles)?;
                Ok(HttpResponse::Ok().body(token))
            }

            #[get("/admin")]
            async fn admin_only(user: RUser) -> impl actix_web::Responder {
                if user.has_role("admin") {
                    HttpResponse::Ok().body(format!("Admin access granted to {}", user.id))
                } else {
                    HttpResponse::Forbidden().body("Admin access denied")
                }
            }

            #[get("/editor")]
            async fn editor_only(user: RUser) -> impl actix_web::Responder {
                if user.has_role("editor") {
                    HttpResponse::Ok().body(format!("Editor access granted to {}", user.id))
                } else {
                    HttpResponse::Forbidden().body("Editor access denied")
                }
            }

            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(manager))
                    .service(login)
                    .service(admin_only)
                    .service(editor_only),
            )
            .await;

            // Admin user can access admin endpoint
            let req = actix_test::TestRequest::post()
                .uri("/login")
                .set_payload("admin_user:admin")
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            let admin_token =
                String::from_utf8(actix_test::read_body(resp).await.to_vec()).unwrap();

            let req = actix_test::TestRequest::get()
                .uri("/admin")
                .insert_header(("Authorization", admin_token.as_str()))
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);

            // Regular user cannot access admin endpoint
            let req = actix_test::TestRequest::post()
                .uri("/login")
                .set_payload("regular_user:user")
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            let user_token = String::from_utf8(actix_test::read_body(resp).await.to_vec()).unwrap();

            let req = actix_test::TestRequest::get()
                .uri("/admin")
                .insert_header(("Authorization", user_token.as_str()))
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 403);

            // User with both admin and editor roles can access both
            let req = actix_test::TestRequest::post()
                .uri("/login")
                .set_payload("super_user:admin:editor")
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            let super_token =
                String::from_utf8(actix_test::read_body(resp).await.to_vec()).unwrap();

            let req = actix_test::TestRequest::get()
                .uri("/admin")
                .insert_header(("Authorization", super_token.as_str()))
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);

            let req = actix_test::TestRequest::get()
                .uri("/editor")
                .insert_header(("Authorization", super_token.as_str()))
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);
        }
    }

    // ============ Redis RBAC Tests ============

    #[cfg(feature = "redis")]
    mod redis_rbac_tests {
        use r_token::RTokenRedisManager;
        use redis::AsyncCommands;
        use std::net::TcpListener;
        use std::process::{Child, Command, Stdio};
        use std::sync::OnceLock;

        struct RedisTestServer {
            child: Child,
            url: String,
        }

        impl Drop for RedisTestServer {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }

        static REDIS_TEST_SERVER: OnceLock<RedisTestServer> = OnceLock::new();

        fn free_port() -> u16 {
            TcpListener::bind(("127.0.0.1", 0))
                .and_then(|listener| listener.local_addr())
                .map(|addr| addr.port())
                .expect("get free port failed")
        }

        fn spawn_redis_server() -> RedisTestServer {
            let port = free_port();
            let mut child = Command::new("redis-server")
                .arg("--port")
                .arg(port.to_string())
                .arg("--save")
                .arg("")
                .arg("--appendonly")
                .arg("no")
                .arg("--protected-mode")
                .arg("no")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn redis-server failed");

            if let Ok(Some(status)) = child.try_wait() {
                panic!("redis-server exited early: {status}");
            }

            RedisTestServer {
                child,
                url: format!("redis://127.0.0.1:{port}/"),
            }
        }

        async fn wait_redis_ready(url: &str) {
            let client = redis::Client::open(url).expect("redis client open failed");

            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                if tokio::time::Instant::now() >= deadline {
                    panic!("redis-server not ready at {url}");
                }

                if let Ok(mut connection) = client.get_connection_manager().await
                    && connection.ping::<String>().await.as_deref() == Ok("PONG")
                {
                    return;
                }

                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }

        async fn test_redis_url() -> String {
            if let Ok(url) = std::env::var("REDIS_URL") {
                return url;
            }

            let server = REDIS_TEST_SERVER.get_or_init(spawn_redis_server);
            wait_redis_ready(&server.url).await;
            server.url.clone()
        }

        fn unique_prefix(test_name: &str) -> String {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            format!("r_token:rbac:{}:{}:", test_name, nanos)
        }

        #[tokio::test]
        async fn redis_login_with_roles() {
            let redis_url = test_redis_url().await;
            let manager =
                RTokenRedisManager::connect(&redis_url, unique_prefix("login_with_roles"))
                    .await
                    .expect("redis connect failed");

            let roles = vec!["admin".to_string(), "user".to_string()];
            let token = manager
                .login_with_roles("alice", 60, roles.clone())
                .await
                .expect("login failed");

            assert_eq!(token.len(), 36);

            let user_info = manager
                .validate_with_roles(&token)
                .await
                .expect("validate failed");
            assert!(user_info.is_some());
            let (user_id, retrieved_roles) = user_info.unwrap();
            assert_eq!(user_id, "alice");
            assert_eq!(retrieved_roles, roles);
        }

        #[tokio::test]
        async fn redis_get_roles() {
            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("get_roles"))
                .await
                .expect("redis connect failed");

            let roles = vec!["editor".to_string(), "viewer".to_string()];
            let token = manager
                .login_with_roles("bob", 60, roles.clone())
                .await
                .expect("login failed");

            let retrieved_roles = manager.get_roles(&token).await.expect("get_roles failed");

            assert!(retrieved_roles.is_some());
            assert_eq!(retrieved_roles.unwrap(), roles);
        }

        #[tokio::test]
        async fn redis_get_roles_for_nonexistent_token() {
            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("get_roles_none"))
                .await
                .expect("redis connect failed");

            let retrieved_roles = manager
                .get_roles("nonexistent-token")
                .await
                .expect("get_roles failed");

            assert!(retrieved_roles.is_none());
        }

        #[tokio::test]
        async fn redis_set_roles() {
            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("set_roles"))
                .await
                .expect("redis connect failed");

            let initial_roles = vec!["user".to_string()];
            let token = manager
                .login_with_roles("charlie", 60, initial_roles)
                .await
                .expect("login failed");

            let new_roles = vec!["admin".to_string(), "moderator".to_string()];
            manager
                .set_roles(&token, new_roles.clone())
                .await
                .expect("set_roles failed");

            let retrieved_roles = manager.get_roles(&token).await.expect("get_roles failed");

            assert!(retrieved_roles.is_some());
            assert_eq!(retrieved_roles.unwrap(), new_roles);
        }

        #[tokio::test]
        async fn redis_set_roles_preserves_ttl() {
            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("set_roles_ttl"))
                .await
                .expect("redis connect failed");

            let token = manager
                .login_with_roles("ttl_user", 3, vec!["user".to_string()])
                .await
                .expect("login failed");

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            manager
                .set_roles(&token, vec!["admin".to_string()])
                .await
                .expect("set_roles failed");

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;

            let user_info = manager
                .validate_with_roles(&token)
                .await
                .expect("validate failed");

            assert!(user_info.is_none());
        }

        #[tokio::test]
        async fn redis_login_with_roles_stores_expire_at() {
            let prefix = unique_prefix("expire_at");
            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, prefix.clone())
                .await
                .expect("redis connect failed");

            let token = manager
                .login_with_roles("alice", 60, vec!["admin".to_string()])
                .await
                .expect("login failed");

            let client = redis::Client::open(redis_url.as_str()).expect("redis client open failed");
            let mut connection = client
                .get_connection_manager()
                .await
                .expect("redis connection failed");

            let key = format!("{}{}", prefix, token);
            let raw: String = connection.get(key).await.expect("redis get failed");

            let value = serde_json::from_str::<serde_json::Value>(&raw).expect("json parse failed");
            let expire_at = value
                .get("expire_at")
                .and_then(|v| v.as_u64())
                .expect("expire_at missing");

            let now_ms = chrono::Utc::now().timestamp_millis() as u64;
            assert!(expire_at > now_ms);
        }

        #[tokio::test]
        async fn redis_validate_with_roles_handles_legacy_plain_value() {
            let prefix = unique_prefix("legacy_plain");
            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, prefix.clone())
                .await
                .expect("redis connect failed");

            let token = "legacy-token";
            let client = redis::Client::open(redis_url.as_str()).expect("redis client open failed");
            let mut connection = client
                .get_connection_manager()
                .await
                .expect("redis connection failed");

            let key = format!("{prefix}{token}");
            let _: () = connection
                .set_ex(&key, "legacy_user", 60u64)
                .await
                .expect("redis set_ex failed");

            let user_info = manager
                .validate_with_roles(token)
                .await
                .expect("validate_with_roles failed");

            assert!(user_info.is_some());
            let (user_id, roles) = user_info.unwrap();
            assert_eq!(user_id, "legacy_user");
            assert!(roles.is_empty());
        }

        #[tokio::test]
        async fn redis_set_roles_for_nonexistent_token() {
            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("set_roles_none"))
                .await
                .expect("redis connect failed");

            let roles = vec!["admin".to_string()];

            // Setting roles on a non-existent token should not fail
            let result = manager.set_roles("nonexistent-token", roles).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn redis_validate_returns_user_id_and_roles() {
            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("validate_roles"))
                .await
                .expect("redis connect failed");

            let roles = vec!["admin".to_string(), "editor".to_string()];
            let token = manager
                .login_with_roles("dave", 60, roles.clone())
                .await
                .expect("login failed");

            let user_info = manager
                .validate_with_roles(&token)
                .await
                .expect("validate failed");
            assert!(user_info.is_some());

            let (user_id, retrieved_roles) = user_info.unwrap();
            assert_eq!(user_id, "dave");
            assert_eq!(retrieved_roles, roles);
        }

        #[tokio::test]
        async fn redis_multiple_users_with_different_roles() {
            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("multiple_users"))
                .await
                .expect("redis connect failed");

            let token1 = manager
                .login_with_roles("alice", 60, vec!["admin".to_string()])
                .await
                .expect("login failed");

            let token2 = manager
                .login_with_roles("bob", 60, vec!["user".to_string()])
                .await
                .expect("login failed");

            let token3 = manager
                .login_with_roles(
                    "charlie",
                    60,
                    vec!["moderator".to_string(), "user".to_string()],
                )
                .await
                .expect("login failed");

            let roles1 = manager.get_roles(&token1).await.unwrap().unwrap();
            let roles2 = manager.get_roles(&token2).await.unwrap().unwrap();
            let roles3 = manager.get_roles(&token3).await.unwrap().unwrap();

            assert_eq!(roles1, vec!["admin"]);
            assert_eq!(roles2, vec!["user"]);
            assert_eq!(roles3, vec!["moderator", "user"]);
        }

        #[tokio::test]
        async fn redis_logout_removes_roles() {
            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("logout_roles"))
                .await
                .expect("redis connect failed");

            let roles = vec!["admin".to_string()];
            let token = manager
                .login_with_roles("eve", 60, roles)
                .await
                .expect("login failed");

            manager.logout(&token).await.expect("logout failed");

            let user_info = manager.validate(&token).await.expect("validate failed");
            assert!(user_info.is_none());

            let user_info = manager
                .validate_with_roles(&token)
                .await
                .expect("validate_with_roles failed");
            assert!(user_info.is_none());

            let retrieved_roles = manager.get_roles(&token).await.expect("get_roles failed");
            assert!(retrieved_roles.is_none());
        }
    }
}
