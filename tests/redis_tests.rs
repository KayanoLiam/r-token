#[cfg(feature = "redis")]
mod redis_tests {
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
        format!("r_token:test:{}:{}:", test_name, nanos)
    }

    #[tokio::test]
    async fn redis_login_validate_roundtrip() {
        let redis_url = test_redis_url().await;
        let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("roundtrip"))
            .await
            .expect("redis connect failed");

        let token = manager.login("alice", 60).await.expect("login failed");

        let user_id = manager.validate(&token).await.expect("validate failed");

        assert_eq!(user_id.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn redis_logout_revokes_token() {
        let redis_url = test_redis_url().await;
        let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("logout"))
            .await
            .expect("redis connect failed");

        let token = manager.login("bob", 60).await.expect("login failed");

        manager.logout(&token).await.expect("logout failed");

        let user_id = manager.validate(&token).await.expect("validate failed");

        assert!(user_id.is_none());
    }

    #[tokio::test]
    async fn redis_ttl_expires_token() {
        let redis_url = test_redis_url().await;
        let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("ttl"))
            .await
            .expect("redis connect failed");

        let token = manager.login("carol", 1).await.expect("login failed");

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let user_id = manager.validate(&token).await.expect("validate failed");

        assert!(user_id.is_none());
    }

    #[cfg(feature = "actix")]
    mod actix_redis_extractor_tests {
        use super::*;
        use actix_web::cookie::Cookie;
        use actix_web::{App, HttpResponse, get, test as actix_test, web};
        use r_token::RRedisUser;

        #[actix_web::test]
        async fn redis_extractor_accepts_authorization_header() {
            #[get("/protected")]
            async fn protected(user: RRedisUser) -> impl actix_web::Responder {
                HttpResponse::Ok().body(user.id)
            }

            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("actix_header"))
                .await
                .expect("redis connect failed");

            let token = manager.login("alice", 60).await.expect("login failed");

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
            let body = actix_test::read_body(resp).await;
            assert_eq!(body, "alice");
        }

        #[actix_web::test]
        async fn redis_extractor_accepts_cookie_token() {
            #[get("/protected")]
            async fn protected(user: RRedisUser) -> impl actix_web::Responder {
                HttpResponse::Ok().body(user.id)
            }

            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("actix_cookie"))
                .await
                .expect("redis connect failed");

            let token = manager.login("bob", 60).await.expect("login failed");

            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(manager))
                    .service(protected),
            )
            .await;

            let req = actix_test::TestRequest::get()
                .uri("/protected")
                .cookie(Cookie::new(r_token::TOKEN_COOKIE_NAME, token))
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);
            let body = actix_test::read_body(resp).await;
            assert_eq!(body, "bob");
        }

        #[actix_web::test]
        async fn authorization_header_takes_precedence_over_cookie() {
            #[get("/protected")]
            async fn protected(user: RRedisUser) -> impl actix_web::Responder {
                HttpResponse::Ok().body(user.id)
            }

            let redis_url = test_redis_url().await;
            let manager =
                RTokenRedisManager::connect(&redis_url, unique_prefix("actix_precedence"))
                    .await
                    .expect("redis connect failed");

            let token = manager.login("carol", 60).await.expect("login failed");

            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(manager))
                    .service(protected),
            )
            .await;

            let req = actix_test::TestRequest::get()
                .uri("/protected")
                .insert_header(("Authorization", "invalid-token-xyz"))
                .cookie(Cookie::new(r_token::TOKEN_COOKIE_NAME, token))
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 401);
        }

        #[actix_web::test]
        async fn token_source_config_cookie_first_can_override_header() {
            #[get("/protected")]
            async fn protected(user: RRedisUser) -> impl actix_web::Responder {
                HttpResponse::Ok().body(user.id)
            }

            let redis_url = test_redis_url().await;
            let manager = RTokenRedisManager::connect(&redis_url, unique_prefix("actix_cfg"))
                .await
                .expect("redis connect failed");

            let token = manager.login("dave", 60).await.expect("login failed");

            let cfg = r_token::TokenSourceConfig {
                priority: r_token::TokenSourcePriority::CookieFirst,
                header_names: vec!["Authorization".to_string()],
                cookie_names: vec![r_token::TOKEN_COOKIE_NAME.to_string()],
            };

            let app = actix_test::init_service(
                App::new()
                    .app_data(web::Data::new(manager))
                    .app_data(web::Data::new(cfg))
                    .service(protected),
            )
            .await;

            let req = actix_test::TestRequest::get()
                .uri("/protected")
                .insert_header(("Authorization", "invalid-token-xyz"))
                .cookie(Cookie::new(r_token::TOKEN_COOKIE_NAME, token))
                .to_request();

            let resp = actix_test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);
            let body = actix_test::read_body(resp).await;
            assert_eq!(body, "dave");
        }
    }
}
