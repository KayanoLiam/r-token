#[cfg(feature = "redis")]
mod redis_tests {
    use r_token::RTokenRedisManager;

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1/".to_string())
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
        let manager = RTokenRedisManager::connect(&redis_url(), unique_prefix("roundtrip"))
            .await
            .expect("redis connect failed");

        let token = manager
            .login("alice", 60)
            .await
            .expect("login failed");

        let user_id = manager
            .validate(&token)
            .await
            .expect("validate failed");

        assert_eq!(user_id.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn redis_logout_revokes_token() {
        let manager = RTokenRedisManager::connect(&redis_url(), unique_prefix("logout"))
            .await
            .expect("redis connect failed");

        let token = manager
            .login("bob", 60)
            .await
            .expect("login failed");

        manager.logout(&token).await.expect("logout failed");

        let user_id = manager
            .validate(&token)
            .await
            .expect("validate failed");

        assert!(user_id.is_none());
    }

    #[tokio::test]
    async fn redis_ttl_expires_token() {
        let manager = RTokenRedisManager::connect(&redis_url(), unique_prefix("ttl"))
            .await
            .expect("redis connect failed");

        let token = manager
            .login("carol", 1)
            .await
            .expect("login failed");

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        let user_id = manager
            .validate(&token)
            .await
            .expect("validate failed");

        assert!(user_id.is_none());
    }
}

