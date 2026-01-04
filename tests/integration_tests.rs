//! Integration tests for the r-token library.
//!
//! These tests verify the complete functionality of r-token in realistic scenarios.

use actix_web::{test as actix_test, web, App, HttpResponse, get, post};
use r_token::{RTokenManager, RUser, RTokenError};
use std::sync::Arc;
use std::thread;

// ============ Basic Functionality Tests ============

#[test]
fn login_generates_valid_token() {
    let manager = RTokenManager::new();
    let result = manager.login("user_123");
    
    assert!(result.is_ok());
    let token = result.unwrap();
    
    // UUID v4 should be 36 characters (including hyphens)
    assert_eq!(token.len(), 36);
    assert!(token.contains('-'));
}

#[test]
fn login_creates_unique_tokens() {
    let manager = RTokenManager::new();
    
    let token1 = manager.login("user_1").unwrap();
    let token2 = manager.login("user_1").unwrap();
    
    // Even for the same user, tokens should be unique
    assert_ne!(token1, token2);
}

#[test]
fn logout_succeeds() {
    let manager = RTokenManager::new();
    let token = manager.login("user_456").unwrap();
    
    let result = manager.logout(&token);
    assert!(result.is_ok());
}

#[test]
fn logout_nonexistent_token() {
    let manager = RTokenManager::new();
    
    // Logging out a non-existent token should not fail
    let result = manager.logout("nonexistent-token");
    assert!(result.is_ok());
}

#[test]
fn multiple_users() {
    let manager = RTokenManager::new();
    
    let token1 = manager.login("alice").unwrap();
    let token2 = manager.login("bob").unwrap();
    let token3 = manager.login("charlie").unwrap();
    
    assert_ne!(token1, token2);
    assert_ne!(token2, token3);
    assert_ne!(token1, token3);
}

// ============ Concurrency Tests ============

#[test]
fn concurrent_logins() {
    let manager = Arc::new(RTokenManager::new());
    let mut handles = vec![];
    
    // Spawn 10 threads, each creating a token
    for i in 0..10 {
        let manager_clone = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            let user_id = format!("user_{}", i);
            manager_clone.login(&user_id)
        });
        handles.push(handle);
    }
    
    // Collect results
    let results: Vec<_> = handles.into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    
    // All should succeed
    assert_eq!(results.len(), 10);
    for result in &results {
        assert!(result.is_ok());
    }
    
    // All tokens should be unique
    let tokens: Vec<String> = results.into_iter()
        .map(|r| r.unwrap())
        .collect();
    
    for i in 0..tokens.len() {
        for j in (i + 1)..tokens.len() {
            assert_ne!(tokens[i], tokens[j]);
        }
    }
}

#[test]
fn concurrent_logout() {
    let manager = Arc::new(RTokenManager::new());
    
    // Create tokens first
    let tokens: Vec<String> = (0..10)
        .map(|i| manager.login(&format!("user_{}", i)).unwrap())
        .collect();
    
    let mut handles = vec![];
    
    // Logout concurrently
    for token in tokens {
        let manager_clone = Arc::clone(&manager);
        let handle = thread::spawn(move || {
            manager_clone.logout(&token)
        });
        handles.push(handle);
    }
    
    // All should succeed
    for handle in handles {
        let result = handle.join().unwrap();
        assert!(result.is_ok());
    }
}

// ============ actix-web Integration Tests ============

#[actix_web::test]
async fn protected_route_without_token() {
    #[get("/protected")]
    async fn protected(user: RUser) -> impl actix_web::Responder {
        HttpResponse::Ok().body(format!("User: {}", user.id))
    }
    
    let manager = RTokenManager::new();
    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(manager))
            .service(protected)
    ).await;
    
    let req = actix_test::TestRequest::get()
        .uri("/protected")
        .to_request();
    
    let resp = actix_test::call_service(&app, req).await;
    
    // Should return 401 Unauthorized
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn protected_route_with_invalid_token() {
    #[get("/protected")]
    async fn protected(user: RUser) -> impl actix_web::Responder {
        HttpResponse::Ok().body(format!("User: {}", user.id))
    }
    
    let manager = RTokenManager::new();
    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(manager))
            .service(protected)
    ).await;
    
    let req = actix_test::TestRequest::get()
        .uri("/protected")
        .insert_header(("Authorization", "invalid-token-xyz"))
        .to_request();
    
    let resp = actix_test::call_service(&app, req).await;
    
    // Should return 401 Unauthorized
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn protected_route_with_valid_token() {
    #[get("/protected")]
    async fn protected(user: RUser) -> impl actix_web::Responder {
        HttpResponse::Ok().body(format!("User: {}", user.id))
    }
    
    let manager = RTokenManager::new();
    let token = manager.login("test_user").unwrap();
    
    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(manager))
            .service(protected)
    ).await;
    
    let req = actix_test::TestRequest::get()
        .uri("/protected")
        .insert_header(("Authorization", token.as_str()))
        .to_request();
    
    let resp = actix_test::call_service(&app, req).await;
    
    // Should return 200 OK
    assert_eq!(resp.status(), 200);
    
    let body = actix_test::read_body(resp).await;
    assert_eq!(body, "User: test_user");
}

#[actix_web::test]
async fn protected_route_with_bearer_token() {
    #[get("/protected")]
    async fn protected(user: RUser) -> impl actix_web::Responder {
        HttpResponse::Ok().body(format!("User: {}", user.id))
    }
    
    let manager = RTokenManager::new();
    let token = manager.login("bearer_user").unwrap();
    
    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(manager))
            .service(protected)
    ).await;
    
    // Test with "Bearer " prefix
    let req = actix_test::TestRequest::get()
        .uri("/protected")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    
    let resp = actix_test::call_service(&app, req).await;
    
    assert_eq!(resp.status(), 200);
    
    let body = actix_test::read_body(resp).await;
    assert_eq!(body, "User: bearer_user");
}

#[actix_web::test]
async fn complete_authentication_flow() {
    #[post("/login")]
    async fn login(
        manager: web::Data<RTokenManager>,
        body: String,
    ) -> Result<HttpResponse, RTokenError> {
        let token = manager.login(&body)?;
        Ok(HttpResponse::Ok().body(token))
    }
    
    #[get("/profile")]
    async fn profile(user: RUser) -> impl actix_web::Responder {
        HttpResponse::Ok().body(format!("Profile: {}", user.id))
    }
    
    #[post("/logout")]
    async fn logout(
        manager: web::Data<RTokenManager>,
        user: RUser,
    ) -> Result<HttpResponse, RTokenError> {
        manager.logout(&user.token)?;
        Ok(HttpResponse::Ok().body("Logged out"))
    }
    
    let manager = RTokenManager::new();
    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(manager))
            .service(login)
            .service(profile)
            .service(logout)
    ).await;
    
    // Step 1: Login
    let req = actix_test::TestRequest::post()
        .uri("/login")
        .set_payload("alice")
        .to_request();
    
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    
    let token = String::from_utf8(actix_test::read_body(resp).await.to_vec()).unwrap();
    assert_eq!(token.len(), 36);
    
    // Step 2: Access protected route with token
    let req = actix_test::TestRequest::get()
        .uri("/profile")
        .insert_header(("Authorization", token.as_str()))
        .to_request();
    
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    
    let body = actix_test::read_body(resp).await;
    assert_eq!(body, "Profile: alice");
    
    // Step 3: Logout
    let req = actix_test::TestRequest::post()
        .uri("/logout")
        .insert_header(("Authorization", token.as_str()))
        .to_request();
    
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    
    // Step 4: Try to access protected route again (should fail)
    let req = actix_test::TestRequest::get()
        .uri("/profile")
        .insert_header(("Authorization", token.as_str()))
        .to_request();
    
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

// ============ Edge Cases ============

#[test]
fn empty_user_id() {
    let manager = RTokenManager::new();
    let result = manager.login("");
    
    // Should still work (empty string is valid)
    assert!(result.is_ok());
}

#[test]
fn special_characters_in_user_id() {
    let manager = RTokenManager::new();
    
    let special_ids = vec![
        "user@example.com",
        "user-with-dashes",
        "user_with_underscores",
        "用户123", // Unicode
        "user with spaces",
        "user/with/slashes",
    ];
    
    for user_id in special_ids {
        let result = manager.login(user_id);
        assert!(result.is_ok(), "Failed for user_id: {}", user_id);
    }
}

#[test]
fn very_long_user_id() {
    let manager = RTokenManager::new();
    let long_id = "a".repeat(10000);
    
    let result = manager.login(&long_id);
    assert!(result.is_ok());
}

#[actix_web::test]
async fn missing_token_manager() {
    #[get("/protected")]
    async fn protected(user: RUser) -> impl actix_web::Responder {
        HttpResponse::Ok().body(format!("User: {}", user.id))
    }
    
    // Don't register the token manager
    let app = actix_test::init_service(
        App::new()
            .service(protected)
    ).await;
    
    let req = actix_test::TestRequest::get()
        .uri("/protected")
        .insert_header(("Authorization", "some-token"))
        .to_request();
    
    let resp = actix_test::call_service(&app, req).await;
    
    // Should return 500 Internal Server Error
    assert_eq!(resp.status(), 500);
}

#[test]
fn manager_clone_shares_state() {
    let manager1 = RTokenManager::new();
    let manager2 = manager1.clone();
    
    // Login with manager1
    let token = manager1.login("shared_user").unwrap();
    
    // Logout with manager2 (should work because they share state)
    let result = manager2.logout(&token);
    assert!(result.is_ok());
}

#[test]
fn default_implementation() {
    let manager: RTokenManager = Default::default();
    let result = manager.login("default_user");
    assert!(result.is_ok());
}
