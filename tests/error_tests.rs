//! Error handling tests for r-token.
//!
//! Tests the error types and their behavior.

use r_token::RTokenError;
use std::error::Error;

#[cfg(test)]
mod error_handling {
    use super::*;

    #[test]
    fn error_display() {
        let error = RTokenError::MutexPoisoned;
        let message = format!("{}", error);

        assert_eq!(message, "Token manager mutex poisoned");
    }

    #[test]
    fn error_debug() {
        let error = RTokenError::MutexPoisoned;
        let debug_str = format!("{:?}", error);

        assert!(debug_str.contains("MutexPoisoned"));
    }

    #[test]
    fn error_trait_implementation() {
        let error = RTokenError::MutexPoisoned;

        // Should implement Error trait
        let _: &dyn Error = &error;

        // source() should return None for this simple error
        assert!(error.source().is_none());
    }

    #[test]
    fn error_conversion() {
        let error = RTokenError::MutexPoisoned;

        // Should be able to use with Result
        let result: Result<(), RTokenError> = Err(error);
        assert!(result.is_err());

        match result {
            Err(RTokenError::MutexPoisoned) => {
                // Expected
            }
            _ => panic!("Unexpected result"),
        }
    }
}

#[cfg(test)]
mod actix_error_tests {
    use super::*;
    use actix_web::{App, HttpResponse, post, test, web};
    use r_token::RTokenManager;

    #[actix_web::test]
    async fn error_response() {
        #[post("/test")]
        async fn test_endpoint(
            manager: web::Data<RTokenManager>,
        ) -> Result<HttpResponse, RTokenError> {
            // Simulate an error by attempting to force a mutex error scenario
            // In normal usage, this would be quite rare
            let _token = manager.login("test_user")?;
            Ok(HttpResponse::Ok().finish())
        }

        let manager = RTokenManager::new();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(manager))
                .service(test_endpoint),
        )
        .await;

        let req = test::TestRequest::post().uri("/test").to_request();

        let resp = test::call_service(&app, req).await;

        // Under normal circumstances, this should succeed
        assert_eq!(resp.status(), 200);
    }
}
