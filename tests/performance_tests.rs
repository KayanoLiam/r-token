//! Performance and stress tests for r-token.
//!
//! These tests verify the library's behavior under load.

use r_token::RTokenManager;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

#[cfg(test)]
mod performance {
    use super::*;

    #[test]
    fn login_performance() {
        let manager = RTokenManager::new();
        let iterations = 1000;
        
        let start = Instant::now();
        
        for i in 0..iterations {
            let user_id = format!("user_{}", i);
            manager.login(&user_id).unwrap();
        }
        
        let duration = start.elapsed();
        
        println!("Created {} tokens in {:?}", iterations, duration);
        println!("Average time per token: {:?}", duration / iterations);
        
        // Should be reasonably fast (< 1ms per token on average)
        assert!(duration.as_millis() < (iterations as u128));
    }

    #[test]
    fn logout_performance() {
        let manager = RTokenManager::new();
        let iterations = 1000;
        
        // First, create tokens
        let tokens: Vec<String> = (0..iterations)
            .map(|i| manager.login(&format!("user_{}", i)).unwrap())
            .collect();
        
        let start = Instant::now();
        
        for token in tokens {
            manager.logout(&token).unwrap();
        }
        
        let duration = start.elapsed();
        
        println!("Removed {} tokens in {:?}", iterations, duration);
        println!("Average time per logout: {:?}", duration / iterations);
    }

    #[test]
    fn concurrent_load() {
        let manager = Arc::new(RTokenManager::new());
        let num_threads = 10;
        let operations_per_thread = 100;
        
        let start = Instant::now();
        
        let handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let manager_clone = Arc::clone(&manager);
                thread::spawn(move || {
                    for i in 0..operations_per_thread {
                        let user_id = format!("thread_{}_user_{}", thread_id, i);
                        let token = manager_clone.login(&user_id).unwrap();
                        
                        // Simulate some work
                        thread::yield_now();
                        
                        manager_clone.logout(&token).unwrap();
                    }
                })
            })
            .collect();
        
        for handle in handles {
            handle.join().unwrap();
        }
        
        let duration = start.elapsed();
        let total_operations = num_threads * operations_per_thread * 2; // login + logout
        
        println!(
            "Completed {} operations across {} threads in {:?}",
            total_operations, num_threads, duration
        );
        println!(
            "Average time per operation: {:?}",
            duration / (total_operations as u32)
        );
    }

    #[test]
    fn memory_usage_with_many_tokens() {
        let manager = RTokenManager::new();
        let num_tokens = 10_000;
        
        let mut tokens = Vec::with_capacity(num_tokens);
        
        for i in 0..num_tokens {
            let token = manager.login(&format!("user_{}", i)).unwrap();
            tokens.push(token);
        }
        
        println!("Created {} tokens", num_tokens);
        
        // Clean up
        for token in tokens {
            manager.logout(&token).unwrap();
        }
        
        println!("Cleaned up {} tokens", num_tokens);
    }

    #[test]
    fn rapid_login_logout_cycles() {
        let manager = RTokenManager::new();
        let cycles = 1000;
        
        let start = Instant::now();
        
        for i in 0..cycles {
            let user_id = format!("cycling_user_{}", i);
            
            // Login
            let token = manager.login(&user_id).unwrap();
            
            // Immediately logout
            manager.logout(&token).unwrap();
        }
        
        let duration = start.elapsed();
        
        println!("Completed {} login-logout cycles in {:?}", cycles, duration);
        println!("Average cycle time: {:?}", duration / cycles);
    }

    #[test]
    fn clone_overhead() {
        let manager1 = RTokenManager::new();
        let iterations = 1000;
        
        let start = Instant::now();
        
        for _ in 0..iterations {
            let _cloned = manager1.clone();
        }
        
        let duration = start.elapsed();
        
        println!("Cloned manager {} times in {:?}", iterations, duration);
        println!("Average clone time: {:?}", duration / iterations);
        
        // Cloning should be very fast since it's just Arc cloning
        assert!(duration.as_micros() < ((iterations * 10) as u128));
    }

    #[test]
    fn contention_under_load() {
        use std::sync::Barrier;
        
        let manager = Arc::new(RTokenManager::new());
        let num_threads = 20;
        let barrier = Arc::new(Barrier::new(num_threads));
        
        let handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let manager_clone = Arc::clone(&manager);
                let barrier_clone = Arc::clone(&barrier);
                
                thread::spawn(move || {
                    // Wait for all threads to be ready
                    barrier_clone.wait();
                    
                    // All threads hit the manager at the same time
                    let user_id = format!("concurrent_user_{}", thread_id);
                    manager_clone.login(&user_id).unwrap()
                })
            })
            .collect();
        
        let tokens: Vec<String> = handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        
        // All tokens should be unique despite high contention
        for i in 0..tokens.len() {
            for j in (i + 1)..tokens.len() {
                assert_ne!(tokens[i], tokens[j]);
            }
        }
    }
}
