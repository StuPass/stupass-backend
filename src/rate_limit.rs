use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::warn;

// TODO: Implement eviction for old entries
/// Tracks password reset request attempts per email address
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Maps email address to (request_count, window_start_time)
    requests: Arc<Mutex<HashMap<String, (usize, DateTime<Utc>)>>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new() -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Check if a password reset request is allowed for the given email.
    /// Allows up to `max_requests` per `window_duration_hours`.
    ///
    /// Returns `Ok(())` if allowed, `Err(elapsed_seconds)` if rate limited.
    pub fn check_password_reset(&self, email: &str) -> Result<(), u64> {
        const MAX_REQUESTS: usize = 3;
        const WINDOW_HOURS: i64 = 1;

        let mut requests = match self.requests.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!(
                    "RateLimiter mutex poisoned; denying password reset request for {}",
                    email
                );
                // Fail closed: treat as fully rate limited for the full window duration
                return Err((WINDOW_HOURS * 3600) as u64);
            }
        };
        let now = Utc::now();

        let entry = requests.entry(email.to_lowercase()).or_insert((0, now));
        let window_start = entry.1;

        // Reset window if expired
        if now.signed_duration_since(window_start).num_hours() >= WINDOW_HOURS {
            *entry = (1, now);
            return Ok(());
        }

        // Check if limit exceeded
        if entry.0 >= MAX_REQUESTS {
            let elapsed_secs = now.signed_duration_since(window_start).num_seconds();
            let window_secs = WINDOW_HOURS * 3600;
            let remaining_secs = (window_secs - elapsed_secs).max(0) as u64;
            warn!(
                "Rate limit exceeded for email {}: {}/{} requests",
                email, entry.0, MAX_REQUESTS
            );
            return Err(remaining_secs);
        }

        // Increment counter
        entry.0 += 1;
        Ok(())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}
