//! Redis-backed rate limiter using an atomic token-bucket Lua script.
//!
//! Implements the [`RateLimiter`] trait from `buzz-auth`. The bucket holds up
//! to `limit` tokens and refills at `limit / window_secs` tokens per second,
//! so it allows a bounded burst up to the configured limit and then enforces
//! the average rate — there is no fixed-window boundary burst.
//!
//! Bucket state is a Redis hash (`tokens`, `last` refill timestamp) mutated
//! atomically in one Lua script (refill, consume, persist, expire), so a crash
//! can never leave a key without a TTL.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use buzz_auth::{
    error::AuthError,
    rate_limit::{LimitType, RateLimitResult, RateLimiter},
};
use buzz_core::TenantContext;
use nostr::PublicKey;
use redis::Script;

/// Atomic token-bucket: refill from `last`, consume `cost` if available, write
/// the new state, and (re)arm the idle TTL — all in one script.
///
/// - `KEYS[1]` — bucket key
/// - `ARGV[1]` — capacity (max tokens)
/// - `ARGV[2]` — refill rate, tokens per second
/// - `ARGV[3]` — now, Unix seconds (float)
/// - `ARGV[4]` — cost (tokens consumed per request)
/// - `ARGV[5]` — idle TTL in seconds
///
/// Returns `{allowed, remaining_tokens, capacity}`.
const TOKEN_BUCKET_SCRIPT: &str = r#"
local data = redis.call('HMGET', KEYS[1], 'tokens', 'last')
local tokens = tonumber(data[1])
local last = tonumber(data[2])
if tokens == nil then
    tokens = tonumber(ARGV[1])
    last = tonumber(ARGV[3])
end
local elapsed = math.max(0, tonumber(ARGV[3]) - last)
tokens = math.min(tonumber(ARGV[1]), tokens + elapsed * tonumber(ARGV[2]))
local allowed = 0
if tokens >= tonumber(ARGV[4]) then
    tokens = tokens - tonumber(ARGV[4])
    allowed = 1
end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'last', tostring(tonumber(ARGV[3])))
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[5]))
return {allowed, tokens, tonumber(ARGV[1])}
"#;

/// Run the token-bucket script against `key` and return a [`RateLimitResult`].
///
/// The bucket derives from the trait's `(window_secs, limit)` pair: capacity =
/// `limit`, refill = `limit / window_secs` tokens per second, cost = 1.
async fn run_rate_limit(
    pool: &deadpool_redis::Pool,
    key: &str,
    window_secs: u64,
    limit: u64,
) -> Result<RateLimitResult, AuthError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AuthError::Internal(format!("Redis pool: {e}")))?;

    let capacity = limit;
    let refill = limit as f64 / window_secs.max(1) as f64;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0);
    let cost = 1u64;
    // Keys are idle-expired: a bucket that stops being used clears itself.
    let ttl_secs = window_secs.saturating_mul(2).saturating_add(60);

    let script = Script::new(TOKEN_BUCKET_SCRIPT);
    let (allowed, remaining, cap): (u64, f64, u64) = script
        .key(key)
        .arg(capacity)
        .arg(refill)
        .arg(now)
        .arg(cost)
        .arg(ttl_secs)
        .invoke_async(&mut *conn)
        .await
        .map_err(|e| AuthError::Internal(format!("Redis token bucket script: {e}")))?;

    let current = remaining.floor().max(0.0) as u64;
    let reset_in_secs = if allowed == 1 {
        0
    } else {
        // Seconds until at least one token is available (cost is 1).
        let wait = (cost as f64 - remaining) / refill.max(f64::EPSILON);
        wait.ceil().max(1.0) as u64
    };

    if allowed == 1 {
        Ok(RateLimitResult::allowed(current, cap, reset_in_secs))
    } else {
        Ok(RateLimitResult::denied(current, cap, reset_in_secs))
    }
}

/// Redis-backed rate limiter using an atomic token bucket.
///
/// Pubkey keys are community-scoped via `&TenantContext`:
/// `buzz:{community}:ratelimit:{pubkey_hex}:{suffix}`. IP keys remain
/// operator-global: `buzz:ratelimit:ip:{ip}:conn`.
pub struct RedisRateLimiter {
    pool: deadpool_redis::Pool,
}

impl RedisRateLimiter {
    /// Create a new `RedisRateLimiter` backed by the given connection pool.
    pub fn new(pool: deadpool_redis::Pool) -> Self {
        Self { pool }
    }
}

impl RateLimiter for RedisRateLimiter {
    async fn check_and_increment(
        &self,
        ctx: &TenantContext,
        pubkey: &PublicKey,
        limit_type: LimitType,
        window_secs: u64,
        limit: u64,
    ) -> Result<RateLimitResult, AuthError> {
        let key = buzz_auth::rate_limit::rate_limit_key(ctx, pubkey, &limit_type);
        run_rate_limit(&self.pool, &key, window_secs, limit).await
    }

    async fn check_ip_connection(
        &self,
        ip: &IpAddr,
        window_secs: u64,
        limit: u64,
    ) -> Result<RateLimitResult, AuthError> {
        let key = buzz_auth::rate_limit::ip_rate_limit_key(ip);
        run_rate_limit(&self.pool, &key, window_secs, limit).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::{CommunityId, TenantContext};
    use deadpool_redis::{Config, Runtime};
    use uuid::Uuid;

    fn redis_pool() -> deadpool_redis::Pool {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        Config::from_url(url)
            .create_pool(Some(Runtime::Tokio1))
            .expect("create pool")
    }

    fn fresh_ctx() -> TenantContext {
        let host = format!("rate-test-{}.example", Uuid::new_v4().simple());
        TenantContext::resolved(CommunityId::from_uuid(Uuid::new_v4()), &host)
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn consumes_tokens_until_denied() {
        let limiter = RedisRateLimiter::new(redis_pool());
        let ctx = fresh_ctx();
        let keys = nostr::Keys::generate();
        let pk = keys.public_key();

        let results = [
            limiter
                .check_and_increment(&ctx, &pk, LimitType::Messages, 60, 3)
                .await
                .expect("first"),
            limiter
                .check_and_increment(&ctx, &pk, LimitType::Messages, 60, 3)
                .await
                .expect("second"),
            limiter
                .check_and_increment(&ctx, &pk, LimitType::Messages, 60, 3)
                .await
                .expect("third"),
            limiter
                .check_and_increment(&ctx, &pk, LimitType::Messages, 60, 3)
                .await
                .expect("fourth"),
        ];
        assert!(results[0].allowed, "first must be allowed");
        assert!(results[1].allowed, "second must be allowed");
        assert!(results[2].allowed, "third must be allowed");
        assert!(!results[3].allowed, "fourth must be denied");
        assert!(results[3].reset_in_secs >= 1, "denied must report retry-in");
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn refills_tokens_over_time() {
        let limiter = RedisRateLimiter::new(redis_pool());
        let ctx = fresh_ctx();
        let keys = nostr::Keys::generate();
        let pk = keys.public_key();

        let first = limiter
            .check_and_increment(&ctx, &pk, LimitType::ApiCalls, 1, 1)
            .await
            .expect("first");
        assert!(first.allowed, "first must be allowed");

        let second = limiter
            .check_and_increment(&ctx, &pk, LimitType::ApiCalls, 1, 1)
            .await
            .expect("second");
        assert!(!second.allowed, "second must be denied (bucket empty)");

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let third = limiter
            .check_and_increment(&ctx, &pk, LimitType::ApiCalls, 1, 1)
            .await
            .expect("third");
        assert!(third.allowed, "third must be allowed after refill");
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn quotas_are_isolated_per_community() {
        let limiter = RedisRateLimiter::new(redis_pool());
        let ctx_a = fresh_ctx();
        let ctx_b = fresh_ctx();
        let keys = nostr::Keys::generate();
        let pk = keys.public_key();

        // Exhaust the quota in community A (limit 1) ...
        let a1 = limiter
            .check_and_increment(&ctx_a, &pk, LimitType::Messages, 60, 1)
            .await
            .expect("a1");
        let a2 = limiter
            .check_and_increment(&ctx_a, &pk, LimitType::Messages, 60, 1)
            .await
            .expect("a2");
        assert!(a1.allowed);
        assert!(!a2.allowed, "A quota must be exhausted");

        // ... while community B has an independent quota.
        let b1 = limiter
            .check_and_increment(&ctx_b, &pk, LimitType::Messages, 60, 1)
            .await
            .expect("b1");
        assert!(b1.allowed, "B must have an independent quota");
    }

    #[tokio::test]
    #[ignore = "requires Redis"]
    async fn ip_connections_are_operator_global() {
        let limiter = RedisRateLimiter::new(redis_pool());
        let ip: IpAddr = "203.0.113.7".parse().expect("ip");

        let first = limiter
            .check_ip_connection(&ip, 60, 1)
            .await
            .expect("first");
        let second = limiter
            .check_ip_connection(&ip, 60, 1)
            .await
            .expect("second");
        assert!(first.allowed);
        assert!(
            !second.allowed,
            "IP quota (operator-global) must be exhausted"
        );
    }
}
