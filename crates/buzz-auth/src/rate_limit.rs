//! Rate limiting types and interface.
//!
//! Defines the [`RateLimiter`] trait. The Redis-backed implementation lives in
//! `buzz-pubsub` (`RedisRateLimiter`) and uses a token-bucket algorithm:
//! capacity = `limit`, refill = `limit / window_secs` tokens per second, so
//! there is no fixed-window boundary burst.

use std::net::IpAddr;

use buzz_core::TenantContext;
use nostr::PublicKey;
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

/// The outcome of a rate-limit check, including counter state for response headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitResult {
    /// Whether the request is permitted (`true`) or should be rejected (`false`).
    pub allowed: bool,
    /// Current counter value after this increment.
    pub current: u64,
    /// The configured limit for this window.
    pub limit: u64,
    /// Seconds until the current window resets.
    pub reset_in_secs: u64,
}

impl RateLimitResult {
    /// Construct an **allowed** result.
    pub fn allowed(current: u64, limit: u64, reset_in_secs: u64) -> Self {
        Self {
            allowed: true,
            current,
            limit,
            reset_in_secs,
        }
    }

    /// Construct a **denied** result.
    pub fn denied(current: u64, limit: u64, reset_in_secs: u64) -> Self {
        Self {
            allowed: false,
            current,
            limit,
            reset_in_secs,
        }
    }
}

/// The category of operation being rate-limited.
///
/// Each variant maps to a distinct Redis key suffix so limits are tracked
/// independently per operation type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitType {
    /// Nostr message events (kind:1 etc.) sent via WebSocket.
    Messages,
    /// HTTP REST API calls.
    ApiCalls,
    /// All WebSocket events (broader than `Messages`).
    WsEvents,
    /// Concurrent WebSocket connections from a single IP address.
    IpConnections,
}

impl LimitType {
    /// Short suffix used in Redis key construction (e.g. `"msg"`, `"api"`).
    pub fn key_suffix(&self) -> &'static str {
        match self {
            Self::Messages => "msg",
            Self::ApiCalls => "api",
            Self::WsEvents => "ws",
            Self::IpConnections => "conn",
        }
    }
}

/// Per-tier rate limit thresholds.
///
/// All values are counts per the relevant time window (per-minute or per-second).
/// Loaded from the relay config file; sensible defaults are provided for all fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum messages per minute for human users. Default: 60.
    #[serde(default = "default_human_msg")]
    pub human_messages_per_min: u64,
    /// Maximum HTTP API calls per minute for human users. Default: 300.
    #[serde(default = "default_human_api")]
    pub human_api_calls_per_min: u64,
    /// Maximum WebSocket events per second for human users. Default: 10.
    #[serde(default = "default_human_ws")]
    pub human_ws_events_per_sec: u64,
    /// Maximum messages per minute for standard-tier agent tokens. Default: 120.
    #[serde(default = "default_agent_std_msg")]
    pub agent_standard_messages_per_min: u64,
    /// Maximum HTTP API calls per minute for standard-tier agent tokens. Default: 600.
    #[serde(default = "default_agent_std_api")]
    pub agent_standard_api_calls_per_min: u64,
    /// Maximum messages per minute for elevated-tier agent tokens. Default: 300.
    #[serde(default = "default_agent_elev_msg")]
    pub agent_elevated_messages_per_min: u64,
    /// Maximum messages per minute for platform-tier agent tokens. Default: 600.
    #[serde(default = "default_agent_plat_msg")]
    pub agent_platform_messages_per_min: u64,
    /// Hex pubkeys of agents granted the **elevated** message tier. Empty by
    /// default (no agent is elevated until an operator lists one).
    #[serde(default)]
    pub elevated_pubkeys: Vec<String>,
    /// Hex pubkeys of agents granted the **platform** message tier. Empty by
    /// default. A pubkey listed in both allowlists resolves to platform.
    #[serde(default)]
    pub platform_pubkeys: Vec<String>,
}

fn default_human_msg() -> u64 {
    60
}
fn default_human_api() -> u64 {
    300
}
fn default_human_ws() -> u64 {
    10
}
fn default_agent_std_msg() -> u64 {
    120
}
fn default_agent_std_api() -> u64 {
    600
}
fn default_agent_elev_msg() -> u64 {
    300
}
fn default_agent_plat_msg() -> u64 {
    600
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            human_messages_per_min: default_human_msg(),
            human_api_calls_per_min: default_human_api(),
            human_ws_events_per_sec: default_human_ws(),
            agent_standard_messages_per_min: default_agent_std_msg(),
            agent_standard_api_calls_per_min: default_agent_std_api(),
            agent_elevated_messages_per_min: default_agent_elev_msg(),
            agent_platform_messages_per_min: default_agent_plat_msg(),
            elevated_pubkeys: Vec::new(),
            platform_pubkeys: Vec::new(),
        }
    }
}

/// The agent tier a principal is rate-limited as.
///
/// Resolution is a pure function of the config's operator-provided
/// elevated/platform pubkey allowlists — there is no other tier signal in the
/// system today. See [`resolve_tier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTier {
    /// Human (non-agent) principal.
    Human,
    /// Agent not present in either operator allowlist.
    Standard,
    /// Agent listed in the operator's elevated allowlist.
    Elevated,
    /// Agent listed in the operator's platform allowlist.
    Platform,
}

/// Resolve the rate-limit tier for a principal.
///
/// `is_agent` is the NIP-OA / DB-backed agent determination; the operator's
/// elevated/platform pubkey allowlists lift an agent into a higher tier.
/// Platform wins over elevated when a pubkey is listed in both.
pub fn resolve_tier(limits: &RateLimitConfig, pubkey: &PublicKey, is_agent: bool) -> AgentTier {
    if !is_agent {
        return AgentTier::Human;
    }
    let hex = pubkey.to_hex();
    if limits
        .platform_pubkeys
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&hex))
    {
        AgentTier::Platform
    } else if limits
        .elevated_pubkeys
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&hex))
    {
        AgentTier::Elevated
    } else {
        AgentTier::Standard
    }
}

/// The message-per-minute limit for a resolved tier.
pub fn message_limit_for(limits: &RateLimitConfig, tier: AgentTier) -> u64 {
    match tier {
        AgentTier::Human => limits.human_messages_per_min,
        AgentTier::Standard => limits.agent_standard_messages_per_min,
        AgentTier::Elevated => limits.agent_elevated_messages_per_min,
        AgentTier::Platform => limits.agent_platform_messages_per_min,
    }
}

/// The API-calls-per-minute limit for a resolved tier.
///
/// The config exposes a single agent API tier (`agent_standard_api_calls_per_min`);
/// elevated/platform agents share it.
pub fn api_limit_for(limits: &RateLimitConfig, tier: AgentTier) -> u64 {
    match tier {
        AgentTier::Human => limits.human_api_calls_per_min,
        AgentTier::Standard | AgentTier::Elevated | AgentTier::Platform => {
            limits.agent_standard_api_calls_per_min
        }
    }
}

/// Async rate-limiting interface.
///
/// The Redis-backed production implementation (`RedisRateLimiter`) lives in
/// `buzz-pubsub` and uses a token bucket. A no-op `AlwaysAllowRateLimiter` is
/// provided for unit tests.
///
/// ## Tenant scoping
///
/// Pubkey-keyed limits ([`check_and_increment`]) take `&TenantContext` and the Redis
/// key is community-prefixed (`buzz:{community}:ratelimit:{pubkey}:{suffix}`). The
/// same pubkey active in two communities consumes two independent quotas — that is
/// the correct behavior under multi-tenant isolation (S1 cross-community fence).
///
/// IP-keyed limits ([`check_ip_connection`]) are **operator-global** by design. They
/// gate connection acceptance at the network edge, before host→community resolution
/// has completed (or, on resolve failure, instead of it). Threading `&TenantContext`
/// through the connection-rate fence would invert the order of operations. If
/// per-(community, IP) caps are ever needed as a tenant-fairness signal, that
/// belongs in an additive `LimitType` keyed on `(community, ip)`, not in this trait.
///
/// The token-bucket implementation allows a bounded burst up to `limit` tokens,
/// then enforces the configured average rate (`limit / window_secs` per second).
pub trait RateLimiter: Send + Sync {
    /// Increment the per-(community, pubkey) counter for `limit_type` and return
    /// whether the request is within `limit` for the given `window_secs`.
    ///
    /// `ctx` scopes the counter to the resolved community; the same pubkey in two
    /// communities is two independent quotas.
    fn check_and_increment(
        &self,
        ctx: &TenantContext,
        pubkey: &PublicKey,
        limit_type: LimitType,
        window_secs: u64,
        limit: u64,
    ) -> impl std::future::Future<Output = Result<RateLimitResult, AuthError>> + Send;

    /// Increment the per-IP connection counter and return whether the connection
    /// is within `limit` for the given `window_secs`.
    ///
    /// Operator-global — see trait docs. This fence runs before / outside of host
    /// resolution and intentionally does not take a `TenantContext`.
    fn check_ip_connection(
        &self,
        ip: &IpAddr,
        window_secs: u64,
        limit: u64,
    ) -> impl std::future::Future<Output = Result<RateLimitResult, AuthError>> + Send;
}

/// Redis key for pubkey-based rate limit:
/// `buzz:{community}:ratelimit:{pubkey_hex}:{suffix}`.
///
/// Community-prefixed: the same pubkey in two communities maps to two distinct
/// keys, so quotas don't bleed across the tenancy fence.
pub fn rate_limit_key(ctx: &TenantContext, pubkey: &PublicKey, limit_type: &LimitType) -> String {
    format!(
        "buzz:{}:ratelimit:{}:{}",
        ctx.community(),
        pubkey.to_hex(),
        limit_type.key_suffix()
    )
}

/// Redis key for IP-based rate limit: `buzz:ratelimit:ip:{ip}:conn`.
///
/// Operator-global by design — see [`RateLimiter`] docs.
pub fn ip_rate_limit_key(ip: &IpAddr) -> String {
    format!("buzz:ratelimit:ip:{}:conn", ip)
}

/// Always-allow rate limiter for unit tests.
#[cfg(any(test, feature = "test-utils"))]
pub struct AlwaysAllowRateLimiter;

#[cfg(any(test, feature = "test-utils"))]
impl RateLimiter for AlwaysAllowRateLimiter {
    async fn check_and_increment(
        &self,
        _ctx: &TenantContext,
        _pubkey: &PublicKey,
        _limit_type: LimitType,
        window_secs: u64,
        limit: u64,
    ) -> Result<RateLimitResult, AuthError> {
        Ok(RateLimitResult::allowed(1, limit, window_secs))
    }

    async fn check_ip_connection(
        &self,
        _ip: &IpAddr,
        window_secs: u64,
        limit: u64,
    ) -> Result<RateLimitResult, AuthError> {
        Ok(RateLimitResult::allowed(1, limit, window_secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::CommunityId;
    use nostr::Keys;
    use sha2::Digest;
    use std::net::Ipv4Addr;
    use uuid::Uuid;

    fn fixture_ctx(host: &str) -> TenantContext {
        // Deterministic community id from host so test assertions can name the prefix.
        let bytes = sha2::Sha256::digest(host.as_bytes());
        let mut uuid_bytes = [0u8; 16];
        uuid_bytes.copy_from_slice(&bytes[..16]);
        let id = CommunityId::from_uuid(Uuid::from_bytes(uuid_bytes));
        TenantContext::resolved(id, host)
    }

    #[test]
    fn rate_limit_key_includes_community_prefix() {
        let ctx = fixture_ctx("relay-a.example");
        let keys = Keys::generate();
        let key = rate_limit_key(&ctx, &keys.public_key(), &LimitType::Messages);
        let expected_prefix = format!("buzz:{}:ratelimit:", ctx.community());
        assert!(
            key.starts_with(&expected_prefix),
            "key {key} should start with {expected_prefix}"
        );
        assert!(key.ends_with(":msg"));
    }

    #[test]
    fn rate_limit_key_isolates_communities_for_same_pubkey() {
        // The S1 cross-community isolation fence at the rate-limit key layer:
        // same pubkey, two communities -> two distinct Redis keys -> independent quotas.
        let keys = Keys::generate();
        let ctx_a = fixture_ctx("relay-a.example");
        let ctx_b = fixture_ctx("relay-b.example");
        let key_a = rate_limit_key(&ctx_a, &keys.public_key(), &LimitType::Messages);
        let key_b = rate_limit_key(&ctx_b, &keys.public_key(), &LimitType::Messages);
        assert_ne!(
            key_a, key_b,
            "same pubkey in two communities must not share a rate-limit key"
        );
    }

    #[test]
    fn rate_limit_key_components_are_lowercase() {
        // Stability/idempotence invariant: if pubkey hex or community Display
        // ever started emitting uppercase, the same (community, pubkey) would
        // produce two distinct Redis keys → effective 2× quota. Pin the
        // lowercase property here so the regression surfaces in unit tests,
        // not in production traffic.
        let ctx = fixture_ctx("relay-a.example");
        let keys = Keys::generate();
        let key = rate_limit_key(&ctx, &keys.public_key(), &LimitType::Messages);
        for c in key.chars() {
            assert!(
                !c.is_ascii_uppercase(),
                "rate-limit key {key} must be all-lowercase ASCII"
            );
        }
    }

    #[test]
    fn ip_rate_limit_key_format() {
        // IP fence stays operator-global — no community in the key.
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ip_rate_limit_key(&ip), "buzz:ratelimit:ip:192.168.1.1:conn");
    }

    #[tokio::test]
    async fn always_allow_limiter() {
        let limiter = AlwaysAllowRateLimiter;
        let ctx = fixture_ctx("relay-a.example");
        let keys = Keys::generate();
        let result = limiter
            .check_and_increment(&ctx, &keys.public_key(), LimitType::Messages, 60, 60)
            .await
            .unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn humans_resolve_to_human_tier_even_when_listed() {
        // A pubkey in the operator allowlists is only elevated when the
        // principal is an agent — a human listing must not grant agent tiers.
        let keys = Keys::generate();
        let limits = RateLimitConfig {
            elevated_pubkeys: vec![keys.public_key().to_hex()],
            ..RateLimitConfig::default()
        };
        assert_eq!(
            resolve_tier(&limits, &keys.public_key(), false),
            AgentTier::Human
        );
    }

    #[test]
    fn unlisted_agent_is_standard_tier() {
        let keys = Keys::generate();
        let limits = RateLimitConfig::default();
        assert_eq!(
            resolve_tier(&limits, &keys.public_key(), true),
            AgentTier::Standard
        );
    }

    #[test]
    fn elevated_allowlist_lifts_agent() {
        let keys = Keys::generate();
        let limits = RateLimitConfig {
            elevated_pubkeys: vec![keys.public_key().to_hex()],
            ..RateLimitConfig::default()
        };
        assert_eq!(
            resolve_tier(&limits, &keys.public_key(), true),
            AgentTier::Elevated
        );
    }

    #[test]
    fn platform_allowlist_wins_over_elevated() {
        let keys = Keys::generate();
        let hex = keys.public_key().to_hex();
        let limits = RateLimitConfig {
            elevated_pubkeys: vec![hex.clone()],
            platform_pubkeys: vec![hex],
            ..RateLimitConfig::default()
        };
        assert_eq!(
            resolve_tier(&limits, &keys.public_key(), true),
            AgentTier::Platform
        );
    }

    #[test]
    fn allowlist_matching_is_case_insensitive() {
        let keys = Keys::generate();
        let limits = RateLimitConfig {
            elevated_pubkeys: vec![keys.public_key().to_hex().to_uppercase()],
            ..RateLimitConfig::default()
        };
        assert_eq!(
            resolve_tier(&limits, &keys.public_key(), true),
            AgentTier::Elevated
        );
    }

    #[test]
    fn message_limits_follow_resolved_tier() {
        let limits = RateLimitConfig {
            human_messages_per_min: 10,
            agent_standard_messages_per_min: 20,
            agent_elevated_messages_per_min: 30,
            agent_platform_messages_per_min: 40,
            ..RateLimitConfig::default()
        };

        assert_eq!(message_limit_for(&limits, AgentTier::Human), 10);
        assert_eq!(message_limit_for(&limits, AgentTier::Standard), 20);
        assert_eq!(message_limit_for(&limits, AgentTier::Elevated), 30);
        assert_eq!(message_limit_for(&limits, AgentTier::Platform), 40);
    }

    #[test]
    fn api_limits_share_one_agent_tier() {
        let limits = RateLimitConfig {
            human_api_calls_per_min: 100,
            agent_standard_api_calls_per_min: 200,
            ..RateLimitConfig::default()
        };

        assert_eq!(api_limit_for(&limits, AgentTier::Human), 100);
        assert_eq!(api_limit_for(&limits, AgentTier::Standard), 200);
        assert_eq!(api_limit_for(&limits, AgentTier::Elevated), 200);
        assert_eq!(api_limit_for(&limits, AgentTier::Platform), 200);
    }
}
