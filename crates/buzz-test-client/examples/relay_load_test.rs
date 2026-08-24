//! Relay load test: measure ingest throughput (WS publish acks) and fan-out
//! latency (publish -> subscriber receipt) against a running relay.
//!
//! Usage (dev relay running on :3010):
//!   RELAY_URL_A=http://a.localhost:3010 \
//!   LOAD_SUBSCRIBERS=10 LOAD_EVENTS=500 \
//!   cargo run -p buzz-test-client --example relay_load_test
//!
//! For an unthrottled run, start the relay with high rate limits:
//!   BUZZ_RATE_LIMIT_HUMAN_MESSAGES_PER_MIN=100000
//!   BUZZ_RATE_LIMIT_HUMAN_WS_EVENTS_PER_SEC=100000
//!   BUZZ_RATE_LIMIT_HUMAN_API_CALLS_PER_MIN=100000

use std::time::{Duration, Instant};

use buzz_test_client::BuzzTestClient;
use nostr::{Alphabet, EventBuilder, Filter, Keys, Kind, SingleLetterTag, Tag};

#[tokio::main]
async fn main() {
    let base =
        std::env::var("RELAY_URL_A").unwrap_or_else(|_| "http://a.localhost:3010".to_string());
    let ws_url = base
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let subscribers: usize = std::env::var("LOAD_SUBSCRIBERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);
    let events: usize = std::env::var("LOAD_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(500);

    let owner = Keys::generate();
    let http = reqwest::Client::new();

    // 1. Create an open channel so the owner is a member.
    let channel_uuid = uuid::Uuid::new_v4().to_string();
    let chan = EventBuilder::new(Kind::Custom(9007), "")
        .tags(vec![
            Tag::parse(["h", &channel_uuid]).unwrap(),
            Tag::parse(["name", "load-test"]).unwrap(),
        ])
        .sign_with_keys(&owner)
        .unwrap();
    let resp = http
        .post(format!("{base}/events"))
        .header("X-Pubkey", owner.public_key().to_hex())
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&chan).unwrap())
        .send()
        .await
        .expect("create channel");
    assert!(
        resp.status().is_success(),
        "channel create: {}",
        resp.status()
    );

    // 2. Connect the subscribers and subscribe to the channel.
    let filter = Filter::new()
        .kinds(vec![Kind::Custom(9)])
        .custom_tag(SingleLetterTag::lowercase(Alphabet::H), &channel_uuid);
    let mut subs = Vec::new();
    for i in 0..subscribers {
        let mut c = BuzzTestClient::connect(&ws_url, &Keys::generate())
            .await
            .unwrap_or_else(|e| panic!("subscriber {i} connect: {e}"));
        c.subscribe("s", vec![filter.clone()]).await.unwrap();
        subs.push(c);
    }

    // 3. Connect the publisher (the channel owner).
    let mut pubc = BuzzTestClient::connect(&ws_url, &owner)
        .await
        .expect("publisher connect");

    // 4. Phase A: ingest throughput — publish `events` messages, time the acks.
    let start = Instant::now();
    for i in 0..events {
        pubc.send_text_message(&owner, &channel_uuid, &format!("load-{i}"), 9)
            .await
            .unwrap_or_else(|e| panic!("publish {i}: {e}"));
    }
    let ingest_elapsed = start.elapsed();
    let rate = events as f64 / ingest_elapsed.as_secs_f64();

    // 5. Phase B: fan-out latency — publish one probe, time each subscriber's
    //    receipt (events arrive in order per subscription).
    let probe = format!("fanout-probe-{}", uuid::Uuid::new_v4().simple());
    let t0 = Instant::now();
    pubc.send_text_message(&owner, &channel_uuid, &probe, 9)
        .await
        .expect("probe publish");
    let probe_ack = t0.elapsed();

    let mut latencies = Vec::new();
    for (i, s) in subs.iter_mut().enumerate() {
        // Drain until the probe arrives.
        loop {
            match s.recv_event(Duration::from_millis(2000)).await {
                Ok(buzz_test_client::RelayMessage::Event { event, .. }) => {
                    if event.content == probe {
                        latencies.push(t0.elapsed());
                        break;
                    }
                }
                Ok(_) => continue,
                Err(e) => panic!("subscriber {i} recv: {e}"),
            }
        }
    }

    let mut sorted = latencies.clone();
    sorted.sort();
    let p50 = sorted[sorted.len() * 50 / 100];
    let p99 = sorted[(sorted.len() * 99 / 100).min(sorted.len() - 1)];
    let max = *sorted.last().unwrap();

    println!("=== relay load test ===");
    println!("subscribers={subscribers} events={events}");
    println!(
        "ingest: {events} events in {:.2}s = {:.0} events/sec",
        ingest_elapsed.as_secs_f64(),
        rate
    );
    println!(
        "probe ack latency: {:.2}ms",
        probe_ack.as_secs_f64() * 1000.0
    );
    println!(
        "fan-out latency (ack->receipt, {} subs): p50 {:.1}ms, p99 {:.1}ms, max {:.1}ms",
        latencies.len(),
        p50.as_secs_f64() * 1000.0,
        p99.as_secs_f64() * 1000.0,
        max.as_secs_f64() * 1000.0,
    );
}
