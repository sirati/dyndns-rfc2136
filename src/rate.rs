use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const MAX_TRACKED_PEERS: usize = 4096;

pub struct RateLimiter {
    global_limit: u32,
    host_limit: u32,
    peer_limit: u32,
    state: Mutex<State>,
}

struct State {
    window_start: Instant,
    authenticated: u32,
    hosts: HashMap<String, u32>,
    peers: HashMap<IpAddr, u32>,
}

impl RateLimiter {
    #[must_use]
    pub fn new(global_limit: u32, host_limit: u32, peer_limit: u32) -> Self {
        Self {
            global_limit,
            host_limit,
            peer_limit,
            state: Mutex::new(State {
                window_start: Instant::now(),
                authenticated: 0,
                hosts: HashMap::new(),
                peers: HashMap::new(),
            }),
        }
    }

    pub async fn peer_blocked(&self, peer: IpAddr) -> bool {
        let mut state = self.state.lock().await;
        reset_if_needed(&mut state);
        let blocked = state
            .peers
            .get(&peer)
            .is_some_and(|count| *count >= self.peer_limit);
        drop(state);
        blocked
    }

    pub async fn record_unauthenticated(&self, peer: IpAddr) {
        let mut state = self.state.lock().await;
        reset_if_needed(&mut state);
        if !state.peers.contains_key(&peer)
            && state.peers.len() >= MAX_TRACKED_PEERS
            && let Some(evicted) = state.peers.keys().next().copied()
        {
            state.peers.remove(&evicted);
        }
        *state.peers.entry(peer).or_default() += 1;
        drop(state);
    }

    pub async fn allow_authenticated(&self, hostname: &str) -> bool {
        let mut state = self.state.lock().await;
        reset_if_needed(&mut state);
        if state.authenticated >= self.global_limit
            || state.hosts.get(hostname).copied().unwrap_or_default() >= self.host_limit
        {
            return false;
        }
        state.authenticated += 1;
        *state.hosts.entry(hostname.to_owned()).or_default() += 1;
        drop(state);
        true
    }
}

fn reset_if_needed(state: &mut State) {
    if state.window_start.elapsed() >= Duration::from_secs(60) {
        state.window_start = Instant::now();
        state.authenticated = 0;
        state.hosts.clear();
        state.peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_TRACKED_PEERS, RateLimiter};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn peers_cannot_consume_authenticated_budget() {
        let rate = RateLimiter::new(1, 1, 2);
        let attacker = IpAddr::V4(Ipv4Addr::LOCALHOST);
        rate.record_unauthenticated(attacker).await;
        rate.record_unauthenticated(attacker).await;
        assert!(rate.peer_blocked(attacker).await);
        assert!(rate.allow_authenticated("home.example").await);
        assert!(!rate.allow_authenticated("other.example").await);
    }

    #[tokio::test]
    async fn peer_map_is_bounded() {
        let rate = RateLimiter::new(1, 1, 1);
        for index in 0..=MAX_TRACKED_PEERS {
            let address = Ipv6Addr::from(index as u128);
            rate.record_unauthenticated(IpAddr::V6(address)).await;
        }
        let state = rate.state.lock().await;
        assert_eq!(state.peers.len(), MAX_TRACKED_PEERS);
    }
}
