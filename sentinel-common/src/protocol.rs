//! Wire protocol spoken between a `sentinel-agent` (runs on each monitored
//! Linux host, owns the eBPF probe) and the `sentinel-server` (central
//! collector + dashboard). Transport is a single WebSocket connection per
//! agent; messages are JSON, one per WebSocket text frame.
//!
//! Connection lifecycle:
//!
//!   agent --[TCP+TLS, ws://server/agent/ws?token=SHARED_TOKEN]--> server
//!   agent --AgentMessage::Hello----------------------------------> server
//!   agent <--ServerMessage::HelloAck------------------------------ server
//!   agent --AgentMessage::Event------------------------------------> server   (as execs happen)
//!   agent --AgentMessage::Heartbeat (every HEARTBEAT_INTERVAL_SECS)-> server
//!   ...
//!
//! The server treats ANY inbound message (Hello, Event, or Heartbeat) as a
//! liveness signal and resets that agent's "last seen" timestamp. An agent
//! is considered offline once `OFFLINE_AFTER_SECS` pass without one.
//!
//! Auth (v1): a single shared bearer token, passed as `?token=` on the
//! WebSocket URL and checked by the server before completing the upgrade.
//! This is deliberately simple to start; per-agent tokens (issued by the
//! server, stored alongside the agent's identity) are the natural v2 step
//! once there's a registration/enrollment flow.

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;

/// Agents send a heartbeat at least this often while idle.
pub const HEARTBEAT_INTERVAL_SECS: u64 = 15;

/// Server marks an agent offline if nothing (Hello/Event/Heartbeat) arrives
/// within this window. Must be comfortably larger than the heartbeat
/// interval to tolerate normal network jitter.
pub const OFFLINE_AFTER_SECS: u64 = 45;

/// Messages sent from an agent to the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentMessage {
    Hello(AgentHello),
    Event(ExecEventWire),
    Heartbeat { ts_unix_ms: i64 },
}

/// First message an agent must send after the WebSocket upgrade succeeds.
/// The server will not forward/persist anything from a connection until it
/// receives this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHello {
    pub protocol_version: u32,
    /// Stable identity for this agent, generated once and persisted locally
    /// (e.g. in /var/lib/sentinel/agent-id) so re-registration after a
    /// restart is recognized as the *same* agent, not a new one.
    pub agent_id: String,
    pub hostname: String,
    /// Primary IP as the agent sees itself (best-effort; the server also
    /// records the IP the TCP connection actually came from, which is the
    /// more trustworthy of the two behind NAT).
    pub ip: String,
    /// Free-form labels for grouping in the dashboard, e.g. ["prod", "db"].
    pub tags: Vec<String>,
    pub agent_version: String,
}

/// One exec event, enriched and ready for display/storage. This mirrors
/// `sentinel`'s existing `WireEvent` but adds the fields a multi-agent
/// server needs (agent_id is implicit — the server stamps it from the
/// connection, the agent never needs to know its own DB key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecEventWire {
    pub ts_unix_ms: i64,
    pub comm: String,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub cmdline: String,
    pub alert: bool,
    /// Name of the rule that matched, once the rule-engine lands (None for
    /// plain substring-watchlist matches, for now).
    pub matched_rule: Option<String>,
}

/// Messages sent from the server to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    HelloAck {
        ok: bool,
        server_time_unix_ms: i64,
        /// Set when ok=false (e.g. bad protocol version, revoked agent).
        /// The agent should log this and stop reconnecting rather than
        /// retry in a hot loop.
        message: Option<String>,
    },
    Error {
        message: String,
    },
}
