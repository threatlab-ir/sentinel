use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use serde::Serialize;
use sentinel_common::protocol::OFFLINE_AFTER_SECS;
use tokio::sync::broadcast;

use crate::db::Pool;

#[derive(Clone)]
pub struct LiveAgent {
    pub hostname: String,
    pub ip: String,
    pub tags: Vec<String>,
    pub agent_version: String,
    pub connected: bool,
    pub last_seen_ms: i64,
}

#[derive(Clone, Serialize)]
pub struct AgentView {
    pub agent_id: String,
    pub hostname: String,
    pub ip: String,
    pub tags: Vec<String>,
    pub agent_version: String,
    pub connected: bool,
    pub last_seen_ms: i64,
    pub online: bool,
}

/// Everything broadcast to connected dashboard browser tabs.
#[derive(Clone, Serialize)]
#[serde(tag = "type")]
pub enum DashboardMsg {
    Event {
        agent_id: String,
        ts: String,
        comm: String,
        pid: u32,
        uid: u32,
        gid: u32,
        cgroup_id: u64,
        cmdline: String,
        alert: bool,
    },
    AgentStatus(AgentView),
}

#[derive(Clone)]
pub struct AppState {
    pub pool: Pool,
    pub agents: Arc<RwLock<HashMap<String, LiveAgent>>>,
    pub dash_tx: broadcast::Sender<DashboardMsg>,
    pub token: String,
}

impl AppState {
    pub fn new(pool: Pool, token: String) -> Self {
        let (dash_tx, _) = broadcast::channel(4096);
        Self {
            pool,
            agents: Arc::new(RwLock::new(HashMap::new())),
            dash_tx,
            token,
        }
    }

    pub fn agent_view(agent_id: &str, a: &LiveAgent) -> AgentView {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let online = a.connected && (now_ms - a.last_seen_ms) < (OFFLINE_AFTER_SECS as i64 * 1000);
        AgentView {
            agent_id: agent_id.to_string(),
            hostname: a.hostname.clone(),
            ip: a.ip.clone(),
            tags: a.tags.clone(),
            agent_version: a.agent_version.clone(),
            connected: a.connected,
            last_seen_ms: a.last_seen_ms,
            online,
        }
    }

    pub fn list_agent_views(&self) -> Vec<AgentView> {
        let agents = self.agents.read().unwrap();
        agents.iter().map(|(id, a)| Self::agent_view(id, a)).collect()
    }

    pub fn broadcast_status(&self, agent_id: &str) {
        let view = {
            let agents = self.agents.read().unwrap();
            agents.get(agent_id).map(|a| Self::agent_view(agent_id, a))
        };
        if let Some(view) = view {
            let _ = self.dash_tx.send(DashboardMsg::AgentStatus(view));
        }
    }
}
