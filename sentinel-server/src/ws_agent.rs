use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, Query, State, WebSocketUpgrade};
use axum::response::{IntoResponse, Response};
use log::{info, warn};
use sentinel_common::protocol::{AgentMessage, ExecEventWire, ServerMessage, PROTOCOL_VERSION};
use serde::Deserialize;

use crate::state::{AppState, DashboardMsg, LiveAgent};
use crate::{db, now_ms};

#[derive(Deserialize)]
pub struct AgentWsQuery {
    token: String,
}

pub async fn handler(
    ws: WebSocketUpgrade,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Query(q): Query<AgentWsQuery>,
    State(state): State<AppState>,
) -> Response {
    if q.token != state.token {
        warn!("agent ws rejected: bad token from {remote}");
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
    ws.on_upgrade(move |socket| handle_agent(socket, remote, state))
}

async fn handle_agent(mut socket: WebSocket, remote: SocketAddr, state: AppState) {
    // First message must be Hello, within a short grace period.
    let hello = match tokio::time::timeout(Duration::from_secs(10), socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => match serde_json::from_str::<AgentMessage>(&text) {
            Ok(AgentMessage::Hello(h)) => h,
            Ok(_) => {
                warn!("agent at {remote} sent non-Hello as first message, dropping");
                return;
            }
            Err(e) => {
                warn!("agent at {remote} sent invalid Hello: {e}");
                return;
            }
        },
        _ => {
            warn!("agent at {remote} did not send Hello in time, dropping");
            return;
        }
    };

    if hello.protocol_version != PROTOCOL_VERSION {
        let ack = ServerMessage::HelloAck {
            ok: false,
            server_time_unix_ms: now_ms(),
            message: Some(format!(
                "protocol mismatch: server speaks v{PROTOCOL_VERSION}, agent sent v{}",
                hello.protocol_version
            )),
        };
        let _ = socket.send(Message::Text(serde_json::to_string(&ack).unwrap())).await;
        return;
    }

    let agent_id = hello.agent_id.clone();
    let ip = remote.ip().to_string();

    info!(
        "agent connected: id={agent_id} hostname={} ip={ip} tags={:?}",
        hello.hostname, hello.tags
    );

    if let Err(e) = db::upsert_agent(
        &state.pool,
        &agent_id,
        &hello.hostname,
        &ip,
        &hello.tags,
        &hello.agent_version,
        now_ms(),
    ) {
        warn!("failed to persist agent {agent_id}: {e}");
    }

    {
        let mut agents = state.agents.write().unwrap();
        agents.insert(
            agent_id.clone(),
            LiveAgent {
                hostname: hello.hostname.clone(),
                ip: ip.clone(),
                tags: hello.tags.clone(),
                agent_version: hello.agent_version.clone(),
                connected: true,
                last_seen_ms: now_ms(),
            },
        );
    }
    state.broadcast_status(&agent_id);

    let ack = ServerMessage::HelloAck {
        ok: true,
        server_time_unix_ms: now_ms(),
        message: None,
    };
    if socket.send(Message::Text(serde_json::to_string(&ack).unwrap())).await.is_err() {
        return;
    }

    loop {
        let msg = match socket.recv().await {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(Message::Close(_))) | None => break,
            Some(Ok(_)) => continue,
            Some(Err(e)) => {
                warn!("ws error from agent {agent_id}: {e}");
                break;
            }
        };

        let parsed = match serde_json::from_str::<AgentMessage>(&msg) {
            Ok(m) => m,
            Err(e) => {
                warn!("agent {agent_id} sent invalid message: {e}");
                continue;
            }
        };

        touch(&state, &agent_id);

        match parsed {
            AgentMessage::Event(e) => on_event(&state, &agent_id, e),
            AgentMessage::Heartbeat { .. } => {}
            AgentMessage::Hello(_) => {}
        }
    }

    info!("agent disconnected: id={agent_id}");
    {
        let mut agents = state.agents.write().unwrap();
        if let Some(a) = agents.get_mut(&agent_id) {
            a.connected = false;
            a.last_seen_ms = now_ms();
        }
    }
    state.broadcast_status(&agent_id);
}

fn touch(state: &AppState, agent_id: &str) {
    let t = now_ms();
    {
        let mut agents = state.agents.write().unwrap();
        if let Some(a) = agents.get_mut(agent_id) {
            a.last_seen_ms = t;
        }
    }
    if let Err(e) = db::touch_agent(&state.pool, agent_id, t) {
        warn!("failed to touch agent {agent_id}: {e}");
    }
}

fn on_event(state: &AppState, agent_id: &str, e: ExecEventWire) {
    if let Err(err) = db::insert_event(&state.pool, agent_id, &e) {
        warn!("failed to persist event for {agent_id}: {err}");
    }

    let ts = chrono::DateTime::from_timestamp_millis(e.ts_unix_ms)
        .unwrap_or_else(chrono::Utc::now)
        .with_timezone(&chrono::Local)
        .format("%H:%M:%S%.3f")
        .to_string();

    let _ = state.dash_tx.send(DashboardMsg::Event {
        agent_id: agent_id.to_string(),
        ts,
        comm: e.comm,
        pid: e.pid,
        uid: e.uid,
        gid: e.gid,
        cgroup_id: e.cgroup_id,
        cmdline: e.cmdline,
        alert: e.alert,
    });
}
