use std::path::Path;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use log::{info, warn};
use sentinel_common::protocol::{
    AgentHello, AgentMessage, ExecEventWire, ServerMessage, HEARTBEAT_INTERVAL_SECS, PROTOCOL_VERSION,
};
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;

use crate::events::WireEvent;

/// Reads a persisted agent id from `path`, or generates + persists a new
/// one. A stable id means the server recognizes this host as the same
/// agent across restarts instead of minting a new row each time.
fn load_or_create_agent_id(path: &str) -> String {
    if let Ok(existing) = std::fs::read_to_string(path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Some(parent) = Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(path, &id) {
        warn!("could not persist agent id to {path} ({e}); it will change on restart");
    }
    id
}

fn local_hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown-host".to_string())
}

/// Best-effort "what IP would I use to reach the outside world" — doesn't
/// actually send any traffic, just asks the kernel which local address a
/// UDP socket would bind to for that route.
fn local_ip() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

pub struct AgentClientConfig {
    pub server_url: String,
    pub token: String,
    pub tags: Vec<String>,
    pub agent_id_file: String,
}

/// Connects to a sentinel-server, forwarding every event broadcast on
/// `web_tx` as a protocol::Event message. Reconnects with backoff on any
/// failure; never gives up, since a flaky network link to the collector
/// shouldn't stop local eBPF capture.
pub async fn run(config: AgentClientConfig, web_tx: broadcast::Sender<WireEvent>) {
    let agent_id = load_or_create_agent_id(&config.agent_id_file);
    let hostname = local_hostname();
    let ip = local_ip();

    info!("agent mode: id={agent_id} hostname={hostname} ip={ip} server={}", config.server_url);

    let mut backoff = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(30);

    loop {
        match connect_and_stream(&config, &agent_id, &hostname, &ip, web_tx.subscribe()).await {
            Ok(()) => {
                // Clean shutdown (server closed the socket); retry from a short delay.
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                warn!("agent connection to {} lost: {e}", config.server_url);
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn connect_and_stream(
    config: &AgentClientConfig,
    agent_id: &str,
    hostname: &str,
    ip: &str,
    mut rx: broadcast::Receiver<WireEvent>,
) -> anyhow::Result<()> {
    let url = format!("{}?token={}", config.server_url, config.token);
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await?;
    let (mut write, mut read) = ws_stream.split();

    let hello = AgentMessage::Hello(AgentHello {
        protocol_version: PROTOCOL_VERSION,
        agent_id: agent_id.to_string(),
        hostname: hostname.to_string(),
        ip: ip.to_string(),
        tags: config.tags.clone(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
    });
    write.send(Message::Text(serde_json::to_string(&hello)?)).await?;

    match read.next().await {
        Some(Ok(Message::Text(text))) => match serde_json::from_str::<ServerMessage>(&text) {
            Ok(ServerMessage::HelloAck { ok: true, .. }) => {
                info!("connected to server, hello acknowledged");
            }
            Ok(ServerMessage::HelloAck { ok: false, message, .. }) => {
                anyhow::bail!("server rejected hello: {}", message.unwrap_or_default());
            }
            other => anyhow::bail!("unexpected response to hello: {other:?}"),
        },
        other => anyhow::bail!("no hello ack from server: {other:?}"),
    }

    let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
    heartbeat.tick().await; // first tick fires immediately; skip it, we just said hello

    loop {
        tokio::select! {
            event = rx.recv() => {
                let event = match event {
                    Ok(e) => e,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                };
                let wire = ExecEventWire {
                    ts_unix_ms: chrono::Local::now().timestamp_millis(),
                    comm: event.comm,
                    pid: event.pid,
                    uid: event.uid,
                    gid: event.gid,
                    cgroup_id: event.cgroup_id,
                    cmdline: event.cmdline,
                    alert: event.alert,
                    matched_rule: None,
                };
                let msg = AgentMessage::Event(wire);
                write.send(Message::Text(serde_json::to_string(&msg)?)).await?;
            }
            _ = heartbeat.tick() => {
                let msg = AgentMessage::Heartbeat { ts_unix_ms: chrono::Local::now().timestamp_millis() };
                write.send(Message::Text(serde_json::to_string(&msg)?)).await?;
            }
            incoming = read.next() => {
                match incoming {
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Err(e)) => anyhow::bail!("websocket read error: {e}"),
                    _ => {}
                }
            }
        }
    }
}
