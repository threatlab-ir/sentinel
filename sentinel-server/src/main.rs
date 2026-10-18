mod dashboard;
mod db;
mod state;
mod ws_agent;

use std::net::SocketAddr;

use axum::routing::get;
use axum::Router;
use clap::Parser;
use log::info;

use state::AppState;

#[derive(Parser)]
struct Args {
    /// Address to listen on for both the agent WebSocket endpoint and the dashboard.
    #[clap(long, default_value = "0.0.0.0:9000")]
    listen: SocketAddr,

    /// Shared secret agents must present as ?token=... when connecting.
    #[clap(long, env = "SENTINEL_SERVER_TOKEN")]
    token: String,

    /// Path to the SQLite database file (created if missing).
    #[clap(long, default_value = "sentinel-server.db")]
    db_path: String,
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();
    let pool = db::init(&args.db_path)?;

    let state = AppState::new(pool.clone(), args.token);

    // Agents known from a previous run start out "known but disconnected"
    // until they reconnect; only in-memory `connected` state (never
    // persisted) reflects a live socket.
    for row in db::list_agents(&pool)? {
        state.agents.write().unwrap().insert(
            row.agent_id,
            state::LiveAgent {
                hostname: row.hostname,
                ip: row.ip,
                tags: row.tags,
                agent_version: row.agent_version,
                connected: false,
                last_seen_ms: row.last_seen_ms,
            },
        );
    }

    let app = Router::new()
        .route("/agent/ws", get(ws_agent::handler))
        .route("/", get(dashboard::index))
        .route("/ws", get(dashboard::ws_handler))
        .route("/api/agents", get(dashboard::api_agents))
        .route("/api/events", get(dashboard::api_events))
        .with_state(state);

    info!("sentinel-server listening on http://{}", args.listen);
    info!("agent endpoint:      ws://{}/agent/ws?token=<TOKEN>", args.listen);

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
