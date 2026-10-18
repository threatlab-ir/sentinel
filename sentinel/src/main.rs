mod agent_client;
mod events;
mod telegram;

use std::convert::TryInto;

use anyhow::Context;
use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::TracePoint,
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use clap::Parser;
use events::WireEvent;
use log::{info, warn};
use sentinel_common::ExecEvent;
use telegram::Telegram;

#[derive(Parser)]
struct Args {
    /// Comma-separated list of process names to flag as suspicious, e.g. "nc,ncat,bash"
    #[clap(long, default_value = "nc,ncat,socat,nmap")]
    watch: String,

    /// Telegram bot token (from @BotFather). Enables Telegram alerts together with --telegram-chat-id.
    #[clap(long, env = "SENTINEL_TELEGRAM_TOKEN")]
    telegram_token: Option<String>,

    /// Telegram chat id to send alerts to.
    #[clap(long, env = "SENTINEL_TELEGRAM_CHAT_ID")]
    telegram_chat_id: Option<String>,

    /// sentinel-server WebSocket URL to forward every event to, e.g.
    /// ws://collector.internal:9000/agent/ws. This is the only way to see
    /// events from this host now — run sentinel-server and point every
    /// agent at it, instead of each host carrying its own dashboard.
    #[clap(long, env = "SENTINEL_SERVER_URL")]
    server_url: Option<String>,

    /// Shared token for authenticating to --server-url.
    #[clap(long, env = "SENTINEL_SERVER_TOKEN")]
    server_token: Option<String>,

    /// Comma-separated labels reported to the server, e.g. "prod,db".
    #[clap(long, default_value = "")]
    tags: String,

    /// Where this agent's stable identity is persisted across restarts.
    #[clap(long, default_value = "/var/lib/sentinel/agent-id")]
    agent_id_file: String,
}

/// Best-effort read of the full command line for a still-running process.
/// Racy by nature (the process may have already exited), but good enough
/// for an alert/audit trail: worst case we fall back to `comm`.
fn read_cmdline(pid: u32) -> String {
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(bytes) => String::from_utf8_lossy(&bytes)
            .split('\0')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" "),
        Err(_) => String::new(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    let args = Args::parse();
    let watchlist: Vec<String> = args.watch.split(',').map(|s| s.trim().to_string()).collect();

    // Bump memlock rlimit, required on older kernels for BPF maps.
    let rlim = libc_rlimit();
    if let Err(e) = rlim {
        warn!("failed to raise rlimit, continuing anyway: {e}");
    }

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sentinel"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let program: &mut TracePoint = ebpf
        .program_mut("sentinel_execve")
        .context("program not found")?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let mut perf_array: AsyncPerfEventArray<_> =
        ebpf.take_map("EVENTS").context("EVENTS map not found")?.try_into()?;

    let telegram = match (&args.telegram_token, &args.telegram_chat_id) {
        (Some(token), Some(chat_id)) => {
            info!("telegram alerts enabled for chat {chat_id}");
            Some(Telegram::new(token.clone(), chat_id.clone()))
        }
        (None, None) => None,
        _ => {
            warn!("--telegram-token and --telegram-chat-id must be set together; telegram alerts disabled");
            None
        }
    };

    let event_tx = events::make_channel();

    match (&args.server_url, &args.server_token) {
        (Some(server_url), Some(server_token)) => {
            let tags: Vec<String> = args
                .tags
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let config = agent_client::AgentClientConfig {
                server_url: server_url.clone(),
                token: server_token.clone(),
                tags,
                agent_id_file: args.agent_id_file.clone(),
            };
            let tx = event_tx.clone();
            tokio::spawn(agent_client::run(config, tx));
        }
        (None, None) => {
            warn!(
                "no --server-url/--server-token set: events will only be logged to this \
                 console (nothing to view them in). Run sentinel-server and pass \
                 --server-url/--server-token to forward events there."
            );
        }
        _ => warn!("--server-url and --server-token must be set together; agent mode disabled"),
    }

    let cpus = online_cpus().map_err(|(_, e)| e)?;
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;
        let watchlist = watchlist.clone();
        let event_tx = event_tx.clone();
        let telegram = telegram.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(core::mem::size_of::<ExecEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = match buf.read_events(&mut buffers).await {
                    Ok(events) => events,
                    Err(e) => {
                        warn!("error reading perf events: {e}");
                        continue;
                    }
                };

                for buf in buffers.iter().take(events.read) {
                    let ptr = buf.as_ptr() as *const ExecEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    let comm_len = data.comm.iter().position(|&b| b == 0).unwrap_or(data.comm.len());
                    let comm = String::from_utf8_lossy(&data.comm[..comm_len]).to_string();

                    let flagged = watchlist.iter().any(|w| comm.contains(w.as_str()));
                    let cmdline = read_cmdline(data.pid);

                    if flagged {
                        println!(
                            "[ALERT] suspicious exec: comm={comm} pid={} uid={} gid={} cgroup_id={} cmd={cmdline}",
                            data.pid, data.uid, data.gid, data.cgroup_id
                        );
                        if let Some(tg) = &telegram {
                            tg.notify_alert(&comm, data.pid, data.uid, data.gid, &cmdline);
                        }
                    } else {
                        info!(
                            "exec: comm={comm} pid={} uid={} gid={} cgroup_id={}",
                            data.pid, data.uid, data.gid, data.cgroup_id
                        );
                    }

                    let _ = event_tx.send(WireEvent {
                        comm,
                        pid: data.pid,
                        uid: data.uid,
                        gid: data.gid,
                        cgroup_id: data.cgroup_id,
                        alert: flagged,
                        cmdline,
                    });
                }
            }
        });
    }

    info!("sentinel running, watching for exec of: {watchlist:?}. Ctrl-C to exit.");
    tokio::signal::ctrl_c().await?;
    info!("exiting");

    Ok(())
}

fn libc_rlimit() -> anyhow::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        anyhow::bail!("setrlimit failed");
    }
    Ok(())
}
