use tokio::sync::broadcast;

/// One captured exec event, passed internally from the eBPF perf-buffer
/// reader to whatever consumes it (today: the agent_client forwarder to
/// sentinel-server; nothing else, now that there's no local dashboard).
#[derive(Clone)]
pub struct WireEvent {
    pub comm: String,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: u64,
    pub alert: bool,
    pub cmdline: String,
}

pub fn make_channel() -> broadcast::Sender<WireEvent> {
    let (tx, _rx) = broadcast::channel(1024);
    tx
}
