use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::response::{Html, IntoResponse};
use axum::Json;
use serde::Deserialize;

use crate::db;
use crate::state::AppState;

pub async fn index() -> impl IntoResponse {
    Html(INDEX_HTML)
}

pub async fn api_agents(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.list_agent_views())
}

#[derive(Deserialize)]
pub struct EventsQuery {
    agent_id: Option<String>,
    limit: Option<i64>,
}

pub async fn api_events(State(state): State<AppState>, Query(q): Query<EventsQuery>) -> impl IntoResponse {
    let rows = tokio::task::spawn_blocking(move || {
        db::recent_events(&state.pool, q.agent_id.as_deref(), q.limit.unwrap_or(300))
    })
    .await
    .unwrap()
    .unwrap_or_default();
    Json(rows)
}

pub async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.dash_tx.subscribe();
    loop {
        match rx.recv().await {
            Ok(msg) => {
                let Ok(payload) = serde_json::to_string(&msg) else { continue };
                if socket.send(Message::Text(payload)).await.is_err() {
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>sentinel fleet</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { font-family: ui-monospace, Menlo, Consolas, monospace; background: #0b0f14; color: #d6e2ea; margin: 0; display: flex; height: 100vh; overflow: hidden; }

  #sidebar { width: 280px; flex-shrink: 0; border-right: 1px solid #1c2733; display: flex; flex-direction: column; }
  #sidebar header { padding: 14px 16px; border-bottom: 1px solid #1c2733; }
  #sidebar header h1 { font-size: 15px; margin: 0; }
  #agentList { overflow-y: auto; flex: 1; }
  .agent-item { padding: 10px 16px; border-bottom: 1px solid #141b23; cursor: pointer; display: flex; flex-direction: column; gap: 3px; }
  .agent-item:hover { background: #121a23; }
  .agent-item.selected { background: #15202c; border-left: 3px solid #4fa3ff; padding-left: 13px; }
  .agent-top { display: flex; align-items: center; gap: 7px; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: #4a5a6a; flex-shrink: 0; }
  .dot.online { background: #4fe08a; box-shadow: 0 0 6px #4fe08a88; }
  .agent-name { font-weight: 600; font-size: 13px; }
  .agent-ip { color: #7891a3; font-size: 11px; margin-left: auto; }
  .agent-tags { display: flex; gap: 4px; flex-wrap: wrap; margin-left: 15px; }
  .tag { font-size: 10px; background: #1c2733; color: #9fb3c4; padding: 1px 6px; border-radius: 8px; }
  .agent-count { font-size: 11px; color: #ff8c8c; margin-left: 15px; }

  #main { flex: 1; display: flex; flex-direction: column; min-width: 0; }
  header#top { padding: 14px 20px; border-bottom: 1px solid #1c2733; display: flex; align-items: center; gap: 12px; }
  header#top h2 { font-size: 15px; margin: 0; }
  #topSub { font-size: 12px; color: #7891a3; }
  #count { font-size: 12px; color: #7891a3; margin-left: auto; }
  #wsStatus { font-size: 11px; padding: 2px 8px; border-radius: 10px; background: #1c2733; }
  #wsStatus.connected { background: #16432c; color: #6fe3a1; }
  #wsStatus.disconnected { background: #432222; color: #ff8c8c; }

  #wrap { flex: 1; overflow-y: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 6px 16px; border-bottom: 1px solid #141b23; white-space: nowrap; }
  th { position: sticky; top: 0; background: #0b0f14; color: #7891a3; font-weight: 500; z-index: 1; }
  tbody tr { cursor: pointer; }
  tbody tr:hover { background: #121a23; }
  tr.alert { background: #2a1414; color: #ff9d9d; }
  tr.alert:hover { background: #351818; }
  tr.alert td:first-child::before { content: "ALERT  "; color: #ff5555; font-weight: bold; }
  .pid { color: #7fb3ff; }
  .agentcol { color: #a893ff; }

  #overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.55); display: none; align-items: center; justify-content: center; }
  #overlay.open { display: flex; }
  #modal { background: #0f151c; border: 1px solid #243040; border-radius: 10px; width: min(640px, 90vw); padding: 20px 22px; box-shadow: 0 20px 60px rgba(0,0,0,0.5); }
  #modal h2 { margin: 0 0 4px; font-size: 15px; display: flex; align-items: center; gap: 8px; }
  #modal h2 .badge { font-size: 10px; background: #432222; color: #ff8c8c; padding: 2px 7px; border-radius: 8px; display: none; }
  #modal h2 .badge.show { display: inline-block; }
  #modal .sub { color: #7891a3; font-size: 12px; margin-bottom: 14px; }
  #modal dl { display: grid; grid-template-columns: 90px 1fr; gap: 8px 12px; font-size: 13px; margin: 0 0 14px; }
  #modal dt { color: #7891a3; }
  #modal dd { margin: 0; }
  #cmdline { background: #070b10; border: 1px solid #1c2733; border-radius: 6px; padding: 10px 12px; font-size: 12.5px; white-space: pre-wrap; word-break: break-all; color: #9fe3b0; }
  #modal .close { float: right; cursor: pointer; color: #7891a3; font-size: 13px; background: none; border: 1px solid #243040; border-radius: 6px; padding: 5px 10px; }
  #modal .close:hover { color: #d6e2ea; }
  .empty { padding: 40px; text-align: center; color: #44525f; }
</style>
</head>
<body>

<div id="sidebar">
  <header><h1>sentinel fleet</h1></header>
  <div id="agentList"></div>
</div>

<div id="main">
  <header id="top">
    <h2 id="topTitle">All agents</h2>
    <span id="topSub"></span>
    <span id="wsStatus" class="disconnected">connecting&hellip;</span>
    <span id="count">0 events</span>
  </header>
  <div id="wrap">
    <table>
      <thead>
        <tr><th>time</th><th id="agentHeader">agent</th><th>comm</th><th>pid</th><th>uid</th><th>gid</th><th>cgroup</th></tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>
  </div>
</div>

<div id="overlay">
  <div id="modal">
    <button class="close" id="modalClose">close</button>
    <h2 id="modalComm">&mdash; <span class="badge" id="modalBadge">ALERT</span></h2>
    <div class="sub" id="modalSub"></div>
    <dl>
      <dt>agent</dt><dd id="modalAgent"></dd>
      <dt>pid</dt><dd id="modalPid"></dd>
      <dt>uid / gid</dt><dd id="modalUg"></dd>
      <dt>cgroup</dt><dd id="modalCgroup"></dd>
    </dl>
    <dt style="color:#7891a3; font-size:12px; margin-bottom:6px; display:block;">command line</dt>
    <div id="cmdline"></div>
  </div>
</div>

<script>
  let agents = {};          // agent_id -> view
  let selected = null;      // null = all agents
  let count = 0;
  const MAX_ROWS = 2000;

  const rowsEl = document.getElementById('rows');
  const agentListEl = document.getElementById('agentList');
  const countEl = document.getElementById('count');
  const wrap = document.getElementById('wrap');
  const wsStatusEl = document.getElementById('wsStatus');
  const topTitle = document.getElementById('topTitle');
  const topSub = document.getElementById('topSub');
  const overlay = document.getElementById('overlay');

  function fmtAgo(ms) {
    const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    return Math.floor(s / 3600) + 'h ago';
  }

  function renderSidebar() {
    agentListEl.innerHTML = '';

    const allItem = document.createElement('div');
    allItem.className = 'agent-item' + (selected === null ? ' selected' : '');
    allItem.innerHTML = `<div class="agent-top"><span class="dot online"></span><span class="agent-name">All agents</span><span class="agent-ip">${Object.keys(agents).length}</span></div>`;
    allItem.onclick = () => selectAgent(null);
    agentListEl.appendChild(allItem);

    const sorted = Object.values(agents).sort((a, b) => a.hostname.localeCompare(b.hostname));
    for (const a of sorted) {
      const item = document.createElement('div');
      item.className = 'agent-item' + (selected === a.agent_id ? ' selected' : '');
      const tags = a.tags.map(t => `<span class="tag">${escapeHtml(t)}</span>`).join('');
      item.innerHTML = `
        <div class="agent-top">
          <span class="dot ${a.online ? 'online' : ''}"></span>
          <span class="agent-name">${escapeHtml(a.hostname)}</span>
          <span class="agent-ip">${escapeHtml(a.ip)}</span>
        </div>
        <div class="agent-tags">${tags}</div>
      `;
      item.onclick = () => selectAgent(a.agent_id);
      agentListEl.appendChild(item);
    }
  }

  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function selectAgent(agentId) {
    selected = agentId;
    renderSidebar();
    const a = agentId ? agents[agentId] : null;
    topTitle.textContent = a ? a.hostname : 'All agents';
    topSub.textContent = a ? `${a.ip} · ${a.online ? 'online' : 'offline, ' + fmtAgo(a.last_seen_ms)}` : '';
    document.getElementById('agentHeader').style.display = agentId ? 'none' : '';
    loadHistory();
  }

  async function loadHistory() {
    rowsEl.innerHTML = '';
    count = 0;
    countEl.textContent = '0 events';
    const url = selected ? `/api/events?agent_id=${encodeURIComponent(selected)}&limit=300` : '/api/events?limit=300';
    try {
      const res = await fetch(url);
      const events = await res.json();
      for (const e of events) {
        addRow({
          agent_id: e.agent_id, ts: new Date(e.ts_unix_ms).toLocaleTimeString('en-GB', {hour12:false}) + '.' + String(e.ts_unix_ms % 1000).padStart(3,'0'),
          comm: e.comm, pid: e.pid, uid: e.uid, gid: e.gid, cgroup_id: e.cgroup_id, cmdline: e.cmdline, alert: e.alert,
        });
      }
      wrap.scrollTop = wrap.scrollHeight;
    } catch (err) { /* server might be mid-restart; live feed will catch up */ }
  }

  function openModal(e) {
    document.getElementById('modalComm').firstChild.textContent = e.comm + ' ';
    document.getElementById('modalBadge').className = e.alert ? 'badge show' : 'badge';
    document.getElementById('modalSub').textContent = e.ts;
    const a = agents[e.agent_id];
    document.getElementById('modalAgent').textContent = a ? `${a.hostname} (${a.ip})` : e.agent_id;
    document.getElementById('modalPid').textContent = e.pid;
    document.getElementById('modalUg').textContent = `${e.uid} / ${e.gid}`;
    document.getElementById('modalCgroup').textContent = e.cgroup_id;
    document.getElementById('cmdline').textContent = e.cmdline && e.cmdline.length ? e.cmdline : '(unavailable)';
    overlay.className = 'open';
  }
  function closeModal() { overlay.className = ''; }
  document.getElementById('modalClose').onclick = closeModal;
  overlay.addEventListener('click', (ev) => { if (ev.target === overlay) closeModal(); });
  document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closeModal(); });

  function addRow(e) {
    if (selected !== null && e.agent_id !== selected) return;
    const tr = document.createElement('tr');
    if (e.alert) tr.className = 'alert';
    const cell = (text, cls) => { const td = document.createElement('td'); if (cls) td.className = cls; td.textContent = text; return td; };
    tr.appendChild(cell(e.ts));
    if (selected === null) {
      const a = agents[e.agent_id];
      tr.appendChild(cell(a ? a.hostname : e.agent_id, 'agentcol'));
    } else {
      tr.appendChild(cell('', 'agentcol'));
      tr.lastChild.style.display = 'none';
    }
    tr.appendChild(cell(e.comm));
    tr.appendChild(cell(e.pid, 'pid'));
    tr.appendChild(cell(e.uid));
    tr.appendChild(cell(e.gid));
    tr.appendChild(cell(e.cgroup_id));
    tr.addEventListener('click', () => openModal(e));
    const atBottom = wrap.scrollTop + wrap.clientHeight >= wrap.scrollHeight - 40;
    rowsEl.appendChild(tr);
    count += 1;
    countEl.textContent = `${count} events`;
    while (rowsEl.childElementCount > MAX_ROWS) rowsEl.removeChild(rowsEl.firstChild);
    if (atBottom) wrap.scrollTop = wrap.scrollHeight;
  }

  async function loadAgents() {
    const res = await fetch('/api/agents');
    const list = await res.json();
    agents = {};
    for (const a of list) agents[a.agent_id] = a;
    renderSidebar();
  }

  function connectWs() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws`);
    ws.onopen = () => { wsStatusEl.textContent = 'live'; wsStatusEl.className = 'connected'; };
    ws.onclose = () => { wsStatusEl.textContent = 'disconnected, retrying…'; wsStatusEl.className = 'disconnected'; setTimeout(connectWs, 1000); };
    ws.onerror = () => ws.close();
    ws.onmessage = (msg) => {
      const m = JSON.parse(msg.data);
      if (m.type === 'Event') {
        addRow(m);
      } else if (m.type === 'AgentStatus') {
        const view = m;
        delete view.type;
        agents[view.agent_id] = view;
        renderSidebar();
        if (selected === view.agent_id) {
          topSub.textContent = `${view.ip} · ${view.online ? 'online' : 'offline, ' + fmtAgo(view.last_seen_ms)}`;
        }
      }
    };
  }

  loadAgents().then(() => selectAgent(null));
  connectWs();
  setInterval(loadAgents, 10000);
</script>
</body>
</html>"#;
