use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::params;
use serde::Serialize;

pub type Pool = r2d2::Pool<SqliteConnectionManager>;

pub fn init(path: &str) -> anyhow::Result<Pool> {
    let manager = SqliteConnectionManager::file(path);
    let pool = r2d2::Pool::new(manager)?;

    let conn = pool.get()?;
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;

        CREATE TABLE IF NOT EXISTS agents (
            agent_id      TEXT PRIMARY KEY,
            hostname      TEXT NOT NULL,
            ip            TEXT NOT NULL,
            tags          TEXT NOT NULL,
            agent_version TEXT NOT NULL,
            first_seen_ms INTEGER NOT NULL,
            last_seen_ms  INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id     TEXT NOT NULL,
            ts_unix_ms   INTEGER NOT NULL,
            comm         TEXT NOT NULL,
            pid          INTEGER NOT NULL,
            uid          INTEGER NOT NULL,
            gid          INTEGER NOT NULL,
            cgroup_id    INTEGER NOT NULL,
            cmdline      TEXT NOT NULL,
            alert        INTEGER NOT NULL,
            matched_rule TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_events_agent_ts ON events (agent_id, ts_unix_ms DESC);
        "#,
    )?;

    Ok(pool)
}

#[derive(Clone, Serialize)]
pub struct AgentRow {
    pub agent_id: String,
    pub hostname: String,
    pub ip: String,
    pub tags: Vec<String>,
    pub agent_version: String,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
}

pub fn upsert_agent(
    pool: &Pool,
    agent_id: &str,
    hostname: &str,
    ip: &str,
    tags: &[String],
    agent_version: &str,
    now_ms: i64,
) -> anyhow::Result<()> {
    let conn = pool.get()?;
    let tags_json = serde_json::to_string(tags)?;
    conn.execute(
        r#"
        INSERT INTO agents (agent_id, hostname, ip, tags, agent_version, first_seen_ms, last_seen_ms)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
        ON CONFLICT(agent_id) DO UPDATE SET
            hostname = excluded.hostname,
            ip = excluded.ip,
            tags = excluded.tags,
            agent_version = excluded.agent_version,
            last_seen_ms = excluded.last_seen_ms
        "#,
        params![agent_id, hostname, ip, tags_json, agent_version, now_ms],
    )?;
    Ok(())
}

pub fn touch_agent(pool: &Pool, agent_id: &str, now_ms: i64) -> anyhow::Result<()> {
    let conn = pool.get()?;
    conn.execute(
        "UPDATE agents SET last_seen_ms = ?2 WHERE agent_id = ?1",
        params![agent_id, now_ms],
    )?;
    Ok(())
}

pub fn list_agents(pool: &Pool) -> anyhow::Result<Vec<AgentRow>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT agent_id, hostname, ip, tags, agent_version, first_seen_ms, last_seen_ms FROM agents ORDER BY hostname",
    )?;
    let rows = stmt
        .query_map([], |row| {
            let tags_json: String = row.get(3)?;
            let tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
            Ok(AgentRow {
                agent_id: row.get(0)?,
                hostname: row.get(1)?,
                ip: row.get(2)?,
                tags,
                agent_version: row.get(4)?,
                first_seen_ms: row.get(5)?,
                last_seen_ms: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[derive(Clone, Serialize)]
pub struct EventRow {
    pub agent_id: String,
    pub ts_unix_ms: i64,
    pub comm: String,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub cgroup_id: i64,
    pub cmdline: String,
    pub alert: bool,
    pub matched_rule: Option<String>,
}

pub fn insert_event(pool: &Pool, agent_id: &str, e: &sentinel_common::protocol::ExecEventWire) -> anyhow::Result<()> {
    let conn = pool.get()?;
    conn.execute(
        r#"
        INSERT INTO events (agent_id, ts_unix_ms, comm, pid, uid, gid, cgroup_id, cmdline, alert, matched_rule)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        "#,
        params![
            agent_id,
            e.ts_unix_ms,
            e.comm,
            e.pid,
            e.uid,
            e.gid,
            e.cgroup_id as i64,
            e.cmdline,
            e.alert as i64,
            e.matched_rule,
        ],
    )?;
    Ok(())
}

pub fn recent_events(pool: &Pool, agent_id: Option<&str>, limit: i64) -> anyhow::Result<Vec<EventRow>> {
    let conn = pool.get()?;
    let map_row = |row: &rusqlite::Row| -> rusqlite::Result<EventRow> {
        Ok(EventRow {
            agent_id: row.get(0)?,
            ts_unix_ms: row.get(1)?,
            comm: row.get(2)?,
            pid: row.get(3)?,
            uid: row.get(4)?,
            gid: row.get(5)?,
            cgroup_id: row.get(6)?,
            cmdline: row.get(7)?,
            alert: row.get::<_, i64>(8)? != 0,
            matched_rule: row.get(9)?,
        })
    };

    let mut rows = if let Some(agent_id) = agent_id {
        let mut stmt = conn.prepare(
            "SELECT agent_id, ts_unix_ms, comm, pid, uid, gid, cgroup_id, cmdline, alert, matched_rule \
             FROM events WHERE agent_id = ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let result = stmt
            .query_map(params![agent_id, limit], map_row)?
            .collect::<Result<Vec<_>, _>>()?;
        result
    } else {
        let mut stmt = conn.prepare(
            "SELECT agent_id, ts_unix_ms, comm, pid, uid, gid, cgroup_id, cmdline, alert, matched_rule \
             FROM events ORDER BY id DESC LIMIT ?1",
        )?;
        let result = stmt.query_map(params![limit], map_row)?.collect::<Result<Vec<_>, _>>()?;
        result
    };

    rows.reverse();
    Ok(rows)
}
