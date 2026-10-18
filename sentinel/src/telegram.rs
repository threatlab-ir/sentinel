use log::warn;

#[derive(Clone)]
pub struct Telegram {
    token: String,
    chat_id: String,
    client: reqwest::Client,
}

impl Telegram {
    pub fn new(token: String, chat_id: String) -> Self {
        Self {
            token,
            chat_id,
            client: reqwest::Client::new(),
        }
    }

    /// Fire-and-forget: spawns the HTTP call so the perf-event reader never blocks on it.
    pub fn notify_alert(&self, comm: &str, pid: u32, uid: u32, gid: u32, cmdline: &str) {
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.token);
        let text = format!(
            "\u{1F6A8} *sentinel alert*\n`{comm}` \\(pid {pid}, uid {uid}, gid {gid}\\)\ncmd: `{}`",
            escape_markdown(cmdline)
        );
        let client = self.client.clone();
        let chat_id = self.chat_id.clone();

        tokio::spawn(async move {
            let res = client
                .post(&url)
                .json(&serde_json::json!({
                    "chat_id": chat_id,
                    "text": text,
                    "parse_mode": "MarkdownV2",
                }))
                .send()
                .await;

            match res {
                Ok(r) if !r.status().is_success() => {
                    let status = r.status();
                    let body = r.text().await.unwrap_or_default();
                    warn!("telegram notify failed: {status} {body}");
                }
                Err(e) => warn!("telegram notify failed: {e}"),
                _ => {}
            }
        });
    }
}

fn escape_markdown(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "_*[]()~`>#+-=|{}.!\\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}
