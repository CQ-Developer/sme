//! ratatui 参考客户端（M4，仅文本）。
//!
//! 热键：
//! - `Enter`：口令界面解锁 / 聊天界面发送
//! - `/peer <账号ID>`：选择对端并拉取一次性预密钥
//! - `Ctrl+X`：紧急擦除（内存 + keystore）并退出
//! - `Esc` / `Ctrl+C`：正常退出
//! - 空闲 5 分钟自动锁定，内存中的明文与会话被擦除
//!
//! 明文只存在于 `sme-client-core` 的内存缓冲与本界面的渲染字符串里。

use std::io::Stdout;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossterm::event::{Event as TermEvent, EventStream, KeyCode, KeyEvent, KeyModifiers};
use futures_util::StreamExt;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use sme_client_tui::session::{Event, Session};
use sme_proto::AccountId;
use zeroize::Zeroizing;

/// 空闲多久自动锁定。
const IDLE_LIMIT: Duration = Duration::from_secs(5 * 60);

/// UI 界面上保留的消息条数（与核心缓冲一致）。
const UI_MESSAGE_LIMIT: usize = 10;

struct App {
    server: String,
    keystore_path: PathBuf,
    password: Zeroizing<String>,
    session: Option<Session>,
    status: String,
    messages: Vec<(String, String)>,
    dropped: usize,
    input: Zeroizing<String>,
    peer: Option<AccountId>,
    last_activity: Instant,
    quit: bool,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let server = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:8080/ws".to_string());
    let keystore_path = default_data_dir().join("keystore.bin");

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, server, keystore_path).await;
    ratatui::restore();
    result
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    server: String,
    keystore_path: PathBuf,
) -> std::io::Result<()> {
    let mut app = App {
        server,
        keystore_path,
        password: Zeroizing::new(String::new()),
        session: None,
        status: "输入口令后按 Enter（首次运行会创建账号）".to_string(),
        messages: Vec::new(),
        dropped: 0,
        input: Zeroizing::new(String::new()),
        peer: None,
        last_activity: Instant::now(),
        quit: false,
    };

    let mut keys = EventStream::new();
    loop {
        terminal.draw(|frame| draw(frame, &app))?;

        if let Some(session) = app.session.as_mut() {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                maybe_key = keys.next() => {
                    if let Some(Ok(TermEvent::Key(key))) = maybe_key {
                        handle_key(&mut app, key).await;
                    }
                }
                event = session.next_event() => match event {
                    Ok(event) => apply_event(&mut app, event),
                    Err(error) => {
                        app.session = None;
                        app.status = format!("连接断开（{error}）；输入口令按 Enter 重连");
                    }
                },
            }
        } else {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                maybe_key = keys.next() => {
                    if let Some(Ok(TermEvent::Key(key))) = maybe_key {
                        handle_key(&mut app, key).await;
                    }
                }
            }
        }

        if app.session.is_some() && app.last_activity.elapsed() > IDLE_LIMIT {
            app.session = None;
            app.status = "空闲锁定：明文与会话已从内存擦除，输入口令按 Enter 解锁".to_string();
        }
        if app.quit {
            return Ok(());
        }
    }
}

async fn handle_key(app: &mut App, key: KeyEvent) {
    app.last_activity = Instant::now();
    match (key.code, key.modifiers) {
        (KeyCode::Char('x'), KeyModifiers::CONTROL) => {
            if let Some(session) = app.session.as_mut() {
                session.wipe_memory();
                let _ = session.delete_keystore();
            }
            app.session = None;
            app.messages.clear();
            app.input.clear();
            app.password.clear();
            app.status = "已紧急擦除：内存清空，本地 keystore 已删除".to_string();
            app.quit = true;
        }
        (KeyCode::Esc, _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            if let Some(session) = app.session.as_mut() {
                session.wipe_memory();
            }
            app.quit = true;
        }
        (KeyCode::Enter, _) => {
            if app.session.is_none() {
                connect(app).await;
            } else {
                send_input(app).await;
            }
        }
        (KeyCode::Backspace, _) => {
            if app.session.is_none() {
                app.password.pop();
            } else {
                app.input.pop();
            }
        }
        (KeyCode::Char(character), _) => {
            if app.session.is_none() {
                app.password.push(character);
            } else {
                app.input.push(character);
            }
        }
        _ => {}
    }
}

async fn connect(app: &mut App) {
    if app.password.is_empty() {
        app.status = "先输入口令".to_string();
        return;
    }
    app.status = "连接中…".to_string();
    match Session::connect(&app.server, &app.keystore_path, app.password.as_bytes()).await {
        Ok(mut session) => {
            app.status = format!("已登录 {}", session.account_id());
            // 顺手上传一批一次性预密钥，供对端发起握手。
            let _ = session
                .upload_prekeys(sme_client_tui::session::PREKEY_BATCH)
                .await;
            app.session = Some(session);
        }
        Err(error) => app.status = format!("连接失败: {error}"),
    }
}

async fn send_input(app: &mut App) {
    let text = app.input.trim().to_string();
    app.input.clear();
    if text.is_empty() {
        return;
    }

    if let Some(rest) = text.strip_prefix("/peer ") {
        match rest.trim().parse::<AccountId>() {
            Ok(peer) => {
                app.peer = Some(peer);
                if let Some(session) = app.session.as_mut()
                    && let Err(error) = session.fetch_prekey(peer).await
                {
                    app.status = format!("拉取预密钥失败: {error}");
                    return;
                }
                app.status = format!("对端已设为 {peer}（已请求预密钥）");
            }
            Err(_) => app.status = "账号 ID 格式无效（26 位 base32）".to_string(),
        }
        return;
    }

    let Some(peer) = app.peer else {
        app.status = "先用 /peer <账号> 选择对端".to_string();
        return;
    };
    let Some(session) = app.session.as_mut() else {
        return;
    };
    match session.send_text(peer, text.as_bytes()).await {
        Ok(()) => push_message(app, "我".to_string(), text),
        Err(error) => app.status = format!("发送失败: {error}"),
    }
}

fn apply_event(app: &mut App, event: Event) {
    match event {
        Event::Received { from, text } => push_message(app, from.to_string(), text),
        Event::DecryptFailed { from } => {
            app.status = format!("丢弃了一条重复/无法解密的消息（来自 {from}）");
        }
        Event::ServerError { code, detail } => {
            app.status = format!("服务端错误 {code:?}: {detail}");
        }
        Event::Ready | Event::Registered | Event::Sent { .. } | Event::PreKeysUploaded { .. } => {}
        Event::SessionEstablished { peer } => app.status = format!("与 {peer} 的会话已建立"),
        Event::ProtocolError { detail } => app.status = format!("协议错误: {detail}"),
    }
}

fn push_message(app: &mut App, from: String, text: String) {
    app.messages.push((from, text));
    while app.messages.len() > UI_MESSAGE_LIMIT {
        app.messages.remove(0);
        app.dropped += 1;
    }
}

fn draw(frame: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(frame.area());

    let mut lines: Vec<Line> = Vec::new();
    if app.dropped > 0 {
        lines.push(Line::from(Span::styled(
            format!(
                "—— {} 条更早消息已按策略丢弃（明文只保留最近 {UI_MESSAGE_LIMIT} 条）——",
                app.dropped
            ),
            Style::default().fg(Color::DarkGray),
        )));
    }
    for (from, text) in &app.messages {
        lines.push(Line::from(format!("{from}: {text}")));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "这里是空白：本应用不保存历史，重启后对话清空。",
            Style::default().fg(Color::DarkGray),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title("sme · 端到端加密（消息仅在内存，≤10 条）"),
        ),
        chunks[0],
    );

    let (input_text, title) = if app.session.is_some() {
        (
            app.input.as_str(),
            "输入：Enter 发送 · /peer <账号> 选对端 · Ctrl+X 紧急擦除",
        )
    } else {
        (
            app.password.as_str(),
            "口令：Enter 解锁/登录 · Ctrl+X 紧急擦除并删除本地数据",
        )
    };
    frame.render_widget(
        Paragraph::new(input_text).block(Block::default().borders(Borders::ALL).title(title)),
        chunks[1],
    );

    frame.render_widget(
        Paragraph::new(app.status.as_str()).style(Style::default().fg(Color::Gray)),
        chunks[2],
    );
}

fn default_data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        return home().join("Library/Application Support/sme");
    }
    #[cfg(target_os = "windows")]
    {
        return std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("sme");
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home().join(".local/share"));
        base.join("sme")
    }
}

#[cfg(not(target_os = "windows"))]
fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
