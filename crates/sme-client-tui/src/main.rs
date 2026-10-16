//! ratatui reference client (M4, text only).
//!
//! Hotkeys:
//! - `Enter`: unlock on the password screen / send on the chat screen
//! - `/peer <account-id>`: pick a peer and fetch a one-time prekey
//! - `Ctrl+X`: emergency wipe (memory + keystore) and exit
//! - `Esc` / `Ctrl+C`: normal exit
//! - Auto-lock after 5 minutes idle wipes in-memory plaintext and sessions
//!
//! Plaintext exists only in the `sme-client-core` buffer and in this UI's render-time strings.

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
use sme_client::{Event, ReceivedKind, Session};
use sme_proto::AccountId;
use zeroize::Zeroizing;

/// How long until an idle session auto-locks.
const IDLE_LIMIT: Duration = Duration::from_secs(5 * 60);

/// Number of messages kept in the UI list (matches the core buffer).
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
        status: "Enter a passphrase and press Enter (first run creates an account)".to_string(),
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
                        app.status = format!("Disconnected ({error}); enter the passphrase and press Enter to reconnect");
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
            app.status = "Idle lock: plaintext and sessions wiped from memory; enter the passphrase and press Enter to unlock".to_string();
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
            app.status = "Emergency wipe done: memory cleared, local keystore deleted".to_string();
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
        app.status = "Enter the passphrase first".to_string();
        return;
    }
    app.status = "Connecting…".to_string();
    match Session::connect(&app.server, &app.keystore_path, app.password.as_bytes()).await {
        Ok(mut session) => {
            app.status = format!("Logged in as {}", session.account_id());
            // Also upload a batch of one-time prekeys so peers can start a handshake.
            let _ = session.upload_prekeys(sme_client::PREKEY_BATCH).await;
            app.session = Some(session);
        }
        Err(error) => app.status = format!("Connection failed: {error}"),
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
                    app.status = format!("Failed to fetch prekey: {error}");
                    return;
                }
                app.status = format!("Peer set to {peer} (prekey requested)");
            }
            Err(_) => app.status = "Invalid account ID (26 base32 characters)".to_string(),
        }
        return;
    }

    let Some(peer) = app.peer else {
        app.status = "Pick a peer first with /peer <account-id>".to_string();
        return;
    };
    let Some(session) = app.session.as_mut() else {
        return;
    };
    match session.send_text(peer, &text).await {
        Ok(()) => push_message(app, "me".to_string(), text),
        Err(error) => app.status = format!("Send failed: {error}"),
    }
}

fn apply_event(app: &mut App, event: Event) {
    match event {
        Event::Received { from, kind } => match kind {
            ReceivedKind::Text(text) => push_message(app, from.to_string(), text),
            ReceivedKind::Image {
                width,
                height,
                bytes,
            } => push_message(
                app,
                from.to_string(),
                format!("[image {width}x{height}, {} bytes]", bytes.len()),
            ),
        },
        Event::DecryptFailed { from } => {
            app.status = format!("Dropped a duplicate/undecryptable message (from {from})");
        }
        Event::ServerError { code, detail } => {
            app.status = format!("Server error {code:?}: {detail}");
        }
        Event::Ready | Event::Registered | Event::Sent { .. } | Event::PreKeysUploaded { .. } => {}
        Event::SessionEstablished { peer } => {
            app.status = format!("Session established with {peer}")
        }
        Event::ProtocolError { detail } => app.status = format!("Protocol error: {detail}"),
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
                "— {} older messages dropped by policy (only the latest {UI_MESSAGE_LIMIT} are kept) —",
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
            "Blank by design: no history is stored, the conversation is empty after a restart.",
            Style::default().fg(Color::DarkGray),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title("sme · end-to-end encrypted (messages in memory only, max 10)"),
        ),
        chunks[0],
    );

    let (input_text, title) = if app.session.is_some() {
        (
            app.input.as_str(),
            "Input: Enter sends · /peer <account-id> picks a peer · Ctrl+X emergency wipe",
        )
    } else {
        (
            app.password.as_str(),
            "Passphrase: Enter unlocks/signs in · Ctrl+X wipes memory and deletes local data",
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
