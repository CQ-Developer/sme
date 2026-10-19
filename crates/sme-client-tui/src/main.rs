//! ratatui reference client (text + inline image preview).
//!
//! Hotkeys:
//! - `Enter`: unlock on the password screen / send on the chat screen / confirm a save path
//! - `/peer <account-id>`: pick a peer and fetch a one-time prekey
//! - `Ctrl+S`: save the latest buffered image to a user-chosen path
//! - `Ctrl+X`: emergency wipe (memory + keystore) and exit
//! - `Esc` / `Ctrl+C`: normal exit (`Esc` cancels the save prompt first)
//! - Auto-lock after 5 minutes idle wipes in-memory plaintext, sessions and the passphrase
//!
//! Plaintext exists only in the `sme-client-core` buffer and in this UI's render-time
//! strings. Images are decoded for display; resize/encode runs on a background thread.

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
use ratatui_image::StatefulImage;
use ratatui_image::picker::Picker;
use ratatui_image::thread::{ResizeRequest, ResizeResponse, ThreadProtocol};
use sme_client::{ATTACHMENT_BYTES_LIMIT, MESSAGE_BUFFER_LIMIT};
use sme_client::{Event, PeerPin, ReceivedKind, Session};
use sme_proto::{AccountId, MessageBody};
use zeroize::Zeroizing;

mod save;

/// How long until an idle session auto-locks.
const IDLE_LIMIT: Duration = Duration::from_secs(5 * 60);

/// Height of the image preview pane.
const PREVIEW_PERCENTAGE: u16 = 40;

enum UiMessage {
    Chat { from: String, text: String },
    Notice(String),
}

struct App {
    server: String,
    data_dir: PathBuf,
    keystore_path: PathBuf,
    password: Zeroizing<String>,
    session: Option<Session>,
    status: String,
    messages: Vec<UiMessage>,
    dropped: usize,
    input: Zeroizing<String>,
    peer: Option<AccountId>,
    last_activity: Instant,
    quit: bool,
    picker: Picker,
    resize_tx: std::sync::mpsc::Sender<ResizeRequest>,
    encoder_rx: tokio::sync::mpsc::UnboundedReceiver<ResizeResponse>,
    image: Option<ThreadProtocol>,
    save_prompt: Option<Zeroizing<String>>,
    /// Bytes captured when the save prompt opened; dropped (and zeroized) on cancel.
    save_target: Option<Zeroizing<Vec<u8>>>,
    /// Set after a TOFU pin mismatch; sends to this peer are refused until it is confirmed again.
    blocked_peer: Option<AccountId>,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let server = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:8080/ws".to_string());
    let data_dir = default_data_dir();
    let keystore_path = data_dir.join("keystore.bin");

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, server, data_dir, keystore_path).await;
    ratatui::restore();
    result
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    server: String,
    data_dir: PathBuf,
    keystore_path: PathBuf,
) -> std::io::Result<()> {
    let (resize_tx, encoder_rx) = spawn_encoder_worker();
    // Detection may fail on terminals that do not answer the query; halfblocks always work.
    let picker = Picker::from_query_stdio().unwrap_or_else(|_| Picker::halfblocks());

    let mut app = App {
        server,
        data_dir,
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
        picker,
        resize_tx,
        encoder_rx,
        image: None,
        save_prompt: None,
        save_target: None,
        blocked_peer: None,
    };

    let mut keys = EventStream::new();
    loop {
        // Apply completed image encodes without blocking the UI.
        while let Ok(response) = app.encoder_rx.try_recv() {
            if let Some(image) = app.image.as_mut() {
                let _ = image.update_resized_protocol(response);
            }
        }

        terminal.draw(|frame| draw(frame, &mut app))?;

        if app.session.is_some() {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                maybe_key = keys.next() => {
                    if let Some(Ok(TermEvent::Key(key))) = maybe_key {
                        handle_key(&mut app, key).await;
                    }
                }
                event = app.session.as_mut().expect("session checked").next_event() => match event {
                    Ok(event) => apply_event(&mut app, event),
                    Err(error) => disconnect(&mut app, &format!("Disconnected ({error})")),
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
            lock(
                &mut app,
                "Idle lock: plaintext, sessions and passphrase wiped; enter the passphrase and press Enter to unlock",
            );
        }
        if app.quit {
            return Ok(());
        }
    }
}

/// Spawn a worker that turns resize requests into encoded terminal protocols.
fn spawn_encoder_worker() -> (
    std::sync::mpsc::Sender<ResizeRequest>,
    tokio::sync::mpsc::UnboundedReceiver<ResizeResponse>,
) {
    let (request_tx, request_rx) = std::sync::mpsc::channel::<ResizeRequest>();
    let (response_tx, response_rx) = tokio::sync::mpsc::unbounded_channel::<ResizeResponse>();

    std::thread::spawn(move || {
        while let Ok(request) = request_rx.recv() {
            let Ok(response) = request.resize_encode() else {
                // The widget will ask again on a later redraw.
                continue;
            };
            if response_tx.send(response).is_err() {
                break;
            }
        }
    });

    (request_tx, response_rx)
}

async fn handle_key(app: &mut App, key: KeyEvent) {
    app.last_activity = Instant::now();
    let control = key.modifiers.contains(KeyModifiers::CONTROL);

    // Emergency and normal exit stay available in every mode.
    if control && key.code == KeyCode::Char('x') {
        emergency_wipe(app);
        return;
    }
    if control && key.code == KeyCode::Char('c') {
        quit(app);
        return;
    }

    if app.save_prompt.is_some() {
        match key.code {
            KeyCode::Esc => {
                app.save_prompt = None;
                app.save_target = None;
                app.status = "Save cancelled".to_string();
            }
            KeyCode::Enter => save_current_image(app),
            KeyCode::Backspace => {
                if let Some(path) = app.save_prompt.as_mut() {
                    path.pop();
                }
            }
            KeyCode::Char(character) if !control => {
                if let Some(path) = app.save_prompt.as_mut() {
                    path.push(character);
                }
            }
            _ => {}
        }
        return;
    }

    if key.code == KeyCode::Esc {
        quit(app);
        return;
    }

    if app.session.is_none() {
        match key.code {
            KeyCode::Enter => connect(app).await,
            KeyCode::Backspace => {
                app.password.pop();
            }
            KeyCode::Char(character) if !control => app.password.push(character),
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Enter => send_input(app).await,
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Char('s') if control => start_save(app),
        KeyCode::Char(character) if !control => app.input.push(character),
        _ => {}
    }
}

fn quit(app: &mut App) {
    if let Some(session) = app.session.as_mut() {
        session.wipe_memory();
    }
    clear_plaintext(app);
    app.quit = true;
}

fn emergency_wipe(app: &mut App) {
    if let Some(session) = app.session.as_mut() {
        session.wipe_memory();
        let _ = session.delete_keystore();
    }
    clear_plaintext(app);
    app.status = "Emergency wipe done: memory cleared, local keystore deleted".to_string();
    app.quit = true;
}

/// Drop everything that can hold plaintext or key material.
fn clear_plaintext(app: &mut App) {
    app.session = None; // Dropping the session zeroizes the core buffer and Olm sessions.
    app.messages.clear();
    app.input.clear();
    app.password.clear();
    app.image = None;
    app.save_prompt = None;
    app.save_target = None;
    app.blocked_peer = None;
}

/// Network loss drops the session (and its plaintext) but keeps the peer selection.
fn disconnect(app: &mut App, reason: &str) {
    app.session = None;
    app.messages.clear();
    app.image = None;
    app.save_prompt = None;
    app.save_target = None;
    // Keep `blocked_peer`: an identity alarm must survive a transient disconnect.
    app.status = format!("{reason}; enter the passphrase and press Enter to reconnect");
}

fn lock(app: &mut App, reason: &str) {
    clear_plaintext(app);
    app.status = reason.to_string();
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
            app.last_activity = Instant::now();
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
                app.status = match app
                    .session
                    .as_ref()
                    .and_then(|session| session.peer_pin(peer))
                {
                    Some(pin) => format!(
                        "Peer set to {peer} (TOFU identity pinned, unverified: {})",
                        fingerprint(&pin)
                    ),
                    None => format!(
                        "Peer set to {peer} (prekey requested; identity will be pinned on first contact)"
                    ),
                };
            }
            Err(_) => app.status = "Invalid account ID (26 base32 characters)".to_string(),
        }
        return;
    }

    let Some(peer) = app.peer else {
        app.status = "Pick a peer first with /peer <account-id>".to_string();
        return;
    };
    if app.blocked_peer == Some(peer) {
        app.status = format!(
            "Sending to {peer} is blocked: its identity key changed. Restart to retry with the stored pin."
        );
        return;
    }
    let Some(session) = app.session.as_mut() else {
        return;
    };
    match session.send_text(peer, &text).await {
        Ok(()) => push_message(app, "me".to_string(), text),
        Err(error) => app.status = format!("Send failed: {error}"),
    }
}

fn start_save(app: &mut App) {
    if app.image.is_none() {
        app.status =
            "No image preview yet: wait for an image or ask the peer to resend".to_string();
        return;
    }

    let latest_image = app.session.as_ref().and_then(|session| {
        session
            .messages()
            .iter()
            .filter_map(|message| match message.body() {
                MessageBody::Image { bytes, .. } => Some(bytes.clone()),
                MessageBody::Text { .. } => None,
            })
            .last()
    });
    let Some(bytes) = latest_image else {
        app.status = "The image is no longer buffered (ask the peer to resend it)".to_string();
        return;
    };

    app.save_target = Some(Zeroizing::new(bytes));
    app.save_prompt = Some(Zeroizing::new(String::new()));
    app.status = format!(
        "Save image outside {} and {}: type a path, Enter confirms, Esc cancels",
        app.data_dir.display(),
        std::env::temp_dir().display()
    );
}

fn save_current_image(app: &mut App) {
    // Every failure path drops the captured bytes, which zeroizes them.
    let Some(path_input) = app.save_prompt.take() else {
        return;
    };
    let Some(bytes) = app.save_target.take() else {
        app.status = "Save cancelled: image is no longer available".to_string();
        return;
    };
    if path_input.trim().is_empty() {
        app.status = "Save cancelled: empty path".to_string();
        return;
    }

    app.status = match save::save_image(&path_input, &bytes, &app.data_dir) {
        Ok(path) => format!("Image saved to {}", path.display()),
        Err(error) => {
            // Keep the prompt and the captured bytes so the user can fix the path
            // (for example after choosing an existing file) and press Enter again.
            app.save_prompt = Some(path_input);
            app.save_target = Some(bytes);
            format!("Save failed: {error} (edit the path and press Enter to retry)")
        }
    };
}

fn apply_event(app: &mut App, event: Event) {
    match event {
        Event::Received {
            from,
            kind,
            dropped_images,
        } => {
            if dropped_images > 0 {
                push_notice(
                    app,
                    format!(
                        "{dropped_images} image(s) dropped by the {} MiB attachment budget; ask the peer to resend",
                        ATTACHMENT_BYTES_LIMIT / (1024 * 1024)
                    ),
                );
            }

            match kind {
                ReceivedKind::Text(text) => push_message(app, from.to_string(), text),
                ReceivedKind::Image {
                    width,
                    height,
                    bytes,
                } => {
                    push_message(
                        app,
                        from.to_string(),
                        format!("[image {width}x{height}, {} bytes]", bytes.len()),
                    );
                    show_image(app, &bytes, width, height);
                }
            }
        }
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
        Event::PeerPinned { peer, pin } => {
            push_notice(
                app,
                format!(
                    "TOFU identity pinned for {peer}: {} (unverified; safety code verification is not implemented yet)",
                    fingerprint(&pin)
                ),
            );
            app.status = format!("Pinned identity for {peer}; verify the safety code out of band");
        }
        Event::PeerKeyChanged {
            peer,
            pinned,
            observed,
        } => {
            app.blocked_peer = Some(peer);
            let detail = match observed {
                Some(observed) => format!(
                    "pinned {} / observed {}",
                    fingerprint(&pinned),
                    fingerprint(&observed)
                ),
                None => format!(
                    "pinned {} / an inbound pre-key used a different Curve25519 key",
                    fingerprint(&pinned)
                ),
            };
            push_notice(
                app,
                format!(
                    "WARNING: identity key changed for {peer}; sending is blocked. {detail}. Verify the safety code before continuing."
                ),
            );
            app.status =
                format!("Identity changed for {peer}; sending blocked until the pin is verified");
        }
        Event::PeerKeyConfirmed { peer } => {
            if app.blocked_peer == Some(peer) {
                app.blocked_peer = None;
            }
            push_notice(
                app,
                format!("Identity for {peer} matches the stored pin again"),
            );
            app.status = format!("Identity for {peer} confirmed against the stored pin");
        }
    }
}

/// Short display fingerprint; the full safety code is part of the SAS step.
fn fingerprint(pin: &PeerPin) -> String {
    fn short(bytes: &[u8]) -> String {
        bytes
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    format!("{}:{}", short(&pin.ed25519_pub), short(&pin.curve25519_pub))
}

fn show_image(app: &mut App, bytes: &[u8], width: u32, height: u32) {
    match decode_received_image(bytes) {
        Ok(decoded) if decoded.width() != width || decoded.height() != height => {
            app.image = None;
            app.status = format!(
                "Image rejected: body declares {width}x{height} but the JPEG is {}x{}",
                decoded.width(),
                decoded.height()
            );
        }
        Ok(decoded) => {
            // `new_resize_protocol` only parses the terminal protocol; the expensive
            // resize/encode step is handed to the background worker on each draw.
            let protocol = app.picker.new_resize_protocol(decoded);
            app.image = Some(ThreadProtocol::new(app.resize_tx.clone(), Some(protocol)));
            app.status =
                format!("Image {width}x{height} ready · Ctrl+S saves it to a path you choose");
        }
        Err(error) => {
            app.image = None;
            app.status = format!("Image {width}x{height} could not be decoded: {error}");
        }
    }
}

/// Decode a received image with the sender-side limits applied again.
///
/// `MessageBody` only validates the declared width/height fields; a malicious peer
/// could put a much larger image in the bytes (decompression bomb). Received images
/// must be JPEG (INFRA §7), so the format is fixed instead of sniffed.
fn decode_received_image(bytes: &[u8]) -> Result<image::DynamicImage, image::ImageError> {
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes));
    reader.set_format(image::ImageFormat::Jpeg);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(sme_proto::MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(sme_proto::MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    reader.decode()
}

fn push_message(app: &mut App, from: String, text: String) {
    app.messages.push(UiMessage::Chat { from, text });
    trim_messages(app);
}

fn push_notice(app: &mut App, text: String) {
    app.messages.push(UiMessage::Notice(text));
    trim_messages(app);
}

fn trim_messages(app: &mut App) {
    while app.messages.len() > MESSAGE_BUFFER_LIMIT {
        app.messages.remove(0);
        app.dropped += 1;
    }
}

fn draw(frame: &mut ratatui::Frame, app: &mut App) {
    let mut constraints = vec![Constraint::Min(3)];
    if app.image.is_some() {
        constraints.push(Constraint::Percentage(PREVIEW_PERCENTAGE));
    }
    constraints.push(Constraint::Length(3));
    constraints.push(Constraint::Length(1));

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(frame.area());

    let mut lines: Vec<Line> = Vec::new();
    if let Some(peer) = app.blocked_peer {
        lines.push(Line::from(Span::styled(
            format!(
                "WARNING: identity changed for {peer}; sending is blocked. Verify the safety code before continuing."
            ),
            Style::default().fg(Color::Red),
        )));
    }
    if app.dropped > 0 {
        lines.push(Line::from(Span::styled(
            format!(
                "— {} older messages dropped by policy (only the latest {MESSAGE_BUFFER_LIMIT} are kept) —",
                app.dropped
            ),
            Style::default().fg(Color::DarkGray),
        )));
    }
    for message in &app.messages {
        match message {
            UiMessage::Chat { from, text } => {
                lines.push(Line::from(format!("{from}: {text}")));
            }
            UiMessage::Notice(text) => lines.push(Line::from(Span::styled(
                format!("— {text} —"),
                Style::default().fg(Color::Yellow),
            ))),
        }
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "Blank by design: no history is stored, the conversation is empty after a restart.",
            Style::default().fg(Color::DarkGray),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default().borders(Borders::ALL).title(format!(
                "sme · end-to-end encrypted (messages in memory only, max {MESSAGE_BUFFER_LIMIT}, images ≤{} MiB)",
                ATTACHMENT_BYTES_LIMIT / (1024 * 1024)
            )),
        ),
        chunks[0],
    );

    let input_chunk = if let Some(protocol) = app.image.as_mut() {
        let area = chunks[1];
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Image preview · Ctrl+S saves as");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        frame.render_stateful_widget(StatefulImage::new(), inner, protocol);
        2
    } else {
        1
    };

    let (input_text, title) = if let Some(path) = app.save_prompt.as_ref() {
        (
            path.as_str(),
            "Save as: Enter confirms · Esc cancels · never the app data or temp dir",
        )
    } else if app.session.is_some() {
        (
            app.input.as_str(),
            "Input: Enter sends · /peer <account-id> · Ctrl+S saves image · Ctrl+X wipes",
        )
    } else {
        (
            app.password.as_str(),
            "Passphrase: Enter unlocks/signs in · Ctrl+X wipes memory and deletes local data",
        )
    };
    frame.render_widget(
        Paragraph::new(input_text).block(Block::default().borders(Borders::ALL).title(title)),
        chunks[input_chunk],
    );

    frame.render_widget(
        Paragraph::new(app.status.as_str()).style(Style::default().fg(Color::Gray)),
        chunks[input_chunk + 1],
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

#[cfg(test)]
mod image_tests {
    use super::*;

    pub(super) fn encode_jpeg(width: u32, height: u32) -> Vec<u8> {
        let image = image::RgbImage::from_pixel(width, height, image::Rgb([12, 34, 56]));
        let mut bytes = Vec::new();
        image::codecs::jpeg::JpegEncoder::new(&mut bytes)
            .encode_image(&image)
            .expect("encode fixture");
        bytes
    }

    #[test]
    fn received_images_must_be_jpeg_within_the_protocol_limits() {
        let decoded = decode_received_image(&encode_jpeg(2, 2)).expect("decode JPEG");
        assert_eq!((decoded.width(), decoded.height()), (2, 2));

        assert!(decode_received_image(b"not a JPEG").is_err());
        assert!(
            decode_received_image(&encode_jpeg(sme_proto::MAX_IMAGE_DIMENSION + 1, 1)).is_err()
        );
    }
}

#[cfg(test)]
mod draw_tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn app_with_preview() -> App {
        let (resize_tx, _resize_rx) = std::sync::mpsc::channel();
        let (_encoder_tx, encoder_rx) = tokio::sync::mpsc::unbounded_channel();
        let picker = Picker::halfblocks();
        let decoded = decode_received_image(&super::image_tests::encode_jpeg(8, 8)).unwrap();
        let image =
            ThreadProtocol::new(resize_tx.clone(), Some(picker.new_resize_protocol(decoded)));

        App {
            server: "ws://127.0.0.1:9/ws".to_string(),
            data_dir: std::env::temp_dir().join("sme-draw-test"),
            keystore_path: std::env::temp_dir().join("sme-draw-test/keystore.bin"),
            password: Zeroizing::new(String::new()),
            session: None,
            status: "test".to_string(),
            messages: vec![UiMessage::Chat {
                from: "peer".to_string(),
                text: "[image 8x8, 123 bytes]".to_string(),
            }],
            dropped: 0,
            input: Zeroizing::new(String::new()),
            peer: None,
            last_activity: Instant::now(),
            quit: false,
            picker,
            resize_tx,
            encoder_rx,
            image: Some(image),
            save_prompt: Some(Zeroizing::new("/home/user/photo.jpg".to_string())),
            save_target: None,
            blocked_peer: None,
        }
    }

    #[test]
    fn preview_and_save_prompt_fit_small_terminals() {
        for (width, height) in [(80, 24), (40, 12), (20, 8)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            let mut app = app_with_preview();
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();

            app.blocked_peer = Some(AccountId::random());
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        }
    }
}
