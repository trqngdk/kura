use axum::{
  body::{Body, Bytes},
  http::{header, HeaderValue, StatusCode},
  response::{IntoResponse, Response},
};
use futures_core::Stream;
use opendal::Operator;
use sqlx::{Pool, Sqlite};
use std::{
  collections::HashMap,
  pin::Pin,
  process::Child,
  ptr::write_volatile,
  sync::{
    atomic::{ compiler_fence, AtomicUsize, Ordering },
    Arc, Mutex,
  },
  task::{Context, Poll},
  time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Notify, Semaphore};

use crate::limiter::BlindedRateLimiter;

// ============================================================================
// SYSTEM CAPACITY, CONCURRENCY & CRYPTOGRAPHIC TUNING CONSTANTS
// ============================================================================

// System capacity and buffer constraints
pub const MAX_FILE_SIZE: usize = 200 * 1024 * 1024;
pub const MULTIPART_OVERHEAD: usize = 64 * 1024;
pub const DISK_BUFFER_SIZE: usize = 256 * 1024;
pub const R2_PART_SIZE: usize = 8 * 1024 * 1024;
pub const RESUMABLE_PART_SIZE: usize = 10 * 1024 * 1024;
pub const RESUMABLE_SESSION_TTL: i64 = 86_400;
pub const WORMHOLE_ROOM_TTL: i64 = 1_800;
pub const MAX_WORMHOLE_ROOMS: usize = 256;
pub const SNIFF_BUFFER_SIZE: usize = 4096;
pub const MAX_MULTIPART_FIELDS: usize = 6;

// Concurrency and rate limiting thresholds
pub const MAX_CONCURRENT_UPLOADS: usize = 4;
pub const MAX_CONCURRENT_DOWNLOADS: usize = 16;
pub const MAX_CONCURRENT_ZIP_STREAMS: usize = 4;
pub const MAX_CONCURRENT_AUTH: usize = 4;
pub const MAX_INFLIGHT_QUEUE: usize = 32;
pub const MAX_GLOBAL_PER_MINUTE: u32 = 120;
pub const MAX_ACTOR_PER_MINUTE: u32 = 30;
pub const POW_SOFT_ACTOR_THRESHOLD: u32 = 12;
pub const POW_DIFFICULTY_BITS: u32 = 16;
pub const POW_TTL_SECS: i64 = 300;
pub const MAX_ALBUM_ZIP_DOWNLOADS: i64 = 25;

// Hash tables and sketch sizes (must be powers of two for bitwise masking)
pub const SKETCH_BUCKETS: usize = 4096;
pub const SKETCH_DEPTH: usize = 4;
pub const ZIP_ACTOR_BUCKETS: usize = 1024;
pub const POW_REPLAY_BUCKETS: usize = 2048;

// Identifier specifications
pub const SLUG_LENGTH: usize = 8;
pub const ALBUM_ID_LENGTH: usize = 10;
pub const WORMHOLE_ID_LENGTH: usize = 10;
pub const DELETE_KEY_LENGTH: usize = 24;
pub const SLUG_MAX_RETRIES: usize = 8;

// Cryptographic and worker tuning
pub const PBKDF2_ITERATIONS: u32 = 100_000;
pub const MEMORY_HARD_BLOCKS: usize = 8192;
pub const MEMORY_HARD_ROUNDS: usize = 4;
pub const PRESIGN_EXPIRY_SECS: u64 = 900;
pub const REAPER_INTERVAL: Duration = Duration::from_secs(30);
pub const SEMAPHORE_WAIT_TIMEOUT: Duration = Duration::from_secs(45);
pub const CHUNK_READ_TIMEOUT: Duration = Duration::from_secs(15);
pub const UPLOAD_HARD_TIMEOUT: Duration = Duration::from_secs(180);

// Ephemeral runtime directory and hex lookup table
pub const TMP_DIR: &str = "./tmp";
pub const HEX_LUT: &[u8; 16] = b"0123456789abcdef";

// Compile-time structural invariants for bit-masked hash tables
const _: () = assert!(SKETCH_BUCKETS.is_power_of_two());
const _: () = assert!(ZIP_ACTOR_BUCKETS.is_power_of_two());
const _: () = assert!(POW_REPLAY_BUCKETS.is_power_of_two());
const _: () = assert!(MEMORY_HARD_BLOCKS.is_power_of_two());

// IEEE 802.3 CRC-32 lookup table for zero-allocation streaming ZIP production
pub const CRC32_TABLE: [u32; 256] = {
  let mut table = [0u32; 256];
  let mut i = 0;
  while i < 256 {
    let mut c = i as u32;
    let mut j = 0;
    while j < 8 {
      if c & 1 != 0 {
        c = 0xEDB88320 ^ (c >> 1);
      } else {
        c >>= 1;
      }
      j += 1;
    }
    table[i] = c;
    i += 1;
  }
  table
};

// ============================================================================
// SECURITY SIGNATURES, BOT FILTERS & FORMAT ALLOWLISTS
// ============================================================================

pub const BUILTIN_BLOCKED_HASHES: &[&str] = &[
  "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
];

pub const BOT_USER_AGENTS: &[&str] = &[
  "telegrambot",
  "discordbot",
  "slackbot",
  "twitterbot",
  "facebookexternalhit",
  "whatsapp",
  "linkedinbot",
  "skypeuripreview",
  "vkshare",
  "line-poker",
  "applebot",
  "bingpreview",
  "pinterest",
  "redditbot",
  "embedly",
  "outbrain",
  "quora link preview",
];

pub const VERIFIED_MAGIC_FORMATS: &[(&str, &str, bool)] = &[
  ("png", "image/png", true),
  ("jpg", "image/jpeg", true),
  ("jpeg", "image/jpeg", true),
  ("gif", "image/gif", true),
  ("webp", "image/webp", true),
  ("avif", "image/avif", true),
  ("bmp", "image/bmp", true),
  ("ico", "image/x-icon", true),
  ("mp4", "video/mp4", true),
  ("webm", "video/webm", true),
  ("mkv", "video/x-matroska", false),
  ("mov", "video/quicktime", true),
  ("avi", "video/x-msvideo", false),
  ("mp3", "audio/mpeg", true),
  ("wav", "audio/wav", true),
  ("ogg", "audio/ogg", true),
  ("flac", "audio/flac", true),
  ("m4a", "audio/mp4", true),
  ("pdf", "application/pdf", true),
  ("epub", "application/epub+zip", false),
  ("zip", "application/zip", false),
  ("tar", "application/x-tar", false),
  ("gz", "application/gzip", false),
  ("7z", "application/x-7z-compressed", false),
  ("zst", "application/zstd", false),
  ("rar", "application/vnd.rar", false),
  ("xz", "application/x-xz", false),
  ("sqlite", "application/vnd.sqlite3", false),
];

pub const DANGEROUS_WEB_EXTENSIONS: &[&str] = &[
  "html", "htm", "shtml", "xhtml", "xht", "svg", "svgz", "xml", "xsl", "xslt",
  "js", "mjs", "cjs", "jsx", "ts", "tsx", "wasm", "php", "phtml", "asp", "aspx",
  "jsp", "jspx", "cgi", "pl", "py", "rb", "sh", "bash", "zsh", "ps1", "bat",
  "cmd", "vbs", "vbe", "wsf", "wsh", "hta", "mht", "mhtml", "swf", "jar", "class",
  "msi", "exe", "dll", "scr", "cpl", "lnk", "reg",
];

pub const SAFE_TEXT_EXTENSIONS: &[&str] = &[
  "txt", "note", "log", "md", "csv", "tsv", "json", "toml", "yaml", "yml", "ini", "cfg",
  "conf", "env", "sql", "rs", "go", "c", "h", "cpp", "hpp", "cs", "java", "kt",
  "swift", "css", "scss", "dockerfile", "makefile", "gitignore",
];

pub const FORBIDDEN_POLYGLOT_SIGNATURES: &[&[u8]] = &[
  b"<html", b"<script", b"<svg", b"<iframe", b"<object", b"<embed", b"<applet",
  b"<meta", b"<link", b"<style", b"<base", b"<form", b"<body", b"<!doctype",
  b"<!entity", b"<?xml", b"<?php", b"<math", b"<details", b"<marquee", b"<isindex",
  b"javascript:", b"vbscript:", b"data:text/html", b"xlink:href", b"formaction=",
  b"onload=", b"onerror=", b"onfocus=", b"ontoggle=", b"onanimationstart=",
];

// ============================================================================
// DOMAIN POLICIES, CREDENTIALS & STATE CONTAINERS
// ============================================================================

#[derive(Clone, Copy)]
pub struct ExpiryPolicy {
  pub ttl_seconds: Option<i64>,
  pub burn_after_read: bool,
  pub max_views: Option<i64>,
}

impl ExpiryPolicy {
  #[inline]
  pub fn is_ephemeral(&self) -> bool {
    self.ttl_seconds.is_some() || self.burn_after_read || self.max_views.is_some()
  }
}

#[derive(Clone)]
pub struct SecurityCreds {
  pub pw: Option<([u8; 16], [u8; 32])>,
  pub duress: Option<([u8; 16], [u8; 32])>,
}

impl Drop for SecurityCreds {
  fn drop(&mut self) {
    if let Some((ref mut salt, ref mut hash)) = self.pw {
      for b in salt.iter_mut().chain(hash.iter_mut()) {
        unsafe {
          write_volatile(b, 0u8);
        }
      }
    }
    if let Some((ref mut salt, ref mut hash)) = self.duress {
      for b in salt.iter_mut().chain(hash.iter_mut()) {
        unsafe {
          write_volatile(b, 0u8);
        }
      }
    }
    compiler_fence(Ordering::SeqCst);
  }
}

#[derive(PartialEq, Eq)]
pub enum AuthOutcome {
  ValidPrimary,
  DuressTriggered,
  Invalid,
}

#[derive(Clone)]
pub struct WormholeRoom {
  pub created_at: i64,
  pub sender_token: String,
  pub filename: String,
  pub filesize: u64,
  pub e2ee: bool,
  pub offer: Option<String>,
  pub answer: Option<String>,
  pub sender_ice: Vec<String>,
  pub receiver_ice: Vec<String>,
  pub revision: u64,
  pub notify: Arc<Notify>,
}

// ============================================================================
// RAII RESOURCE & STREAM GUARDS
// ============================================================================

pub struct LitestreamSupervisor {
  pub child: Option<Child>,
}

impl Drop for LitestreamSupervisor {
  fn drop(&mut self) {
    if let Some(mut child) = self.child.take() {
      let _ = child.kill();
      let _ = child.wait();
    }
  }
}

pub struct BodyChunkStream {
  inner: axum::body::BodyDataStream,
}

impl BodyChunkStream {
  #[inline]
  pub fn new(body: Body) -> Self {
    Self {
      inner: body.into_data_stream(),
    }
  }

  #[inline]
  pub async fn next_chunk(&mut self) -> Result<Option<Bytes>, axum::Error> {
    struct NextFuture<'a>(&'a mut axum::body::BodyDataStream);
    impl<'a> std::future::Future for NextFuture<'a> {
      type Output = Option<Result<Bytes, axum::Error>>;
      #[inline]
      fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.0).poll_next(cx)
      }
    }
    match NextFuture(&mut self.inner).await {
      Some(Ok(b)) => Ok(Some(b)),
      Some(Err(e)) => Err(e),
      None => Ok(None),
    }
  }
}

pub struct InflightGuard {
  counter: Arc<AtomicUsize>,
}

impl InflightGuard {
  #[inline]
  pub fn try_acquire(counter: Arc<AtomicUsize>) -> Option<Self> {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
      if current >= MAX_INFLIGHT_QUEUE {
        return None;
      }
      match counter.compare_exchange_weak(
        current,
        current + 1,
        Ordering::Acquire,
        Ordering::Relaxed,
      ) {
        Ok(_) => return Some(Self { counter }),
        Err(actual) => current = actual,
      }
    }
  }
}

impl Drop for InflightGuard {
  #[inline]
  fn drop(&mut self) {
    self.counter.fetch_sub(1, Ordering::Release);
  }
}

pub struct R2ObjectGuard {
  storage: Operator,
  key: String,
  committed: bool,
}

impl R2ObjectGuard {
  #[inline]
  pub fn new(storage: Operator, key: String) -> Self {
    Self {
      storage,
      key,
      committed: false,
    }
  }

  #[inline]
  pub fn commit(&mut self) {
    self.committed = true;
  }
}

impl Drop for R2ObjectGuard {
  fn drop(&mut self) {
    if self.committed || self.key.is_empty() {
      return;
    }
    let storage = self.storage.clone();
    let key = std::mem::take(&mut self.key);
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
      handle.spawn(async move {
        let _ = storage.delete(&key).await;
      });
    }
  }
}

#[derive(Clone)]
pub struct AppState {
  pub db: Pool<Sqlite>,
  pub storage: Operator,
  pub public_url: String,
  pub app_origin: Option<String>,
  pub index_html: Bytes,
  pub upload_semaphore: Arc<Semaphore>,
  pub download_semaphore: Arc<Semaphore>,
  pub zip_semaphore: Arc<Semaphore>,
  pub auth_semaphore: Arc<Semaphore>,
  pub inflight_counter: Arc<AtomicUsize>,
  pub rate_limiter: Arc<BlindedRateLimiter>,
  pub wormhole_rooms: Arc<Mutex<HashMap<String, WormholeRoom>>>,
}

// ============================================================================
// HARDENED ERROR HANDLING & LOG-INJECTION SANITIZATION
// ============================================================================

pub enum AppError {
  BadRequest(&'static str),
  Unauthorized(&'static str),
  Forbidden(&'static str),
  NotFound(&'static str),
  Gone(&'static str),
  Locked(String),
  RequestTimeout(&'static str),
  TooManyRequests(&'static str),
  PowRequired(String),
  PayloadTooLarge(&'static str),
  Internal(String),
}

#[inline]
fn build_plain_error_response(status: StatusCode, body: String) -> Response {
  let mut resp = Response::new(Body::from(body));
  *resp.status_mut() = status;
  resp.headers_mut().insert(
    header::CONTENT_TYPE,
    HeaderValue::from_static("text/plain; charset=utf-8"),
  );
  resp.headers_mut().insert(
    header::CACHE_CONTROL,
    HeaderValue::from_static("no-store, no-cache, must-revalidate"),
  );
  resp
}

/// Strips CR, LF, ANSI escape sequences, and quotes to prevent terminal/SIEM log injection
#[inline]
fn sanitize_log_message(raw: &str) -> String {
  raw
    .chars()
    .map(|c| {
      if c.is_control() || c == '"' || c == '\\' {
        ' '
      } else {
        c
      }
    })
    .take(512)
    .collect()
}

impl IntoResponse for AppError {
  fn into_response(self) -> Response {
    match self {
      AppError::BadRequest(msg) => {
        build_plain_error_response(StatusCode::BAD_REQUEST, format!("{}\n", msg))
      }
      AppError::Unauthorized(msg) => {
        build_plain_error_response(StatusCode::UNAUTHORIZED, format!("{}\n", msg))
      }
      AppError::Forbidden(msg) => {
        build_plain_error_response(StatusCode::FORBIDDEN, format!("{}\n", msg))
      }
      AppError::NotFound(msg) => {
        build_plain_error_response(StatusCode::NOT_FOUND, format!("{}\n", msg))
      }
      AppError::Gone(msg) => {
        build_plain_error_response(StatusCode::GONE, format!("{}\n", msg))
      }
      AppError::Locked(msg) => {
        build_plain_error_response(StatusCode::LOCKED, format!("{}\n", msg))
      }
      AppError::RequestTimeout(msg) => {
        build_plain_error_response(StatusCode::REQUEST_TIMEOUT, format!("{}\n", msg))
      }
      AppError::TooManyRequests(msg) => {
        build_plain_error_response(StatusCode::TOO_MANY_REQUESTS, format!("{}\n", msg))
      }
      AppError::PowRequired(challenge) => {
        let mut resp = build_plain_error_response(
          StatusCode::TOO_MANY_REQUESTS,
          "pow_challenge_required\n".to_string(),
        );
        if let Ok(cv) = HeaderValue::from_str(&challenge) {
          resp
            .headers_mut()
            .insert(header::HeaderName::from_static("x-kura-pow-challenge"), cv);
        }
        resp.headers_mut().insert(
          header::HeaderName::from_static("x-kura-pow-difficulty"),
          HeaderValue::from(POW_DIFFICULTY_BITS),
        );
        resp.headers_mut().insert(
          header::ACCESS_CONTROL_EXPOSE_HEADERS,
          HeaderValue::from_static("X-Kura-Pow-Challenge, X-Kura-Pow-Difficulty"),
        );
        resp
      }
      AppError::PayloadTooLarge(msg) => {
        build_plain_error_response(StatusCode::PAYLOAD_TOO_LARGE, format!("{}\n", msg))
      }
      AppError::Internal(msg) => {
        let safe_msg = sanitize_log_message(&msg);
        eprintln!(
          "ts={} level=error msg=\"{}\"",
          current_unix_timestamp(),
          safe_msg
        );
        build_plain_error_response(
          StatusCode::INTERNAL_SERVER_ERROR,
          "internal_server_error\n".to_string(),
        )
      }
    }
  }
}

impl<E: std::error::Error> From<E> for AppError {
  fn from(err: E) -> Self {
    AppError::Internal(err.to_string())
  }
}

#[inline]
pub fn current_unix_timestamp() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs() as i64
}