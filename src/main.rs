mod album;
mod config;
mod crypto;
mod download;
mod limiter;
mod upload;
mod wormhole;

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, DefaultBodyLimit, Path as AxumPath, State},
    http::{header, HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Router,
};
use opendal::{services::S3, Operator};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Pool, Sqlite,
};
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::{atomic::AtomicUsize, Arc, Mutex},
    time::Duration,
};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    signal,
    sync::Semaphore,
};
use tower_http::set_header::SetResponseHeaderLayer;

use crate::{
    album::{create_album_handler, stream_album_zip_handler, view_album_handler},
    config::*,
    crypto::resolve_request_origin,
    download::{
        delete_file_handler, file_stats_handler, safe_delete_r2_if_unreferenced, vault_gate_get,
        vault_gate_post,
    },
    limiter::BlindedRateLimiter,
    upload::{
        commit_presigned_handler, complete_resumable_handler, init_resumable_handler,
        presign_upload_handler, upload_handler, upload_put_named_handler,
        upload_resumable_part_handler,
    },
    wormhole::{
        init_wormhole_handler, signal_wormhole_handler, state_wormhole_handler,
        view_wormhole_receiver_handler,
    },
};

/// Maximum number of expired records reaped per tick to prevent SQLite write-lock starvation
const REAPER_BATCH_LIMIT: i64 = 250;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    // Clean and recreate ephemeral runtime directory with strict 0700 owner-only permissions
    if Path::new(TMP_DIR).exists() {
        let _ = fs::remove_dir_all(TMP_DIR).await;
    }
    fs::create_dir_all(TMP_DIR).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(TMP_DIR, std::fs::Permissions::from_mode(0o700)).await;
    }

    let index_raw = fs::read("static/index.html")
        .await
        .expect("missing static/index.html");
    let index_html = Bytes::from(index_raw);

    let account_id = env::var("R2_ACCOUNT_ID").expect("missing R2_ACCOUNT_ID");
    let bucket = env::var("R2_BUCKET").expect("missing R2_BUCKET");
    let access_key = env::var("R2_ACCESS_KEY_ID").expect("missing R2_ACCESS_KEY_ID");
    let secret_key = env::var("R2_SECRET_ACCESS_KEY").expect("missing R2_SECRET_ACCESS_KEY");
    let public_url = env::var("PUBLIC_URL_PREFIX")
        .expect("missing PUBLIC_URL_PREFIX")
        .trim_end_matches('/')
        .to_string();
    let app_origin = env::var("APP_ORIGIN")
        .ok()
        .map(|s| s.trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty());
    let pow_always_required = env::var("KURA_POW_REQUIRED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let db_url = env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:kura.db".into());

    let litestream_cfg_path = init_litestream_and_restore(
        &db_url,
        &account_id,
        &bucket,
        &access_key,
        &secret_key,
    )
    .await;

    let connect_options = SqliteConnectOptions::from_str(&db_url)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(Duration::from_secs(5))
        .pragma("temp_store", "MEMORY")
        .pragma("secure_delete", "FAST")
        .pragma("mmap_size", "67108864")
        .pragma("journal_size_limit", "67108864")
        .pragma("cache_size", "-16384")
        .pragma("foreign_keys", "ON");

    let db = SqlitePoolOptions::new()
        .max_connections(16)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(connect_options)
        .await?;

    initialize_and_migrate_schema(&db).await?;

    let _litestream_guard = LitestreamSupervisor {
        child: spawn_litestream_replicate(
            litestream_cfg_path.as_deref(),
            &access_key,
            &secret_key,
        ),
    };

    let builder = S3::default()
        .endpoint(&format!("https://{}.r2.cloudflarestorage.com", account_id))
        .bucket(&bucket)
        .region("auto")
        .access_key_id(&access_key)
        .secret_access_key(&secret_key);

    let storage = Operator::new(builder)?;

    let state = Arc::new(AppState {
        db: db.clone(),
        storage,
        public_url,
        app_origin,
        index_html,
        upload_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_UPLOADS)),
        download_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DOWNLOADS)),
        zip_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_ZIP_STREAMS)),
        auth_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_AUTH)),
        inflight_counter: Arc::new(AtomicUsize::new(0)),
        rate_limiter: Arc::new(BlindedRateLimiter::new(pow_always_required)),
        wormhole_rooms: Arc::new(Mutex::new(HashMap::with_capacity(64))),
    });

    let reaper_state = state.clone();
    let reaper_handle = tokio::spawn(async move {
        reaper_worker(reaper_state).await;
    });

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/static/{folder}/{file}", get(serve_static_asset))
        .route("/healthz", get(health_check))
        .route("/pow", get(issue_pow_handler))
        .route("/kura.sh", get(serve_cli_script))
        .route("/upload", post(upload_handler).put(upload_handler))
        .route(
            "/upload/{filename}",
            put(upload_put_named_handler).post(upload_put_named_handler),
        )
        .route("/upload/presign", post(presign_upload_handler))
        .route("/upload/commit", post(commit_presigned_handler))
        .route("/upload/resumable/init", post(init_resumable_handler))
        .route(
            "/upload/resumable/{session_id}/{part_number}",
            put(upload_resumable_part_handler),
        )
        .route(
            "/upload/resumable/{session_id}/complete",
            post(complete_resumable_handler),
        )
        .route("/wormhole/init", post(init_wormhole_handler))
        .route("/wormhole/{room_id}/signal", post(signal_wormhole_handler))
        .route("/wormhole/{room_id}/state", get(state_wormhole_handler))
        .route("/w/{room_id}", get(view_wormhole_receiver_handler))
        .route("/album", post(create_album_handler))
        .route("/a/{album_id}", get(view_album_handler))
        .route("/a/{album_id}/zip", get(stream_album_zip_handler))
        .route("/stats/{id}", get(file_stats_handler))
        .route("/v/{id}/stats", get(file_stats_handler))
        .route(
            "/v/{id}",
            get(vault_gate_get)
                .post(vault_gate_post)
                .delete(delete_file_handler),
        )
        .route(
            "/{id}",
            get(vault_gate_get)
                .post(vault_gate_post)
                .delete(delete_file_handler),
        )
        .layer(DefaultBodyLimit::max(MAX_FILE_SIZE + MULTIPART_OVERHEAD))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("SAMEORIGIN"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("x-permitted-cross-domain-policies"),
            HeaderValue::from_static("none"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("permissions-policy"),
            HeaderValue::from_static("geolocation=(), microphone=(), camera=(), usb=(), payment=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::HeaderName::from_static("cross-origin-resource-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self' https: stun: turn:; img-src 'self' data: blob: https:; media-src 'self' blob: https:; frame-src 'self' blob: https:; form-action 'self'; frame-ancestors 'self'; base-uri 'none';",
            ),
        ))
        .with_state(state);

    let bind_host = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".into());
    let port = env::var("PORT").unwrap_or_else(|_| "3000".into());
    let addr = format!("{}:{}", bind_host, port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    println!(
        "ts={} level=info event=server.listen addr={}",
        current_unix_timestamp(),
        addr
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    // Graceful database & replication teardown:
    // Stop background reaper, flush SQLite WAL into main DB file, and allow Litestream to sync final frames
    reaper_handle.abort();
    let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE);")
        .execute(&db)
        .await;
    db.close().await;
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let _ = fs::remove_dir_all(TMP_DIR).await;
    Ok(())
}

// ============================================================================
// STATIC ASSET HANDLER (Zero-Dependency & Path-Traversal Safe)
// ============================================================================

async fn serve_static_asset(
    AxumPath((folder, file)): AxumPath<(String, String)>,
) -> Result<Response, AppError> {
    let content_type = match (folder.as_str(), file.as_str()) {
        ("css", "theme.css" | "main.css") => "text/css; charset=utf-8",
        ("js", "app.js" | "crypto.js" | "wormhole.js" | "vault.js" | "ui.js") => {
            "application/javascript; charset=utf-8"
        }
        _ => return Err(AppError::NotFound("asset_not_found")),
    };

    let file_path = format!("static/{}/{}", folder, file);
    let bytes = fs::read(&file_path)
        .await
        .map_err(|_| AppError::NotFound("asset_not_found"))?;

    let mut resp = Response::new(Body::from(bytes));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(content_type),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    );
    Ok(resp)
}

// ============================================================================
// LITESTREAM REPLICATION SUPERVISOR (SECRET-FREE CONFIG GENERATION)
// ============================================================================

async fn init_litestream_and_restore(
    db_url: &str,
    account_id: &str,
    bucket: &str,
    access_key: &str,
    secret_key: &str,
) -> Option<PathBuf> {
    let enabled = env::var("LITESTREAM_ENABLED")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    if !enabled {
        return None;
    }

    let db_path = db_url
        .strip_prefix("sqlite://")
        .or_else(|| db_url.strip_prefix("sqlite:"))
        .unwrap_or("kura.db")
        .split('?')
        .next()
        .unwrap_or("kura.db");

    if db_path == ":memory:" {
        return None;
    }

    let bin = env::var("LITESTREAM_BIN").unwrap_or_else(|_| "litestream".into());
    if Command::new(&bin)
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return None;
    }

    // Security Hardening: Never write R2 secret keys to disk; pass credentials exclusively via process env
    let cfg_path = PathBuf::from(TMP_DIR).join("litestream.yml");
    let yml = format!(
        r#"dbs:
  - path: "{db_path}"
    replicas:
      - type: s3
        bucket: "{bucket}"
        path: "litestream/kura.db"
        endpoint: "https://{account_id}.r2.cloudflarestorage.com"
        region: "auto"
        force-path-style: true
        sync-interval: 1s
"#
    );

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    if let Ok(mut f) = opts.open(&cfg_path).await {
        let _ = f.write_all(yml.as_bytes()).await;
        let _ = f.flush().await;
    } else {
        return None;
    }

    if !Path::new(db_path).exists() {
        let cfg_str = cfg_path.to_string_lossy().to_string();
        let db_owned = db_path.to_string();
        let ak_owned = access_key.to_string();
        let sk_owned = secret_key.to_string();

        let status = tokio::task::spawn_blocking(move || {
            Command::new(&bin)
                .env("LITESTREAM_ACCESS_KEY_ID", &ak_owned)
                .env("LITESTREAM_SECRET_ACCESS_KEY", &sk_owned)
                .args([
                    "restore",
                    "-if-db-not-exists",
                    "-if-replica-exists",
                    "-config",
                    &cfg_str,
                    &db_owned,
                ])
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
        })
        .await;

        if let Ok(Ok(st)) = status {
            if st.success() {
                println!(
                    "ts={} level=info event=litestream.restore.ok db={}",
                    current_unix_timestamp(),
                    db_path
                );
            }
        }
    }

    Some(cfg_path)
}

fn spawn_litestream_replicate(
    cfg_path: Option<&Path>,
    access_key: &str,
    secret_key: &str,
) -> Option<Child> {
    let cfg = cfg_path?;
    let bin = env::var("LITESTREAM_BIN").unwrap_or_else(|_| "litestream".into());
    match Command::new(bin)
        .env("LITESTREAM_ACCESS_KEY_ID", access_key)
        .env("LITESTREAM_SECRET_ACCESS_KEY", secret_key)
        .args(["replicate", "-config", &cfg.to_string_lossy()])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(child) => {
            println!(
                "ts={} level=info event=litestream.replicate.started pid={}",
                current_unix_timestamp(),
                child.id()
            );
            Some(child)
        }
        Err(_) => None,
    }
}

// ============================================================================
// DATABASE INITIALIZATION & SCHEMA MIGRATION
// ============================================================================

async fn initialize_and_migrate_schema(db: &Pool<Sqlite>) -> Result<(), sqlx::Error> {
    let mut conn = db.acquire().await?;

    sqlx::query(
        r#"
    CREATE TABLE IF NOT EXISTS files (
      slug TEXT PRIMARY KEY,
      hash TEXT NOT NULL,
      filename TEXT NOT NULL,
      content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
      size INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER,
      unlock_at INTEGER,
      burn_after_read INTEGER NOT NULL DEFAULT 0,
      password_salt BLOB,
      password_hash BLOB,
      duress_salt BLOB,
      duress_hash BLOB,
      e2ee INTEGER NOT NULL DEFAULT 0,
      shamir_threshold INTEGER,
      server_dek_nonce BLOB,
      server_wrapped_dek BLOB,
      views INTEGER NOT NULL DEFAULT 0,
      max_views INTEGER,
      last_accessed_at INTEGER,
      last_country TEXT,
      delete_token_hash BLOB,
      album_id TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_files_hash ON files(hash);
    CREATE INDEX IF NOT EXISTS idx_files_filename ON files(filename);

    CREATE TABLE IF NOT EXISTS blacklist (
      hash TEXT PRIMARY KEY,
      reason TEXT
    );

    CREATE TABLE IF NOT EXISTS album_stats (
      album_id TEXT PRIMARY KEY,
      zip_downloads INTEGER NOT NULL DEFAULT 0,
      max_zip_downloads INTEGER NOT NULL DEFAULT 25,
      last_download_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS upload_sessions (
      session_id TEXT PRIMARY KEY,
      file_hash TEXT NOT NULL,
      total_size INTEGER NOT NULL,
      part_size INTEGER NOT NULL,
      total_parts INTEGER NOT NULL,
      completed_parts TEXT NOT NULL DEFAULT '',
      ext_hint TEXT,
      expiry_header TEXT,
      unlock_at INTEGER,
      password_salt BLOB,
      password_hash BLOB,
      duress_salt BLOB,
      duress_hash BLOB,
      e2ee INTEGER NOT NULL DEFAULT 0,
      album_id TEXT,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_upload_sessions_hash ON upload_sessions(file_hash, total_size);
    CREATE INDEX IF NOT EXISTS idx_upload_sessions_expires ON upload_sessions(expires_at);
    "#,
    )
    .execute(&mut *conn)
    .await?;

    let alter_statements = [
        "ALTER TABLE files ADD COLUMN content_type TEXT NOT NULL DEFAULT 'application/octet-stream'",
        "ALTER TABLE files ADD COLUMN expires_at INTEGER",
        "ALTER TABLE files ADD COLUMN unlock_at INTEGER",
        "ALTER TABLE files ADD COLUMN burn_after_read INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE files ADD COLUMN password_salt BLOB",
        "ALTER TABLE files ADD COLUMN password_hash BLOB",
        "ALTER TABLE files ADD COLUMN duress_salt BLOB",
        "ALTER TABLE files ADD COLUMN duress_hash BLOB",
        "ALTER TABLE files ADD COLUMN e2ee INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE files ADD COLUMN shamir_threshold INTEGER",
        "ALTER TABLE files ADD COLUMN server_dek_nonce BLOB",
        "ALTER TABLE files ADD COLUMN server_wrapped_dek BLOB",
        "ALTER TABLE files ADD COLUMN views INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE files ADD COLUMN max_views INTEGER",
        "ALTER TABLE files ADD COLUMN last_accessed_at INTEGER",
        "ALTER TABLE files ADD COLUMN last_country TEXT",
        "ALTER TABLE files ADD COLUMN delete_token_hash BLOB",
        "ALTER TABLE files ADD COLUMN album_id TEXT",
        "ALTER TABLE upload_sessions ADD COLUMN unlock_at INTEGER",
    ];
    for stmt in alter_statements {
        let _ = sqlx::query(stmt).execute(&mut *conn).await;
    }

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_files_expires ON files(expires_at) WHERE expires_at IS NOT NULL;",
    )
    .execute(&mut *conn)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_filename ON files(filename);")
        .execute(&mut *conn)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_files_album ON files(album_id) WHERE album_id IS NOT NULL;",
    )
    .execute(&mut *conn)
    .await?;

    for &bad_hash in BUILTIN_BLOCKED_HASHES {
        let _ = sqlx::query(
            "INSERT OR IGNORE INTO blacklist (hash, reason) VALUES (?, 'builtin_signature')",
        )
        .bind(bad_hash)
        .execute(&mut *conn)
        .await;
    }

    Ok(())
}

// ============================================================================
// BACKGROUND REAPER & R2 ORPHAN GARBAGE COLLECTOR
// ============================================================================

async fn reaper_worker(state: Arc<AppState>) {
    let mut ticker = tokio::time::interval(REAPER_INTERVAL);
    let mut ticks = 0u64;

    loop {
        ticker.tick().await;
        ticks = ticks.wrapping_add(1);
        let now = current_unix_timestamp();

        // 1. Reap expired files in bounded batches to avoid long-held SQLite write locks
        let expired_rows = sqlx::query_as::<_, (String, String)>(
            r#"
      DELETE FROM files
      WHERE slug IN (
        SELECT slug FROM files
        WHERE expires_at IS NOT NULL AND expires_at <= ?
        LIMIT ?
      )
      RETURNING filename, hash
      "#,
        )
        .bind(now)
        .bind(REAPER_BATCH_LIMIT)
        .fetch_all(&state.db)
        .await;

        if let Ok(rows) = expired_rows {
            for (filename, hash) in rows {
                safe_delete_r2_if_unreferenced(&state, &filename, &hash).await;
            }
        }

        // 2. Reap expired resumable upload sessions and purge their orphaned chunks in R2
        let expired_sessions = sqlx::query_as::<_, (String, i64)>(
            r#"
      DELETE FROM upload_sessions
      WHERE session_id IN (
        SELECT session_id FROM upload_sessions
        WHERE expires_at <= ?
        LIMIT 50
      )
      RETURNING session_id, total_parts
      "#,
        )
        .bind(now)
        .fetch_all(&state.db)
        .await;

        if let Ok(sessions) = expired_sessions {
            for (sid, total_parts) in sessions {
                let max_p = total_parts.clamp(0, 1000) as usize;
                for p in 1..=max_p {
                    let part_key = format!("kura_upload_sessions/{}/part_{}", sid, p);
                    let _ = state.storage.delete(&part_key).await;
                }
            }
        }

        // 3. Evict expired WebRTC Wormhole signaling rooms and wake any blocked long-pollers
        if let Ok(mut rooms) = state.wormhole_rooms.lock() {
            rooms.retain(|_, room| {
                let alive = now.saturating_sub(room.created_at) < WORMHOLE_ROOM_TTL;
                if !alive {
                    room.notify.notify_waiters();
                }
                alive
            });
        }

        // 4. Periodic maintenance: prune orphaned album_stats & run passive WAL checkpoint
        if ticks % 10 == 0 {
            let _ = sqlx::query(
                "DELETE FROM album_stats WHERE album_id NOT IN (SELECT DISTINCT album_id FROM files WHERE album_id IS NOT NULL);",
            )
            .execute(&state.db)
            .await;

            let _ = sqlx::query("PRAGMA wal_checkpoint(PASSIVE);")
                .execute(&state.db)
                .await;
        }
    }
}

// ============================================================================
// SYSTEM, POW & CLI UTILITY ENDPOINTS
// ============================================================================

async fn serve_index(State(state): State<Arc<AppState>>) -> Html<Bytes> {
    Html(state.index_html.clone())
}

async fn health_check() -> &'static str {
    "ok\n"
}

async fn issue_pow_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !state.rate_limiter.check_and_increment(&peer_addr, &headers) {
        return Err(AppError::TooManyRequests("rate_limit_exceeded"));
    }

    let challenge = state.rate_limiter.issue_pow_challenge(&peer_addr, &headers);
    let json = format!(
        r#"{{"challenge":"{}","difficulty":{},"ttl":{}}}"#,
        challenge, POW_DIFFICULTY_BITS, POW_TTL_SECS
    );
    let mut resp = Response::new(Body::from(format!("{}\n", json)));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    Ok(resp)
}

async fn serve_cli_script(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let origin = resolve_request_origin(
        &peer_addr,
        &headers,
        state.app_origin.as_deref(),
        &state.public_url,
    );
    let script = format!(
        r#"#!/usr/bin/env sh
# kura — Minimalist Anonymous Vault CLI
set -eu
KURA_HOST="${{KURA_HOST:-{origin}}}"
EXPIRE="${{KURA_EXPIRE:-never}}"
PASS="${{KURA_PASSWORD:-}}"
DURESS="${{KURA_DURESS:-}}"
TIMELOCK="${{KURA_TIMELOCK:-}}"
FILE=""

usage() {{
  echo "Usage: kura [-e 1h|24h|7d|1v|5v|10v] [-t 1h|24h] [-p pass] [-d duress_pass] <file | ->" >&2
  exit 1
}}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -e|--expire) EXPIRE="$2"; shift 2 ;;
    -t|--timelock) TIMELOCK="$2"; shift 2 ;;
    -p|--password) PASS="$2"; shift 2 ;;
    -d|--duress) DURESS="$2"; shift 2 ;;
    -h|--help) usage ;;
    --) shift; FILE="${{1:-}}"; break ;;
    *) FILE="$1"; shift ;;
  esac
done

if [ -z "$FILE" ] && [ ! -t 0 ]; then
  FILE="-"
fi
[ -z "$FILE" ] && usage

if [ "$FILE" = "-" ]; then
  curl -sS --fail-with-body -X PUT \
    -H "X-Kura-Expire: $EXPIRE" \
    -H "X-Kura-Timelock: $TIMELOCK" \
    -H "X-Kura-Password: $PASS" \
    -H "X-Kura-Duress-Password: $DURESS" \
    --data-binary @- "$KURA_HOST/upload/stdin.txt"
else
  [ ! -f "$FILE" ] && {{ echo "Error: file not found: $FILE" >&2; exit 1; }}
  SHA=$(sha256sum -- "$FILE" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 -- "$FILE" | cut -d' ' -f1)
  BNAME=$(basename -- "$FILE" | tr -cd 'a-zA-Z0-9._-')
  [ -z "$BNAME" ] && BNAME="payload.bin"
  curl -sS --fail-with-body -X PUT \
    -H "X-Content-Sha256: $SHA" \
    -H "X-Kura-Expire: $EXPIRE" \
    -H "X-Kura-Timelock: $TIMELOCK" \
    -H "X-Kura-Password: $PASS" \
    -H "X-Kura-Duress-Password: $DURESS" \
    --data-binary @"$FILE" "$KURA_HOST/upload/$BNAME"
fi
"#
    );

    let mut resp = Response::new(Body::from(script));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/x-shellscript; charset=utf-8"),
    );
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    resp.into_response()
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    println!(
        "ts={} level=info event=server.shutdown",
        current_unix_timestamp()
    );
}