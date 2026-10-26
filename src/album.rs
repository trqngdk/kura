use axum::{
  body::{Body, Bytes},
  extract::{ConnectInfo, Path as AxumPath, State},
  http::{header, HeaderMap, HeaderValue},
  response::{Html, Response},
};
use sqlx::Row;
use std::{collections::BTreeSet, net::SocketAddr, sync::Arc};
use tokio::time::timeout;

use crate::{config::*, crypto::*, limiter::ZipActorGuard};

// ============================================================================
// PKWARE ZIP STREAMING CONSTANTS & SECURITY LIMITS
// ============================================================================

/// Maximum number of distinct files allowed in a single album
const MAX_ALBUM_FILES: usize = 100;
/// Maximum number of slugs accepted in a single album creation request
const MAX_CREATE_ALBUM_SLUGS: usize = 50;
/// Standard MS-DOS date/time stamp (2024-01-01 00:00:00) for strict archive utility compatibility
const DOS_DEFAULT_TIME: u16 = 0x0000;
const DOS_DEFAULT_DATE: u16 = 0x5821;

/// Shared client-side panic handler (double-tap Escape to wipe browser state and redirect)
const PANIC_ESCAPE_JS: &str = r#"
const panicEscape = () => {
  try { localStorage.clear(); sessionStorage.clear(); navigator.clipboard.writeText(''); } catch (_) {}
  document.body.innerHTML = '';
  window.location.replace('https://en.wikipedia.org/wiki/Special:Random');
};
document.getElementById('panic-btn').onclick = panicEscape;
let lastEsc = 0;
window.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const now = Date.now();
    if (now - lastEsc < 400) panicEscape();
    lastEsc = now;
  }
});
"#;

/// Validates an album identifier parameter
#[inline]
fn validate_album_id(album_id: &str) -> Result<(), AppError> {
  if album_id.len() < 4
    || album_id.len() > 24
    || !album_id.bytes().all(|b| b.is_ascii_alphanumeric())
  {
    return Err(AppError::NotFound("invalid_album_id"));
  }
  Ok(())
}

/// Extracts a clean alphanumeric file extension from an R2 storage key
#[inline]
fn extract_clean_ext(r2_key: &str) -> &str {
  let ext = r2_key.rsplit('.').next().unwrap_or("bin");
  if !ext.is_empty() && ext.len() <= 12 && ext.bytes().all(|b| b.is_ascii_alphanumeric()) {
    ext
  } else {
    "bin"
  }
}

// ============================================================================
// ALBUM CREATION, VIEWING & STREAMING ZIP ARCHIVE HANDLERS
// ============================================================================

pub async fn create_album_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  body: String,
) -> Result<String, AppError> {
  if !state.rate_limiter.check_and_increment(&peer_addr, &headers) {
    return Err(AppError::TooManyRequests("rate_limit_exceeded"));
  }

  if body.len() > 8192 {
    return Err(AppError::PayloadTooLarge("album_request_too_large"));
  }

  // Deduplicate and validate 8-character alphanumeric slugs in deterministic order
  let mut unique_slugs = BTreeSet::new();
  for token in body.split(|c: char| !c.is_ascii_alphanumeric()) {
    if token.len() == SLUG_LENGTH {
      unique_slugs.insert(token);
      if unique_slugs.len() >= MAX_CREATE_ALBUM_SLUGS {
        break;
      }
    }
  }

  if unique_slugs.is_empty() {
    return Err(AppError::BadRequest("no_valid_slugs_provided"));
  }

  let now = current_unix_timestamp();
  let album_id = generate_random_string(ALBUM_ID_LENGTH);
  let mut updated = 0u64;

  // Execute all file bindings within a single atomic SQLite transaction to eliminate WAL lock contention
  let mut tx = state.db.begin().await?;

  // IDOR & Quota-Bypass Mitigation:
  // Only bind public, non-expired, unencrypted, view-unrestricted files that do not already belong to an album
  for slug in unique_slugs {
    let res = sqlx::query(
      r#"
      UPDATE files
      SET album_id = ?
      WHERE slug = ?
        AND album_id IS NULL
        AND (expires_at IS NULL OR expires_at > ?)
        AND unlock_at IS NULL
        AND burn_after_read = 0
        AND max_views IS NULL
        AND password_hash IS NULL
        AND duress_hash IS NULL
        AND e2ee = 0
        AND server_wrapped_dek IS NULL
      "#,
    )
    .bind(&album_id)
    .bind(slug)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    updated += res.rows_affected();
  }

  if updated == 0 {
    let _ = tx.rollback().await;
    return Err(AppError::NotFound("no_matching_public_files_found"));
  }

  sqlx::query(
    "INSERT OR IGNORE INTO album_stats (album_id, zip_downloads, max_zip_downloads) VALUES (?, 0, ?)",
  )
  .bind(&album_id)
  .bind(MAX_ALBUM_ZIP_DOWNLOADS)
  .execute(&mut *tx)
  .await?;

  tx.commit().await?;

  let origin = resolve_request_origin(
    &peer_addr,
    &headers,
    state.app_origin.as_deref(),
    &state.public_url,
  );
  Ok(format!("{}/a/{}\n", origin, album_id))
}

pub async fn view_album_handler(
  State(state): State<Arc<AppState>>,
  AxumPath(album_id): AxumPath<String>,
) -> Result<Html<String>, AppError> {
  validate_album_id(&album_id)?;

  let now = current_unix_timestamp();
  let rows = sqlx::query(
    r#"
    SELECT slug, filename, size, burn_after_read, password_hash, duress_hash, e2ee, server_wrapped_dek
    FROM files
    WHERE album_id = ?
      AND (expires_at IS NULL OR expires_at > ?)
      AND (max_views IS NULL OR views < max_views)
    ORDER BY created_at ASC
    LIMIT ?
    "#,
  )
  .bind(&album_id)
  .bind(now)
  .bind(MAX_ALBUM_FILES as i64)
  .fetch_all(&state.db)
  .await?;

  if rows.is_empty() {
    return Err(AppError::NotFound("album_empty_or_expired"));
  }

  let mut total_bytes = 0i64;
  let mut list_html = String::with_capacity(rows.len() * 128);

  for row in &rows {
    let slug: String = row.get("slug");
    let filename: String = row.get("filename");
    let size: i64 = row.get("size");
    let burn: i64 = row.get("burn_after_read");
    let pw: Option<Vec<u8>> = row.get("password_hash");
    let duress: Option<Vec<u8>> = row.get("duress_hash");
    let e2ee: i64 = row.get("e2ee");
    let wrapped_dek: Option<Vec<u8>> = row.get("server_wrapped_dek");
    total_bytes = total_bytes.saturating_add(size.max(0));

    let ext = extract_clean_ext(&filename);
    let display = format!("{}.{}", slug, ext);

    // Route all links through the application domain to keep underlying R2 bucket URLs hidden
    let is_gated = burn == 1
      || pw.is_some()
      || duress.is_some()
      || e2ee == 1
      || wrapped_dek.is_some()
      || ext == "note"
      || filename.starts_with("vault/");

    let href = if is_gated {
      format!("/v/{}", display)
    } else {
      format!("/{}", display)
    };

    list_html.push_str(&format!(
      r#"<div class="row"><a href="{href}" target="_blank" rel="noopener">{display}</a><span>{size} B</span></div>"#
    ));
  }

  let html = format!(
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Album {album_id} — kura — 蔵</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:#080808;color:#efefef;font-family:"JetBrains Mono",Consolas,monospace;min-height:100vh;display:flex;justify-content:center;align-items:center;padding:2rem 1rem;}}
.card{{width:100%;max-width:600px;background:#0d0d0d;border:1px solid #222;}}
.head{{display:flex;justify-content:space-between;align-items:center;padding:0.9rem 1.25rem;border-bottom:1px solid #222;background:#121212;font-size:0.8rem;gap:0.5rem;flex-wrap:wrap;}}
.row{{display:flex;justify-content:space-between;padding:0.75rem 1.25rem;border-bottom:1px solid #222;font-size:0.75rem;}}
.row:last-child{{border-bottom:none;}}
.row a{{color:#efefef;text-decoration:none;}}
.row a:hover{{text-decoration:underline;}}
.row span{{color:#8a8a8a;}}
.btn{{background:#efefef;color:#080808;text-decoration:none;font-size:0.7rem;font-weight:600;padding:0.3rem 0.7rem;border:none;cursor:pointer;}}
.panic{{background:transparent;color:#525252;border:1px solid #222;font-family:inherit;font-size:0.65rem;padding:0.25rem 0.5rem;cursor:pointer;}}
.panic:hover{{color:#fff;background:#ef4444;border-color:#ef4444;}}
</style>
</head>
<body>
<div class="card">
<div class="head">
<span>Album · {album_id} ({count} files · {total_bytes} B)</span>
<div style="display:flex;gap:0.4rem;">
<a class="btn" href="/a/{album_id}/zip">Download .zip</a>
<button type="button" class="panic" id="panic-btn">ESC×2</button>
</div>
</div>
{list_html}
</div>
<script>
{PANIC_ESCAPE_JS}
</script>
</body>
</html>"#,
    count = rows.len()
  );

  Ok(Html(html))
}

pub async fn stream_album_zip_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  AxumPath(album_id): AxumPath<String>,
) -> Result<Response, AppError> {
  validate_album_id(&album_id)?;

  if !state.rate_limiter.check_and_increment(&peer_addr, &headers) {
    return Err(AppError::TooManyRequests("rate_limit_exceeded"));
  }

  let actor_zip_guard = ZipActorGuard::try_acquire(state.rate_limiter.clone(), &peer_addr, &headers)
    .ok_or(AppError::TooManyRequests("concurrent_zip_stream_active"))?;

  let zip_permit = state
    .zip_semaphore
    .clone()
    .try_acquire_owned()
    .map_err(|_| AppError::TooManyRequests("zip_workers_busy"))?;

  let download_permit = state
    .download_semaphore
    .clone()
    .try_acquire_owned()
    .map_err(|_| AppError::TooManyRequests("server_busy_try_again"))?;

  let now = current_unix_timestamp();

  // Query eligible public files FIRST before consuming the album's ZIP download quota
  let rows = sqlx::query(
    r#"
    SELECT slug, filename, size
    FROM files
    WHERE album_id = ?
      AND (expires_at IS NULL OR expires_at > ?)
      AND (unlock_at IS NULL OR unlock_at <= ?)
      AND burn_after_read = 0
      AND max_views IS NULL
      AND password_hash IS NULL
      AND duress_hash IS NULL
      AND e2ee = 0
      AND server_wrapped_dek IS NULL
    ORDER BY created_at ASC
    LIMIT ?
    "#,
  )
  .bind(&album_id)
  .bind(now)
  .bind(now)
  .bind(MAX_ALBUM_FILES as i64)
  .fetch_all(&state.db)
  .await?;

  if rows.is_empty() {
    return Err(AppError::NotFound("no_public_files_in_album"));
  }

  let _ = sqlx::query(
    "INSERT OR IGNORE INTO album_stats (album_id, zip_downloads, max_zip_downloads) VALUES (?, 0, ?)",
  )
  .bind(&album_id)
  .bind(MAX_ALBUM_ZIP_DOWNLOADS)
  .execute(&state.db)
  .await;

  let quota_claimed = sqlx::query_scalar::<_, i64>(
    r#"
    UPDATE album_stats
    SET zip_downloads = zip_downloads + 1, last_download_at = ?
    WHERE album_id = ? AND zip_downloads < max_zip_downloads
    RETURNING zip_downloads
    "#,
  )
  .bind(now)
  .bind(&album_id)
  .fetch_optional(&state.db)
  .await?;

  if quota_claimed.is_none() {
    return Err(AppError::TooManyRequests("album_zip_quota_exhausted"));
  }

  let entries: Vec<(String, String, u64)> = rows
    .into_iter()
    .map(|r| {
      let slug: String = r.get("slug");
      let r2_key: String = r.get("filename");
      let size: i64 = r.get("size");
      let ext = extract_clean_ext(&r2_key);
      (format!("{}.{}", slug, ext), r2_key, size.max(0) as u64)
    })
    .collect();

  let storage = state.storage.clone();
  let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);

  tokio::spawn(async move {
    let _actor_guard = actor_zip_guard;
    let _zip_permit = zip_permit;
    let _dl_permit = download_permit;

    let mut central_dir = Vec::with_capacity(entries.len() * 64 + 128);
    let mut offset = 0u64;
    let mut written_entries = 0u16;

    for (zip_name, r2_key, file_size) in entries {
      if file_size > u32::MAX as u64 {
        continue;
      }
      // Prevent standard 32-bit ZIP offset overflow by capping stream before 4 GiB boundary
      if offset.saturating_add(file_size).saturating_add(128) > u32::MAX as u64 {
        break;
      }

      let Ok(reader) = storage.reader(&r2_key).await else {
        continue;
      };

      let name_bytes = zip_name.as_bytes();
      let local_header_offset = offset as u32;

      // Build 30-byte Local File Header + filename without intermediate heap re-allocations
      let mut lfh = Vec::with_capacity(30 + name_bytes.len());
      lfh.extend_from_slice(&0x04034b50u32.to_le_bytes()); // Local file header signature
      lfh.extend_from_slice(&20u16.to_le_bytes()); // Version needed to extract (2.0)
      lfh.extend_from_slice(&0x0808u16.to_le_bytes()); // Flags: Bit 3 (Data Descriptor) + Bit 11 (UTF-8)
      lfh.extend_from_slice(&0u16.to_le_bytes()); // Compression method: 0 (STORE)
      lfh.extend_from_slice(&DOS_DEFAULT_TIME.to_le_bytes());
      lfh.extend_from_slice(&DOS_DEFAULT_DATE.to_le_bytes());
      lfh.extend_from_slice(&0u32.to_le_bytes()); // CRC-32 deferred to Data Descriptor
      lfh.extend_from_slice(&0u32.to_le_bytes()); // Compressed size deferred
      lfh.extend_from_slice(&0u32.to_le_bytes()); // Uncompressed size deferred
      lfh.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
      lfh.extend_from_slice(&0u16.to_le_bytes()); // Extra field length
      lfh.extend_from_slice(name_bytes);

      offset = offset.saturating_add(lfh.len() as u64);
      if tx.send(Ok(Bytes::from(lfh))).await.is_err() {
        return;
      }

      let mut crc = 0xFFFF_FFFFu32;
      let mut read_offset = 0u64;
      let mut remaining = file_size as usize;

      while remaining > 0 {
        let chunk_len = remaining.min(DISK_BUFFER_SIZE);
        match timeout(
          CHUNK_READ_TIMEOUT,
          reader.read(read_offset..read_offset + chunk_len as u64),
        )
        .await
        {
          Ok(Ok(buf)) => {
            let b = buf.to_bytes();
            if b.is_empty() {
              break;
            }
            crc = crc32_update(crc, &b);
            read_offset += b.len() as u64;
            remaining = remaining.saturating_sub(b.len());
            offset = offset.saturating_add(b.len() as u64);
            if tx.send(Ok(b)).await.is_err() {
              return;
            }
          }
          _ => return,
        }
      }

      let final_crc = !crc;
      let actual_size = read_offset as u32;

      let mut dd = [0u8; 16];
      dd[0..4].copy_from_slice(&0x08074b50u32.to_le_bytes()); // Data descriptor signature
      dd[4..8].copy_from_slice(&final_crc.to_le_bytes());
      dd[8..12].copy_from_slice(&actual_size.to_le_bytes());
      dd[12..16].copy_from_slice(&actual_size.to_le_bytes());
      offset = offset.saturating_add(16);
      if tx.send(Ok(Bytes::copy_from_slice(&dd))).await.is_err() {
        return;
      }

      // Append Central Directory File Header
      central_dir.extend_from_slice(&0x02014b50u32.to_le_bytes()); // Central directory signature
      central_dir.extend_from_slice(&20u16.to_le_bytes()); // Version made by
      central_dir.extend_from_slice(&20u16.to_le_bytes()); // Version needed to extract
      central_dir.extend_from_slice(&0x0808u16.to_le_bytes()); // Flags: Data Descriptor + UTF-8
      central_dir.extend_from_slice(&0u16.to_le_bytes()); // Compression method: STORE
      central_dir.extend_from_slice(&DOS_DEFAULT_TIME.to_le_bytes());
      central_dir.extend_from_slice(&DOS_DEFAULT_DATE.to_le_bytes());
      central_dir.extend_from_slice(&final_crc.to_le_bytes());
      central_dir.extend_from_slice(&actual_size.to_le_bytes());
      central_dir.extend_from_slice(&actual_size.to_le_bytes());
      central_dir.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
      central_dir.extend_from_slice(&0u16.to_le_bytes()); // Extra field length
      central_dir.extend_from_slice(&0u16.to_le_bytes()); // File comment length
      central_dir.extend_from_slice(&0u16.to_le_bytes()); // Disk number start
      central_dir.extend_from_slice(&0u16.to_le_bytes()); // Internal file attributes
      central_dir.extend_from_slice(&0u32.to_le_bytes()); // External file attributes
      central_dir.extend_from_slice(&local_header_offset.to_le_bytes());
      central_dir.extend_from_slice(name_bytes);

      written_entries = written_entries.saturating_add(1);
    }

    let cd_offset = offset as u32;
    let cd_size = central_dir.len() as u32;

    // Append End of Central Directory (EOCD) record using exact `written_entries` counter
    central_dir.extend_from_slice(&0x06054b50u32.to_le_bytes());
    central_dir.extend_from_slice(&0u16.to_le_bytes()); // Number of this disk
    central_dir.extend_from_slice(&0u16.to_le_bytes()); // Disk where central directory starts
    central_dir.extend_from_slice(&written_entries.to_le_bytes());
    central_dir.extend_from_slice(&written_entries.to_le_bytes());
    central_dir.extend_from_slice(&cd_size.to_le_bytes());
    central_dir.extend_from_slice(&cd_offset.to_le_bytes());
    central_dir.extend_from_slice(&0u16.to_le_bytes()); // Archive comment length

    let _ = tx.send(Ok(Bytes::from(central_dir))).await;
  });

  let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
  let mut resp = Response::new(body);
  let headers = resp.headers_mut();
  headers.insert(
    header::CONTENT_TYPE,
    HeaderValue::from_static("application/zip"),
  );
  headers.insert(
    header::CACHE_CONTROL,
    HeaderValue::from_static("private, no-store"),
  );
  if let Ok(cd) = HeaderValue::from_str(&format!("attachment; filename=\"kura_{}.zip\"", album_id))
  {
    headers.insert(header::CONTENT_DISPOSITION, cd);
  }
  Ok(resp)
}