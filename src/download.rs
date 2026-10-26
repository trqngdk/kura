use axum::{
  body::{Body, Bytes},
  extract::{ConnectInfo, Form, Path as AxumPath, Query, State},
  http::{header, HeaderMap, HeaderValue, StatusCode},
  response::{Html, IntoResponse, Response},
};
use sqlx::Row;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::time::timeout;

use crate::{config::*, crypto::*};

// ============================================================================
// CORE HELPERS & ATOMIC SECURITY PRIMITIVES
// ============================================================================

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

/// Sanitizes an untrusted path parameter into a safe alphanumeric identifier for HTML/header rendering
#[inline]
fn sanitize_display_id(raw_id: &str) -> String {
  raw_id
    .chars()
    .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
    .collect()
}

/// Escapes special characters in a string for safe manual JSON embedding
#[inline]
fn escape_json_str(s: &str) -> String {
  s.chars()
    .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
    .collect()
}

/// Deletes the underlying R2 object only if no active database records reference it
pub async fn safe_delete_r2_if_unreferenced(state: &AppState, filename: &str, _hash: &str) {
  let remaining = sqlx::query_scalar::<_, i64>(
    "SELECT COUNT(*) FROM files WHERE filename = ?",
  )
  .bind(filename)
  .fetch_one(&state.db)
  .await
  .unwrap_or(0);

  if remaining == 0 {
    let _ = state.storage.delete(filename).await;
  }
}

/// Atomically deletes a file record from SQLite and purges its R2 object if unreferenced
async fn purge_file_record(state: &AppState, slug: &str, filename: &str, file_hash: &str) {
  let _ = sqlx::query("DELETE FROM files WHERE slug = ?")
    .bind(slug)
    .execute(&state.db)
    .await;
  safe_delete_r2_if_unreferenced(state, filename, file_hash).await;
}

/// Validated metadata record for a gated vault file
struct VaultFileRecord {
  slug: String,
  file_hash: String,
  filename: String,
  content_type: String,
  size: i64,
  burn_after_read: bool,
  pw_salt: Option<Vec<u8>>,
  pw_hash: Option<Vec<u8>>,
  duress_salt: Option<Vec<u8>>,
  duress_hash: Option<Vec<u8>>,
  is_e2ee: bool,
  dek_nonce: Option<Vec<u8>>,
  dek_wrapped: Option<Vec<u8>>,
  max_views: Option<i64>,
}

impl VaultFileRecord {
  #[inline]
  fn requires_password(&self) -> bool {
    self.pw_hash.is_some() || self.duress_hash.is_some()
  }

  /// Unwraps the server-side envelope DEK if present
  fn unwrap_dek(&self, boot_secret: &[u8; 32]) -> Result<Option<([u8; 32], [u8; 12])>, AppError> {
    match (self.dek_nonce.as_deref(), self.dek_wrapped.as_deref()) {
      (Some(n), Some(w)) => {
        let dek = unwrap_server_dek(boot_secret, &self.slug, n, w)
          .ok_or(AppError::Gone("envelope_dek_shredded_or_corrupted"))?;
        Ok(Some(dek))
      }
      _ => Ok(None),
    }
  }
}

/// Fetches a file record by slug and enforces TTL expiration and time-lock constraints
async fn load_and_validate_vault_file(
  state: &AppState,
  slug: &str,
  run_shield_on_miss: bool,
) -> Result<VaultFileRecord, AppError> {
  let row_opt = sqlx::query(
    r#"
    SELECT slug, hash, filename, content_type, size, expires_at, unlock_at, burn_after_read,
           password_salt, password_hash, duress_salt, duress_hash, e2ee,
           server_dek_nonce, server_wrapped_dek, max_views
    FROM files WHERE slug = ? LIMIT 1
    "#,
  )
  .bind(slug)
  .fetch_optional(&state.db)
  .await?;

  let Some(row) = row_opt else {
    if run_shield_on_miss {
      run_timing_shield(state, slug).await;
    }
    return Err(AppError::NotFound("file_not_found_or_expired"));
  };

  let now = current_unix_timestamp();
  let expires_at: Option<i64> = row.get("expires_at");
  let unlock_at: Option<i64> = row.get("unlock_at");
  let filename: String = row.get("filename");
  let file_hash: String = row.get("hash");

  if let Some(exp) = expires_at {
    if now >= exp {
      purge_file_record(state, slug, &filename, &file_hash).await;
      if run_shield_on_miss {
        run_timing_shield(state, slug).await;
      }
      return Err(AppError::NotFound("file_not_found_or_expired"));
    }
  }

  if let Some(unlock_ts) = unlock_at {
    if now < unlock_ts {
      return Err(AppError::Locked(format!(
        "time_locked_until_unix_{} ({}s remaining)",
        unlock_ts,
        unlock_ts - now
      )));
    }
  }

  Ok(VaultFileRecord {
    slug: row.get("slug"),
    file_hash,
    filename,
    content_type: row.get("content_type"),
    size: row.get("size"),
    burn_after_read: row.get::<i64, _>("burn_after_read") == 1,
    pw_salt: row.get("password_salt"),
    pw_hash: row.get("password_hash"),
    duress_salt: row.get("duress_salt"),
    duress_hash: row.get("duress_hash"),
    is_e2ee: row.get::<i64, _>("e2ee") == 1,
    dek_nonce: row.get("server_dek_nonce"),
    dek_wrapped: row.get("server_wrapped_dek"),
    max_views: row.get("max_views"),
  })
}

/// Evaluates primary and duress passwords under concurrency semaphore protection
async fn verify_gate_password(
  state: &AppState,
  record: &VaultFileRecord,
  supplied_pw: &[u8],
) -> Result<AuthOutcome, AppError> {
  let _auth_permit = state
    .auth_semaphore
    .acquire()
    .await
    .map_err(|_| AppError::Internal("auth_semaphore_closed".into()))?;

  let pw_owned = supplied_pw.to_vec();
  let pw_salt = record.pw_salt.clone();
  let pw_hash = record.pw_hash.clone();
  let duress_salt = record.duress_salt.clone();
  let duress_hash = record.duress_hash.clone();

  let outcome = tokio::task::spawn_blocking(move || {
    evaluate_password_or_duress(
      &pw_owned,
      pw_salt.as_deref(),
      pw_hash.as_deref(),
      duress_salt.as_deref(),
      duress_hash.as_deref(),
    )
  })
  .await
  .map_err(|_| AppError::Internal("pbkdf_worker_panicked".into()))?;

  if outcome == AuthOutcome::DuressTriggered {
    purge_file_record(state, &record.slug, &record.filename, &record.file_hash).await;
  }

  Ok(outcome)
}

// ============================================================================
// HTTP ROUTE HANDLERS
// ============================================================================

pub async fn delete_file_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  AxumPath(raw_id): AxumPath<String>,
  Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
  if !state.rate_limiter.check_and_increment(&peer_addr, &headers) {
    return Err(AppError::TooManyRequests("rate_limit_exceeded"));
  }

  let slug = extract_slug_from_path(&raw_id)?;
  let supplied_key = headers
    .get("x-kura-delete-key")
    .and_then(|v| v.to_str().ok())
    .or_else(|| params.get("delete_key").map(|s| s.as_str()))
    .map(|s| s.trim())
    .filter(|s| !s.is_empty())
    .ok_or(AppError::Unauthorized("missing_delete_key"))?;

  let row_opt = sqlx::query(
    "SELECT filename, hash, delete_token_hash FROM files WHERE slug = ? LIMIT 1",
  )
  .bind(slug)
  .fetch_optional(&state.db)
  .await?;

  let Some(row) = row_opt else {
    let _ = verify_delete_key(supplied_key.as_bytes(), &[0u8; 32]);
    return Err(AppError::NotFound("file_not_found"));
  };

  let stored_hash: Option<Vec<u8>> = row.get("delete_token_hash");
  let Some(expected_hash) = stored_hash else {
    return Err(AppError::Forbidden("file_has_no_delete_key"));
  };

  if !verify_delete_key(supplied_key.as_bytes(), &expected_hash) {
    return Err(AppError::Unauthorized("invalid_delete_key"));
  }

  let filename: String = row.get("filename");
  let file_hash: String = row.get("hash");

  purge_file_record(&state, slug, &filename, &file_hash).await;

  Ok((StatusCode::OK, "deleted\n").into_response())
}

pub async fn file_stats_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  AxumPath(raw_id): AxumPath<String>,
) -> Result<Response, AppError> {
  if !state.rate_limiter.check_and_increment(&peer_addr, &headers) {
    return Err(AppError::TooManyRequests("rate_limit_exceeded"));
  }

  let slug = extract_slug_from_path(&raw_id)?;

  let row = sqlx::query(
    r#"
    SELECT slug, filename, hash, content_type, size, created_at, expires_at, unlock_at, burn_after_read,
           password_hash, e2ee, shamir_threshold, views, max_views, last_accessed_at, last_country, album_id
    FROM files WHERE slug = ? LIMIT 1
    "#,
  )
  .bind(slug)
  .fetch_optional(&state.db)
  .await?
  .ok_or(AppError::NotFound("file_not_found_or_expired"))?;

  let now = current_unix_timestamp();
  let expires_at: Option<i64> = row.get("expires_at");
  if let Some(exp) = expires_at {
    if now >= exp {
      let filename: String = row.get("filename");
      let file_hash: String = row.get("hash");
      purge_file_record(&state, slug, &filename, &file_hash).await;
      return Err(AppError::NotFound("file_not_found_or_expired"));
    }
  }

  let content_type: String = row.get("content_type");
  let size: i64 = row.get("size");
  let created_at: i64 = row.get("created_at");
  let unlock_at: Option<i64> = row.get("unlock_at");
  let burn_after_read: i64 = row.get("burn_after_read");
  let pw_hash: Option<Vec<u8>> = row.get("password_hash");
  let e2ee: i64 = row.get("e2ee");
  let shamir_m: Option<i64> = row.get("shamir_threshold");
  let views: i64 = row.get("views");
  let max_views: Option<i64> = row.get("max_views");
  let last_accessed_at: Option<i64> = row.get("last_accessed_at");
  let last_country: Option<String> = row.get("last_country");
  let album_id: Option<String> = row.get("album_id");

  let expires_json = expires_at.map(|v| v.to_string()).unwrap_or_else(|| "null".into());
  let unlock_json = unlock_at.map(|v| v.to_string()).unwrap_or_else(|| "null".into());
  let shamir_json = shamir_m.map(|v| v.to_string()).unwrap_or_else(|| "null".into());
  let max_views_json = max_views.map(|v| v.to_string()).unwrap_or_else(|| "null".into());
  let last_access_json = last_accessed_at.map(|v| v.to_string()).unwrap_or_else(|| "null".into());
  let country_json = last_country
    .map(|c| format!("\"{}\"", escape_json_str(&c)))
    .unwrap_or_else(|| "null".into());
  let album_json = album_id
    .map(|a| format!("\"{}\"", escape_json_str(&a)))
    .unwrap_or_else(|| "null".into());

  let json = format!(
    r#"{{"slug":"{}","size":{},"content_type":"{}","created_at":{},"expires_at":{},"unlock_at":{},"views":{},"max_views":{},"burn_after_read":{},"protected":{},"e2ee":{},"shamir_threshold":{},"last_accessed_at":{},"last_country":{},"album_id":{}}}"#,
    slug,
    size,
    content_type,
    created_at,
    expires_json,
    unlock_json,
    views,
    max_views_json,
    burn_after_read == 1,
    pw_hash.is_some(),
    e2ee == 1,
    shamir_json,
    last_access_json,
    country_json,
    album_json
  );

  let mut resp = Response::new(Body::from(format!("{}\n", json)));
  resp.headers_mut().insert(
    header::CONTENT_TYPE,
    HeaderValue::from_static("application/json; charset=utf-8"),
  );
  resp.headers_mut().insert(
    header::CACHE_CONTROL,
    HeaderValue::from_static("no-store"),
  );
  Ok(resp)
}

pub fn is_link_preview_bot(headers: &HeaderMap) -> bool {
  if let Some(ua) = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()) {
    let lower = ua.to_ascii_lowercase();
    if BOT_USER_AGENTS.iter().any(|&bot| lower.contains(bot)) {
      return true;
    }
  }
  if let Some(purpose) = headers
    .get("purpose")
    .or_else(|| headers.get("x-purpose"))
    .and_then(|v| v.to_str().ok())
  {
    if purpose.eq_ignore_ascii_case("preview") || purpose.eq_ignore_ascii_case("prefetch") {
      return true;
    }
  }
  false
}

pub async fn vault_gate_get(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  AxumPath(raw_id): AxumPath<String>,
  Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
  let slug = extract_slug_from_path(&raw_id)?;

  if is_link_preview_bot(&headers) {
    return Ok(render_gate_html(&raw_id, true, false, false, false).into_response());
  }

  let has_pw_header = headers.contains_key("x-kura-password");
  let record = load_and_validate_vault_file(&state, slug, has_pw_header).await?;

  let wants_raw = params.contains_key("raw") || headers.contains_key("x-kura-raw");
  let is_secret_note = raw_id.ends_with(".note") || record.filename.ends_with(".note");
  let is_browser_navigate = params.contains_key("view")
    || headers
      .get("sec-fetch-mode")
      .and_then(|v| v.to_str().ok())
      .map(|m| m == "navigate")
      .unwrap_or(false);

  if record.requires_password() {
    if let Some(header_pw) = headers.get("x-kura-password").and_then(|v| v.to_str().ok()) {
      if !state.rate_limiter.check_and_increment(&peer_addr, &headers) {
        return Err(AppError::TooManyRequests("rate_limit_exceeded"));
      }
      match verify_gate_password(&state, &record, header_pw.as_bytes()).await? {
        AuthOutcome::DuressTriggered => {
          return Err(AppError::Gone("file_corrupted_or_already_expired"));
        }
        AuthOutcome::Invalid => return Err(AppError::Unauthorized("invalid_password")),
        AuthOutcome::ValidPrimary => {}
      }
    } else {
      return Ok(
        render_gate_html(
          &raw_id,
          record.burn_after_read,
          true,
          record.is_e2ee || is_secret_note,
          false,
        )
        .into_response(),
      );
    }
  } else if (record.is_e2ee || is_secret_note) && !wants_raw {
    return Ok(render_gate_html(&raw_id, record.burn_after_read, false, true, false).into_response());
  } else if record.burn_after_read && !params.contains_key("confirm") && !wants_raw {
    return Ok(render_gate_html(&raw_id, true, false, false, false).into_response());
  }

  if !wants_raw && !record.burn_after_read && !record.is_e2ee && is_browser_navigate {
    if record.content_type.starts_with("text/plain") && record.size <= 2 * 1024 * 1024 {
      return Ok(render_code_viewer_html(&raw_id, record.size).into_response());
    }
    if record.content_type.starts_with("video/") || record.content_type.starts_with("audio/") {
      let is_video = record.content_type.starts_with("video/");
      return Ok(
        render_media_player_html(&raw_id, &record.content_type, record.size, is_video)
          .into_response(),
      );
    }
  }

  let unwrapped_dek = record.unwrap_dek(&state.rate_limiter.boot_secret)?;

  deliver_gated_payload(
    &state,
    &headers,
    &record.slug,
    &raw_id,
    &record.filename,
    &record.file_hash,
    &record.content_type,
    record.size,
    record.burn_after_read,
    0,
    record.max_views,
    record.is_e2ee,
    unwrapped_dek,
  )
  .await
}

pub async fn vault_gate_post(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  AxumPath(raw_id): AxumPath<String>,
  Form(form): Form<HashMap<String, String>>,
) -> Result<Response, AppError> {
  if !state.rate_limiter.check_and_increment(&peer_addr, &headers) {
    return Err(AppError::TooManyRequests("rate_limit_exceeded"));
  }

  let slug = extract_slug_from_path(&raw_id)?;
  let record = load_and_validate_vault_file(&state, slug, true).await?;

  if record.requires_password() {
    let supplied = form.get("password").map(|s| s.as_str()).unwrap_or_default();
    match verify_gate_password(&state, &record, supplied.as_bytes()).await? {
      AuthOutcome::DuressTriggered => {
        let mut resp = render_corrupted_html(&raw_id).into_response();
        *resp.status_mut() = StatusCode::GONE;
        return Ok(resp);
      }
      AuthOutcome::Invalid => {
        let mut resp = render_gate_html(
          &raw_id,
          record.burn_after_read,
          true,
          record.is_e2ee,
          true,
        )
        .into_response();
        *resp.status_mut() = StatusCode::UNAUTHORIZED;
        return Ok(resp);
      }
      AuthOutcome::ValidPrimary => {}
    }
  }

  let unwrapped_dek = record.unwrap_dek(&state.rate_limiter.boot_secret)?;

  deliver_gated_payload(
    &state,
    &headers,
    &record.slug,
    &raw_id,
    &record.filename,
    &record.file_hash,
    &record.content_type,
    record.size,
    record.burn_after_read,
    0,
    record.max_views,
    record.is_e2ee,
    unwrapped_dek,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
pub async fn deliver_gated_payload(
  state: &AppState,
  req_headers: &HeaderMap,
  slug: &str,
  display_name: &str,
  r2_key: &str,
  file_hash: &str,
  content_type: &str,
  size: i64,
  burn_after_read: bool,
  _unused_views: i64,
  max_views: Option<i64>,
  is_e2ee: bool,
  server_dek: Option<([u8; 32], [u8; 12])>,
) -> Result<Response, AppError> {
  let download_permit = state
    .download_semaphore
    .clone()
    .try_acquire_owned()
    .map_err(|_| AppError::TooManyRequests("server_busy_try_again"))?;

  let now = current_unix_timestamp();
  let country = extract_anonymized_country(req_headers);

  // Atomic view counter increment & burn evaluation (eliminates TOCTOU max_views race condition)
  let (next_views, should_burn) = if burn_after_read {
    let claimed = sqlx::query_scalar::<_, i64>(
      "DELETE FROM files WHERE slug = ? RETURNING views + 1",
    )
    .bind(slug)
    .fetch_optional(&state.db)
    .await?;

    let Some(v) = claimed else {
      return Err(AppError::NotFound("file_already_burned"));
    };
    (v, true)
  } else if let Some(mv) = max_views {
    let updated = sqlx::query_scalar::<_, i64>(
      r#"
      UPDATE files
      SET views = views + 1, last_accessed_at = ?, last_country = ?
      WHERE slug = ? AND views < ?
      RETURNING views
      "#,
    )
    .bind(now)
    .bind(&country)
    .bind(slug)
    .bind(mv)
    .fetch_optional(&state.db)
    .await?;

    let Some(v) = updated else {
      return Err(AppError::NotFound("file_already_burned"));
    };

    if v >= mv {
      let _ = sqlx::query("DELETE FROM files WHERE slug = ?")
        .bind(slug)
        .execute(&state.db)
        .await;
      (v, true)
    } else {
      (v, false)
    }
  } else {
    let updated = sqlx::query_scalar::<_, i64>(
      r#"
      UPDATE files
      SET views = views + 1, last_accessed_at = ?, last_country = ?
      WHERE slug = ?
      RETURNING views
      "#,
    )
    .bind(now)
    .bind(&country)
    .bind(slug)
    .fetch_optional(&state.db)
    .await?;

    let Some(v) = updated else {
      return Err(AppError::NotFound("file_not_found_or_expired"));
    };
    (v, false)
  };

  let total_size = size.max(0) as u64;
  let range_bounds = if !should_burn && total_size > 0 {
    parse_byte_range(req_headers, total_size)
  } else {
    None
  };

  let (start_offset, end_offset_exclusive, is_partial) = match range_bounds {
    Some((start, end_incl)) => (start, end_incl + 1, true),
    None => (0, total_size, false),
  };
  let content_len = end_offset_exclusive.saturating_sub(start_offset) as usize;

  let reader = match state.storage.reader(r2_key).await {
    Ok(r) => r,
    Err(err) => {
      if should_burn {
        safe_delete_r2_if_unreferenced(state, r2_key, file_hash).await;
      }
      return Err(AppError::Internal(err.to_string()));
    }
  };

  // Force attachment disposition on burned payloads to prevent browsers from issuing secondary range requests
  let inline_safe = !is_e2ee
    && !should_burn
    && VERIFIED_MAGIC_FORMATS
      .iter()
      .find(|&&(_, mime, _)| mime == content_type)
      .map(|&(_, _, safe)| safe)
      .unwrap_or(content_type.starts_with("text/plain"));

  let clean_name = sanitize_display_id(display_name);
  let disposition = if inline_safe {
    format!("inline; filename=\"{}\"", clean_name)
  } else {
    format!("attachment; filename=\"{}\"", clean_name)
  };

  let r2_key_owned = r2_key.to_string();
  let file_hash_owned = file_hash.to_string();
  let state_clone = state.clone();

  // 4-slot read-ahead pipeline (1 MiB max buffer) to saturate TCP throughput without stalling
  let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);

  tokio::spawn(async move {
    let _permit = download_permit;
    let mut offset = start_offset;
    let mut remaining = content_len;

    while remaining > 0 {
      let chunk_len = remaining.min(DISK_BUFFER_SIZE);
      let range_end = offset + chunk_len as u64;

      match timeout(CHUNK_READ_TIMEOUT, reader.read(offset..range_end)).await {
        Ok(Ok(buf)) => {
          if buf.is_empty() {
            break;
          }
          let len = buf.len();
          let out_bytes = if let Some((ref dek, ref nonce)) = server_dek {
            let mut vec_bytes = buf.to_vec();
            chacha20_xor_at_offset(dek, nonce, offset, &mut vec_bytes);
            Bytes::from(vec_bytes)
          } else {
            // Zero-copy conversion from OpenDAL Buffer to Bytes when no server DEK is active
            buf.to_bytes()
          };

          offset += len as u64;
          remaining = remaining.saturating_sub(len);

          if tx.send(Ok(out_bytes)).await.is_err() {
            break;
          }
        }
        Ok(Err(err)) => {
          let _ = tx
            .send(Err(std::io::Error::new(
              std::io::ErrorKind::Other,
              err.to_string(),
            )))
            .await;
          break;
        }
        Err(_) => {
          let _ = tx
            .send(Err(std::io::Error::new(
              std::io::ErrorKind::TimedOut,
              "storage read timeout",
            )))
            .await;
          break;
        }
      }
    }

    if should_burn {
      safe_delete_r2_if_unreferenced(&state_clone, &r2_key_owned, &file_hash_owned).await;
    }
  });

  let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));

  let mut response = Response::new(body);
  if is_partial {
    *response.status_mut() = StatusCode::PARTIAL_CONTENT;
  }

  let headers = response.headers_mut();
  if let Ok(ct) = HeaderValue::from_str(content_type) {
    headers.insert(header::CONTENT_TYPE, ct);
  }
  if let Ok(cd) = HeaderValue::from_str(&disposition) {
    headers.insert(header::CONTENT_DISPOSITION, cd);
  }
  headers.insert(
    header::CONTENT_LENGTH,
    HeaderValue::from(content_len as u64),
  );
  if !should_burn {
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
  }
  if is_partial {
    let cr = format!(
      "bytes {}-{}/{}",
      start_offset,
      end_offset_exclusive.saturating_sub(1),
      total_size
    );
    if let Ok(cr_val) = HeaderValue::from_str(&cr) {
      headers.insert(header::CONTENT_RANGE, cr_val);
    }
  }
  headers.insert(
    header::CACHE_CONTROL,
    HeaderValue::from_static("private, no-store, no-cache, must-revalidate"),
  );
  headers.insert(
    header::CONTENT_SECURITY_POLICY,
    HeaderValue::from_static(
      "default-src 'none'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'unsafe-inline'; sandbox",
    ),
  );
  headers.insert(
    header::HeaderName::from_static("x-kura-views"),
    HeaderValue::from(next_views as u64),
  );
  if is_e2ee {
    headers.insert(
      header::HeaderName::from_static("x-kura-e2ee"),
      HeaderValue::from_static("1"),
    );
  }

  Ok(response)
}

// ============================================================================
// HTML VIEW & GATE RENDERERS
// ============================================================================

pub fn render_corrupted_html(raw_id: &str) -> Html<String> {
  let safe_id = sanitize_display_id(raw_id);

  let html = format!(
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>410 Gone — kura — 蔵</title>
<style>
*{{box-sizing:border-box;}}
body{{background:#080808;color:#efefef;font-family:"JetBrains Mono",Consolas,monospace;min-height:100vh;display:flex;justify-content:center;align-items:center;margin:0;padding:1rem;}}
.card{{width:100%;max-width:420px;background:#0d0d0d;border:1px solid #222;padding:1.5rem;}}
</style>
</head>
<body>
<div class="card">
<div style="font-size:0.9rem;font-weight:600;color:#ef4444;margin-bottom:0.4rem;">ERR_OBJECT_CORRUPTED_OR_EXPIRED</div>
<div style="font-size:0.74rem;color:#8a8a8a;line-height:1.5;">The requested object ({safe_id}) failed R2 checksum verification or its retention TTL has elapsed.</div>
</div>
</body>
</html>"#
  );
  Html(html)
}

pub fn render_code_viewer_html(raw_id: &str, size: i64) -> Html<String> {
  let safe_id = sanitize_display_id(raw_id);

  let html = format!(
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{safe_id} — kura — 蔵</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:#080808;color:#efefef;font-family:"JetBrains Mono",Consolas,monospace;min-height:100vh;padding:1.5rem;}}
.frame{{max-width:960px;margin:0 auto;border:1px solid #222;background:#0d0d0d;}}
.bar{{display:flex;justify-content:space-between;align-items:center;padding:0.75rem 1rem;border-bottom:1px solid #222;background:#121212;font-size:0.74rem;gap:0.5rem;flex-wrap:wrap;}}
.btn{{background:#0d0d0d;color:#efefef;border:1px solid #383838;font-family:inherit;font-size:0.68rem;padding:0.25rem 0.65rem;cursor:pointer;text-decoration:none;}}
.btn:hover{{background:#efefef;color:#080808;}}
.panic:hover{{background:#ef4444;color:#fff;border-color:#ef4444;}}
.code-wrap{{display:flex;overflow-x:auto;font-size:0.76rem;line-height:1.55;padding:1rem;}}
.gutter{{user-select:none;color:#525252;text-align:right;padding-right:1rem;border-right:1px solid #222;margin-right:1rem;}}
.gutter.hidden{{display:none;}}
pre{{margin:0;white-space:pre;color:#efefef;}}
.kw{{color:#ff79c6;}} .str{{color:#10b981;}} .num{{color:#f59e0b;}} .cmt{{color:#525252;}}
</style>
</head>
<body>
<div class="frame">
<div class="bar">
<span>{safe_id} · <span id="meta-info">{size} B</span></span>
<div style="display:flex;gap:0.4rem;">
<button class="btn" id="btn-lines">Toggle Lines</button>
<button class="btn" id="btn-copy">Copy</button>
<a class="btn" href="/v/{safe_id}?raw=1">Raw</a>
<button class="btn panic" id="panic-btn" title="Double-tap Esc to wipe trace &amp; exit">ESC×2</button>
</div>
</div>
<div class="code-wrap">
<div class="gutter" id="gutter"></div>
<pre id="code-block">Loading...</pre>
</div>
</div>
<script>
{PANIC_ESCAPE_JS}
let rawText = '';
const codeEl = document.getElementById('code-block');
const gutterEl = document.getElementById('gutter');
const metaEl = document.getElementById('meta-info');
const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const highlight = s => esc(s)
  .replace(/(\/\/.*|#.*)/g, '<span class="cmt">$1</span>')
  .replace(/(&quot;.*?&quot;|".*?"|'.*?')/g, '<span class="str">$1</span>')
  .replace(/\b(fn|let|mut|pub|async|await|return|if|else|match|for|while|loop|struct|enum|impl|use|const|def|class|import|from|function|var)\b/g, '<span class="kw">$1</span>')
  .replace(/\b(\d+)\b/g, '<span class="num">$1</span>');

fetch('/v/{safe_id}?raw=1').then(r => r.text()).then(t => {{
  rawText = t;
  const lines = t.split('\n');
  metaEl.textContent = `{size} B · ${{lines.length}} lines`;
  gutterEl.innerHTML = lines.map((_, i) => i + 1).join('<br>');
  codeEl.innerHTML = highlight(t);
}});
document.getElementById('btn-lines').onclick = () => gutterEl.classList.toggle('hidden');
document.getElementById('btn-copy').onclick = async (e) => {{
  await navigator.clipboard.writeText(rawText);
  e.target.textContent = 'Copied';
  setTimeout(() => e.target.textContent = 'Copy', 1200);
}};
</script>
</body>
</html>"#
  );

  Html(html)
}

pub fn render_media_player_html(
  raw_id: &str,
  content_type: &str,
  size: i64,
  is_video: bool,
) -> Html<String> {
  let safe_id = sanitize_display_id(raw_id);

  let media_tag = if is_video {
    format!(
      r#"<video id="media" src="/v/{safe_id}?raw=1" autoplay playsinline style="max-width:100%;max-height:72vh;display:block;margin:0 auto;"></video>"#
    )
  } else {
    format!(
      r#"<audio id="media" src="/v/{safe_id}?raw=1" autoplay></audio><div style="padding:3rem 1rem;text-align:center;font-size:0.85rem;color:#8a8a8a;">Audio Stream · {safe_id}</div>"#
    )
  };

  let html = format!(
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{safe_id} — kura — 蔵</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:#080808;color:#efefef;font-family:"JetBrains Mono",Consolas,monospace;min-height:100vh;display:flex;justify-content:center;align-items:center;padding:1.5rem;}}
.player{{width:100%;max-width:820px;border:1px solid #222;background:#0d0d0d;}}
.top{{display:flex;justify-content:space-between;align-items:center;padding:0.75rem 1rem;border-bottom:1px solid #222;background:#121212;font-size:0.74rem;}}
.stage{{background:#040404;position:relative;}}
.ctrl{{display:flex;align-items:center;gap:0.65rem;padding:0.75rem 1rem;border-top:1px solid #222;font-size:0.72rem;}}
.btn{{background:#0d0d0d;color:#efefef;border:1px solid #383838;font-family:inherit;font-size:0.68rem;padding:0.25rem 0.6rem;cursor:pointer;text-decoration:none;}}
.btn:hover{{background:#efefef;color:#080808;}}
.panic:hover{{background:#ef4444;color:#fff;border-color:#ef4444;}}
.bar{{flex:1;height:6px;background:#222;cursor:pointer;position:relative;}}
.fill{{height:100%;background:#10b981;width:0%;}}
</style>
</head>
<body>
<div class="player">
<div class="top">
<span>{safe_id} · {content_type} ({size} B)</span>
<div style="display:flex;gap:0.4rem;">
<a class="btn" href="/v/{safe_id}?raw=1" download="{safe_id}">Download</a>
<button class="btn panic" id="panic-btn">ESC×2</button>
</div>
</div>
<div class="stage">{media_tag}</div>
<div class="ctrl">
<button class="btn" id="play-btn">Pause</button>
<div class="bar" id="seek-bar"><div class="fill" id="seek-fill"></div></div>
<span id="time-lbl">0:00 / 0:00</span>
<button class="btn" id="mute-btn">Mute</button>
</div>
</div>
<script>
{PANIC_ESCAPE_JS}
const m = document.getElementById('media');
const playBtn = document.getElementById('play-btn');
const muteBtn = document.getElementById('mute-btn');
const fill = document.getElementById('seek-fill');
const bar = document.getElementById('seek-bar');
const lbl = document.getElementById('time-lbl');
const fmt = s => {{ if (!isFinite(s)) return '0:00'; const m = Math.floor(s/60), r = Math.floor(s%60); return m + ':' + (r<10?'0':'') + r; }};
const togglePlay = () => m.paused ? m.play() : m.pause();
playBtn.onclick = togglePlay;
m.onplay = () => playBtn.textContent = 'Pause';
m.onpause = () => playBtn.textContent = 'Play';
m.ontimeupdate = () => {{
  fill.style.width = ((m.currentTime / (m.duration || 1)) * 100) + '%';
  lbl.textContent = fmt(m.currentTime) + ' / ' + fmt(m.duration);
}};
bar.onclick = e => {{
  const rect = bar.getBoundingClientRect();
  m.currentTime = ((e.clientX - rect.left) / rect.width) * (m.duration || 0);
}};
muteBtn.onclick = () => {{ m.muted = !m.muted; muteBtn.textContent = m.muted ? 'Unmute' : 'Mute'; }};
window.addEventListener('keydown', e => {{
  if (e.code === 'Space') {{ e.preventDefault(); togglePlay(); }}
  else if (e.key === 'j' || e.key === 'J') m.currentTime = Math.max(0, m.currentTime - 5);
  else if (e.key === 'l' || e.key === 'L') m.currentTime = Math.min(m.duration || 0, m.currentTime + 5);
  else if (e.key === 'm' || e.key === 'M') muteBtn.click();
  else if ((e.key === 'f' || e.key === 'F') && m.requestFullscreen) m.requestFullscreen();
}});
</script>
</body>
</html>"#
  );

  Html(html)
}

pub fn render_gate_html(
  raw_id: &str,
  is_burn: bool,
  needs_password: bool,
  is_e2ee: bool,
  auth_failed: bool,
) -> Html<String> {
  let safe_id = sanitize_display_id(raw_id);
  let is_note = safe_id.ends_with(".note");

  let subtitle = match (is_note, is_e2ee, is_burn, needs_password) {
    (true, _, _, _) => "One-Time Secret Note · Copy & Destroy in-memory",
    (false, true, true, _) => "Cascade E2EE (AES-256-GCM + ChaCha20 + AAD) · Burn after reading",
    (false, true, false, _) => "Zero-Knowledge End-to-End Encrypted payload",
    (false, false, true, true) => "Password protected · One-time download",
    (false, false, true, false) => "One-time link · Deleted immediately after download",
    (false, false, false, _) => "Protected payload · Authentication required",
  };

  let error_banner = if auth_failed {
    r#"<div id="gate-err" style="color:#ef4444;font-size:0.75rem;margin-bottom:0.85rem;">Invalid password or key shares.</div>"#
  } else {
    r#"<div id="gate-err" style="color:#ef4444;font-size:0.75rem;margin-bottom:0.85rem;display:none;"></div>"#
  };

  let password_input = if needs_password {
    r#"<input type="password" id="gate-pw" name="password" placeholder="Password" maxlength="128" required autofocus style="width:100%;background:#080808;border:1px solid #282828;color:#efefef;font-family:inherit;font-size:0.8rem;padding:0.65rem 0.75rem;margin-bottom:0.85rem;outline:none;">"#
  } else {
    r#"<input type="hidden" name="confirm" value="1">"#
  };

  let btn_label = if is_note {
    "Reveal Secret Note"
  } else if is_e2ee {
    "Decrypt & Download"
  } else if is_burn {
    "Download"
  } else {
    "Continue"
  };

  let e2ee_or_note_script = if is_e2ee || is_note {
    format!(
      r#"<script>
const form = document.getElementById('gate-form');
const errEl = document.getElementById('gate-err');
const btn = document.getElementById('gate-btn');
const noteBox = document.getElementById('note-box');
const noteArea = document.getElementById('note-area');
const copyDestroyBtn = document.getElementById('btn-copy-destroy');
const shamirBox = document.getElementById('shamir-box');
const shamirInput = document.getElementById('shamir-shares');

const gfMul = (a, b) => {{
  let p = 0;
  for (let i = 0; i < 8; i++) {{
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xFF;
    if (hi) a ^= 0x1B;
    b >>= 1;
  }}
  return p;
}};
const gfPow = (a, e) => {{
  let r = 1;
  while (e > 0) {{
    if (e & 1) r = gfMul(r, a);
    a = gfMul(a, a);
    e >>= 1;
  }}
  return r;
}};
const gfInv = a => gfPow(a, 254);

const combineShamirShares = (lines) => {{
  const parsed = lines.map(l => l.trim()).filter(Boolean).map(l => {{
    const [xStr, b64] = l.split(':');
    const x = parseInt(xStr, 16);
    const bytes = Uint8Array.from(atob(b64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    return {{ x, bytes }};
  }});
  if (parsed.length < 2) throw new Error('Enter at least 2 valid key shares.');
  const len = parsed[0].bytes.length;
  const secret = new Uint8Array(len);
  for (let byteIdx = 0; byteIdx < len; byteIdx++) {{
    let accum = 0;
    for (let i = 0; i < parsed.length; i++) {{
      let num = 1, den = 1;
      for (let j = 0; j < parsed.length; j++) {{
        if (i === j) continue;
        num = gfMul(num, parsed[j].x);
        den = gfMul(den, parsed[i].x ^ parsed[j].x);
      }}
      const basis = gfMul(num, gfInv(den));
      accum ^= gfMul(parsed[i].bytes[byteIdx], basis);
    }}
    secret[byteIdx] = accum;
  }}
  return secret;
}};

const chacha20Xor = (keyBytes, nonceBytes, dataBytes) => {{
  const rotl = (v, c) => (v << c) | (v >>> (32 - c));
  const qr = (s, a, b, c, d) => {{
    s[a] = (s[a] + s[b]) | 0; s[d] = rotl(s[d] ^ s[a], 16);
    s[c] = (s[c] + s[d]) | 0; s[b] = rotl(s[b] ^ s[c], 12);
    s[a] = (s[a] + s[b]) | 0; s[d] = rotl(s[d] ^ s[a], 8);
    s[c] = (s[c] + s[d]) | 0; s[b] = rotl(s[b] ^ s[c], 7);
  }};
  const kView = new DataView(keyBytes.buffer, keyBytes.byteOffset, 32);
  const nView = new DataView(nonceBytes.buffer, nonceBytes.byteOffset, 12);
  const out = new Uint8Array(dataBytes.length);
  const block = new Uint8Array(64);
  const bView = new DataView(block.buffer);

  for (let offset = 0, counter = 1; offset < dataBytes.length; offset += 64, counter++) {{
    const st = new Int32Array([
      0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
      kView.getInt32(0, true), kView.getInt32(4, true), kView.getInt32(8, true), kView.getInt32(12, true),
      kView.getInt32(16, true), kView.getInt32(20, true), kView.getInt32(24, true), kView.getInt32(28, true),
      counter, nView.getInt32(0, true), nView.getInt32(4, true), nView.getInt32(8, true)
    ]);
    const init = new Int32Array(st);
    for (let r = 0; r < 10; r++) {{
      qr(st,0,4,8,12); qr(st,1,5,9,13); qr(st,2,6,10,14); qr(st,3,7,11,15);
      qr(st,0,5,10,15); qr(st,1,6,11,12); qr(st,2,7,8,13); qr(st,3,4,9,14);
    }}
    for (let i = 0; i < 16; i++) bView.setInt32(i * 4, (st[i] + init[i]) | 0, true);
    const take = Math.min(64, dataBytes.length - offset);
    for (let i = 0; i < take; i++) out[offset + i] = dataBytes[offset + i] ^ block[i];
  }}
  return out;
}};

if (window.location.hash.slice(1).startsWith('sss:')) {{
  shamirBox.style.display = 'block';
}}

form.addEventListener('submit', async (e) => {{
  e.preventDefault();
  errEl.style.display = 'none';
  const hashFrag = window.location.hash.slice(1);
  btn.disabled = true;
  btn.textContent = 'Processing locally...';
  try {{
    let masterKeyBytes = null;
    if (hashFrag.startsWith('sss:') || shamirBox.style.display === 'block') {{
      shamirBox.style.display = 'block';
      const lines = shamirInput.value.split('\n').map(s => s.trim()).filter(Boolean);
      if (lines.length < 2) throw new Error('Please paste your M-of-N Shamir Key Shares.');
      masterKeyBytes = combineShamirShares(lines);
    }} else if (hashFrag) {{
      masterKeyBytes = Uint8Array.from(atob(hashFrag.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    }}

    const headers = {{ 'X-Kura-Raw': '1' }};
    const pwInput = document.getElementById('gate-pw');
    if (pwInput && pwInput.value) headers['X-Kura-Password'] = pwInput.value;
    const res = await fetch('/v/{safe_id}?raw=1', {{ headers }});
    if (res.status === 401) throw new Error('Invalid password.');
    if (res.status === 423) {{
      const msg = await res.text();
      throw new Error(msg.trim() || 'File is Time-Locked and cannot be unlocked yet.');
    }}
    if (res.status === 410) throw new Error('Object corrupted or already expired.');
    if (!res.ok) throw new Error('File expired or unavailable (' + res.status + ').');

    const isE2eeHeader = res.headers.get('X-Kura-E2EE') === '1';
    const payload = new Uint8Array(await res.arrayBuffer());

    let plainBytes = payload;
    let origName = '{safe_id}'.replace(/\.enc$/i, '');
    let origMime = 'application/octet-stream';
    let isSecretNote = origName.endsWith('.note');

    if (isE2eeHeader || masterKeyBytes) {{
      if (!masterKeyBytes) {{
        shamirBox.style.display = 'block';
        throw new Error('Missing URL #key fragment. If using Shamir M-of-N Split Key, paste shares above.');
      }}
      if (payload.byteLength < 29) throw new Error('Corrupted E2EE ciphertext.');

      const iv = payload.slice(0, 12);
      const metaLen = payload[12];
      const metaBytes = payload.slice(13, 13 + metaLen);
      const ciphertext = payload.slice(13 + metaLen);

      let meta = {{}};
      if (metaLen > 0) {{
        try {{ meta = JSON.parse(new TextDecoder().decode(metaBytes)); }} catch (_) {{}}
      }}

      if (meta.v === 2) {{
        const hkdfBase = await crypto.subtle.importKey('raw', masterKeyBytes, 'HKDF', false, ['deriveBits']);
        const derivedBits = await crypto.subtle.deriveBits(
          {{ name: 'HKDF', hash: 'SHA-256', salt: iv, info: metaBytes }},
          hkdfBase,
          512
        );
        const aesKeyBytes = new Uint8Array(derivedBits, 0, 32);
        const chachaKeyBytes = new Uint8Array(derivedBits, 32, 32);
        const aesKey = await crypto.subtle.importKey('raw', aesKeyBytes, 'AES-GCM', false, ['decrypt']);
        const afterAes = new Uint8Array(
          await crypto.subtle.decrypt({{ name: 'AES-GCM', iv, additionalData: metaBytes }}, aesKey, ciphertext)
        );
        plainBytes = chacha20Xor(chachaKeyBytes, iv, afterAes);
      }} else {{
        const cryptoKey = await crypto.subtle.importKey('raw', masterKeyBytes, 'AES-GCM', false, ['decrypt']);
        let decrypted;
        try {{
          decrypted = await crypto.subtle.decrypt({{ name: 'AES-GCM', iv, additionalData: metaBytes }}, cryptoKey, ciphertext);
        }} catch (_) {{
          decrypted = await crypto.subtle.decrypt({{ name: 'AES-GCM', iv }}, cryptoKey, ciphertext);
        }}
        plainBytes = new Uint8Array(decrypted);
      }}

      if (typeof meta.s === 'number' && meta.s >= 0 && meta.s <= plainBytes.byteLength) {{
        plainBytes = plainBytes.subarray(0, meta.s);
      }}
      if (meta.n) origName = meta.n;
      if (meta.t) origMime = meta.t;
      if (meta.note || meta.t === 'text/kura-note' || origName.endsWith('.note')) isSecretNote = true;
    }}

    if (isSecretNote) {{
      let secretText = new TextDecoder().decode(plainBytes);
      form.style.display = 'none';
      noteArea.value = secretText;
      noteBox.style.display = 'block';
      copyDestroyBtn.onclick = async () => {{
        try {{ await navigator.clipboard.writeText(secretText); }} catch (_) {{}}
        secretText = '';
        plainBytes.fill(0);
        noteArea.value = '[DESTROYED FROM MEMORY]';
        copyDestroyBtn.disabled = true;
        copyDestroyBtn.textContent = 'Copied to Clipboard & Wiped';
      }};
      return;
    }}

    const blob = new Blob([plainBytes], {{ type: origMime }});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = origName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    btn.textContent = 'Decrypted & Downloaded';
  }} catch (err) {{
    btn.disabled = false;
    btn.textContent = '{btn_label}';
    errEl.textContent = err.message || 'Decryption or AAD integrity check failed.';
    errEl.style.display = 'block';
  }}
}});
</script>"#
    )
  } else {
    String::new()
  };

  let html = format!(
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{safe_id} — kura — 蔵</title>
<style>
*{{box-sizing:border-box;}}
body{{background:#080808;color:#efefef;font-family:"JetBrains Mono",Consolas,monospace;min-height:100vh;display:flex;justify-content:center;align-items:center;margin:0;padding:1rem;}}
.card{{width:100%;max-width:460px;background:#0d0d0d;border:1px solid #222;padding:1.5rem;}}
.top{{display:flex;justify-content:space-between;align-items:center;margin-bottom:0.3rem;gap:0.5rem;}}
.panic{{background:transparent;color:#525252;border:1px solid #222;font-family:inherit;font-size:0.62rem;padding:0.15rem 0.4rem;cursor:pointer;}}
.panic:hover{{color:#fff;background:#ef4444;border-color:#ef4444;}}
.btn{{width:100%;background:#efefef;color:#080808;border:none;font-family:inherit;font-size:0.78rem;font-weight:600;padding:0.65rem;cursor:pointer;}}
.btn:hover{{background:#fff;}}
.btn:disabled{{opacity:0.5;cursor:not-allowed;}}
.note-area{{width:100%;height:160px;background:#080808;border:1px solid #282828;color:#10b981;font-family:inherit;font-size:0.76rem;padding:0.75rem;margin-bottom:0.85rem;resize:vertical;outline:none;}}
.shamir-area{{width:100%;height:95px;background:#080808;border:1px solid #282828;color:#efefef;font-family:inherit;font-size:0.72rem;padding:0.6rem;margin-bottom:0.85rem;resize:vertical;outline:none;}}
</style>
</head>
<body>
<div class="card">
<div class="top">
<div style="font-size:0.9rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{safe_id}</div>
<button type="button" class="panic" id="panic-btn" title="Double-tap Esc to wipe trace &amp; exit">ESC×2</button>
</div>
<div style="font-size:0.72rem;color:#8a8a8a;margin-bottom:1.25rem;">{subtitle}</div>
<form id="gate-form" method="POST" action="/v/{safe_id}">
{error_banner}
<div id="shamir-box" style="display:none;">
<div style="font-size:0.66rem;color:#8a8a8a;margin-bottom:0.35rem;">Shamir M-of-N Key Shares (1 share per line):</div>
<textarea id="shamir-shares" class="shamir-area" placeholder="01:base64share1&#10;02:base64share2"></textarea>
</div>
{password_input}
<button type="submit" class="btn" id="gate-btn">{btn_label}</button>
</form>
<div id="note-box" style="display:none;">
<textarea id="note-area" class="note-area" readonly></textarea>
<button type="button" class="btn" id="btn-copy-destroy">Copy &amp; Destroy From Memory</button>
</div>
</div>
<script>
{PANIC_ESCAPE_JS}
</script>
{e2ee_or_note_script}
</body>
</html>"#
  );

  Html(html)
}