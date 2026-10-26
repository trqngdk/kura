use axum::{
  body::{Body, Bytes},
  extract::{
    multipart::Field, ConnectInfo, FromRequest, Multipart, Path as AxumPath, Request, State,
  },
  http::{header, HeaderMap, HeaderValue},
  response::Response,
};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{collections::BTreeSet, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::timeout;

use crate::{config::*, crypto::*, limiter::RateLimitDecision};

// ============================================================================
// CORESHARED HELPERS (Zero-Duplication Security & Storage Primitives)
// ============================================================================

/// Zero-cost abstraction unifying raw HTTP body streams and multipart fields
enum PayloadStream<'a> {
  Raw(BodyChunkStream),
  Multipart(Field<'a>),
}

impl<'a> PayloadStream<'a> {
  #[inline]
  async fn next_chunk(&mut self) -> Result<Option<Bytes>, AppError> {
    match self {
      PayloadStream::Raw(s) => timeout(CHUNK_READ_TIMEOUT, s.next_chunk())
        .await
        .map_err(|_| AppError::RequestTimeout("stream_stalled"))?
        .map_err(|_| AppError::BadRequest("stream_interrupted")),
      PayloadStream::Multipart(f) => timeout(CHUNK_READ_TIMEOUT, f.chunk())
        .await
        .map_err(|_| AppError::RequestTimeout("stream_stalled"))?
        .map_err(|_| AppError::BadRequest("stream_interrupted")),
    }
  }
}

/// Allocates a collision-free random slug from the database
async fn allocate_unique_slug(state: &AppState) -> Result<String, AppError> {
  for _ in 0..SLUG_MAX_RETRIES {
    let candidate = generate_random_string(SLUG_LENGTH);
    let exists = sqlx::query_scalar::<_, i64>("SELECT 1 FROM files WHERE slug = ? LIMIT 1")
      .bind(&candidate)
      .fetch_optional(&state.db)
      .await?;
    if exists.is_none() {
      return Ok(candidate);
    }
  }
  Err(AppError::Internal("slug_allocation_exhausted".into()))
}

/// Checks whether a SHA-256 hex digest is present in the blacklist table
async fn ensure_not_blacklisted(state: &AppState, file_hash: &str) -> Result<(), AppError> {
  let is_blacklisted = sqlx::query_scalar::<_, i64>(
    "SELECT 1 FROM blacklist WHERE hash = ? LIMIT 1",
  )
  .bind(file_hash)
  .fetch_optional(&state.db)
  .await?;

  if is_blacklisted.is_some() {
    return Err(AppError::Forbidden("payload_blacklisted"));
  }
  Ok(())
}

/// Queries for an existing public, immutable, unencrypted file matching the SHA-256 digest
async fn find_deduplicated_file(
  state: &AppState,
  file_hash: &str,
) -> Result<Option<(String, String)>, AppError> {
  let record = sqlx::query_as::<_, (String, String)>(
    r#"
    SELECT slug, filename FROM files
    WHERE hash = ?
      AND expires_at IS NULL
      AND unlock_at IS NULL
      AND burn_after_read = 0
      AND max_views IS NULL
      AND password_hash IS NULL
      AND duress_hash IS NULL
      AND e2ee = 0
      AND server_wrapped_dek IS NULL
    LIMIT 1
    "#,
  )
  .bind(file_hash)
  .fetch_optional(&state.db)
  .await?;

  Ok(record)
}

/// Best-effort cleanup of R2 resumable session chunks when assembly aborts
async fn purge_resumable_parts_r2(state: &AppState, session_id: &str, total_parts: usize) {
  for p in 1..=total_parts {
    let part_key = format!("kura_upload_sessions/{}/part_{}", session_id, p);
    let _ = state.storage.delete(&part_key).await;
  }
}

// ============================================================================
// RESUMABLE UPLOAD HANDLERS
// ============================================================================

pub async fn init_resumable_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  match state.rate_limiter.check_upload_admission(&peer_addr, &headers) {
    RateLimitDecision::Allowed => {}
    RateLimitDecision::PowRequired(c) => return Err(AppError::PowRequired(c)),
    RateLimitDecision::Rejected => return Err(AppError::TooManyRequests("rate_limit_exceeded")),
  }

  let total_size = headers
    .get("x-kura-size")
    .and_then(|v| v.to_str().ok())
    .and_then(|s| s.trim().parse::<usize>().ok())
    .ok_or(AppError::BadRequest("missing_or_invalid_x_kura_size"))?;

  if total_size == 0 || total_size > MAX_FILE_SIZE {
    return Err(AppError::PayloadTooLarge("payload_exceeds_limit"));
  }

  let client_sha256 = extract_client_sha256(&headers)?
    .ok_or(AppError::BadRequest("resumable_requires_x_content_sha256"))?;
  let hash_str = std::str::from_utf8(&client_sha256).unwrap_or_default();

  ensure_not_blacklisted(&state, hash_str).await?;

  let now = current_unix_timestamp();

  if let Some((existing_sid, part_size, total_parts, completed_csv)) =
    sqlx::query_as::<_, (String, i64, i64, String)>(
      r#"
      SELECT session_id, part_size, total_parts, completed_parts
      FROM upload_sessions
      WHERE file_hash = ? AND total_size = ? AND expires_at > ?
      ORDER BY created_at DESC LIMIT 1
      "#,
    )
    .bind(hash_str)
    .bind(total_size as i64)
    .bind(now)
    .fetch_optional(&state.db)
    .await?
  {
    let parts_json = completed_csv
      .split(',')
      .filter(|s| !s.is_empty())
      .collect::<Vec<_>>()
      .join(",");

    let json = format!(
      r#"{{"resumed":true,"session_id":"{}","part_size":{},"total_parts":{},"uploaded_parts":[{}]}}"#,
      existing_sid, part_size, total_parts, parts_json
    );
    let mut resp = Response::new(Body::from(format!("{}\n", json)));
    resp.headers_mut().insert(
      header::CONTENT_TYPE,
      HeaderValue::from_static("application/json; charset=utf-8"),
    );
    return Ok(resp);
  }

  let _ = extract_expiry_policy(&headers)?;
  let unlock_at = extract_timelock_header(&headers)?;
  let expiry_raw = headers
    .get("x-kura-expire")
    .and_then(|v| v.to_str().ok())
    .map(|s| s.trim().to_string());
  let ext_hint = headers
    .get("x-kura-filename")
    .and_then(|v| v.to_str().ok())
    .and_then(extract_safe_client_extension);
  let is_e2ee = extract_e2ee_flag(&headers);
  let album_id = extract_album_id(&headers);
  let creds = derive_security_creds(&state, &headers).await?;

  let total_parts = (total_size + RESUMABLE_PART_SIZE - 1) / RESUMABLE_PART_SIZE;
  let session_id = generate_random_string(24);

  let (pw_salt, pw_hash) = match creds.pw {
    Some((s, h)) => (Some(s.to_vec()), Some(h.to_vec())),
    None => (None, None),
  };
  let (duress_salt, duress_hash) = match creds.duress {
    Some((s, h)) => (Some(s.to_vec()), Some(h.to_vec())),
    None => (None, None),
  };

  sqlx::query(
    r#"
    INSERT INTO upload_sessions (
      session_id, file_hash, total_size, part_size, total_parts, completed_parts,
      ext_hint, expiry_header, unlock_at, password_salt, password_hash, duress_salt, duress_hash,
      e2ee, album_id, created_at, expires_at
    ) VALUES (?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    "#,
  )
  .bind(&session_id)
  .bind(hash_str)
  .bind(total_size as i64)
  .bind(RESUMABLE_PART_SIZE as i64)
  .bind(total_parts as i64)
  .bind(ext_hint)
  .bind(expiry_raw)
  .bind(unlock_at)
  .bind(pw_salt)
  .bind(pw_hash)
  .bind(duress_salt)
  .bind(duress_hash)
  .bind(if is_e2ee { 1i64 } else { 0i64 })
  .bind(album_id)
  .bind(now)
  .bind(now + RESUMABLE_SESSION_TTL)
  .execute(&state.db)
  .await?;

  let json = format!(
    r#"{{"resumed":false,"session_id":"{}","part_size":{},"total_parts":{},"uploaded_parts":[]}}"#,
    session_id, RESUMABLE_PART_SIZE, total_parts
  );
  let mut resp = Response::new(Body::from(format!("{}\n", json)));
  resp.headers_mut().insert(
    header::CONTENT_TYPE,
    HeaderValue::from_static("application/json; charset=utf-8"),
  );
  Ok(resp)
}

pub async fn upload_resumable_part_handler(
  State(state): State<Arc<AppState>>,
  AxumPath((session_id, part_number)): AxumPath<(String, usize)>,
  req: Request,
) -> Result<Response, AppError> {
  if session_id.len() != 24 || !session_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
    return Err(AppError::NotFound("invalid_session_id"));
  }

  let _inflight = InflightGuard::try_acquire(state.inflight_counter.clone())
    .ok_or(AppError::TooManyRequests("server_busy_try_again"))?;

  let _permit = timeout(SEMAPHORE_WAIT_TIMEOUT, state.upload_semaphore.acquire())
    .await
    .map_err(|_| AppError::TooManyRequests("server_busy_try_again"))?
    .map_err(|_| AppError::Internal("semaphore_closed".into()))?;

  let now = current_unix_timestamp();
  let row = sqlx::query(
    "SELECT total_size, part_size, total_parts, completed_parts FROM upload_sessions WHERE session_id = ? AND expires_at > ? LIMIT 1",
  )
  .bind(&session_id)
  .bind(now)
  .fetch_optional(&state.db)
  .await?
  .ok_or(AppError::NotFound("session_not_found_or_expired"))?;

  let total_size = row.get::<i64, _>("total_size") as usize;
  let part_size = row.get::<i64, _>("part_size") as usize;
  let total_parts = row.get::<i64, _>("total_parts") as usize;
  let completed_csv: String = row.get("completed_parts");

  if part_number == 0 || part_number > total_parts {
    return Err(AppError::BadRequest("part_number_out_of_range"));
  }

  let expected_part_len = if part_number < total_parts {
    part_size
  } else {
    let rem = total_size % part_size;
    if rem == 0 { part_size } else { rem }
  };

  let part_key = format!("kura_upload_sessions/{}/part_{}", session_id, part_number);
  let mut part_guard = R2ObjectGuard::new(state.storage.clone(), part_key.clone());
  let mut writer = state
    .storage
    .writer(&part_key)
    .await
    .map_err(|_| AppError::Internal("r2_writer_init_failed".into()))?;

  let mut stream = BodyChunkStream::new(req.into_body());
  let mut written = 0usize;

  while let Some(chunk) = timeout(CHUNK_READ_TIMEOUT, stream.next_chunk())
    .await
    .map_err(|_| AppError::RequestTimeout("stream_stalled"))?
    .map_err(|_| AppError::BadRequest("stream_interrupted"))?
  {
    written = written.saturating_add(chunk.len());
    if written > expected_part_len {
      let _ = writer.abort().await;
      return Err(AppError::PayloadTooLarge("part_exceeds_expected_size"));
    }
    writer
      .write(chunk)
      .await
      .map_err(|_| AppError::Internal("r2_write_failed".into()))?;
  }

  if written != expected_part_len {
    let _ = writer.abort().await;
    return Err(AppError::BadRequest("incomplete_part_payload"));
  }

  writer
    .close()
    .await
    .map_err(|_| AppError::Internal("r2_close_failed".into()))?;
  part_guard.commit();

  let mut set: BTreeSet<usize> = completed_csv
    .split(',')
    .filter_map(|s| s.parse::<usize>().ok())
    .collect();
  set.insert(part_number);
  let updated_csv = set
    .iter()
    .map(|n| n.to_string())
    .collect::<Vec<_>>()
    .join(",");

  sqlx::query("UPDATE upload_sessions SET completed_parts = ? WHERE session_id = ?")
    .bind(&updated_csv)
    .bind(&session_id)
    .execute(&state.db)
    .await?;

  let json = format!(
    r#"{{"part_number":{},"size":{},"status":"ok"}}"#,
    part_number, written
  );
  let mut resp = Response::new(Body::from(format!("{}\n", json)));
  resp.headers_mut().insert(
    header::CONTENT_TYPE,
    HeaderValue::from_static("application/json; charset=utf-8"),
  );
  Ok(resp)
}

pub async fn complete_resumable_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  AxumPath(session_id): AxumPath<String>,
) -> Result<Response, AppError> {
  if session_id.len() != 24 || !session_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
    return Err(AppError::NotFound("invalid_session_id"));
  }

  let _inflight = InflightGuard::try_acquire(state.inflight_counter.clone())
    .ok_or(AppError::TooManyRequests("server_busy_try_again"))?;

  let _permit = timeout(SEMAPHORE_WAIT_TIMEOUT, state.upload_semaphore.acquire())
    .await
    .map_err(|_| AppError::TooManyRequests("server_busy_try_again"))?
    .map_err(|_| AppError::Internal("semaphore_closed".into()))?;

  let now = current_unix_timestamp();

  // Atomically claim and delete session record to eliminate TOCTOU race conditions
  let row = sqlx::query(
    r#"
    DELETE FROM upload_sessions
    WHERE session_id = ? AND expires_at > ?
    RETURNING file_hash, total_size, total_parts, completed_parts, ext_hint, expiry_header,
              unlock_at, password_salt, password_hash, duress_salt, duress_hash, e2ee, album_id
    "#,
  )
  .bind(&session_id)
  .bind(now)
  .fetch_optional(&state.db)
  .await?
  .ok_or(AppError::NotFound("session_not_found_or_already_completing"))?;

  let expected_hash: String = row.get("file_hash");
  let total_size = row.get::<i64, _>("total_size") as usize;
  let total_parts = row.get::<i64, _>("total_parts") as usize;
  let completed_csv: String = row.get("completed_parts");
  let ext_hint: Option<String> = row.get("ext_hint");
  let expiry_str: Option<String> = row.get("expiry_header");
  let unlock_at: Option<i64> = row.get("unlock_at");
  let pw_salt: Option<Vec<u8>> = row.get("password_salt");
  let pw_hash: Option<Vec<u8>> = row.get("password_hash");
  let duress_salt: Option<Vec<u8>> = row.get("duress_salt");
  let duress_hash: Option<Vec<u8>> = row.get("duress_hash");
  let is_e2ee = row.get::<i64, _>("e2ee") == 1;
  let album_id: Option<String> = row.get("album_id");

  let completed_set: BTreeSet<usize> = completed_csv
    .split(',')
    .filter_map(|s| s.parse::<usize>().ok())
    .collect();

  for p in 1..=total_parts {
    if !completed_set.contains(&p) {
      purge_resumable_parts_r2(&state, &session_id, total_parts).await;
      return Err(AppError::BadRequest("missing_resumable_parts"));
    }
  }

  let part1_key = format!("kura_upload_sessions/{}/part_1", session_id);
  let sniff_len = total_size.min(SNIFF_BUFFER_SIZE);
  let sniff_buf = match state
    .storage
    .read_with(&part1_key)
    .range(0..sniff_len as u64)
    .await
  {
    Ok(buf) => buf.to_vec(),
    Err(_) => {
      purge_resumable_parts_r2(&state, &session_id, total_parts).await;
      return Err(AppError::BadRequest("r2_sniff_read_failed"));
    }
  };

  let (safe_ext, content_type, inline_safe) = if is_e2ee {
    let ext = ext_hint.unwrap_or_else(|| "enc".to_string());
    (ext, "application/octet-stream", false)
  } else {
    match resolve_safe_format(&sniff_buf, ext_hint.as_deref()) {
      Ok(res) => res,
      Err(err) => {
        purge_resumable_parts_r2(&state, &session_id, total_parts).await;
        return Err(err);
      }
    }
  };

  let mut fake_headers = HeaderMap::new();
  if let Some(ref exp) = expiry_str {
    if let Ok(hv) = HeaderValue::from_str(exp) {
      fake_headers.insert(header::HeaderName::from_static("x-kura-expire"), hv);
    }
  }
  let expiry_policy = extract_expiry_policy(&fake_headers)?;
  let shamir_m = extract_shamir_threshold(&headers)?;
  let is_protected_or_ephemeral = expiry_policy.is_ephemeral()
    || pw_hash.is_some()
    || duress_hash.is_some()
    || is_e2ee
    || unlock_at.is_some()
    || shamir_m.is_some();

  let slug = match allocate_unique_slug(&state).await {
    Ok(s) => s,
    Err(e) => {
      purge_resumable_parts_r2(&state, &session_id, total_parts).await;
      return Err(e);
    }
  };

  let r2_storage_key = if is_protected_or_ephemeral {
    format!("vault/{}.{}", generate_random_string(24), safe_ext)
  } else {
    format!("{}.{}", slug, safe_ext)
  };

  let download_filename = format!("{}.{}", slug, safe_ext);
  let disposition = if inline_safe {
    format!("inline; filename=\"{}\"", download_filename)
  } else {
    format!("attachment; filename=\"{}\"", download_filename)
  };
  let cache_ctrl = if is_protected_or_ephemeral {
    "private, no-store"
  } else {
    "public, max-age=31536000, immutable"
  };

  let server_dek_opt = if is_protected_or_ephemeral {
    Some(generate_wrapped_server_dek(&state.rate_limiter.boot_secret, &slug))
  } else {
    None
  };

  let mut r2_guard = R2ObjectGuard::new(state.storage.clone(), r2_storage_key.clone());
  let mut writer = state
    .storage
    .writer_with(&r2_storage_key)
    .content_type(content_type)
    .content_disposition(&disposition)
    .cache_control(cache_ctrl)
    .await
    .map_err(|_| AppError::Internal("r2_final_writer_failed".into()))?;

  let mut hasher = Sha256::new();
  let mut streamed_bytes = 0usize;
  let mut cipher_offset = 0u64;

  for p in 1..=total_parts {
    let part_key = format!("kura_upload_sessions/{}/part_{}", session_id, p);
    let mut part_bytes = match state.storage.read(&part_key).await {
      Ok(b) => b.to_vec(),
      Err(_) => {
        let _ = writer.abort().await;
        purge_resumable_parts_r2(&state, &session_id, total_parts).await;
        return Err(AppError::BadRequest("missing_part_in_r2"));
      }
    };

    streamed_bytes = streamed_bytes.saturating_add(part_bytes.len());
    hasher.update(&part_bytes);

    if let Some((ref dek, ref nonce, _)) = server_dek_opt {
      chacha20_xor_at_offset(dek, nonce, cipher_offset, &mut part_bytes);
      cipher_offset += part_bytes.len() as u64;
    }

    if writer.write(part_bytes).await.is_err() {
      let _ = writer.abort().await;
      purge_resumable_parts_r2(&state, &session_id, total_parts).await;
      return Err(AppError::Internal("r2_assembly_write_failed".into()));
    }

    let _ = state.storage.delete(&part_key).await;
  }

  let computed_hex = encode_hex_sha256(&hasher.finalize());
  let computed_str = std::str::from_utf8(&computed_hex).unwrap_or_default();

  if streamed_bytes != total_size
    || !constant_time_eq(computed_str.as_bytes(), expected_hash.as_bytes())
  {
    let _ = writer.abort().await;
    return Err(AppError::BadRequest("sha256_or_size_mismatch_on_complete"));
  }

  writer
    .close()
    .await
    .map_err(|_| AppError::Internal("r2_assembly_close_failed".into()))?;

  let mut creds = SecurityCreds {
    pw: None,
    duress: None,
  };
  if let (Some(s), Some(h)) = (pw_salt, pw_hash) {
    if s.len() == 16 && h.len() == 32 {
      let mut sa = [0u8; 16];
      let mut ha = [0u8; 32];
      sa.copy_from_slice(&s);
      ha.copy_from_slice(&h);
      creds.pw = Some((sa, ha));
    }
  }
  if let (Some(ds), Some(dh)) = (duress_salt, duress_hash) {
    if ds.len() == 16 && dh.len() == 32 {
      let mut sa = [0u8; 16];
      let mut ha = [0u8; 32];
      sa.copy_from_slice(&ds);
      ha.copy_from_slice(&dh);
      creds.duress = Some((sa, ha));
    }
  }

  let stored_dek = server_dek_opt.map(|(_, nonce, wrapped)| (nonce, wrapped));

  finalize_upload_record(
    &state,
    &peer_addr,
    &headers,
    &slug,
    &safe_ext,
    computed_str,
    &r2_storage_key,
    content_type,
    total_size,
    expiry_policy,
    unlock_at,
    shamir_m,
    stored_dek,
    creds,
    is_e2ee,
    is_protected_or_ephemeral,
    album_id,
    &mut r2_guard,
  )
  .await
}

// ============================================================================
// PRESIGNED UPLOAD HANDLERS
// ============================================================================

pub async fn presign_upload_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  match state.rate_limiter.check_upload_admission(&peer_addr, &headers) {
    RateLimitDecision::Allowed => {}
    RateLimitDecision::PowRequired(c) => return Err(AppError::PowRequired(c)),
    RateLimitDecision::Rejected => return Err(AppError::TooManyRequests("rate_limit_exceeded")),
  }

  let declared_size = headers
    .get("x-kura-size")
    .and_then(|v| v.to_str().ok())
    .and_then(|s| s.trim().parse::<usize>().ok())
    .ok_or(AppError::BadRequest("missing_or_invalid_x_kura_size"))?;

  if declared_size == 0 || declared_size > MAX_FILE_SIZE {
    return Err(AppError::PayloadTooLarge("payload_exceeds_limit"));
  }

  let client_sha256 = extract_client_sha256(&headers)?
    .ok_or(AppError::BadRequest("presign_requires_x_content_sha256"))?;
  let hash_str = std::str::from_utf8(&client_sha256).unwrap_or_default();

  ensure_not_blacklisted(&state, hash_str).await?;

  let expiry_policy = extract_expiry_policy(&headers)?;
  let unlock_at = extract_timelock_header(&headers)?;
  let shamir_m = extract_shamir_threshold(&headers)?;
  let has_password = headers
    .get("x-kura-password")
    .map(|v| !v.as_bytes().trim_ascii().is_empty())
    .unwrap_or(false);
  let has_duress = headers
    .get("x-kura-duress-password")
    .map(|v| !v.as_bytes().trim_ascii().is_empty())
    .unwrap_or(false);
  let is_e2ee = extract_e2ee_flag(&headers);
  let is_protected_or_ephemeral = expiry_policy.is_ephemeral()
    || has_password
    || has_duress
    || is_e2ee
    || unlock_at.is_some()
    || shamir_m.is_some();

  if !is_protected_or_ephemeral {
    if let Some((_, existing_filename)) = find_deduplicated_file(&state, hash_str).await? {
      let origin = resolve_request_origin(
        &peer_addr,
        &headers,
        state.app_origin.as_deref(),
        &state.public_url,
      );
      let url = format!("{}/{}", origin, existing_filename);
      let json = format!(r#"{{"deduplicated":true,"url":"{}"}}"#, url);
      let mut resp = Response::new(Body::from(format!("{}\n", json)));
      resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
      );
      return Ok(resp);
    }
  }

  let ext_hint = headers
    .get("x-kura-filename")
    .and_then(|v| v.to_str().ok())
    .and_then(extract_safe_client_extension)
    .unwrap_or_else(|| "bin".to_string());

  let safe_ext = if is_e2ee {
    "enc".to_string()
  } else if SAFE_TEXT_EXTENSIONS.contains(&ext_hint.as_str())
    || VERIFIED_MAGIC_FORMATS.iter().any(|&(e, _, _)| e == ext_hint)
  {
    ext_hint
  } else {
    "bin".to_string()
  };

  let slug = allocate_unique_slug(&state).await?;

  let r2_key = if is_protected_or_ephemeral {
    format!("vault/{}.{}", generate_random_string(24), safe_ext)
  } else {
    format!("{}.{}", slug, safe_ext)
  };

  let presigned = state
    .storage
    .presign_write(&r2_key, Duration::from_secs(PRESIGN_EXPIRY_SECS))
    .await
    .map_err(|e| AppError::Internal(format!("presign_failed: {}", e)))?;

  let deadline = current_unix_timestamp() + PRESIGN_EXPIRY_SECS as i64;
  let token_payload = format!(
    "{}|{}|{}|{}|{}|{}",
    slug, r2_key, hash_str, declared_size, safe_ext, deadline
  );
  let sig = state.rate_limiter.sign_token(&token_payload);
  let commit_token = format!("{}|{}", token_payload, sig);

  let json = format!(
    r#"{{"deduplicated":false,"slug":"{}","upload_url":"{}","method":"{}","commit_token":"{}"}}"#,
    slug,
    presigned.uri(),
    presigned.method(),
    commit_token
  );

  let mut resp = Response::new(Body::from(format!("{}\n", json)));
  resp.headers_mut().insert(
    header::CONTENT_TYPE,
    HeaderValue::from_static("application/json; charset=utf-8"),
  );
  Ok(resp)
}

pub async fn commit_presigned_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  let token = headers
    .get("x-kura-commit-token")
    .and_then(|v| v.to_str().ok())
    .ok_or(AppError::BadRequest("missing_commit_token"))?
    .trim();

  let (payload, sig) = token
    .rsplit_once('|')
    .ok_or(AppError::BadRequest("malformed_commit_token"))?;

  if !state.rate_limiter.verify_token(payload, sig) {
    return Err(AppError::Forbidden("invalid_commit_token_signature"));
  }

  let parts: Vec<&str> = payload.split('|').collect();
  if parts.len() != 6 {
    return Err(AppError::BadRequest("malformed_commit_token"));
  }

  let slug = parts[0];
  let r2_key = parts[1];
  let file_hash = parts[2];
  let expected_size = parts[3]
    .parse::<usize>()
    .map_err(|_| AppError::BadRequest("malformed_commit_token"))?;
  let safe_ext = parts[4];
  let deadline = parts[5]
    .parse::<i64>()
    .map_err(|_| AppError::BadRequest("malformed_commit_token"))?;

  let now = current_unix_timestamp();
  if now > deadline {
    let _ = state.storage.delete(r2_key).await;
    return Err(AppError::RequestTimeout("commit_token_expired"));
  }

  let mut r2_guard = R2ObjectGuard::new(state.storage.clone(), r2_key.to_string());

  let meta = state
    .storage
    .stat(r2_key)
    .await
    .map_err(|_| AppError::BadRequest("r2_object_not_found"))?;

  if meta.content_length() as usize != expected_size {
    return Err(AppError::BadRequest("uploaded_size_mismatch"));
  }

  ensure_not_blacklisted(&state, file_hash).await?;

  let expiry_policy = extract_expiry_policy(&headers)?;
  let unlock_at = extract_timelock_header(&headers)?;
  let shamir_m = extract_shamir_threshold(&headers)?;
  let is_e2ee = extract_e2ee_flag(&headers);
  let album_id = extract_album_id(&headers);
  let creds = derive_security_creds(&state, &headers).await?;
  let is_protected_or_ephemeral = expiry_policy.is_ephemeral()
    || creds.pw.is_some()
    || creds.duress.is_some()
    || is_e2ee
    || unlock_at.is_some()
    || shamir_m.is_some();

  let sniff_len = expected_size.min(SNIFF_BUFFER_SIZE);
  let first_bytes = state
    .storage
    .read_with(r2_key)
    .range(0..sniff_len as u64)
    .await
    .map_err(|_| AppError::BadRequest("r2_sniff_read_failed"))?
    .to_vec();

  let content_type = if is_e2ee {
    "application/octet-stream"
  } else {
    let (_, mime, _) = resolve_safe_format(&first_bytes, Some(safe_ext))?;
    mime
  };

  finalize_upload_record(
    &state,
    &peer_addr,
    &headers,
    slug,
    safe_ext,
    file_hash,
    r2_key,
    content_type,
    expected_size,
    expiry_policy,
    unlock_at,
    shamir_m,
    None,
    creds,
    is_e2ee,
    is_protected_or_ephemeral,
    album_id,
    &mut r2_guard,
  )
  .await
}

// ============================================================================
// DIRECT STREAM & MULTIPART UPLOAD HANDLERS
// ============================================================================

pub async fn upload_put_named_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  AxumPath(filename): AxumPath<String>,
  mut req: Request,
) -> Result<Response, AppError> {
  if let Ok(hv) = HeaderValue::from_str(&filename) {
    req.headers_mut()
      .insert(header::HeaderName::from_static("x-kura-filename"), hv);
  }
  upload_handler(State(state), ConnectInfo(peer_addr), req).await
}

pub async fn upload_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  req: Request,
) -> Result<Response, AppError> {
  let headers = req.headers().clone();

  let mut content_length = 0usize;
  if let Some(cl_val) = headers.get(header::CONTENT_LENGTH) {
    let cl_str = cl_val
      .to_str()
      .map_err(|_| AppError::BadRequest("invalid_content_length"))?;
    content_length = cl_str
      .parse::<usize>()
      .map_err(|_| AppError::BadRequest("invalid_content_length"))?;
    if content_length > MAX_FILE_SIZE + MULTIPART_OVERHEAD {
      return Err(AppError::PayloadTooLarge("payload_exceeds_limit"));
    }
  }

  let client_sha256 = extract_client_sha256(&headers)?;
  let expiry_policy = extract_expiry_policy(&headers)?;
  let unlock_at = extract_timelock_header(&headers)?;
  let shamir_m = extract_shamir_threshold(&headers)?;
  let is_e2ee = extract_e2ee_flag(&headers);
  let album_id = extract_album_id(&headers);

  match state.rate_limiter.check_upload_admission(&peer_addr, &headers) {
    RateLimitDecision::Allowed => {}
    RateLimitDecision::PowRequired(c) => return Err(AppError::PowRequired(c)),
    RateLimitDecision::Rejected => return Err(AppError::TooManyRequests("rate_limit_exceeded")),
  }

  let creds = derive_security_creds(&state, &headers).await?;
  let is_protected_or_ephemeral = expiry_policy.is_ephemeral()
    || creds.pw.is_some()
    || creds.duress.is_some()
    || is_e2ee
    || unlock_at.is_some()
    || shamir_m.is_some();

  let mut preflight_dedup_url: Option<(String, String)> = None;
  if let Some(ref hash_bytes) = client_sha256 {
    let hash_str = std::str::from_utf8(hash_bytes).unwrap_or_default();

    ensure_not_blacklisted(&state, hash_str).await?;

    if !is_protected_or_ephemeral && album_id.is_none() {
      if let Some((existing_slug, existing_filename)) =
        find_deduplicated_file(&state, hash_str).await?
      {
        let origin = resolve_request_origin(
          &peer_addr,
          &headers,
          state.app_origin.as_deref(),
          &state.public_url,
        );
        let url = format!("{}/{}\n", origin, existing_filename);
        if headers.contains_key(header::EXPECT) || content_length <= MULTIPART_OVERHEAD {
          return build_upload_response(url, &existing_slug, None, true);
        }
        preflight_dedup_url = Some((existing_slug, url));
      }
    }
  }

  let _inflight = InflightGuard::try_acquire(state.inflight_counter.clone())
    .ok_or(AppError::TooManyRequests("server_busy_try_again"))?;

  let _permit = timeout(SEMAPHORE_WAIT_TIMEOUT, state.upload_semaphore.acquire())
    .await
    .map_err(|_| AppError::TooManyRequests("server_busy_try_again"))?
    .map_err(|_| AppError::Internal("semaphore_closed".into()))?;

  let is_multipart = headers
    .get(header::CONTENT_TYPE)
    .and_then(|v| v.to_str().ok())
    .map(|ct| ct.starts_with("multipart/form-data"))
    .unwrap_or(false);

  if is_multipart {
    let multipart = Multipart::from_request(req, &state)
      .await
      .map_err(|_| AppError::BadRequest("invalid_multipart_request"))?;

    timeout(
      UPLOAD_HARD_TIMEOUT,
      process_multipart_upload(
        &state,
        &peer_addr,
        &headers,
        multipart,
        client_sha256,
        preflight_dedup_url,
        expiry_policy,
        unlock_at,
        shamir_m,
        creds,
        is_e2ee,
        album_id,
      ),
    )
    .await
    .map_err(|_| AppError::RequestTimeout("upload_deadline_exceeded"))?
  } else {
    let ext_hint = headers
      .get("x-kura-filename")
      .and_then(|v| v.to_str().ok())
      .and_then(extract_safe_client_extension);
    let body_stream = BodyChunkStream::new(req.into_body());

    timeout(
      UPLOAD_HARD_TIMEOUT,
      process_raw_stream_upload(
        &state,
        &peer_addr,
        &headers,
        body_stream,
        ext_hint,
        client_sha256,
        preflight_dedup_url,
        expiry_policy,
        unlock_at,
        shamir_m,
        creds,
        is_e2ee,
        album_id,
      ),
    )
    .await
    .map_err(|_| AppError::RequestTimeout("upload_deadline_exceeded"))?
  }
}

/// Unified Military-Grade Streaming Pipeline:
/// - Single-pass R2 direct write (eliminates redundant R2 Copy/Rename operations)
/// - Constant-time SHA-256 verification
/// - Batched 256 KiB encryption buffer (eliminates per-chunk heap allocations)
#[allow(clippy::too_many_arguments)]
async fn execute_unified_stream_upload<'a>(
  state: &AppState,
  peer_addr: &SocketAddr,
  headers: &HeaderMap,
  mut source: PayloadStream<'a>,
  client_ext_hint: Option<String>,
  client_sha256: Option<[u8; 64]>,
  expiry_policy: ExpiryPolicy,
  unlock_at: Option<i64>,
  shamir_m: Option<i64>,
  creds: SecurityCreds,
  is_e2ee: bool,
  album_id: Option<String>,
) -> Result<Response, AppError> {
  let is_protected_or_ephemeral = expiry_policy.is_ephemeral()
    || creds.pw.is_some()
    || creds.duress.is_some()
    || is_e2ee
    || unlock_at.is_some()
    || shamir_m.is_some();

  let mut hasher = Sha256::new();
  let mut total_size: usize = 0;
  let mut mem_buffer = Vec::with_capacity(SNIFF_BUFFER_SIZE.max(64 * 1024));
  let mut stream_eof = false;

  while mem_buffer.len() < R2_PART_SIZE {
    match source.next_chunk().await? {
      Some(chunk) => {
        total_size = total_size.saturating_add(chunk.len());
        if total_size > MAX_FILE_SIZE {
          return Err(AppError::PayloadTooLarge("payload_exceeds_limit"));
        }
        hasher.update(&chunk);
        mem_buffer.extend_from_slice(&chunk);
      }
      None => {
        stream_eof = true;
        break;
      }
    }
  }

  if total_size == 0 {
    return Err(AppError::BadRequest("empty_payload"));
  }

  let sniff_len = mem_buffer.len().min(SNIFF_BUFFER_SIZE);
  let (safe_ext, content_type, inline_safe) = if is_e2ee {
    let ext = client_ext_hint.unwrap_or_else(|| "enc".to_string());
    (ext, "application/octet-stream", false)
  } else {
    resolve_safe_format(&mem_buffer[..sniff_len], client_ext_hint.as_deref())?
  };

  let slug = allocate_unique_slug(state).await?;

  let r2_storage_key = if is_protected_or_ephemeral {
    format!("vault/{}.{}", generate_random_string(24), safe_ext)
  } else {
    format!("{}.{}", slug, safe_ext)
  };

  let download_filename = format!("{}.{}", slug, safe_ext);
  let disposition = if inline_safe {
    format!("inline; filename=\"{}\"", download_filename)
  } else {
    format!("attachment; filename=\"{}\"", download_filename)
  };
  let cache_ctrl = if is_protected_or_ephemeral {
    "private, no-store"
  } else {
    "public, max-age=31536000, immutable"
  };

  let server_dek_opt = if is_protected_or_ephemeral {
    Some(generate_wrapped_server_dek(&state.rate_limiter.boot_secret, &slug))
  } else {
    None
  };

  let mut r2_guard = R2ObjectGuard::new(state.storage.clone(), r2_storage_key.clone());

  if stream_eof {
    let computed_hex = encode_hex_sha256(&hasher.finalize());
    if let Some(ref expected_hex) = client_sha256 {
      if !constant_time_eq(&computed_hex, expected_hex) {
        return Err(AppError::BadRequest("sha256_integrity_mismatch"));
      }
    }
    let file_hash = std::str::from_utf8(&computed_hex).unwrap_or_default();

    ensure_not_blacklisted(state, file_hash).await?;

    if !is_protected_or_ephemeral && album_id.is_none() {
      if let Some((existing_slug, existing_filename)) =
        find_deduplicated_file(state, file_hash).await?
      {
        let origin = resolve_request_origin(
          peer_addr,
          headers,
          state.app_origin.as_deref(),
          &state.public_url,
        );
        return build_upload_response(
          format!("{}/{}\n", origin, existing_filename),
          &existing_slug,
          None,
          true,
        );
      }
    }

    if let Some((ref dek, ref nonce, _)) = server_dek_opt {
      chacha20_xor_at_offset(dek, nonce, 0, &mut mem_buffer);
    }

    state
      .storage
      .write_with(&r2_storage_key, mem_buffer)
      .content_type(content_type)
      .content_disposition(&disposition)
      .cache_control(cache_ctrl)
      .await
      .map_err(|_| AppError::Internal("r2_write_failed".into()))?;

    let stored_dek = server_dek_opt.map(|(_, nonce, wrapped)| (nonce, wrapped));

    return finalize_upload_record(
      state,
      peer_addr,
      headers,
      &slug,
      &safe_ext,
      file_hash,
      &r2_storage_key,
      content_type,
      total_size,
      expiry_policy,
      unlock_at,
      shamir_m,
      stored_dek,
      creds,
      is_e2ee,
      is_protected_or_ephemeral,
      album_id,
      &mut r2_guard,
    )
    .await;
  }

  // Large payload (> 8 MiB): Stream directly to final R2 key with full HTTP metadata
  let mut writer = state
    .storage
    .writer_with(&r2_storage_key)
    .content_type(content_type)
    .content_disposition(&disposition)
    .cache_control(cache_ctrl)
    .await
    .map_err(|_| AppError::Internal("r2_writer_init_failed".into()))?;

  let mut cipher_offset = 0u64;
  if let Some((ref dek, ref nonce, _)) = server_dek_opt {
    chacha20_xor_at_offset(dek, nonce, cipher_offset, &mut mem_buffer);
    cipher_offset += mem_buffer.len() as u64;
  }

  writer
    .write(Bytes::from(std::mem::take(&mut mem_buffer)))
    .await
    .map_err(|_| AppError::Internal("r2_stream_write_failed".into()))?;

  // Reusable batch buffer to eliminate per-chunk heap allocations
  let mut batch_buf = Vec::with_capacity(DISK_BUFFER_SIZE);

  while let Some(chunk) = source.next_chunk().await? {
    total_size = total_size.saturating_add(chunk.len());
    if total_size > MAX_FILE_SIZE {
      let _ = writer.abort().await;
      return Err(AppError::PayloadTooLarge("payload_exceeds_limit"));
    }
    hasher.update(&chunk);
    batch_buf.extend_from_slice(&chunk);

    if batch_buf.len() >= DISK_BUFFER_SIZE {
      if let Some((ref dek, ref nonce, _)) = server_dek_opt {
        chacha20_xor_at_offset(dek, nonce, cipher_offset, &mut batch_buf);
        cipher_offset += batch_buf.len() as u64;
      }
      if writer
        .write(Bytes::copy_from_slice(&batch_buf))
        .await
        .is_err()
      {
        let _ = writer.abort().await;
        return Err(AppError::Internal("r2_stream_write_failed".into()));
      }
      batch_buf.clear();
    }
  }

  if !batch_buf.is_empty() {
    if let Some((ref dek, ref nonce, _)) = server_dek_opt {
      chacha20_xor_at_offset(dek, nonce, cipher_offset, &mut batch_buf);
    }
    if writer.write(Bytes::from(batch_buf)).await.is_err() {
      let _ = writer.abort().await;
      return Err(AppError::Internal("r2_stream_write_failed".into()));
    }
  }

  let computed_hex = encode_hex_sha256(&hasher.finalize());
  if let Some(ref expected_hex) = client_sha256 {
    if !constant_time_eq(&computed_hex, expected_hex) {
      let _ = writer.abort().await;
      return Err(AppError::BadRequest("sha256_integrity_mismatch"));
    }
  }

  let file_hash = std::str::from_utf8(&computed_hex).unwrap_or_default();
  if let Err(e) = ensure_not_blacklisted(state, file_hash).await {
    let _ = writer.abort().await;
    return Err(e);
  }

  if !is_protected_or_ephemeral && album_id.is_none() {
    if let Some((existing_slug, existing_filename)) =
      find_deduplicated_file(state, file_hash).await?
    {
      let _ = writer.abort().await;
      let origin = resolve_request_origin(
        peer_addr,
        headers,
        state.app_origin.as_deref(),
        &state.public_url,
      );
      return build_upload_response(
        format!("{}/{}\n", origin, existing_filename),
        &existing_slug,
        None,
        true,
      );
    }
  }

  writer
    .close()
    .await
    .map_err(|_| AppError::Internal("r2_stream_close_failed".into()))?;

  let stored_dek = server_dek_opt.map(|(_, nonce, wrapped)| (nonce, wrapped));

  finalize_upload_record(
    state,
    peer_addr,
    headers,
    &slug,
    &safe_ext,
    file_hash,
    &r2_storage_key,
    content_type,
    total_size,
    expiry_policy,
    unlock_at,
    shamir_m,
    stored_dek,
    creds,
    is_e2ee,
    is_protected_or_ephemeral,
    album_id,
    &mut r2_guard,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
pub async fn process_raw_stream_upload(
  state: &AppState,
  peer_addr: &SocketAddr,
  headers: &HeaderMap,
  mut stream: BodyChunkStream,
  client_ext_hint: Option<String>,
  client_sha256: Option<[u8; 64]>,
  preflight_dedup_url: Option<(String, String)>,
  expiry_policy: ExpiryPolicy,
  unlock_at: Option<i64>,
  shamir_m: Option<i64>,
  creds: SecurityCreds,
  is_e2ee: bool,
  album_id: Option<String>,
) -> Result<Response, AppError> {
  if let Some((existing_slug, url)) = preflight_dedup_url {
    let mut drained = 0usize;
    while let Some(chunk) = timeout(CHUNK_READ_TIMEOUT, stream.next_chunk())
      .await
      .map_err(|_| AppError::RequestTimeout("stream_stalled"))?
      .map_err(|_| AppError::BadRequest("stream_interrupted"))?
    {
      drained = drained.saturating_add(chunk.len());
      if drained > MAX_FILE_SIZE {
        return Err(AppError::PayloadTooLarge("payload_exceeds_limit"));
      }
    }
    return build_upload_response(url, &existing_slug, None, true);
  }

  execute_unified_stream_upload(
    state,
    peer_addr,
    headers,
    PayloadStream::Raw(stream),
    client_ext_hint,
    client_sha256,
    expiry_policy,
    unlock_at,
    shamir_m,
    creds,
    is_e2ee,
    album_id,
  )
  .await
}

#[allow(clippy::too_many_arguments)]
pub async fn process_multipart_upload(
  state: &AppState,
  peer_addr: &SocketAddr,
  headers: &HeaderMap,
  mut multipart: Multipart,
  client_sha256: Option<[u8; 64]>,
  preflight_dedup_url: Option<(String, String)>,
  expiry_policy: ExpiryPolicy,
  unlock_at: Option<i64>,
  shamir_m: Option<i64>,
  creds: SecurityCreds,
  is_e2ee: bool,
  album_id: Option<String>,
) -> Result<Response, AppError> {
  if let Some((existing_slug, url)) = preflight_dedup_url {
    let mut drained = 0usize;
    while let Some(mut field) = timeout(CHUNK_READ_TIMEOUT, multipart.next_field())
      .await
      .map_err(|_| AppError::RequestTimeout("stream_stalled"))?
      .map_err(|_| AppError::BadRequest("malformed_multipart_stream"))?
    {
      while let Some(chunk) = timeout(CHUNK_READ_TIMEOUT, field.chunk())
        .await
        .map_err(|_| AppError::RequestTimeout("stream_stalled"))?
        .map_err(|_| AppError::BadRequest("stream_interrupted"))?
      {
        drained = drained.saturating_add(chunk.len());
        if drained > MAX_FILE_SIZE {
          return Err(AppError::PayloadTooLarge("payload_exceeds_limit"));
        }
      }
    }
    return build_upload_response(url, &existing_slug, None, true);
  }

  let mut inspected_fields = 0usize;
  while let Some(field) = timeout(CHUNK_READ_TIMEOUT, multipart.next_field())
    .await
    .map_err(|_| AppError::RequestTimeout("stream_stalled"))?
    .map_err(|_| AppError::BadRequest("malformed_multipart_stream"))?
  {
    inspected_fields += 1;
    if inspected_fields > MAX_MULTIPART_FIELDS {
      return Err(AppError::BadRequest("excessive_multipart_fields"));
    }

    if field.name() != Some("file") {
      continue;
    }

    let client_ext_hint = field.file_name().and_then(extract_safe_client_extension);

    return execute_unified_stream_upload(
      state,
      peer_addr,
      headers,
      PayloadStream::Multipart(field),
      client_ext_hint,
      client_sha256,
      expiry_policy,
      unlock_at,
      shamir_m,
      creds,
      is_e2ee,
      album_id,
    )
    .await;
  }

  Err(AppError::BadRequest("missing_file_field"))
}

// ============================================================================
// DATABASE COMMIT & RESPONSE BUILDERS
// ============================================================================

#[allow(clippy::too_many_arguments)]
pub async fn finalize_upload_record(
  state: &AppState,
  peer_addr: &SocketAddr,
  headers: &HeaderMap,
  slug: &str,
  safe_ext: &str,
  file_hash: &str,
  r2_storage_key: &str,
  content_type: &str,
  total_size: usize,
  expiry_policy: ExpiryPolicy,
  unlock_at: Option<i64>,
  shamir_m: Option<i64>,
  stored_dek: Option<([u8; 12], Vec<u8>)>,
  creds: SecurityCreds,
  is_e2ee: bool,
  is_protected_or_ephemeral: bool,
  album_id: Option<String>,
  r2_guard: &mut R2ObjectGuard,
) -> Result<Response, AppError> {
  if !is_protected_or_ephemeral && album_id.is_none() {
    if let Some((concurrent_slug, concurrent_filename)) =
      find_deduplicated_file(state, file_hash).await?
    {
      let origin = resolve_request_origin(
        peer_addr,
        headers,
        state.app_origin.as_deref(),
        &state.public_url,
      );
      return build_upload_response(
        format!("{}/{}\n", origin, concurrent_filename),
        &concurrent_slug,
        None,
        true,
      );
    }
  }

  let now = current_unix_timestamp();
  let expires_at = expiry_policy.ttl_seconds.map(|ttl| now.saturating_add(ttl));
  let burn_flag: i64 = if expiry_policy.burn_after_read { 1 } else { 0 };
  let e2ee_flag: i64 = if is_e2ee { 1 } else { 0 };
  let (pw_salt, pw_hash) = match creds.pw {
    Some((s, h)) => (Some(s.to_vec()), Some(h.to_vec())),
    None => (None, None),
  };
  let (duress_salt, duress_hash) = match creds.duress {
    Some((s, h)) => (Some(s.to_vec()), Some(h.to_vec())),
    None => (None, None),
  };
  let (dek_nonce, dek_wrapped) = match stored_dek {
    Some((n, w)) => (Some(n.to_vec()), Some(w)),
    None => (None, None),
  };

  let (delete_key, delete_token_hash) = generate_delete_key_pair();

  sqlx::query(
    r#"
    INSERT INTO files (
      slug, hash, filename, content_type, size, created_at,
      expires_at, unlock_at, burn_after_read, password_salt, password_hash,
      duress_salt, duress_hash, e2ee, shamir_threshold,
      server_dek_nonce, server_wrapped_dek, max_views, delete_token_hash, album_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    "#,
  )
  .bind(slug)
  .bind(file_hash)
  .bind(r2_storage_key)
  .bind(content_type)
  .bind(total_size as i64)
  .bind(now)
  .bind(expires_at)
  .bind(unlock_at)
  .bind(burn_flag)
  .bind(pw_salt)
  .bind(pw_hash)
  .bind(duress_salt)
  .bind(duress_hash)
  .bind(e2ee_flag)
  .bind(shamir_m)
  .bind(dek_nonce)
  .bind(dek_wrapped)
  .bind(expiry_policy.max_views)
  .bind(delete_token_hash.to_vec())
  .bind(album_id)
  .execute(&state.db)
  .await?;

  r2_guard.commit();

  let origin = resolve_request_origin(
    peer_addr,
    headers,
    state.app_origin.as_deref(),
    &state.public_url,
  );

  let final_url = if is_protected_or_ephemeral || safe_ext == "note" {
    format!("{}/v/{}.{}\n", origin, slug, safe_ext)
  } else {
    format!("{}/{}.{}\n", origin, slug, safe_ext)
  };

  build_upload_response(final_url, slug, Some(&delete_key), false)
}

pub fn build_upload_response(
  url_body: String,
  slug: &str,
  delete_key: Option<&str>,
  deduplicated: bool,
) -> Result<Response, AppError> {
  let mut resp = Response::new(Body::from(url_body));
  let headers = resp.headers_mut();
  headers.insert(
    header::CONTENT_TYPE,
    HeaderValue::from_static("text/plain; charset=utf-8"),
  );
  if let Ok(sv) = HeaderValue::from_str(slug) {
    headers.insert(header::HeaderName::from_static("x-kura-slug"), sv);
  }
  if let Some(dk) = delete_key {
    if let Ok(dv) = HeaderValue::from_str(dk) {
      headers.insert(header::HeaderName::from_static("x-kura-delete-key"), dv);
    }
  }
  headers.insert(
    header::HeaderName::from_static("x-kura-deduplicated"),
    HeaderValue::from_static(if deduplicated { "1" } else { "0" }),
  );
  headers.insert(
    header::ACCESS_CONTROL_EXPOSE_HEADERS,
    HeaderValue::from_static("X-Kura-Delete-Key, X-Kura-Slug, X-Kura-Deduplicated"),
  );
  Ok(resp)
}