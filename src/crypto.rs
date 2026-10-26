use axum::http::{header, HeaderMap};
use rand::{distr::Alphanumeric, RngExt};
use sha2::{Digest, Sha256};
use std::{
  hint::black_box,
  net::{IpAddr, SocketAddr},
  path::Path,
  ptr::write_volatile,
  sync::atomic::{compiler_fence, Ordering},
  time::Duration,
};
use tokio::time::timeout;

use crate::config::*;

const CHACHA_BLOCK_SIZE: usize = 64;
const CHACHA_CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
const DELETE_KEY_DOMAIN: &[u8] = b"kura_del_v1:";
const MAX_JSON_NESTING_DEPTH: usize = 32;

// ============================================================================
// VOLATILE MEMORY ZEROIZATION & CONSTANT-TIME BARRIERS
// ============================================================================

/// Compiler-barrier backed volatile memory scrubber (immune to LLVM dead-store elimination)
#[inline]
fn secure_zeroize_bytes(buf: &mut [u8]) {
  for byte in buf.iter_mut() {
    unsafe {
      write_volatile(byte, 0u8);
    }
  }
  compiler_fence(Ordering::SeqCst);
}

/// Volatile memory scrubber for 32-bit word arrays (ChaCha20 state & key schedules)
#[inline]
fn secure_zeroize_u32(buf: &mut [u32]) {
  for word in buf.iter_mut() {
    unsafe {
      write_volatile(word, 0u32);
    }
  }
  compiler_fence(Ordering::SeqCst);
}

/// Branchless constant-time byte slice comparison protected by LLVM `black_box` barriers
#[inline]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
  if a.len() != b.len() {
    return false;
  }
  let mut diff = 0u8;
  for (&x, &y) in a.iter().zip(b.iter()) {
    diff = black_box(diff | black_box(x ^ y));
  }
  black_box(diff) == 0
}

// ============================================================================
// RFC 8439 CHACHA20 STREAM CIPHER ENGINE (VECTORIZED WORD-LEVEL CORE)
// ============================================================================

/// Constant-Time RFC 8439 ChaCha20 Quarter-Round (100% Immune to Cache-Timing Attacks)
#[inline(always)]
fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
  state[a] = state[a].wrapping_add(state[b]);
  state[d] = (state[d] ^ state[a]).rotate_left(16);
  state[c] = state[c].wrapping_add(state[d]);
  state[b] = (state[b] ^ state[c]).rotate_left(12);
  state[a] = state[a].wrapping_add(state[b]);
  state[d] = (state[d] ^ state[a]).rotate_left(8);
  state[c] = state[c].wrapping_add(state[d]);
  state[b] = (state[b] ^ state[c]).rotate_left(7);
}

/// Initializes the 16-word ChaCha20 state matrix from key, counter, and 96-bit nonce
#[inline(always)]
fn chacha20_init_state(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u32; 16] {
  [
    CHACHA_CONSTANTS[0],
    CHACHA_CONSTANTS[1],
    CHACHA_CONSTANTS[2],
    CHACHA_CONSTANTS[3],
    u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
    u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
    u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
    u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
    u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
    u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
    u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
    u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
    counter,
    u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
    u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
    u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
  ]
}

/// Executes 20 rounds (10 double-rounds) of the ChaCha20 core permutation in-place
#[inline(always)]
fn chacha20_permute(state: &mut [u32; 16]) {
  let initial = *state;
  for _ in 0..10 {
    chacha20_quarter_round(state, 0, 4, 8, 12);
    chacha20_quarter_round(state, 1, 5, 9, 13);
    chacha20_quarter_round(state, 2, 6, 10, 14);
    chacha20_quarter_round(state, 3, 7, 11, 15);
    chacha20_quarter_round(state, 0, 5, 10, 15);
    chacha20_quarter_round(state, 1, 6, 11, 12);
    chacha20_quarter_round(state, 2, 7, 8, 13);
    chacha20_quarter_round(state, 3, 4, 9, 14);
  }
  for i in 0..16 {
    state[i] = state[i].wrapping_add(initial[i]);
  }
}

pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
  let mut state = chacha20_init_state(key, counter, nonce);
  chacha20_permute(&mut state);

  let mut out = [0u8; 64];
  for (dst, &word) in out.chunks_exact_mut(4).zip(state.iter()) {
    dst.copy_from_slice(&word.to_le_bytes());
  }
  secure_zeroize_u32(&mut state);
  out
}

/// Applies ChaCha20 stream cipher in-place at arbitrary byte offset (supports HTTP Range requests)
/// Optimized with word-aligned 64-byte full-block fast paths for SIMD auto-vectorization
pub fn chacha20_xor_at_offset(
  key: &[u8; 32],
  nonce: &[u8; 12],
  start_offset: u64,
  data: &mut [u8],
) {
  if data.is_empty() {
    return;
  }

  let mut processed = 0usize;
  let total_len = data.len();

  // 1. Handle unaligned leading partial block if start_offset is not a multiple of 64
  let initial_byte_in_block = (start_offset & 63) as usize;
  if initial_byte_in_block != 0 {
    let block_idx = (start_offset >> 6) as u32;
    let mut keystream = chacha20_block(key, block_idx.wrapping_add(1), nonce);
    let take = (CHACHA_BLOCK_SIZE - initial_byte_in_block).min(total_len);
    for i in 0..take {
      data[i] ^= keystream[initial_byte_in_block + i];
    }
    secure_zeroize_bytes(&mut keystream);
    processed += take;
  }

  // 2. Fast-path: Process contiguous 64-byte aligned blocks directly via 32-bit word XORs
  let mut current_block_idx = ((start_offset.saturating_add(processed as u64)) >> 6) as u32;
  let base_state = chacha20_init_state(key, 0, nonce);

  while total_len - processed >= CHACHA_BLOCK_SIZE {
    current_block_idx = current_block_idx.wrapping_add(1);
    let mut state = base_state;
    state[12] = current_block_idx;
    chacha20_permute(&mut state);

    let block_slice = &mut data[processed..processed + CHACHA_BLOCK_SIZE];
    for (chunk, &ks_word) in block_slice.chunks_exact_mut(4).zip(state.iter()) {
      let plain_word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
      chunk.copy_from_slice(&(plain_word ^ ks_word).to_le_bytes());
    }
    processed += CHACHA_BLOCK_SIZE;
  }

  // 3. Handle remaining trailing bytes (< 64 bytes)
  let remaining = total_len - processed;
  if remaining > 0 {
    current_block_idx = current_block_idx.wrapping_add(1);
    let mut state = base_state;
    state[12] = current_block_idx;
    chacha20_permute(&mut state);

    let mut keystream = [0u8; 64];
    for (dst, &word) in keystream.chunks_exact_mut(4).zip(state.iter()) {
      dst.copy_from_slice(&word.to_le_bytes());
    }
    for i in 0..remaining {
      data[processed + i] ^= keystream[i];
    }
    secure_zeroize_bytes(&mut keystream);
    secure_zeroize_u32(&mut state);
  }
}

// ============================================================================
// ZERO-ALLOCATION HMAC-SHA256, HKDF-SHA256 & ENVELOPE CRYPTO-SHREDDING
// ============================================================================

/// Zero-allocation multi-part HMAC-SHA256 engine with automatic key-pad scrubbing
#[inline]
fn hmac_sha256_iov(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
  let mut k_block = [0u8; 64];
  if key.len() > 64 {
    let mut h = Sha256::new();
    h.update(key);
    k_block[..32].copy_from_slice(&h.finalize());
  } else {
    k_block[..key.len()].copy_from_slice(key);
  }

  let mut ipad = [0x36u8; 64];
  let mut opad = [0x5cu8; 64];
  for i in 0..64 {
    ipad[i] ^= k_block[i];
    opad[i] ^= k_block[i];
  }
  secure_zeroize_bytes(&mut k_block);

  let mut inner = Sha256::new();
  inner.update(ipad);
  for part in parts {
    inner.update(part);
  }
  let mut inner_digest: [u8; 32] = inner.finalize().into();
  secure_zeroize_bytes(&mut ipad);

  let mut outer = Sha256::new();
  outer.update(opad);
  outer.update(inner_digest);
  let result: [u8; 32] = outer.finalize().into();

  secure_zeroize_bytes(&mut opad);
  secure_zeroize_bytes(&mut inner_digest);
  result
}

#[inline]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
  hmac_sha256_iov(key, &[message])
}

/// RFC 5869 HKDF-SHA256 Extract & Expand (Zero-Heap-Allocation implementation)
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
  let effective_salt = if salt.is_empty() { &[0u8; 32] } else { salt };
  let mut prk = hmac_sha256_iov(effective_salt, &[ikm]);
  let out = hmac_sha256_iov(&prk, &[info, &[0x01]]);
  secure_zeroize_bytes(&mut prk);
  out
}

/// Generates full-byte cryptographic entropy from the OS CSPRNG
pub fn generate_csprng_bytes<const N: usize>() -> [u8; N] {
  let mut rng = rand::rng();
  let mut raw = [0u8; N];
  rng.fill(&mut raw);
  raw
}

/// Generates wrapped Server DEK for R2 Crypto-Shredding using orthogonal Encryption & MAC subkeys
/// and full Associated Data (AAD) binding over (domain || slug || nonce || ciphertext)
pub fn generate_wrapped_server_dek(
  master_secret: &[u8; 32],
  slug: &str,
) -> ([u8; 32], [u8; 12], Vec<u8>) {
  let dek = generate_csprng_bytes::<32>();
  let nonce = generate_csprng_bytes::<12>();

  // Cryptographic key separation: distinct subkeys for encryption vs authentication
  let mut enc_kek = hkdf_sha256(master_secret, slug.as_bytes(), b"kura_r2_crypto_shred_enc_v2");
  let mut mac_kek = hkdf_sha256(master_secret, slug.as_bytes(), b"kura_r2_crypto_shred_mac_v2");

  let mut wrapped = Vec::with_capacity(64);
  wrapped.extend_from_slice(&dek);
  chacha20_xor_at_offset(&enc_kek, &nonce, 0, &mut wrapped);

  // Bind slug and nonce into the authentication tag to prevent chosen-nonce DEK mutation
  let tag = hmac_sha256_iov(
    &mac_kek,
    &[b"kura_dek_aad_v2:", slug.as_bytes(), &[0xFF], &nonce, &wrapped],
  );
  wrapped.extend_from_slice(&tag);

  secure_zeroize_bytes(&mut enc_kek);
  secure_zeroize_bytes(&mut mac_kek);
  (dek, nonce, wrapped)
}

/// Unwraps and authenticates the Server DEK in constant time
/// Includes backward-compatible verification for v2 legacy envelopes if present
pub fn unwrap_server_dek(
  master_secret: &[u8; 32],
  slug: &str,
  nonce_slice: &[u8],
  wrapped: &[u8],
) -> Option<([u8; 32], [u8; 12])> {
  if nonce_slice.len() != 12 || wrapped.len() != 64 {
    return None;
  }

  let (ct, tag) = wrapped.split_at(32);
  let mut nonce = [0u8; 12];
  nonce.copy_from_slice(nonce_slice);

  let mut enc_kek = hkdf_sha256(master_secret, slug.as_bytes(), b"kura_r2_crypto_shred_enc_v2");
  let mut mac_kek = hkdf_sha256(master_secret, slug.as_bytes(), b"kura_r2_crypto_shred_mac_v2");

  let expected_aad_tag = hmac_sha256_iov(
    &mac_kek,
    &[b"kura_dek_aad_v2:", slug.as_bytes(), &[0xFF], &nonce, ct],
  );
  secure_zeroize_bytes(&mut mac_kek);

  if constant_time_eq(tag, &expected_aad_tag) {
    let mut dek = [0u8; 32];
    dek.copy_from_slice(ct);
    chacha20_xor_at_offset(&enc_kek, &nonce, 0, &mut dek);
    secure_zeroize_bytes(&mut enc_kek);
    return Some((dek, nonce));
  }
  secure_zeroize_bytes(&mut enc_kek);

  // Seamless fallback for envelopes created prior to subkey separation
  let mut legacy_kek = hkdf_sha256(master_secret, slug.as_bytes(), b"kura_r2_crypto_shred_kek_v2");
  let expected_legacy_tag = hmac_sha256(&legacy_kek, ct);
  if !constant_time_eq(tag, &expected_legacy_tag) {
    secure_zeroize_bytes(&mut legacy_kek);
    return None;
  }

  let mut dek = [0u8; 32];
  dek.copy_from_slice(ct);
  chacha20_xor_at_offset(&legacy_kek, &nonce, 0, &mut dek);
  secure_zeroize_bytes(&mut legacy_kek);
  Some((dek, nonce))
}

// ============================================================================
// MEMORY-HARD KDF & CONSTANT-TIME DUAL-CREDENTIAL AUTHENTICATION
// ============================================================================

pub async fn run_timing_shield(state: &AppState, seed: &str) {
  if let Ok(_permit) = timeout(Duration::from_millis(250), state.auth_semaphore.acquire()).await {
    let owned = seed.as_bytes().to_vec();
    let dummy_salt = state.rate_limiter.boot_secret;
    let _ = tokio::task::spawn_blocking(move || {
      let _ = black_box(derive_password_verifier(&owned, &dummy_salt[..16]));
    })
    .await;
  }
}

/// Evaluates primary and duress credentials in strict constant time:
/// - Always executes exactly 2 KDF operations regardless of which credentials are configured
/// - Fixes authentication bypass when only a duress password is set (`pw_hash == None`)
pub fn evaluate_password_or_duress(
  candidate: &[u8],
  pw_salt: Option<&[u8]>,
  pw_hash: Option<&[u8]>,
  duress_salt: Option<&[u8]>,
  duress_hash: Option<&[u8]>,
) -> AuthOutcome {
  let dummy_salt_primary = duress_salt.unwrap_or(b"kura_dummy_psalt");
  let dummy_salt_duress = pw_salt.unwrap_or(b"kura_dummy_dsalt");
  let dummy_hash = [0xAAu8; 32];

  let primary_ok = match (pw_salt, pw_hash) {
    (Some(s), Some(h)) => verify_password(candidate, s, h),
    _ => {
      let _ = black_box(verify_password(candidate, dummy_salt_primary, &dummy_hash));
      // Only allow automatic primary pass-through if neither primary nor duress password was configured
      duress_hash.is_none()
    }
  };

  let duress_ok = match (duress_salt, duress_hash) {
    (Some(ds), Some(dh)) => verify_password(candidate, ds, dh),
    _ => {
      let _ = black_box(verify_password(candidate, dummy_salt_duress, &dummy_hash));
      false
    }
  };

  if duress_ok {
    AuthOutcome::DuressTriggered
  } else if primary_ok {
    AuthOutcome::ValidPrimary
  } else {
    AuthOutcome::Invalid
  }
}

pub async fn derive_security_creds(
  state: &AppState,
  headers: &HeaderMap,
) -> Result<SecurityCreds, AppError> {
  let raw_pw = extract_raw_password(headers)?;
  let raw_duress = extract_duress_password(headers)?;

  if let (Some(ref p), Some(ref d)) = (&raw_pw, &raw_duress) {
    if constant_time_eq(p, d) {
      return Err(AppError::BadRequest("duress_must_differ_from_password"));
    }
  }

  if raw_pw.is_none() && raw_duress.is_none() {
    return Ok(SecurityCreds {
      pw: None,
      duress: None,
    });
  }

  let _auth_permit = state
    .auth_semaphore
    .acquire()
    .await
    .map_err(|_| AppError::Internal("auth_semaphore_closed".into()))?;

  tokio::task::spawn_blocking(move || {
    let pw = raw_pw.map(|mut b| {
      let res = generate_password_verifier(&b);
      secure_zeroize_bytes(&mut b);
      res
    });
    let duress = raw_duress.map(|mut b| {
      let res = generate_password_verifier(&b);
      secure_zeroize_bytes(&mut b);
      res
    });
    Ok(SecurityCreds { pw, duress })
  })
  .await
  .map_err(|_| AppError::Internal("pbkdf_worker_panicked".into()))?
}

pub fn generate_password_verifier(raw: &[u8]) -> ([u8; 16], [u8; 32]) {
  let salt = generate_csprng_bytes::<16>();
  let verifier = derive_password_verifier(raw, &salt);
  (salt, verifier)
}

/// Argon2id-style Hybrid Memory-Hard KDF (Data-Independent Phase + Data-Dependent Phase)
/// Hardened with Full-Lane XOR Folding and Volatile Memory Scrubbing
pub fn derive_password_verifier(password: &[u8], salt: &[u8]) -> [u8; 32] {
  let mut u = hmac_sha256_iov(password, &[salt, &1u32.to_be_bytes()]);
  let mut pbkdf2_out = u;

  for _ in 1..PBKDF2_ITERATIONS {
    u = hmac_sha256_iov(password, &[&u]);
    for i in 0..32 {
      pbkdf2_out[i] ^= u[i];
    }
  }
  secure_zeroize_bytes(&mut u);

  let mut index_seed = hkdf_sha256(salt, b"kura_argon2i_index_stream", &[]);
  let mut nonce = [0u8; 12];
  let copy_len = salt.len().min(12);
  nonce[..copy_len].copy_from_slice(&salt[..copy_len]);

  let mut matrix = vec![[0u8; 32]; MEMORY_HARD_BLOCKS];
  matrix[0] = pbkdf2_out;
  secure_zeroize_bytes(&mut pbkdf2_out);

  for i in 1..MEMORY_HARD_BLOCKS {
    let mut block = chacha20_block(&matrix[i - 1], i as u32, &nonce);
    matrix[i].copy_from_slice(&block[..32]);
    secure_zeroize_bytes(&mut block);
  }

  let mask = MEMORY_HARD_BLOCKS - 1;
  let total_rounds = MEMORY_HARD_ROUNDS + 2;

  for r in 0..total_rounds {
    let mut addr_stream = [0u8; 64];
    for i in 0..MEMORY_HARD_BLOCKS {
      let prev = matrix[(i + MEMORY_HARD_BLOCKS - 1) & mask];

      let dep_idx = if r < 2 {
        if i % 16 == 0 {
          addr_stream = chacha20_block(
            &index_seed,
            ((r * MEMORY_HARD_BLOCKS + i) / 16) as u32,
            &nonce,
          );
        }
        let offset = (i % 16) * 4;
        (u32::from_le_bytes([
          addr_stream[offset],
          addr_stream[offset + 1],
          addr_stream[offset + 2],
          addr_stream[offset + 3],
        ]) as usize)
          & mask
      } else {
        (u32::from_le_bytes([prev[0], prev[1], prev[2], prev[3]]) as usize) & mask
      };

      let dep = matrix[dep_idx];
      let mut h = Sha256::new();
      h.update(prev);
      h.update(dep);
      h.update(((r * MEMORY_HARD_BLOCKS + i) as u32).to_le_bytes());
      matrix[i] = h.finalize().into();
    }
    secure_zeroize_bytes(&mut addr_stream);
  }
  secure_zeroize_bytes(&mut index_seed);

  // Full-lane XOR folding: binds all 8,192 memory blocks into the final extraction state
  // to prevent TMTO / memory-pruning attacks while preserving the terminal block dependency
  let mut lane_accumulator = matrix[MEMORY_HARD_BLOCKS - 1];
  for block in matrix.iter().take(MEMORY_HARD_BLOCKS - 1) {
    for j in 0..32 {
      lane_accumulator[j] ^= block[j];
    }
  }

  let mut final_ikm = [0u8; 64];
  final_ikm[..32].copy_from_slice(&matrix[MEMORY_HARD_BLOCKS - 1]);
  final_ikm[32..].copy_from_slice(&lane_accumulator);

  let verifier = hkdf_sha256(salt, &final_ikm, b"kura_kdf_final_v2");

  // Scrub the entire 256 KiB memory matrix before deallocation
  for block in matrix.iter_mut() {
    secure_zeroize_bytes(block);
  }
  secure_zeroize_bytes(&mut lane_accumulator);
  secure_zeroize_bytes(&mut final_ikm);

  verifier
}

#[inline]
pub fn verify_password(candidate: &[u8], salt: &[u8], expected_hash: &[u8]) -> bool {
  if candidate.is_empty() || candidate.len() > 128 || expected_hash.len() != 32 {
    return false;
  }
  let mut derived = derive_password_verifier(candidate, salt);
  let matched = constant_time_eq(&derived, expected_hash);
  secure_zeroize_bytes(&mut derived);
  matched
}

// ============================================================================
// DELETE TOKEN DERIVATION & VERIFICATION
// ============================================================================

#[inline]
fn hash_delete_token(raw_token: &[u8]) -> [u8; 32] {
  let mut h = Sha256::new();
  h.update(DELETE_KEY_DOMAIN);
  h.update(raw_token);
  h.finalize().into()
}

pub fn generate_delete_key_pair() -> (String, [u8; 32]) {
  let raw_key = generate_random_string(DELETE_KEY_LENGTH);
  let digest = hash_delete_token(raw_key.as_bytes());
  (raw_key, digest)
}

#[inline]
pub fn verify_delete_key(candidate: &[u8], expected_hash: &[u8]) -> bool {
  if candidate.is_empty() || candidate.len() > 64 || expected_hash.len() != 32 {
    return false;
  }
  let mut derived = hash_delete_token(candidate);
  let matched = constant_time_eq(&derived, expected_hash);
  secure_zeroize_bytes(&mut derived);
  matched
}

// ============================================================================
// HTTP HEADER EXTRACTION & NETWORK ORIGIN / IP HARDENING
// ============================================================================

pub fn parse_byte_range(headers: &HeaderMap, total_size: u64) -> Option<(u64, u64)> {
  if total_size == 0 {
    return None;
  }
  let val = headers.get(header::RANGE)?.to_str().ok()?;
  let range_spec = val.strip_prefix("bytes=")?;
  if range_spec.contains(',') {
    return None;
  }
  let (start_str, end_str) = range_spec.split_once('-')?;
  if start_str.is_empty() {
    let suffix_len = end_str.parse::<u64>().ok()?;
    if suffix_len == 0 || suffix_len > total_size {
      return None;
    }
    Some((total_size - suffix_len, total_size - 1))
  } else {
    let start = start_str.parse::<u64>().ok()?;
    if start >= total_size {
      return None;
    }
    let end = if end_str.is_empty() {
      total_size - 1
    } else {
      end_str.parse::<u64>().ok()?.min(total_size - 1)
    };
    if start > end {
      return None;
    }
    Some((start, end))
  }
}

pub fn extract_anonymized_country(headers: &HeaderMap) -> Option<String> {
  let raw = headers.get("cf-ipcountry")?.to_str().ok()?.trim();
  if raw.len() == 2 && raw.bytes().all(|b| b.is_ascii_alphabetic()) {
    Some(raw.to_ascii_uppercase())
  } else {
    None
  }
}

pub fn extract_album_id(headers: &HeaderMap) -> Option<String> {
  let s = headers.get("x-kura-album")?.to_str().ok()?.trim();
  if (4..=24).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric()) {
    Some(s.to_string())
  } else {
    None
  }
}

pub fn extract_e2ee_flag(headers: &HeaderMap) -> bool {
  headers
    .get("x-kura-e2ee")
    .and_then(|v| v.to_str().ok())
    .map(|s| {
      let t = s.trim();
      t == "1"
        || t.eq_ignore_ascii_case("true")
        || t.eq_ignore_ascii_case("aes-gcm")
        || t.eq_ignore_ascii_case("cascade-v2")
    })
    .unwrap_or(false)
}

pub fn extract_timelock_header(headers: &HeaderMap) -> Result<Option<i64>, AppError> {
  let Some(val) = headers.get("x-kura-timelock") else {
    return Ok(None);
  };
  let s = val
    .to_str()
    .map_err(|_| AppError::BadRequest("invalid_timelock_header"))?
    .trim();
  if s.is_empty() || s == "0" {
    return Ok(None);
  }
  let now = current_unix_timestamp();
  let unlock_ts = if let Some(mins) = s.strip_suffix('m') {
    let m = mins.parse::<i64>().map_err(|_| AppError::BadRequest("invalid_timelock"))?;
    now.saturating_add(m.saturating_mul(60))
  } else if let Some(hours) = s.strip_suffix('h') {
    let h = hours.parse::<i64>().map_err(|_| AppError::BadRequest("invalid_timelock"))?;
    now.saturating_add(h.saturating_mul(3600))
  } else if let Some(days) = s.strip_suffix('d') {
    let d = days.parse::<i64>().map_err(|_| AppError::BadRequest("invalid_timelock"))?;
    now.saturating_add(d.saturating_mul(86_400))
  } else {
    s.parse::<i64>()
      .map_err(|_| AppError::BadRequest("invalid_timelock_timestamp"))?
  };

  if unlock_ts <= now || unlock_ts > now + 86_400 * 365 {
    return Err(AppError::BadRequest("timelock_out_of_bounds"));
  }
  Ok(Some(unlock_ts))
}

pub fn extract_shamir_threshold(headers: &HeaderMap) -> Result<Option<i64>, AppError> {
  let Some(val) = headers.get("x-kura-shamir-m") else {
    return Ok(None);
  };
  let m = val
    .to_str()
    .map_err(|_| AppError::BadRequest("invalid_shamir_header"))?
    .trim()
    .parse::<i64>()
    .map_err(|_| AppError::BadRequest("invalid_shamir_threshold"))?;
  if !(2..=16).contains(&m) {
    return Err(AppError::BadRequest("shamir_threshold_must_be_2_to_16"));
  }
  Ok(Some(m))
}

pub fn extract_expiry_policy(headers: &HeaderMap) -> Result<ExpiryPolicy, AppError> {
  let Some(val) = headers.get("x-kura-expire") else {
    return Ok(ExpiryPolicy {
      ttl_seconds: None,
      burn_after_read: false,
      max_views: None,
    });
  };
  let s = val
    .to_str()
    .map_err(|_| AppError::BadRequest("invalid_expiry_header"))?
    .trim();

  match s {
    "" | "never" | "0" => Ok(ExpiryPolicy {
      ttl_seconds: None,
      burn_after_read: false,
      max_views: None,
    }),
    "1h" | "3600" => Ok(ExpiryPolicy {
      ttl_seconds: Some(3600),
      burn_after_read: false,
      max_views: None,
    }),
    "24h" | "1d" | "86400" => Ok(ExpiryPolicy {
      ttl_seconds: Some(86_400),
      burn_after_read: false,
      max_views: None,
    }),
    "7d" | "604800" => Ok(ExpiryPolicy {
      ttl_seconds: Some(604_800),
      burn_after_read: false,
      max_views: None,
    }),
    "1v" | "burn" => Ok(ExpiryPolicy {
      ttl_seconds: Some(86_400 * 7),
      burn_after_read: true,
      max_views: Some(1),
    }),
    "5v" => Ok(ExpiryPolicy {
      ttl_seconds: Some(86_400 * 7),
      burn_after_read: false,
      max_views: Some(5),
    }),
    "10v" => Ok(ExpiryPolicy {
      ttl_seconds: Some(86_400 * 7),
      burn_after_read: false,
      max_views: Some(10),
    }),
    _ => Err(AppError::BadRequest("unsupported_expiry_policy")),
  }
}

/// Shared helper for extracting bounded secret headers without code duplication
#[inline]
fn extract_bounded_secret_header(
  headers: &HeaderMap,
  header_name: &'static str,
  too_long_err: &'static str,
) -> Result<Option<Vec<u8>>, AppError> {
  let Some(val) = headers.get(header_name) else {
    return Ok(None);
  };
  let raw = val.as_bytes().trim_ascii();
  if raw.is_empty() {
    return Ok(None);
  }
  if raw.len() > 128 {
    return Err(AppError::BadRequest(too_long_err));
  }
  Ok(Some(raw.to_vec()))
}

pub fn extract_raw_password(headers: &HeaderMap) -> Result<Option<Vec<u8>>, AppError> {
  extract_bounded_secret_header(headers, "x-kura-password", "password_too_long")
}

pub fn extract_duress_password(headers: &HeaderMap) -> Result<Option<Vec<u8>>, AppError> {
  extract_bounded_secret_header(headers, "x-kura-duress-password", "duress_password_too_long")
}

pub fn extract_slug_from_path(raw_id: &str) -> Result<&str, AppError> {
  let slug = raw_id.split('.').next().unwrap_or("");
  if slug.len() != SLUG_LENGTH || !slug.bytes().all(|b| b.is_ascii_alphanumeric()) {
    return Err(AppError::NotFound("invalid_identifier"));
  }
  Ok(slug)
}

/// Checks whether a socket peer belongs to a trusted local/private reverse-proxy network
#[inline]
fn is_trusted_proxy_peer(ip: IpAddr) -> bool {
  match ip {
    IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
    IpAddr::V6(v6) => {
      v6.is_loopback()
        || (v6.segments()[0] & 0xfe00) == 0xfc00 // RFC 4193 Unique Local (fc00::/7)
        || (v6.segments()[0] & 0xffc0) == 0xfe80 // Link-Local (fe80::/10)
        || v6.to_ipv4_mapped().map(|v4| v4.is_loopback() || v4.is_private()).unwrap_or(false)
    }
  }
}

/// Strictly validates RFC 1123 hostnames (with optional port) to prevent Host header injection
#[inline]
fn is_valid_host_authority(host: &str) -> bool {
  if host.is_empty() || host.len() > 253 {
    return false;
  }
  let (hostname, port_opt) = match host.rsplit_once(':') {
    Some((h, p)) if !h.contains(':') => (h, Some(p)),
    _ => (host, None),
  };
  if let Some(port_str) = port_opt {
    if port_str.parse::<u16>().is_err() {
      return false;
    }
  }
  if hostname.is_empty()
    || hostname.starts_with('.')
    || hostname.ends_with('.')
    || hostname.starts_with('-')
    || hostname.ends_with('-')
    || hostname.contains("..")
  {
    return false;
  }
  hostname
    .bytes()
    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

pub fn resolve_request_origin(
  peer_addr: &SocketAddr,
  headers: &HeaderMap,
  configured_origin: Option<&str>,
  fallback: &str,
) -> String {
  if let Some(origin) = configured_origin {
    return origin.to_string();
  }
  if let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
    let clean_host = host.trim();
    if is_valid_host_authority(clean_host) {
      let is_https = if is_trusted_proxy_peer(peer_addr.ip()) {
        let xfp_https = headers
          .get("x-forwarded-proto")
          .and_then(|v| v.to_str().ok())
          .map(|p| p.trim().eq_ignore_ascii_case("https"))
          .unwrap_or(false);
        let cf_https = headers
          .get("cf-visitor")
          .and_then(|v| v.to_str().ok())
          .map(|v| v.contains("\"https\""))
          .unwrap_or(false);
        xfp_https || cf_https
      } else {
        false
      };
      let scheme = if is_https { "https" } else { "http" };
      return format!("{}://{}", scheme, clean_host);
    }
  }
  fallback.to_string()
}

pub fn extract_client_sha256(headers: &HeaderMap) -> Result<Option<[u8; 64]>, AppError> {
  let Some(val) = headers.get("x-content-sha256") else {
    return Ok(None);
  };
  let raw = val.as_bytes().trim_ascii();
  if raw.len() != 64 {
    return Err(AppError::BadRequest("invalid_sha256_header"));
  }

  let mut normalized = [0u8; 64];
  for (i, &b) in raw.iter().enumerate() {
    normalized[i] = match b {
      b'0'..=b'9' | b'a'..=b'f' => b,
      b'A'..=b'F' => b | 0x20,
      _ => return Err(AppError::BadRequest("invalid_sha256_header")),
    };
  }
  Ok(Some(normalized))
}

/// Canonicalizes IPv4-mapped IPv6 addresses and rejects spoofed loopback/unspecified bogons from headers
#[inline]
fn sanitize_forwarded_ip(ip: IpAddr) -> Option<IpAddr> {
  let canonical = match ip {
    IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
      Some(v4) => IpAddr::V4(v4),
      None => IpAddr::V6(v6),
    },
    IpAddr::V4(v4) => IpAddr::V4(v4),
  };

  if canonical.is_loopback() || canonical.is_unspecified() || canonical.is_multicast() {
    return None;
  }
  Some(canonical)
}

pub fn extract_proxy_client_ip(headers: &HeaderMap) -> Option<IpAddr> {
  if let Some(val) = headers.get("cf-connecting-ip") {
    if let Some(ip) = parse_ip_bytes(val.as_bytes()).and_then(sanitize_forwarded_ip) {
      return Some(ip);
    }
  }
  if let Some(val) = headers.get("x-real-ip") {
    if let Some(ip) = parse_ip_bytes(val.as_bytes()).and_then(sanitize_forwarded_ip) {
      return Some(ip);
    }
  }
  if let Some(val) = headers.get("x-forwarded-for") {
    if let Some(last) = val.as_bytes().split(|&b| b == b',').next_back() {
      if let Some(ip) = parse_ip_bytes(last).and_then(sanitize_forwarded_ip) {
        return Some(ip);
      }
    }
  }
  None
}

#[inline]
pub fn parse_ip_bytes(raw: &[u8]) -> Option<IpAddr> {
  let s = std::str::from_utf8(raw.trim_ascii()).ok()?;
  if let Ok(ip) = s.parse::<IpAddr>() {
    return Some(ip);
  }
  s.parse::<SocketAddr>().ok().map(|sa| sa.ip())
}

// ============================================================================
// DEEP MAGIC-BYTE, POLYGLOT, UTF-16 XSS & ACTIVE-PDF DISARMER
// ============================================================================

pub fn extract_safe_client_extension(filename: &str) -> Option<String> {
  let ext = Path::new(filename)
    .extension()
    .and_then(|e| e.to_str())?
    .trim()
    .to_ascii_lowercase();

  if ext.is_empty() || ext.len() > 12 || !ext.bytes().all(|b| b.is_ascii_alphanumeric()) {
    return None;
  }

  if DANGEROUS_WEB_EXTENSIONS.contains(&ext.as_str()) {
    return None;
  }

  Some(ext)
}

/// Detects native executable headers across Windows (PE/LNK), Linux (ELF), macOS/iOS (Mach-O),
/// Java Class / Universal Binaries, and WebAssembly modules
#[inline]
fn is_executable_or_bytecode_binary(buf: &[u8]) -> bool {
  if buf.starts_with(b"MZ") || buf.starts_with(b"\x7FELF") || buf.starts_with(b"\0asm") {
    return true;
  }
  if buf.len() >= 4 {
    let magic32 = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if matches!(
      magic32,
      0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE | 0xCAFEBABE
    ) {
      return true;
    }
  }
  // Windows Shell Link (.LNK) binary header
  if buf.len() >= 8 && buf[..8] == [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00] {
    return true;
  }
  false
}

/// Scans PDF buffers for embedded JavaScript, Launch actions, or XFA forms that could trigger XSS/RCE
#[inline]
fn pdf_contains_active_content(buf: &[u8]) -> bool {
  const PDF_DANGEROUS_TAGS: &[&[u8]] = &[
    b"/javascript",
    b"/js",
    b"/launch",
    b"/openaction",
    b"/aa",
    b"/submitform",
    b"/importdata",
    b"/richmedia",
  ];
  PDF_DANGEROUS_TAGS.iter().any(|&tag| {
    buf
      .windows(tag.len())
      .any(|w| w.eq_ignore_ascii_case(tag))
  })
}

pub fn resolve_safe_format(
  magic_buffer: &[u8],
  client_ext_hint: Option<&str>,
) -> Result<(String, &'static str, bool), AppError> {
  let has_polyglot_sig = contains_forbidden_polyglot_signature(magic_buffer);

  if is_executable_or_bytecode_binary(magic_buffer) {
    if let Some(ext) = client_ext_hint {
      if VERIFIED_MAGIC_FORMATS.iter().any(|&(e, _, inline)| e == ext && inline) {
        return Err(AppError::Forbidden("disguised_executable_blocked"));
      }
    }
    return Ok(("bin".to_string(), "application/octet-stream", false));
  }

  if magic_buffer.starts_with(b"SQLite format 3\0") {
    let ext = match client_ext_hint {
      Some(e @ ("db" | "sqlite" | "sqlite3" | "db3")) => e,
      _ => "db",
    };
    return Ok((ext.to_string(), "application/vnd.sqlite3", false));
  }

  if let Some(kind) = infer::get(magic_buffer) {
    let detected_ext = kind.extension();
    if let Some(&(safe_ext, mime, inline_safe)) = VERIFIED_MAGIC_FORMATS
      .iter()
      .find(|&&(s, _, _)| s == detected_ext)
    {
      if has_polyglot_sig && inline_safe {
        return Ok(("bin".to_string(), "application/octet-stream", false));
      }
      if safe_ext == "pdf" && pdf_contains_active_content(magic_buffer) {
        // Disarm active PDFs by forcing attachment download instead of inline browser execution
        return Ok(("pdf".to_string(), mime, false));
      }
      if safe_ext == "sqlite" && client_ext_hint == Some("db") {
        return Ok(("db".to_string(), mime, false));
      }
      return Ok((safe_ext.to_string(), mime, inline_safe));
    }
  }

  let text_target = if magic_buffer.starts_with(&[0xEF, 0xBB, 0xBF]) {
    &magic_buffer[3..]
  } else {
    magic_buffer
  };

  let valid_slice = match std::str::from_utf8(text_target) {
    Ok(s) => Some(s),
    Err(err) => {
      let valid_len = err.valid_up_to();
      if valid_len > 0 && err.error_len().is_none() {
        std::str::from_utf8(&text_target[..valid_len]).ok()
      } else {
        None
      }
    }
  };

  if let Some(slice) = valid_slice {
    let has_binary_ctrl = slice
      .bytes()
      .any(|b| (b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r') || b == 0x7F);

    if !slice.is_empty() && !has_binary_ctrl && !has_polyglot_sig {
      if let Some(ext) = client_ext_hint {
        if SAFE_TEXT_EXTENSIONS.contains(&ext) {
          return Ok((ext.to_string(), "text/plain; charset=utf-8", true));
        }
        return Ok((ext.to_string(), "application/octet-stream", false));
      }
      return Ok(("txt".to_string(), "text/plain; charset=utf-8", true));
    }
  }

  if let Some(ext) = client_ext_hint {
    let is_media_or_pdf = VERIFIED_MAGIC_FORMATS
      .iter()
      .any(|&(s, _, inline)| s == ext && inline);
    if !is_media_or_pdf {
      return Ok((ext.to_string(), "application/octet-stream", false));
    }
  }

  Ok(("bin".to_string(), "application/octet-stream", false))
}

/// High-speed 4-way unrolled CRC-32 (IEEE 802.3) calculation for streaming ZIP archives
#[inline]
pub fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
  let mut iter = bytes.chunks_exact(4);
  for chunk in &mut iter {
    crc ^= u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    crc = (crc >> 8) ^ CRC32_TABLE[(crc & 0xFF) as usize];
    crc = (crc >> 8) ^ CRC32_TABLE[(crc & 0xFF) as usize];
    crc = (crc >> 8) ^ CRC32_TABLE[(crc & 0xFF) as usize];
    crc = (crc >> 8) ^ CRC32_TABLE[(crc & 0xFF) as usize];
  }
  for &b in iter.remainder() {
    crc = (crc >> 8) ^ CRC32_TABLE[((crc ^ (b as u32)) & 0xFF) as usize];
  }
  crc
}

/// Deep Polyglot Detector:
/// - Detects standard ASCII forbidden HTML/JS signatures
/// - Detects whitespace-padded HTML tags (e.g., `<  script`, `<\niframe`)
/// - Detects UTF-16LE / UTF-16BE null-interleaved polyglot payloads (`<\0s\0c\0r\0i\0p\0t`)
#[inline]
pub fn contains_forbidden_polyglot_signature(haystack: &[u8]) -> bool {
  if haystack.is_empty() {
    return false;
  }

  // 1. Check UTF-16 BOM markers disguised inside binary/text streams
  if haystack.starts_with(&[0xFE, 0xFF, 0x00, b'<'])
    || haystack.starts_with(&[0xFF, 0xFE, b'<', 0x00])
  {
    return true;
  }

  // 2. Direct ASCII & Normalized Stream Compaction (strips interleaved 0x00 and redundant whitespace after '<')
  let mut compacted = [0u8; 512];
  let mut comp_len = 0usize;
  let mut after_lt = false;

  for &b in haystack.iter() {
    if b == 0 {
      continue;
    }
    if b == b'<' {
      after_lt = true;
      if comp_len < compacted.len() {
        compacted[comp_len] = b'<';
        comp_len += 1;
      }
      continue;
    }
    if after_lt && b.is_ascii_whitespace() {
      continue;
    }
    after_lt = false;
    if comp_len < compacted.len() {
      compacted[comp_len] = b.to_ascii_lowercase();
      comp_len += 1;
    }
  }

  let norm_slice = &compacted[..comp_len];

  FORBIDDEN_POLYGLOT_SIGNATURES.iter().any(|&sig| {
    norm_slice.windows(sig.len()).any(|w| w == sig)
      || haystack
        .windows(sig.len())
        .any(|window| window.eq_ignore_ascii_case(sig))
  })
}

#[inline]
pub fn encode_hex_sha256(bytes: &[u8]) -> [u8; 64] {
  let mut hex = [0u8; 64];
  for (i, &b) in bytes.iter().enumerate() {
    hex[i * 2] = HEX_LUT[(b >> 4) as usize];
    hex[i * 2 + 1] = HEX_LUT[(b & 0x0F) as usize];
  }
  hex
}

#[inline]
pub fn generate_random_string(length: usize) -> String {
  let mut rng = rand::rng();
  (0..length)
    .map(|_| rng.sample(Alphanumeric) as char)
    .collect()
}

/// Finite-State Machine (FSM) JSON Structural Validator:
/// Enforces balanced braces/brackets, valid string escaping, control-character rejection,
/// and a strict maximum nesting depth (<= 32) to prevent JSON Bomb / SDP injection attacks
pub fn is_safe_json_object(raw: &str) -> bool {
  let bytes = raw.trim().as_bytes();
  if bytes.len() < 2
    || bytes.len() > 65_536
    || bytes[0] != b'{'
    || bytes[bytes.len() - 1] != b'}'
  {
    return false;
  }

  let mut depth = 0usize;
  let mut in_string = false;
  let mut escaped = false;
  let mut stack = [0u8; MAX_JSON_NESTING_DEPTH];

  for &b in bytes {
    if b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t' {
      return false;
    }
    if in_string {
      if escaped {
        escaped = false;
      } else if b == b'\\' {
        escaped = true;
      } else if b == b'"' {
        in_string = false;
      }
      continue;
    }

    match b {
      b'"' => in_string = true,
      b'{' | b'[' => {
        if depth >= MAX_JSON_NESTING_DEPTH {
          return false;
        }
        stack[depth] = if b == b'{' { b'}' } else { b']' };
        depth += 1;
      }
      b'}' | b']' => {
        if depth == 0 || stack[depth - 1] != b {
          return false;
        }
        depth -= 1;
      }
      _ => {}
    }
  }

  !in_string && !escaped && depth == 0
}