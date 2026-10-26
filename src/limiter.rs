use axum::http::HeaderMap;
use sha2::{Digest, Sha256};
use std::{
  net::{IpAddr, SocketAddr},
  sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
  },
  time::{SystemTime, UNIX_EPOCH},
};

use crate::{config::*, crypto::*};

// ============================================================================
// BIT-PACKED ATOMIC SLIDING-WINDOW & CACHE CONSTANTS
// ============================================================================

/// 64-bit Dual-Epoch Sliding-Window Layout:
/// [63..40: 24-bit Minute Epoch] | [39..20: 20-bit Previous Minute Count] | [19..0: 20-bit Current Minute Count]
const EPOCH_MASK_24: u64 = 0x00FF_FFFF;
const COUNT_MASK_20: u64 = 0x000F_FFFF;
const MAX_PACKED_COUNT: u32 = 0x000F_FFFF;

/// 4-Way Set-Associative Cache geometry for PoW Replay Ring (2048 slots = 512 sets x 4 ways)
const POW_SET_WAYS: usize = 4;
const POW_NUM_SETS: usize = POW_REPLAY_BUCKETS / POW_SET_WAYS;
const POW_SET_MASK: usize = POW_NUM_SETS - 1;

/// Maximum lease duration (in seconds) for a concurrent ZIP stream lock before auto-eviction
const ZIP_LOCK_LEASE_SECS: u64 = 300;

#[derive(PartialEq, Eq)]
pub enum RateLimitDecision {
  Allowed,
  PowRequired(String),
  Rejected,
}

pub struct BlindedRateLimiter {
  pub boot_secret: [u8; 32],
  pub pow_always_required: bool,
  pub global_slot: AtomicU64,
  pub actor_sketch: Box<[AtomicU64; SKETCH_BUCKETS]>,
  pub pow_replay_ring: Box<[AtomicU64; POW_REPLAY_BUCKETS]>,
  pub zip_active_locks: Box<[AtomicU64; ZIP_ACTOR_BUCKETS]>,
}

impl BlindedRateLimiter {
  pub fn new(pow_always_required: bool) -> Self {
    let entropy_seed = generate_csprng_bytes::<64>();
    let now_nanos = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_nanos()
      .to_le_bytes();

    // Extract high-entropy master boot secret via HKDF-SHA256
    let boot_secret = hkdf_sha256(&now_nanos, &entropy_seed, b"kura_master_boot_secret_v2");

    let actor_sketch = std::iter::repeat_with(|| AtomicU64::new(0))
      .take(SKETCH_BUCKETS)
      .collect::<Vec<_>>()
      .into_boxed_slice()
      .try_into()
      .expect("sketch init");

    let pow_replay_ring = std::iter::repeat_with(|| AtomicU64::new(0))
      .take(POW_REPLAY_BUCKETS)
      .collect::<Vec<_>>()
      .into_boxed_slice()
      .try_into()
      .expect("pow init");

    let zip_active_locks = std::iter::repeat_with(|| AtomicU64::new(0))
      .take(ZIP_ACTOR_BUCKETS)
      .collect::<Vec<_>>()
      .into_boxed_slice()
      .try_into()
      .expect("zip init");

    Self {
      boot_secret,
      pow_always_required,
      global_slot: AtomicU64::new(0),
      actor_sketch,
      pow_replay_ring,
      zip_active_locks,
    }
  }

  // ==========================================================================
  // DOMAIN-SEPARATED ZERO-ALLOCATION TOKEN SIGNING & VERIFICATION
  // ==========================================================================

  /// Computes a raw 64-byte hex HMAC-SHA256 signature on the stack without heap allocation
  #[inline]
  fn sign_raw_hex(&self, domain: &[u8], payload: &[u8]) -> [u8; 64] {
    let subkey = hkdf_sha256(&self.boot_secret, domain, b"kura_token_subkey_v2");
    let tag = hmac_sha256(&subkey, payload);
    encode_hex_sha256(&tag)
  }

  pub fn sign_token(&self, payload: &str) -> String {
    let hex = self.sign_raw_hex(b"kura_presign_commit_token", payload.as_bytes());
    std::str::from_utf8(&hex).unwrap_or_default().to_string()
  }

  /// Zero-allocation constant-time token verification
  pub fn verify_token(&self, payload: &str, signature_hex: &str) -> bool {
    if signature_hex.len() != 64 {
      return false;
    }
    let expected_hex = self.sign_raw_hex(b"kura_presign_commit_token", payload.as_bytes());
    constant_time_eq(&expected_hex, signature_hex.as_bytes())
  }

  // ==========================================================================
  // BLINDED ACTOR FINGERPRINTING (PROXY-AWARE & IPV6 /64 NORMALIZED)
  // ==========================================================================

  #[inline]
  fn is_trusted_proxy_ip(ip: IpAddr) -> bool {
    match ip {
      IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
      IpAddr::V6(v6) => {
        v6.is_loopback()
          || (v6.segments()[0] & 0xfe00) == 0xfc00
          || (v6.segments()[0] & 0xffc0) == 0xfe80
          || v6
            .to_ipv4_mapped()
            .map(|v4| v4.is_loopback() || v4.is_private())
            .unwrap_or(false)
      }
    }
  }

  pub fn actor_fingerprint(&self, peer_addr: &SocketAddr, headers: &HeaderMap) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"kura_actor_fp_v2:");
    h.update(self.boot_secret);

    let resolved_ip = if Self::is_trusted_proxy_ip(peer_addr.ip()) {
      extract_proxy_client_ip(headers).unwrap_or_else(|| peer_addr.ip())
    } else {
      peer_addr.ip()
    };

    match resolved_ip {
      IpAddr::V4(v4) => {
        h.update(b"v4:");
        h.update(v4.octets());
      }
      IpAddr::V6(v6) => {
        if let Some(mapped_v4) = v6.to_ipv4_mapped() {
          h.update(b"v4:");
          h.update(mapped_v4.octets());
        } else {
          // Bind to /64 prefix to neutralize IPv6 SLAAC privacy-extension rotation attacks
          h.update(b"v6/64:");
          h.update(&v6.octets()[..8]);
        }
      }
    }

    let digest = h.finalize();
    let mut fp = [0u8; 16];
    fp.copy_from_slice(&digest[..16]);
    fp
  }

  // ==========================================================================
  // STATELESS PROOF-OF-WORK (POW) ENGINE & 4-WAY SET-ASSOCIATIVE REPLAY CACHE
  // ==========================================================================

  pub fn issue_pow_challenge(&self, peer_addr: &SocketAddr, headers: &HeaderMap) -> String {
    let now = current_unix_timestamp();
    let fp = self.actor_fingerprint(peer_addr, headers);
    let mut fp_hex = [0u8; 16];
    for i in 0..8 {
      fp_hex[i * 2] = HEX_LUT[(fp[i] >> 4) as usize];
      fp_hex[i * 2 + 1] = HEX_LUT[(fp[i] & 0x0F) as usize];
    }
    let fp_str = std::str::from_utf8(&fp_hex).unwrap_or_default();
    let rand_nonce = generate_random_string(8);
    let data = format!("{}.{}.{}", now, fp_str, rand_nonce);
    let sig_hex = self.sign_raw_hex(b"kura_pow_challenge_v2", data.as_bytes());
    let sig_str = std::str::from_utf8(&sig_hex[..24]).unwrap_or_default();
    format!("{}.{}", data, sig_str)
  }

  pub fn verify_pow_header(&self, peer_addr: &SocketAddr, headers: &HeaderMap) -> bool {
    let Some(raw_pow) = headers.get("x-kura-pow").and_then(|v| v.to_str().ok()) else {
      return false;
    };
    let Some((challenge, nonce)) = raw_pow.trim().split_once(':') else {
      return false;
    };
    if nonce.is_empty() || nonce.len() > 64 || challenge.len() > 128 {
      return false;
    }

    // Zero-allocation 4-part dot splitter (`ts.fp_hex.rand_nonce.sig`)
    let mut iter = challenge.split('.');
    let (Some(p_ts), Some(p_fp), Some(p_rnd), Some(p_sig), None) = (
      iter.next(),
      iter.next(),
      iter.next(),
      iter.next(),
      iter.next(),
    ) else {
      return false;
    };

    if p_fp.len() != 16 || p_sig.len() != 24 || p_rnd.is_empty() {
      return false;
    }

    let Ok(ts) = p_ts.parse::<i64>() else {
      return false;
    };
    let now = current_unix_timestamp();
    // Reject expired challenges or timestamps skewed > 30s into the future
    if now.saturating_sub(ts) > POW_TTL_SECS || ts.saturating_sub(now) > 30 {
      return false;
    }

    let fp = self.actor_fingerprint(peer_addr, headers);
    let mut fp_hex = [0u8; 16];
    for i in 0..8 {
      fp_hex[i * 2] = HEX_LUT[(fp[i] >> 4) as usize];
      fp_hex[i * 2 + 1] = HEX_LUT[(fp[i] & 0x0F) as usize];
    }
    if !constant_time_eq(p_fp.as_bytes(), &fp_hex) {
      return false;
    }

    // Slice the exact `ts.fp_hex.rand_nonce` prefix directly from `challenge` without allocating a String
    let signed_prefix_len = challenge.len().saturating_sub(25);
    let signed_data = &challenge.as_bytes()[..signed_prefix_len];
    let expected_sig_hex = self.sign_raw_hex(b"kura_pow_challenge_v2", signed_data);
    if !constant_time_eq(&expected_sig_hex[..24], p_sig.as_bytes()) {
      return false;
    }

    // Verify leading zero bits of SHA-256(challenge || ":" || nonce)
    let mut h = Sha256::new();
    h.update(challenge.as_bytes());
    h.update(b":");
    h.update(nonce.as_bytes());
    let digest = h.finalize();

    let full_bytes = (POW_DIFFICULTY_BITS / 8) as usize;
    let rem_bits = POW_DIFFICULTY_BITS % 8;
    for i in 0..full_bytes {
      if digest[i] != 0 {
        return false;
      }
    }
    if rem_bits > 0 && (digest[full_bytes] & (0xFFu8 << (8 - rem_bits))) != 0 {
      return false;
    }

    // 4-Way Set-Associative Temporal Replay Cache:
    // Pack `[63..44: 20-bit timestamp_secs] | [43..0: 44-bit non-zero solution fingerprint]`
    let now_u20 = ((now.max(0) as u64) & 0x000F_FFFF) << 44;
    let raw_fp44 = u64::from_le_bytes([
      digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14], digest[15],
    ]) & 0x0000_0FFF_FFFF_FFFF;
    let fp44 = raw_fp44 | 1;
    let new_entry = now_u20 | fp44;

    let set_idx = (u16::from_le_bytes([digest[16], digest[17]]) as usize) & POW_SET_MASK;
    let base_slot = set_idx * POW_SET_WAYS;
    let ttl_u20 = (POW_TTL_SECS as u64).min(0x0007_FFFF);

    // Retry loop guarantees atomic check-and-insert across the 4 ways in the cache set
    for _ in 0..8 {
      let mut victim_way = 0usize;
      let mut oldest_age = 0u64;
      let mut found_empty = false;

      for way in 0..POW_SET_WAYS {
        let cur = self.pow_replay_ring[base_slot + way].load(Ordering::Acquire);
        if cur == 0 {
          if !found_empty {
            victim_way = way;
            found_empty = true;
          }
          continue;
        }
        let cur_fp = cur & 0x0000_0FFF_FFFF_FFFF;
        let cur_ts = cur >> 44;
        let age = ((now.max(0) as u64) & 0x000F_FFFF).wrapping_sub(cur_ts) & 0x000F_FFFF;

        // If the exact solution fingerprint is already present and within TTL, reject as replay!
        if cur_fp == fp44 && age <= ttl_u20 {
          return false;
        }

        if !found_empty && age >= oldest_age {
          oldest_age = age;
          victim_way = way;
        }
      }

      let target_slot = &self.pow_replay_ring[base_slot + victim_way];
      let cur_val = target_slot.load(Ordering::Relaxed);
      if (cur_val & 0x0000_0FFF_FFFF_FFFF) == fp44 {
        return false;
      }
      if target_slot
        .compare_exchange_weak(cur_val, new_entry, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
      {
        return true;
      }
    }

    false
  }

  // ==========================================================================
  // SLIDING-WINDOW COUNT-MIN SKETCH & ADMISSION CONTROLLERS
  // ==========================================================================

  #[inline]
  fn current_time_coordinates() -> (u32, u32) {
    let secs = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_secs();
    let minute_epoch = ((secs / 60) as u64 & EPOCH_MASK_24) as u32;
    let secs_in_min = (secs % 60) as u32;
    (minute_epoch, secs_in_min)
  }

  /// Evaluates the sliding-window effective request rate from a bit-packed 64-bit slot
  #[inline]
  fn read_sliding_count(packed: u64, current_epoch: u32, secs_in_min: u32) -> (u32, u32) {
    let slot_epoch = ((packed >> 40) & EPOCH_MASK_24) as u32;
    let prev_count = ((packed >> 20) & COUNT_MASK_20) as u32;
    let curr_count = (packed & COUNT_MASK_20) as u32;

    if slot_epoch == current_epoch {
      let weighted_prev = (prev_count.saturating_mul(60 - secs_in_min)) / 60;
      (curr_count.saturating_add(weighted_prev), curr_count)
    } else if slot_epoch.wrapping_add(1) & (EPOCH_MASK_24 as u32) == current_epoch {
      let weighted_prev = (curr_count.saturating_mul(60 - secs_in_min)) / 60;
      (weighted_prev, 0)
    } else {
      (0, 0)
    }
  }

  /// Admission controller for Upload endpoints (enforces Soft/Hard PoW Challenges + Sliding-Window quotas)
  pub fn check_upload_admission(
    &self,
    peer_addr: &SocketAddr,
    headers: &HeaderMap,
  ) -> RateLimitDecision {
    let has_valid_pow = self.verify_pow_header(peer_addr, headers);
    if self.pow_always_required && !has_valid_pow {
      return RateLimitDecision::PowRequired(self.issue_pow_challenge(peer_addr, headers));
    }

    let (minute_epoch, secs_in_min) = Self::current_time_coordinates();

    let (global_sliding, _) = Self::read_sliding_count(
      self.global_slot.load(Ordering::Relaxed),
      minute_epoch,
      secs_in_min,
    );

    // Sovereign PoW Bypass: Clients presenting a valid PoW solution are granted a 2x global burst reserve
    let effective_global_cap = if has_valid_pow {
      MAX_GLOBAL_PER_MINUTE.saturating_mul(2)
    } else {
      MAX_GLOBAL_PER_MINUTE
    };

    if global_sliding >= effective_global_cap {
      return RateLimitDecision::Rejected;
    }

    let indices = self.derive_sketch_indices(minute_epoch, peer_addr, headers);
    let mut min_sliding = u32::MAX;
    let mut min_raw_curr = u32::MAX;

    for &idx in &indices {
      let packed = self.actor_sketch[idx].load(Ordering::Relaxed);
      let (sliding, raw_curr) = Self::read_sliding_count(packed, minute_epoch, secs_in_min);
      if sliding < min_sliding {
        min_sliding = sliding;
      }
      if raw_curr < min_raw_curr {
        min_raw_curr = raw_curr;
      }
    }

    let actor_limit = if has_valid_pow {
      MAX_ACTOR_PER_MINUTE.saturating_mul(2)
    } else {
      MAX_ACTOR_PER_MINUTE
    };

    if min_sliding >= actor_limit {
      return RateLimitDecision::Rejected;
    }

    if !has_valid_pow
      && (min_sliding >= POW_SOFT_ACTOR_THRESHOLD || global_sliding >= MAX_GLOBAL_PER_MINUTE / 2)
    {
      return RateLimitDecision::PowRequired(self.issue_pow_challenge(peer_addr, headers));
    }

    if !Self::increment_slot_sliding(
      &self.global_slot,
      minute_epoch,
      secs_in_min,
      effective_global_cap,
    ) {
      return RateLimitDecision::Rejected;
    }

    for &idx in &indices {
      Self::increment_slot_conservative(&self.actor_sketch[idx], minute_epoch, min_raw_curr);
    }

    RateLimitDecision::Allowed
  }

  /// Strict non-PoW rate limiter for authentication, deletion, metadata stats, and signaling endpoints.
  /// Always increments actor counters on every admitted request (closes the PowRequired infinite-bypass bug)
  /// and isolates per-actor quotas from global upload starvation.
  pub fn check_and_increment(&self, peer_addr: &SocketAddr, headers: &HeaderMap) -> bool {
    let (minute_epoch, secs_in_min) = Self::current_time_coordinates();
    let indices = self.derive_sketch_indices(minute_epoch, peer_addr, headers);

    let mut min_sliding = u32::MAX;
    let mut min_raw_curr = u32::MAX;

    for &idx in &indices {
      let packed = self.actor_sketch[idx].load(Ordering::Relaxed);
      let (sliding, raw_curr) = Self::read_sliding_count(packed, minute_epoch, secs_in_min);
      if sliding < min_sliding {
        min_sliding = sliding;
      }
      if raw_curr < min_raw_curr {
        min_raw_curr = raw_curr;
      }
    }

    if min_sliding >= MAX_ACTOR_PER_MINUTE {
      return false;
    }

    for &idx in &indices {
      Self::increment_slot_conservative(&self.actor_sketch[idx], minute_epoch, min_raw_curr);
    }

    true
  }

  /// Derives 4 independent bucket indices using epoch-invariant keying so sliding-window history
  /// smoothly carries over across minute boundaries for the same actor
  fn derive_sketch_indices(
    &self,
    _minute_epoch: u32,
    peer_addr: &SocketAddr,
    headers: &HeaderMap,
  ) -> [usize; SKETCH_DEPTH] {
    let mut hasher = Sha256::new();
    hasher.update(b"kura_cms_idx_v2:");
    hasher.update(self.boot_secret);
    hasher.update(self.actor_fingerprint(peer_addr, headers));

    let digest = hasher.finalize();
    let mask = SKETCH_BUCKETS - 1;
    [
      (u16::from_le_bytes([digest[0], digest[1]]) as usize) & mask,
      (u16::from_le_bytes([digest[2], digest[3]]) as usize) & mask,
      (u16::from_le_bytes([digest[4], digest[5]]) as usize) & mask,
      (u16::from_le_bytes([digest[6], digest[7]]) as usize) & mask,
    ]
  }

  /// Conservative-Update Sliding-Window Increment:
  /// Only increments buckets matching the minimum current-minute count to suppress hash-collision overestimation
  fn increment_slot_conservative(slot: &AtomicU64, current_epoch: u32, min_raw_curr: u32) {
    let mut current = slot.load(Ordering::Relaxed);
    loop {
      let slot_epoch = ((current >> 40) & EPOCH_MASK_24) as u32;
      let prev_count = ((current >> 20) & COUNT_MASK_20) as u32;
      let curr_count = (current & COUNT_MASK_20) as u32;

      let (next_prev, next_curr) = if slot_epoch == current_epoch {
        if curr_count > min_raw_curr {
          return;
        }
        (prev_count, curr_count.saturating_add(1).min(MAX_PACKED_COUNT))
      } else if slot_epoch.wrapping_add(1) & (EPOCH_MASK_24 as u32) == current_epoch {
        // Roll current minute into previous minute slot on epoch transition
        (curr_count.min(MAX_PACKED_COUNT), 1)
      } else {
        (0, 1)
      };

      let next_val = ((current_epoch as u64 & EPOCH_MASK_24) << 40)
        | ((next_prev as u64 & COUNT_MASK_20) << 20)
        | (next_curr as u64 & COUNT_MASK_20);

      match slot.compare_exchange_weak(current, next_val, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => return,
        Err(actual) => current = actual,
      }
    }
  }

  /// Atomic Sliding-Window Increment for the global admission counter
  fn increment_slot_sliding(
    slot: &AtomicU64,
    current_epoch: u32,
    secs_in_min: u32,
    limit: u32,
  ) -> bool {
    let mut current = slot.load(Ordering::Relaxed);
    loop {
      let (sliding, _) = Self::read_sliding_count(current, current_epoch, secs_in_min);
      if sliding >= limit {
        return false;
      }

      let slot_epoch = ((current >> 40) & EPOCH_MASK_24) as u32;
      let prev_count = ((current >> 20) & COUNT_MASK_20) as u32;
      let curr_count = (current & COUNT_MASK_20) as u32;

      let (next_prev, next_curr) = if slot_epoch == current_epoch {
        (prev_count, curr_count.saturating_add(1).min(MAX_PACKED_COUNT))
      } else if slot_epoch.wrapping_add(1) & (EPOCH_MASK_24 as u32) == current_epoch {
        (curr_count.min(MAX_PACKED_COUNT), 1)
      } else {
        (0, 1)
      };

      let next_val = ((current_epoch as u64 & EPOCH_MASK_24) << 40)
        | ((next_prev as u64 & COUNT_MASK_20) << 20)
        | (next_curr as u64 & COUNT_MASK_20);

      match slot.compare_exchange_weak(current, next_val, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => return true,
        Err(actual) => current = actual,
      }
    }
  }
}

// ============================================================================
// 2-CHOICE HASHING LEASE-BACKED CONCURRENT ZIP STREAM GUARD
// ============================================================================

pub struct ZipActorGuard {
  limiter: Arc<BlindedRateLimiter>,
  bucket_idx: usize,
  actor_tag: u64,
}

impl ZipActorGuard {
  /// Acquires a per-actor concurrent ZIP stream lock using Power-of-Two-Choices hashing
  /// and self-healing timestamp leases (prevents both same-actor parallel abuse and false hash-collision lockouts)
  pub fn try_acquire(
    limiter: Arc<BlindedRateLimiter>,
    peer_addr: &SocketAddr,
    headers: &HeaderMap,
  ) -> Option<Self> {
    let fp = limiter.actor_fingerprint(peer_addr, headers);
    let mask = ZIP_ACTOR_BUCKETS - 1;
    let idx1 = (u16::from_le_bytes([fp[0], fp[1]]) as usize) & mask;
    let idx2 = (u16::from_le_bytes([fp[2], fp[3]]) as usize) & mask;

    let now_secs = SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .unwrap_or_default()
      .as_secs();
    let now_u24 = (now_secs & 0x00FF_FFFF) << 40;

    // 40-bit non-zero actor identity tag + 24-bit acquisition timestamp
    let actor_id40 = (u64::from_le_bytes([
      fp[4], fp[5], fp[6], fp[7], fp[8], fp[9], fp[10], fp[11],
    ]) & 0x0000_00FF_FFFF_FFFF)
      | 1;
    let packed_lock = now_u24 | actor_id40;

    // First, verify this actor does not already hold an active lease in either candidate bucket
    for &idx in &[idx1, idx2] {
      let cur = limiter.zip_active_locks[idx].load(Ordering::Acquire);
      if cur != 0 {
        let holder_id = cur & 0x0000_00FF_FFFF_FFFF;
        let holder_ts = cur >> 40;
        let age = (now_secs & 0x00FF_FFFF).wrapping_sub(holder_ts) & 0x00FF_FFFF;
        if holder_id == actor_id40 && age < ZIP_LOCK_LEASE_SECS {
          return None;
        }
      }
    }

    // Attempt to claim either an empty slot or an expired lease across the 2 candidate buckets
    for &idx in &[idx1, idx2] {
      let slot = &limiter.zip_active_locks[idx];
      let cur = slot.load(Ordering::Relaxed);
      let is_reclaimable = if cur == 0 {
        true
      } else {
        let holder_ts = cur >> 40;
        let age = (now_secs & 0x00FF_FFFF).wrapping_sub(holder_ts) & 0x00FF_FFFF;
        age >= ZIP_LOCK_LEASE_SECS
      };

      if is_reclaimable
        && slot
          .compare_exchange(cur, packed_lock, Ordering::Acquire, Ordering::Relaxed)
          .is_ok()
      {
        return Some(Self {
          limiter,
          bucket_idx: idx,
          actor_tag: packed_lock,
        });
      }
    }

    None
  }
}

impl Drop for ZipActorGuard {
  fn drop(&mut self) {
    let slot = &self.limiter.zip_active_locks[self.bucket_idx];
    let _ = slot.compare_exchange(
      self.actor_tag,
      0,
      Ordering::Release,
      Ordering::Relaxed,
    );
  }
}