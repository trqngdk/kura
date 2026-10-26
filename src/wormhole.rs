use axum::{
  body::Body,
  extract::{ConnectInfo, Path as AxumPath, Query, State},
  http::{header, HeaderMap, HeaderValue, StatusCode},
  response::{Html, IntoResponse, Response},
};
use std::{
  collections::HashMap,
  net::SocketAddr,
  sync::Arc,
  time::Duration,
};
use tokio::{sync::Notify, time::timeout};

use crate::{config::*, crypto::*};

// ============================================================================
// WEBRTC SIGNALING & MEMORY PROTECTION CONSTANTS
// ============================================================================

/// Maximum allowed byte length for an SDP Offer or Answer payload (16 KiB)
const MAX_SDP_PAYLOAD_BYTES: usize = 16 * 1024;
/// Maximum allowed byte length for a single ICE candidate JSON object (1 KiB)
const MAX_ICE_CANDIDATE_BYTES: usize = 1024;
/// Maximum number of ICE candidates stored per peer direction
const MAX_ICE_CANDIDATES_PER_PEER: usize = 32;
/// Maximum long-polling wait duration in milliseconds
const MAX_POLL_WAIT_MS: u64 = 12_000;

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

// ============================================================================
// INTERNAL VALIDATION & ZERO-ALLOCATION HELPERS
// ============================================================================

/// Validates the 10-character alphanumeric room identifier
#[inline]
fn validate_room_id(room_id: &str) -> Result<(), AppError> {
  if room_id.len() != WORMHOLE_ID_LENGTH || !room_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
    return Err(AppError::NotFound("invalid_wormhole_id"));
  }
  Ok(())
}

/// Sanitizes an untrusted filename into a safe alphanumeric display name
#[inline]
fn sanitize_wormhole_filename(raw_name: &str) -> String {
  let clean: String = raw_name
    .chars()
    .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
    .take(96)
    .collect();
  let trimmed = clean.trim_matches('.');
  if trimmed.is_empty() {
    "payload.bin".to_string()
  } else {
    trimmed.to_string()
  }
}

/// Evicts expired wormhole rooms from the active map and wakes any stalled waiters
#[inline]
fn evict_expired_rooms(rooms: &mut HashMap<String, WormholeRoom>, now: i64) {
  rooms.retain(|_, r| {
    let alive = now.saturating_sub(r.created_at) < WORMHOLE_ROOM_TTL;
    if !alive {
      r.notify.notify_waiters();
    }
    alive
  });
}

/// Builds a standard no-store JSON HTTP response
#[inline]
fn build_json_no_store_response(json_body: String) -> Response {
  let mut resp = Response::new(Body::from(json_body));
  resp.headers_mut().insert(
    header::CONTENT_TYPE,
    HeaderValue::from_static("application/json; charset=utf-8"),
  );
  resp.headers_mut().insert(
    header::CACHE_CONTROL,
    HeaderValue::from_static("no-store, no-cache, must-revalidate"),
  );
  resp
}

// ============================================================================
// WEBRTC P2P WORMHOLE SIGNALING HANDLERS
// ============================================================================

pub async fn init_wormhole_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
) -> Result<Response, AppError> {
  if !state.rate_limiter.check_and_increment(&peer_addr, &headers) {
    return Err(AppError::TooManyRequests("rate_limit_exceeded"));
  }

  let raw_name = headers
    .get("x-kura-filename")
    .and_then(|v| v.to_str().ok())
    .unwrap_or("payload.bin");
  let filename = sanitize_wormhole_filename(raw_name);

  let filesize = headers
    .get("x-kura-size")
    .and_then(|v| v.to_str().ok())
    .and_then(|s| s.trim().parse::<u64>().ok())
    .unwrap_or(0);

  if filesize > (MAX_FILE_SIZE as u64) * 50 {
    return Err(AppError::PayloadTooLarge("wormhole_size_exceeds_limit"));
  }

  let is_e2ee = extract_e2ee_flag(&headers);
  let now = current_unix_timestamp();
  let sender_token = generate_random_string(24);
  let mut room_id = String::new();

  {
    let mut rooms = state
      .wormhole_rooms
      .lock()
      .map_err(|_| AppError::Internal("wormhole_lock_poisoned".into()))?;

    evict_expired_rooms(&mut rooms, now);
    if rooms.len() >= MAX_WORMHOLE_ROOMS {
      return Err(AppError::TooManyRequests("wormhole_capacity_full"));
    }

    // Guarantee collision-free room allocation
    for _ in 0..SLUG_MAX_RETRIES {
      let candidate = generate_random_string(WORMHOLE_ID_LENGTH);
      if !rooms.contains_key(&candidate) {
        room_id = candidate;
        break;
      }
    }
    if room_id.is_empty() {
      return Err(AppError::Internal("wormhole_id_allocation_exhausted".into()));
    }

    rooms.insert(
      room_id.clone(),
      WormholeRoom {
        created_at: now,
        sender_token: sender_token.clone(),
        filename,
        filesize,
        e2ee: is_e2ee,
        offer: None,
        answer: None,
        sender_ice: Vec::with_capacity(8),
        receiver_ice: Vec::with_capacity(8),
        revision: 1,
        notify: Arc::new(Notify::new()),
      },
    );
  }

  let origin = resolve_request_origin(
    &peer_addr,
    &headers,
    state.app_origin.as_deref(),
    &state.public_url,
  );
  let share_url = format!("{}/w/{}", origin, room_id);
  let json = format!(
    r#"{{"room_id":"{}","url":"{}","sender_token":"{}"}}"#,
    room_id, share_url, sender_token
  );

  Ok(build_json_no_store_response(format!("{}\n", json)))
}

pub async fn signal_wormhole_handler(
  State(state): State<Arc<AppState>>,
  ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
  headers: HeaderMap,
  AxumPath(room_id): AxumPath<String>,
  Query(params): Query<HashMap<String, String>>,
  body: String,
) -> Result<Response, AppError> {
  validate_room_id(&room_id)?;

  if !state.rate_limiter.check_and_increment(&peer_addr, &headers) {
    return Err(AppError::TooManyRequests("rate_limit_exceeded"));
  }

  let trimmed_body = body.trim();
  if !is_safe_json_object(trimmed_body) {
    return Err(AppError::BadRequest("signal_body_must_be_valid_json_object"));
  }

  let role = params.get("role").map(|s| s.as_str()).unwrap_or("sender");
  let kind = params.get("kind").map(|s| s.as_str()).unwrap_or("offer");

  // Enforce strict per-type payload size caps to prevent RAM exhaustion DoS
  match kind {
    "offer" | "answer" => {
      if trimmed_body.len() > MAX_SDP_PAYLOAD_BYTES {
        return Err(AppError::PayloadTooLarge("sdp_payload_too_large"));
      }
    }
    "ice" => {
      if trimmed_body.len() > MAX_ICE_CANDIDATE_BYTES {
        return Err(AppError::PayloadTooLarge("ice_candidate_too_large"));
      }
    }
    _ => return Err(AppError::BadRequest("invalid_signal_role_or_kind")),
  }

  let supplied_token = headers
    .get("x-kura-wormhole-token")
    .and_then(|v| v.to_str().ok())
    .map(|s| s.trim())
    .unwrap_or("");

  let now = current_unix_timestamp();

  let notify = {
    let mut rooms = state
      .wormhole_rooms
      .lock()
      .map_err(|_| AppError::Internal("wormhole_lock_poisoned".into()))?;

    let room = rooms
      .get_mut(&room_id)
      .ok_or(AppError::NotFound("wormhole_room_expired"))?;

    if now.saturating_sub(room.created_at) >= WORMHOLE_ROOM_TTL {
      let expired_notify = room.notify.clone();
      rooms.remove(&room_id);
      expired_notify.notify_waiters();
      return Err(AppError::NotFound("wormhole_room_expired"));
    }

    // Strict mandatory authentication for sender role (closes empty-token bypass vulnerability)
    if role == "sender" {
      if supplied_token.is_empty()
        || !constant_time_eq(supplied_token.as_bytes(), room.sender_token.as_bytes())
      {
        return Err(AppError::Forbidden("invalid_wormhole_sender_token"));
      }
    }

    match (role, kind) {
      ("sender", "offer") => {
        if room.offer.is_some() {
          return Err(AppError::Forbidden("sdp_offer_already_locked"));
        }
        room.offer = Some(trimmed_body.to_string());
      }
      ("receiver", "answer") => {
        if room.offer.is_none() {
          return Err(AppError::BadRequest("cannot_answer_before_offer"));
        }
        if room.answer.is_some() {
          return Err(AppError::Forbidden("sdp_answer_already_locked"));
        }
        room.answer = Some(trimmed_body.to_string());
      }
      ("sender", "ice") => {
        if room.sender_ice.len() < MAX_ICE_CANDIDATES_PER_PEER
          && !room.sender_ice.iter().any(|c| c == trimmed_body)
        {
          room.sender_ice.push(trimmed_body.to_string());
        }
      }
      ("receiver", "ice") => {
        if room.receiver_ice.len() < MAX_ICE_CANDIDATES_PER_PEER
          && !room.receiver_ice.iter().any(|c| c == trimmed_body)
        {
          room.receiver_ice.push(trimmed_body.to_string());
        }
      }
      _ => return Err(AppError::BadRequest("invalid_signal_role_or_kind")),
    }

    room.revision = room.revision.saturating_add(1);
    room.notify.clone()
  };

  notify.notify_waiters();
  Ok((StatusCode::OK, "ok\n").into_response())
}

pub async fn state_wormhole_handler(
  State(state): State<Arc<AppState>>,
  AxumPath(room_id): AxumPath<String>,
  Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
  validate_room_id(&room_id)?;

  let since_rev = params
    .get("since")
    .and_then(|s| s.parse::<u64>().ok())
    .unwrap_or(0);
  let wait_ms = params
    .get("wait_ms")
    .and_then(|s| s.parse::<u64>().ok())
    .unwrap_or(0)
    .min(MAX_POLL_WAIT_MS);

  let now = current_unix_timestamp();

  let notify_arc = {
    let mut rooms = state
      .wormhole_rooms
      .lock()
      .map_err(|_| AppError::Internal("wormhole_lock_poisoned".into()))?;

    let room = rooms
      .get(&room_id)
      .ok_or(AppError::NotFound("wormhole_room_expired"))?;

    if now.saturating_sub(room.created_at) >= WORMHOLE_ROOM_TTL {
      let expired_notify = room.notify.clone();
      rooms.remove(&room_id);
      expired_notify.notify_waiters();
      return Err(AppError::NotFound("wormhole_room_expired"));
    }

    if room.revision <= since_rev && wait_ms > 0 {
      Some(room.notify.clone())
    } else {
      None
    }
  };

  // Race-free long-polling: register the Notified future and re-verify revision before sleeping
  if let Some(ref notify) = notify_arc {
    let notified = notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();

    let should_sleep = {
      let rooms = state
        .wormhole_rooms
        .lock()
        .map_err(|_| AppError::Internal("wormhole_lock_poisoned".into()))?;
      rooms
        .get(&room_id)
        .map(|r| r.revision <= since_rev)
        .unwrap_or(false)
    };

    if should_sleep {
      let _ = timeout(Duration::from_millis(wait_ms), notified).await;
    }
  }

  let json = {
    let mut rooms = state
      .wormhole_rooms
      .lock()
      .map_err(|_| AppError::Internal("wormhole_lock_poisoned".into()))?;

    let room = rooms
      .get(&room_id)
      .ok_or(AppError::NotFound("wormhole_room_expired"))?;

    if current_unix_timestamp().saturating_sub(room.created_at) >= WORMHOLE_ROOM_TTL {
      rooms.remove(&room_id);
      return Err(AppError::NotFound("wormhole_room_expired"));
    }

    let offer_json = room.offer.as_deref().unwrap_or("null");
    let answer_json = room.answer.as_deref().unwrap_or("null");

    // Pre-allocate single buffer for JSON serialization to avoid intermediate Vec/String allocations
    let approx_cap = 256
      + offer_json.len()
      + answer_json.len()
      + room.sender_ice.iter().map(|s| s.len() + 1).sum::<usize>()
      + room.receiver_ice.iter().map(|s| s.len() + 1).sum::<usize>();

    let mut out = String::with_capacity(approx_cap);
    out.push_str(r#"{"revision":"#);
    out.push_str(&room.revision.to_string());
    out.push_str(r#","filename":""#);
    out.push_str(&room.filename);
    out.push_str(r#"","filesize":"#);
    out.push_str(&room.filesize.to_string());
    out.push_str(r#","e2ee":"#);
    out.push_str(if room.e2ee { "true" } else { "false" });
    out.push_str(r#","offer":"#);
    out.push_str(offer_json);
    out.push_str(r#","answer":"#);
    out.push_str(answer_json);
    out.push_str(r#","sender_ice":["#);
    for (i, ice) in room.sender_ice.iter().enumerate() {
      if i > 0 {
        out.push(',');
      }
      out.push_str(ice);
    }
    out.push_str(r#"],"receiver_ice":["#);
    for (i, ice) in room.receiver_ice.iter().enumerate() {
      if i > 0 {
        out.push(',');
      }
      out.push_str(ice);
    }
    out.push_str("]}\n");
    out
  };

  Ok(build_json_no_store_response(json))
}

pub async fn view_wormhole_receiver_handler(
  State(state): State<Arc<AppState>>,
  AxumPath(room_id): AxumPath<String>,
) -> Result<Html<String>, AppError> {
  validate_room_id(&room_id)?;

  let now = current_unix_timestamp();
  let (filename, filesize, is_e2ee) = {
    let mut rooms = state
      .wormhole_rooms
      .lock()
      .map_err(|_| AppError::Internal("wormhole_lock_poisoned".into()))?;

    let room = rooms
      .get(&room_id)
      .ok_or(AppError::NotFound("wormhole_room_expired"))?;

    if now.saturating_sub(room.created_at) >= WORMHOLE_ROOM_TTL {
      let expired_notify = room.notify.clone();
      rooms.remove(&room_id);
      expired_notify.notify_waiters();
      return Err(AppError::NotFound("wormhole_room_expired"));
    }

    (room.filename.clone(), room.filesize, room.e2ee)
  };

  let mode_badge = if is_e2ee {
    "WebRTC P2P Direct Stream · AES-256-GCM E2EE"
  } else {
    "WebRTC P2P Direct Stream · Zero Server Storage"
  };

  let html = format!(
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{filename} — P2P Wormhole — kura — 蔵</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:#080808;color:#efefef;font-family:"JetBrains Mono",Consolas,monospace;min-height:100vh;display:flex;justify-content:center;align-items:center;padding:1.5rem;}}
.card{{width:100%;max-width:460px;background:#0d0d0d;border:1px solid #222;padding:1.5rem;position:relative;}}
.top{{display:flex;justify-content:space-between;align-items:center;margin-bottom:0.35rem;gap:0.5rem;}}
.title{{font-size:0.9rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
.panic{{background:transparent;color:#525252;border:1px solid #222;font-family:inherit;font-size:0.62rem;padding:0.15rem 0.4rem;cursor:pointer;flex-shrink:0;}}
.panic:hover{{color:#fff;background:#ef4444;border-color:#ef4444;}}
.sub{{font-size:0.7rem;color:#8a8a8a;margin-bottom:1.2rem;}}
.bar{{width:100%;height:4px;background:#161616;margin-bottom:0.75rem;overflow:hidden;}}
.fill{{height:100%;width:0%;background:#10b981;transition:width 0.1s linear;}}
.meta{{display:flex;justify-content:space-between;font-size:0.68rem;color:#8a8a8a;margin-bottom:1.1rem;}}
.btn{{width:100%;background:#efefef;color:#080808;border:none;font-family:inherit;font-size:0.78rem;font-weight:600;padding:0.65rem;cursor:pointer;}}
.btn:hover{{background:#fff;}}
.btn:disabled{{opacity:0.5;cursor:not-allowed;}}
</style>
</head>
<body>
<div class="card">
<div class="top">
<div class="title">{filename}</div>
<button type="button" class="panic" id="panic-btn" title="Double-tap Esc to wipe trace &amp; exit">ESC×2 PANIC</button>
</div>
<div class="sub">{mode_badge}</div>
<div class="bar"><div class="fill" id="p2p-fill"></div></div>
<div class="meta">
<span id="p2p-status">Waiting for peer handshake...</span>
<span id="p2p-bytes">0 B / {filesize} B</span>
</div>
<button type="button" class="btn" id="p2p-btn">Connect &amp; Receive P2P Stream</button>
</div>
<script>
{PANIC_ESCAPE_JS}
const fmt = b => {{
  if (!b) return '0 B';
  const k = 1024, s = ['B','KiB','MiB','GiB'], i = Math.floor(Math.log(b)/Math.log(k));
  return parseFloat((b/Math.pow(k,i)).toFixed(2)) + ' ' + s[i];
}};
const totalSize = {filesize};
const isE2ee = {is_e2ee};
const statusEl = document.getElementById('p2p-status');
const bytesEl = document.getElementById('p2p-bytes');
const fillEl = document.getElementById('p2p-fill');
const btn = document.getElementById('p2p-btn');
bytesEl.textContent = '0 B / ' + fmt(totalSize);

btn.onclick = async () => {{
  btn.disabled = true;
  statusEl.textContent = 'Fetching sender SDP offer...';
  let pc = null;
  let iceSyncActive = true;
  try {{
    let cryptoKey = null;
    if (isE2ee) {{
      const hashKey = window.location.hash.slice(1);
      if (!hashKey) throw new Error('Missing E2EE key in URL #fragment');
      const rawKey = Uint8Array.from(atob(hashKey.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
      cryptoKey = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    }}

    let state = null;
    for (let i = 0; i < 20; i++) {{
      const res = await fetch('/wormhole/{room_id}/state?wait_ms=3000');
      if (!res.ok) throw new Error('Wormhole room expired');
      state = await res.json();
      if (state.offer) break;
    }}
    if (!state || !state.offer) throw new Error('Sender offer not ready');

    pc = new RTCPeerConnection({{
      iceServers: [
        {{ urls: 'stun:stun.l.google.com:19302' }},
        {{ urls: 'stun:stun.cloudflare.com:3478' }}
      ]
    }});

    pc.onicecandidate = e => {{
      if (e.candidate) {{
        fetch('/wormhole/{room_id}/signal?role=receiver&kind=ice', {{
          method: 'POST',
          body: JSON.stringify(e.candidate)
        }}).catch(() => {{}});
      }}
    }};

    const chunks = [];
    let received = 0;
    const hardCap = totalSize > 0 ? totalSize : (200 * 1024 * 1024);
    const t0 = performance.now();

    pc.ondatachannel = ev => {{
      const dc = ev.channel;
      dc.binaryType = 'arraybuffer';
      statusEl.textContent = 'P2P DataChannel open · Streaming...';
      dc.onmessage = async msg => {{
        try {{
          if (typeof msg.data === 'string' && msg.data === 'EOF') {{
            iceSyncActive = false;
            if (totalSize > 0 && received !== totalSize) {{
              throw new Error('Transfer truncated (' + received + ' / ' + totalSize + ' B)');
            }}
            statusEl.textContent = 'Assembling file...';
            const blob = new Blob(chunks, {{ type: 'application/octet-stream' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = '{filename}';
            document.body.appendChild(a);
            a.click();
            a.remove();
            statusEl.textContent = 'P2P Transfer Complete';
            btn.textContent = 'Downloaded';
            dc.close();
            pc.close();
            return;
          }}
          let buf = msg.data;
          if (cryptoKey) {{
            const arr = new Uint8Array(buf);
            if (arr.byteLength < 28) throw new Error('Corrupted E2EE frame');
            const iv = arr.slice(0, 12);
            const ct = arr.slice(12);
            buf = await crypto.subtle.decrypt({{ name: 'AES-GCM', iv }}, cryptoKey, ct);
          }}
          if (received + buf.byteLength > hardCap) {{
            throw new Error('Stream exceeded declared filesize limit');
          }}
          chunks.push(buf);
          received += buf.byteLength;
          const pct = totalSize > 0 ? Math.min(100, Math.round((received / totalSize) * 100)) : 100;
          const elapsed = (performance.now() - t0) / 1000;
          const speed = elapsed > 0 ? fmt(received / elapsed) + '/s' : '--';
          fillEl.style.width = pct + '%';
          statusEl.textContent = pct + '% · ' + speed;
          bytesEl.textContent = fmt(received) + ' / ' + fmt(totalSize);
        }} catch (streamErr) {{
          iceSyncActive = false;
          chunks.length = 0;
          try {{ dc.close(); pc.close(); }} catch (_) {{}}
          btn.disabled = false;
          statusEl.textContent = streamErr.message || 'Stream integrity error';
        }}
      }};
    }};

    await pc.setRemoteDescription(new RTCSessionDescription(state.offer));
    let appliedSenderIce = 0;
    const initialIce = state.sender_ice || [];
    for (const c of initialIce) {{
      try {{ await pc.addIceCandidate(new RTCIceCandidate(c)); appliedSenderIce++; }} catch (_) {{}}
    }}

    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    const ansRes = await fetch('/wormhole/{room_id}/signal?role=receiver&kind=answer', {{
      method: 'POST',
      body: JSON.stringify(pc.localDescription)
    }});
    if (!ansRes.ok) throw new Error('Failed to submit SDP answer');
    statusEl.textContent = 'Handshake sent · Awaiting P2P stream...';

    // Continuous Trickle-ICE synchronization until DataChannel completes or connects
    let lastRev = state.revision || 0;
    (async () => {{
      for (let poll = 0; poll < 15 && iceSyncActive; poll++) {{
        if (pc.connectionState === 'connected' || pc.connectionState === 'closed') break;
        try {{
          const r = await fetch('/wormhole/{room_id}/state?since=' + lastRev + '&wait_ms=2000');
          if (!r.ok) break;
          const st = await r.json();
          lastRev = st.revision || lastRev;
          const allIce = st.sender_ice || [];
          while (appliedSenderIce < allIce.length) {{
            try {{ await pc.addIceCandidate(new RTCIceCandidate(allIce[appliedSenderIce])); }} catch (_) {{}}
            appliedSenderIce++;
          }}
        }} catch (_) {{ break; }}
      }}
    }})();
  }} catch (err) {{
    iceSyncActive = false;
    if (pc) {{ try {{ pc.close(); }} catch (_) {{}} }}
    btn.disabled = false;
    statusEl.textContent = err.message || 'P2P connection failed';
  }}
}};
</script>
</body>
</html>"#
  );

  Ok(Html(html))
}