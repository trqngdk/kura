<div align="center">

# kura — 蔵

**Zero-disk ephemeral object vault, cascade E2EE store, and P2P WebRTC relay.**

[![Rust](https://img.shields.io/badge/rust-1.80%2B-000000.svg?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![Axum](https://img.shields.io/badge/runtime-tokio%20%2F%20axum-0d0d0d.svg?style=flat-square)](https://github.com/tokio-rs/axum)
[![Storage](https://img.shields.io/badge/storage-S3%20%2F%20R2-0d0d0d.svg?style=flat-square)](https://developers.cloudflare.com/r2/)
[![Database](https://img.shields.io/badge/state-SQLite%20WAL%20%2B%20Litestream-0d0d0d.svg?style=flat-square)](https://litestream.io/)

[Architecture](#architecture) · [Cryptography](#cryptography--access-control) · [Rate Limiting](#rate-limiting--abuse-mitigation) · [API & CLI](#api--cli-reference) · [Deployment](#configuration--deployment)

</div>

---

**kura** is a single-binary file and text vault written in Rust. It is designed to operate on minimal compute resources by streaming payloads directly between network sockets and S3-compatible object storage (Cloudflare R2) without writing intermediate files to the local disk.

It pairs server-side envelope encryption and atomic SQLite metadata management with an embedded, dependency-free browser client that supports dual-cipher client-side encryption, Shamir's Secret Sharing ($M$-of-$N$), discrete traffic padding, and direct peer-to-peer WebRTC transfers.

---

## Architecture

```text
                                   ┌──────────────────────────────────────┐
                                   │             kura daemon              │
                                   │                                      │
Client ──► PUT / POST / WebRTC ───►│  BlindedRateLimiter (64-bit Atomic)  │
                                   │                  │                   │
                                   │         ┌────────┴────────┐          │
                                   │         ▼                 ▼          │
                                   │  4 KiB Magic Sniff   Signaling Room  │
                                   │  ChaCha20 Stream     (In-Memory)     │
                                   │         │                 │          │
                                   └─────────┼─────────────────┼──────────┘
                                             │                 │
                         ┌───────────────────┴───┐             ▼
                         ▼                       ▼      Direct WebRTC P2P
               ┌───────────────────┐   ┌───────────────────┐
               │   Cloudflare R2   │   │  SQLite (WAL)     │
               │   Object Storage  │◄──│  + Litestream     │
               └───────────────────┘   └───────────────────┘
```

### Zero-Disk Streaming Pipeline

kura avoids local filesystem staging during both uploads and downloads:

1. **In-Memory Magic Sniffing:** Incoming streams buffer up to the first `8 MiB` in RAM (`4 KiB` minimum inspection window) to verify file signatures, strip polyglot payloads, and compute SHA-256 digests for content-addressable deduplication.
2. **Direct R2 Multipart Streaming:** Payloads exceeding the memory threshold stream directly to the target R2 object in `256 KiB` batched chunks. If an upload is interrupted or fails SHA-256 verification at EOF, an RAII guard (`R2ObjectGuard`) aborts and deletes the partial object automatically.
3. **Zero-Copy Egress:** Unencrypted public downloads convert OpenDAL buffers directly into HTTP `Bytes` frames without intermediate heap copies. Server-encrypted payloads are decrypted in-place at arbitrary byte offsets, preserving full support for `HTTP 206 Partial Content` (`Range` requests).
4. **Resumable Chunk Assembly:** Large uploads (`10 MiB` to `200 MiB`) split into `10 MiB` parts stored as ephemeral R2 objects. Upon completion, the server claims the session atomically (`DELETE ... RETURNING`) and streams the parts into the final destination object.

---

## Cryptography & Access Control

### 1. Client-Side Cascade Encryption (E2EE v2)
When end-to-end encryption is enabled in the browser, plaintext never leaves the client:
* **Key Derivation:** A 256-bit master key is generated via `crypto.getRandomValues`. Using `HKDF-SHA256` salted with a 96-bit IV and bound to the file's metadata JSON, two orthogonal 256-bit subkeys are derived.
* **Dual-Cipher Cascade:** Plaintext is first XORed through a 32-bit word-aligned `ChaCha20` stream cipher, then encrypted and authenticated with `AES-256-GCM` using the metadata header as Additional Authenticated Data (AAD).
* **URL Fragment Transport:** The master key is encoded in the URL `#fragment`, which browsers do not transmit in HTTP requests.

### 2. Shamir's Secret Sharing ($M$-of-$N$ Split Custody)
Instead of embedding the master key in the URL, the 256-bit key can be split into $N$ mathematical shares over the finite field $\text{GF}(2^8)$ (irreducible polynomial `0x11B`, generator `0x03`). Reconstructing the key at the download gate requires Lagrange interpolation over any $M$ valid shares (`2-of-3`, `3-of-5`, or `4-of-7`).

### 3. Server-Side Envelope Encryption & Crypto-Shredding
All protected or ephemeral files (password-locked, time-locked, burn-after-read, or view-limited) are encrypted in transit to R2:
* Each file receives a unique 256-bit Data Encryption Key (DEK) and 96-bit nonce.
* The server derives two distinct subkeys (`enc_kek` and `mac_kek`) from an ephemeral in-memory boot secret and the file's slug via `HKDF-SHA256`.
* The DEK is encrypted with `ChaCha20` and authenticated with an `HMAC-SHA256` tag binding the domain, slug, nonce, and ciphertext.

### 4. Hybrid Memory-Hard Password KDF & Duress Destruction
* **Password Verification:** Passwords are processed through 100,000 rounds of `PBKDF2-HMAC-SHA256` to seed an `8,192`-block (`256 KiB`) memory matrix. The matrix undergoes 2 data-independent rounds (cache-timing resistant) followed by 4 data-dependent rounds (ASIC/GPU resistant) and full-lane XOR folding before final HKDF extraction.
* **Constant-Time Dual Evaluation:** Authentication always executes two full KDF evaluations per attempt to prevent timing side-channels from revealing whether a file has a primary password, a duress password, or both.
* **Duress Wipe:** Entering the configured secondary duress password immediately deletes the database record and purges the underlying R2 object, returning `410 Gone`.
* **Volatile Memory Scrubbing:** Ephemeral keys, KDF matrices, and credential structs are overwritten using `write_volatile` and `compiler_fence(Ordering::SeqCst)` prior to deallocation.

---

## Traffic Privacy & Content Sanitization

* **Discrete Bucket Padding:** To mitigate size-correlation traffic analysis, client-side E2EE can pad payloads with CSPRNG bytes to fixed bucket boundaries (`64 KiB`, `512 KiB`, `2 MiB`, `8 MiB`, `32 MiB`, `200 MiB`). The exact byte length is stored inside the AAD-authenticated metadata header and truncated upon decryption.
* **Polyglot & Active-Content Disarming:** The server inspects the first `4 KiB` of every unencrypted upload:
  * Blocks disguised native executables (`PE/MZ`, `ELF`, `Mach-O`, `WASM`, `.lnk`).
  * Normalizes null-interleaved (`UTF-16`) and whitespace-padded streams to detect embedded HTML/JS/SVG polyglot tags, forcing `application/octet-stream` and `Content-Disposition: attachment`.
  * Scans PDF headers for active directives (`/JavaScript`, `/JS`, `/Launch`, `/OpenAction`, `/RichMedia`) and disables inline browser rendering if detected.
* **Client-Side EXIF Stripping:** JPEG, PNG, and WebP images are re-encoded through an offscreen HTML5 Canvas prior to upload, stripping GPS coordinates and camera metadata.
* **Crawler Shield:** Link preview bots (`TelegramBot`, `Discordbot`, `Slackbot`, `Twitterbot`, `WhatsApp`, etc.) and `Purpose: prefetch` requests receive an inert HTML gate rather than triggering `1-view` burn-after-read counters.

---

## Rate Limiting & Abuse Mitigation

kura implements a lock-free, zero-allocation rate limiter (`BlindedRateLimiter`) backed by fixed-size atomic arrays:

### 1. 64-Bit Bit-Packed Sliding-Window Count-Min Sketch
Per-actor traffic is tracked in a `4 x 4096` Count-Min Sketch using Conservative Update. Each `AtomicU64` slot packs three values into a single 64-bit word:

```text
┌──────────────────────────┬──────────────────────────┬──────────────────────────┐
│   Bits 63..40 (24-bit)   │   Bits 39..20 (20-bit)   │   Bits 19..0  (20-bit)   │
│       Minute Epoch       │   Previous Minute Count  │   Current Minute Count   │
└──────────────────────────┴──────────────────────────┴──────────────────────────┘
```

At second $s \in [0, 59]$ of the current minute, the effective sliding-window rate is evaluated via integer arithmetic without locks or heap allocations:

$$\text{Rate} = \text{Count}_{\text{curr}} + \left\lfloor \frac{\text{Count}_{\text{prev}} \times (60 - s)}{60} \right\rfloor$$

Client IP addresses are blinded with the server's boot secret, and IPv6 addresses are normalized to `/64` prefixes to prevent SLAAC address rotation bypasses.

### 2. Adaptive Hashcash Proof-of-Work & 4-Way Set-Associative Replay Cache
When per-actor or global traffic crosses soft thresholds, the server issues a signed stateless challenge (`X-Kura-Pow-Challenge`) requiring a 16-bit leading-zero `SHA-256` collision.
* **Replay Prevention:** Verified solutions are recorded in a `2,048`-slot atomic array organized as a **512-set, 4-way set-associative cache** packing a 20-bit timestamp and a 44-bit solution fingerprint. This prevents 1-way hash-collision ping-pong replay attacks.

### 3. Power-of-Two-Choices ZIP Stream Leases
Streaming album `.zip` archives are generated on the fly (PKWARE STORE method with streaming CRC-32 calculation). Concurrent ZIP downloads per actor are governed by a 2-choice hashed atomic table with self-healing 300-second timestamp leases.

---

## API & CLI Reference

### Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `POST` / `PUT` | `/upload` | Multipart or raw binary stream upload |
| `PUT` / `POST` | `/upload/{filename}` | Named raw binary stream upload |
| `POST` | `/upload/presign` | Request presigned R2 write URL & HMAC commit token |
| `POST` | `/upload/commit` | Verify R2 object & commit presigned upload |
| `POST` | `/upload/resumable/init` | Initialize or resume a chunked upload session |
| `PUT` | `/upload/resumable/{sid}/{part}` | Stream a `10 MiB` resumable chunk to R2 |
| `POST` | `/upload/resumable/{sid}/complete` | Verify SHA-256, assemble chunks, and finalize |
| `POST` | `/wormhole/init` | Create an ephemeral WebRTC signaling room |
| `POST` | `/wormhole/{id}/signal` | Submit SDP offer/answer or Trickle-ICE candidate |
| `GET` | `/wormhole/{id}/state` | Long-poll room state (`?since={rev}&wait_ms={ms}`) |
| `POST` | `/album` | Bundle newline-separated public slugs into a ZIP album |
| `GET` | `/a/{album_id}/zip` | Stream on-the-fly `.zip` archive of album contents |
| `GET` | `/stats/{id}` | Retrieve JSON telemetry for a file slug |
| `GET` / `POST` | `/v/{id}` or `/{id}` | Access download gate, media player, code viewer, or raw file |
| `DELETE` | `/v/{id}` or `/{id}` | Delete file using `X-Kura-Delete-Key` |

### Request Headers

| Header | Values / Format | Description |
| :--- | :--- | :--- |
| `X-Content-Sha256` | 64-char hex string | Pre-flight deduplication & end-to-end integrity check |
| `X-Kura-Expire` | `never`, `1h`, `24h`, `7d`, `1v`, `5v`, `10v` | Retention TTL or maximum view limit (`1v` = burn after read) |
| `X-Kura-Timelock` | `15m`, `1h`, `6h`, `24h`, `7d`, or Unix TS | Locks file access until the specified future timestamp |
| `X-Kura-Password` | UTF-8 string ($\le 128$ bytes) | Protects file download behind the authentication gate |
| `X-Kura-Duress-Password` | UTF-8 string ($\le 128$ bytes) | Secondary password that permanently wipes the file when entered |
| `X-Kura-E2EE` | `1` or `0` | Flags payload as client-side encrypted |
| `X-Kura-Shamir-M` | Integer `2..=16` | Records required threshold $M$ for Shamir split-key payloads |
| `X-Kura-Pow` | `{challenge}:{nonce}` | Hashcash Proof-of-Work solution token |

### CLI Usage

Stream directly from `stdin` or upload local files with `curl`:

```sh
# Stream stdin
uname -a | curl -T - [https://your-domain.example/upload/sys.txt](https://your-domain.example/upload/sys.txt)

# Upload with 5-view limit, 1-hour time-lock, primary password, and duress wipe code
curl -sS -X PUT \
  -H "X-Kura-Expire: 5v" \
  -H "X-Kura-Timelock: 1h" \
  -H "X-Kura-Password: correct-horse-battery" \
  -H "X-Kura-Duress-Password: panic-wipe-code" \
  --data-binary @archive.tar.zst \
  [https://your-domain.example/upload/archive.tar.zst](https://your-domain.example/upload/archive.tar.zst)

# Use the built-in POSIX shell helper
curl -sSL [https://your-domain.example/kura.sh](https://your-domain.example/kura.sh) | sh -s -- -e 24h -p secret document.pdf
```

---

## Configuration & Deployment

### Environment Variables

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `R2_ACCOUNT_ID` | Yes | — | Cloudflare account ID for R2 S3 endpoint |
| `R2_BUCKET` | Yes | — | Target R2 bucket name |
| `R2_ACCESS_KEY_ID` | Yes | — | R2 S3 API access key ID |
| `R2_SECRET_ACCESS_KEY` | Yes | — | R2 S3 API secret access key |
| `PUBLIC_URL_PREFIX` | Yes | — | Public base URL for fallback link generation |
| `APP_ORIGIN` | No | Dynamic `Host` | Canonical external origin (e.g., `https://vault.example.com`) |
| `DATABASE_URL` | No | `sqlite:kura.db` | SQLite connection URI |
| `BIND_ADDR` | No | `0.0.0.0` | Listening interface address |
| `PORT` | No | `3000` | Listening TCP port |
| `KURA_POW_REQUIRED` | No | `false` | Enforce Hashcash PoW on all uploads regardless of load |
| `LITESTREAM_ENABLED` | No | `true` | Enable automatic SQLite WAL replication to R2 |
| `LITESTREAM_BIN` | No | `litestream` | Path to the `litestream` binary |

### Building from Source

```sh
cargo build --release
```

The compiled binary requires only the `static/index.html` asset in its working directory (and optionally `litestream` in `$PATH` for continuous SQLite replication to R2). On shutdown (`SIGINT` / `SIGTERM`), kura stops the background reaper, executes `PRAGMA wal_checkpoint(TRUNCATE)` to flush all SQLite WAL frames into the primary database file, and waits for Litestream to synchronize before exiting.

---

## Project Layout

```text
src/
├── main.rs       # Server bootstrap, SQLite WAL tuning, Litestream supervisor, background reaper
├── config.rs     # System constants, RAII guards, volatile credential zeroization, error responses
├── crypto.rs     # Vectorized ChaCha20, zero-alloc HMAC/HKDF, hybrid KDF, polyglot/PDF disarmer
├── limiter.rs    # Bit-packed sliding-window Count-Min Sketch, 4-way PoW cache, 2-choice ZIP locks
├── upload.rs     # Unified single-pass R2 streaming, resumable assembly, presigned token handlers
├── download.rs   # Atomic view/burn accounting, zero-copy range streaming, HTML gate & viewers
├── wormhole.rs   # Race-free long-polling WebRTC signaling & Trickle-ICE P2P receiver
└── album.rs      # Single-transaction album binding & streaming PKWARE ZIP generator
static/
└── index.html    # Dependency-free SPA: 32-bit ChaCha20, GF(256) Shamir SSS, QR generator, P2P client
```

---

## License

Released under the MIT License.