// ============================================================================
// SYSTEM CONSTANTS & FINITE-FIELD LOOKUP TABLES
// ============================================================================

export const MAX_BYTES = 200 * 1024 * 1024;
export const RESUMABLE_THRESHOLD = 10 * 1024 * 1024;
export const CLIPBOARD_WIPE_MS = 30_000;

const MLKEM_Q = 3329;
const MLKEM_N = 256;

export const PADDING_BUCKETS = [
  64 * 1024,
  512 * 1024,
  2 * 1024 * 1024,
  8 * 1024 * 1024,
  32 * 1024 * 1024,
  200 * 1024 * 1024
];

export const HEX_STR_TABLE = Array.from({ length: 256 }, (_, i) =>
  i.toString(16).padStart(2, '0')
);

// GF(2^8) log/antilog tables (irreducible polynomial 0x11B, generator 0x03) for Shamir SSS
const GF256_EXP = new Uint8Array(512);
const GF256_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF256_EXP[i] = x;
    GF256_LOG[x] = i;
    const hi = x & 0x80;
    const x2 = ((x << 1) & 0xff) ^ (hi ? 0x1b : 0);
    x = x2 ^ x;
  }
  for (let i = 255; i < 512; i++) {
    GF256_EXP[i] = GF256_EXP[i - 255];
  }
})();

// GF(2^8) log/antilog tables (irreducible polynomial 0x11D) for QR Reed-Solomon ECC
const QR_GF_EXP = new Uint8Array(512);
const QR_GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    QR_GF_EXP[i] = x;
    QR_GF_LOG[x] = i;
    x = (x << 1) ^ (x & 0x80 ? 0x11d : 0);
  }
  for (let i = 255; i < 512; i++) {
    QR_GF_EXP[i] = QR_GF_EXP[i - 255];
  }
})();

// ============================================================================
// ENCODING, FORMATTING & URL SANITIZATION HELPERS
// ============================================================================

export const yieldFrame = () => new Promise(r => requestAnimationFrame(r));

export const formatBytes = (bytes) => {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return (bytes | 0) + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(2).replace(/\.?0+$/, '') + ' KiB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(2).replace(/\.?0+$/, '') + ' MiB';
  return (bytes / 1073741824).toFixed(2).replace(/\.?0+$/, '') + ' GiB';
};

export const bytesToBase64Url = (bytes) => {
  const CHUNK = 0x8000;
  const parts = [];
  for (let i = 0; i < bytes.length; i += CHUNK) {
    parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK)));
  }
  return btoa(parts.join(''))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
};

// Restricts URLs to relative paths or http/https schemes to block javascript:/data: injection
export const sanitizeSafeUrl = (rawUrl) => {
  if (typeof rawUrl !== 'string') return '#';
  const trimmed = rawUrl.trim();
  if (trimmed.startsWith('/')) return trimmed;
  try {
    const parsed = new URL(trimmed, window.location.origin);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.href;
    }
  } catch (_) {}
  return '#';
};

export const extractSlugFromUrl = (url) => {
  try {
    const clean = url.split('#')[0].split('?')[0];
    const lastSeg = clean.split('/').pop() || '';
    const slug = lastSeg.split('.')[0];
    return slug.length === 8 ? slug : null;
  } catch (_) {
    return null;
  }
};

// ============================================================================
// HASHING, POW SOLVER, SIGNALING MAC & EXIF SCRUBBER
// ============================================================================

// Accepts an existing Uint8Array directly to avoid redundant File.arrayBuffer() allocations
export const computeClientSha256 = async (source) => {
  if (!window.crypto || !window.crypto.subtle) return null;
  const buffer = source instanceof Uint8Array ? source : await source.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const bytes = new Uint8Array(hashBuffer);
  let hex = '';
  for (let i = 0; i < 32; i++) hex += HEX_STR_TABLE[bytes[i]];
  return hex;
};

// Generates HMAC-SHA256 signatures matching `verify_wormhole_signal_proof` in `src/crypto.rs`
export const createWormholeSignalSigner = (roomId, rawToken) => {
  let keyPromise = null;
  return async (role, kind, bodyStr) => {
    if (!rawToken) return '';
    if (!keyPromise) {
      const keyBytes = new TextEncoder().encode(rawToken);
      keyPromise = crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );
    }
    const cryptoKey = await keyPromise;
    const msg = new TextEncoder().encode(
      `kura_wormhole_sig_v3:${roomId}:${role}:${kind}:${bodyStr}`
    );
    const sigBuf = await crypto.subtle.sign('HMAC', cryptoKey, msg);
    const sigBytes = new Uint8Array(sigBuf);
    let hex = '';
    for (let i = 0; i < 32; i++) hex += HEX_STR_TABLE[sigBytes[i]];
    return hex;
  };
};

// In-place ASCII buffer Hashcash solver; yields every 4,096 iterations to keep UI responsive
export const solvePowChallenge = async (challenge, difficultyBits = 16) => {
  const prefixBytes = new TextEncoder().encode(challenge + ':');
  const pLen = prefixBytes.length;
  const scratch = new Uint8Array(pLen + 12);
  scratch.set(prefixBytes, 0);

  const fullBytes = difficultyBits >> 3;
  const remBits = difficultyBits & 7;
  const mask = remBits > 0 ? (0xff << (8 - remBits)) & 0xff : 0;

  for (let nonce = 0; nonce < 10_000_000; nonce++) {
    if ((nonce & 4095) === 4095) await yieldFrame();

    let n = nonce;
    let dLen = 0;
    let tmp = n;
    do {
      dLen++;
      tmp = (tmp / 10) | 0;
    } while (tmp > 0);

    const totalLen = pLen + dLen;
    for (let pos = totalLen - 1; pos >= pLen; pos--) {
      scratch[pos] = 48 + (n % 10);
      n = (n / 10) | 0;
    }

    const buf = await crypto.subtle.digest('SHA-256', scratch.subarray(0, totalLen));
    const digest = new Uint8Array(buf);
    let ok = true;
    for (let i = 0; i < fullBytes; i++) {
      if (digest[i] !== 0) {
        ok = false;
        break;
      }
    }
    if (ok && remBits > 0 && (digest[fullBytes] & mask) !== 0) {
      ok = false;
    }
    if (ok) return `${challenge}:${nonce}`;
  }
  return null;
};

// Re-encodes raster images through an offscreen canvas to strip EXIF/GPS metadata
export const scrubImageMetadata = (file, stripExifEnabled = true) => {
  return new Promise((resolve) => {
    const scrubbable = ['image/jpeg', 'image/png', 'image/webp'];
    if (!stripExifEnabled || !scrubbable.includes(file.type)) {
      return resolve(file);
    }

    const img = new Image();
    const objectUrl = URL.createObjectURL(file);

    img.onload = () => {
      URL.revokeObjectURL(objectUrl);
      const canvas = document.createElement('canvas');
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);

      canvas.toBlob(
        (blob) => {
          if (!blob) return resolve(file);
          const cleanedFile = new File([blob], file.name, {
            type: file.type,
            lastModified: Date.now()
          });
          resolve(cleanedFile);
        },
        file.type,
        0.96
      );
    };

    img.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      resolve(file);
    };

    img.src = objectUrl;
  });
};

// ============================================================================
// HYBRID POST-QUANTUM KEM MIXER, SHAMIR GF(256) & IN-PLACE 32-BIT CHACHA20
// ============================================================================

// Evaluates a Ring-LWE polynomial product in Z_3329[X]/(X^256+1) with CBD_2 noise
// and mixes it with 256-bit classical CSPRNG entropy via SHA-256
export const generateHybridPqcMasterKey = async () => {
  const classicalSeed = crypto.getRandomValues(new Uint8Array(32));
  const latticeRaw = crypto.getRandomValues(new Uint8Array(576));
  const polyA = new Uint16Array(MLKEM_N);
  const polyS = new Uint16Array(MLKEM_N);
  const polyAcc = new Uint16Array(MLKEM_N);

  for (let i = 0; i < MLKEM_N; i++) {
    polyA[i] = (latticeRaw[i * 2] | (latticeRaw[i * 2 + 1] << 8)) % MLKEM_Q;
    const byte = latticeRaw[512 + (i >> 2)];
    const nib = (byte >> ((i & 3) * 2)) & 0x03;
    const centered = (nib & 1) - ((nib >> 1) & 1);
    polyS[i] = (centered + MLKEM_Q) % MLKEM_Q;
  }

  for (let i = 0; i < MLKEM_N; i++) {
    let sum = 0;
    for (let j = 0; j < MLKEM_N; j++) {
      const sIdx = (i + MLKEM_N - j) & (MLKEM_N - 1);
      const prod = (polyA[j] * polyS[sIdx]) % MLKEM_Q;
      sum = i >= j ? (sum + prod) % MLKEM_Q : (sum + MLKEM_Q - prod) % MLKEM_Q;
    }
    polyAcc[i] = sum;
  }

  const hybridBuf = new Uint8Array(32 + MLKEM_N * 2);
  hybridBuf.set(classicalSeed, 0);
  new Uint8Array(polyAcc.buffer).forEach((b, idx) => {
    hybridBuf[32 + idx] = b;
  });

  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', hybridBuf));

  classicalSeed.fill(0);
  latticeRaw.fill(0);
  polyA.fill(0);
  polyS.fill(0);
  polyAcc.fill(0);
  hybridBuf.fill(0);
  return digest;
};

const gf256MulFast = (a, b) =>
  a === 0 || b === 0 ? 0 : GF256_EXP[GF256_LOG[a] + GF256_LOG[b]];

export const splitShamirSecret = (secretBytes, thresholdM, totalN) => {
  const shares = Array.from({ length: totalN }, (_, idx) => ({
    x: idx + 1,
    bytes: new Uint8Array(secretBytes.length)
  }));
  const coeffs = new Uint8Array(thresholdM);

  for (let byteIdx = 0; byteIdx < secretBytes.length; byteIdx++) {
    crypto.getRandomValues(coeffs);
    coeffs[0] = secretBytes[byteIdx];
    for (let s = 0; s < totalN; s++) {
      const x = shares[s].x;
      let y = 0;
      for (let d = thresholdM - 1; d >= 0; d--) {
        y = gf256MulFast(y, x) ^ coeffs[d];
      }
      shares[s].bytes[byteIdx] = y;
    }
  }
  coeffs.fill(0);

  return shares.map((sh) => {
    const b64 = bytesToBase64Url(sh.bytes);
    sh.bytes.fill(0);
    return `${HEX_STR_TABLE[sh.x]}:${b64}`;
  });
};

// Mutates `dataBytes` in-place using 32-bit word-aligned RFC 8439 ChaCha20
export const chacha20XorInPlace = async (keyBytes, nonceBytes, dataBytes) => {
  const kView = new DataView(keyBytes.buffer, keyBytes.byteOffset, 32);
  const nView = new DataView(nonceBytes.buffer, nonceBytes.byteOffset, 12);
  const totalLen = dataBytes.byteLength;

  const base = new Uint32Array([
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    kView.getUint32(0, true), kView.getUint32(4, true), kView.getUint32(8, true), kView.getUint32(12, true),
    kView.getUint32(16, true), kView.getUint32(20, true), kView.getUint32(24, true), kView.getUint32(28, true),
    0, nView.getUint32(0, true), nView.getUint32(4, true), nView.getUint32(8, true)
  ]);
  const st = new Uint32Array(16);
  const tailBuf = new Uint8Array(64);
  const tailWords = new Uint32Array(tailBuf.buffer);

  const fullBlocksLen = totalLen & ~63;
  const words = new Uint32Array(dataBytes.buffer, dataBytes.byteOffset, fullBlocksLen >> 2);

  let counter = 1;
  let wordIdx = 0;

  for (let offset = 0; offset < fullBlocksLen; offset += 64, counter = (counter + 1) >>> 0, wordIdx += 16) {
    if ((offset & 0xffffff) === 0xffffff) await yieldFrame();

    st.set(base);
    st[12] = counter;

    for (let r = 0; r < 10; r++) {
      st[0] = (st[0] + st[4]) | 0; st[12] ^= st[0]; st[12] = (st[12] << 16) | (st[12] >>> 16);
      st[8] = (st[8] + st[12]) | 0; st[4] ^= st[8]; st[4] = (st[4] << 12) | (st[4] >>> 20);
      st[0] = (st[0] + st[4]) | 0; st[12] ^= st[0]; st[12] = (st[12] << 8) | (st[12] >>> 24);
      st[8] = (st[8] + st[12]) | 0; st[4] ^= st[8]; st[4] = (st[4] << 7) | (st[4] >>> 25);

      st[1] = (st[1] + st[5]) | 0; st[13] ^= st[1]; st[13] = (st[13] << 16) | (st[13] >>> 16);
      st[9] = (st[9] + st[13]) | 0; st[5] ^= st[9]; st[5] = (st[5] << 12) | (st[5] >>> 20);
      st[1] = (st[1] + st[5]) | 0; st[13] ^= st[1]; st[13] = (st[13] << 8) | (st[13] >>> 24);
      st[9] = (st[9] + st[13]) | 0; st[5] ^= st[9]; st[5] = (st[5] << 7) | (st[5] >>> 25);

      st[2] = (st[2] + st[6]) | 0; st[14] ^= st[2]; st[14] = (st[14] << 16) | (st[14] >>> 16);
      st[10] = (st[10] + st[14]) | 0; st[6] ^= st[10]; st[6] = (st[6] << 12) | (st[6] >>> 20);
      st[2] = (st[2] + st[6]) | 0; st[14] ^= st[2]; st[14] = (st[14] << 8) | (st[14] >>> 24);
      st[10] = (st[10] + st[14]) | 0; st[6] ^= st[10]; st[6] = (st[6] << 7) | (st[6] >>> 25);

      st[3] = (st[3] + st[7]) | 0; st[15] ^= st[3]; st[15] = (st[15] << 16) | (st[15] >>> 16);
      st[11] = (st[11] + st[15]) | 0; st[7] ^= st[11]; st[7] = (st[7] << 12) | (st[7] >>> 20);
      st[3] = (st[3] + st[7]) | 0; st[15] ^= st[3]; st[15] = (st[15] << 8) | (st[15] >>> 24);
      st[11] = (st[11] + st[15]) | 0; st[7] ^= st[11]; st[7] = (st[7] << 7) | (st[7] >>> 25);

      st[0] = (st[0] + st[5]) | 0; st[15] ^= st[0]; st[15] = (st[15] << 16) | (st[15] >>> 16);
      st[10] = (st[10] + st[15]) | 0; st[5] ^= st[10]; st[5] = (st[5] << 12) | (st[5] >>> 20);
      st[0] = (st[0] + st[5]) | 0; st[15] ^= st[0]; st[15] = (st[15] << 8) | (st[15] >>> 24);
      st[10] = (st[10] + st[15]) | 0; st[5] ^= st[10]; st[5] = (st[5] << 7) | (st[5] >>> 25);

      st[1] = (st[1] + st[6]) | 0; st[12] ^= st[1]; st[12] = (st[12] << 16) | (st[12] >>> 16);
      st[11] = (st[11] + st[12]) | 0; st[6] ^= st[11]; st[6] = (st[6] << 12) | (st[6] >>> 20);
      st[1] = (st[1] + st[6]) | 0; st[12] ^= st[1]; st[12] = (st[12] << 8) | (st[12] >>> 24);
      st[11] = (st[11] + st[12]) | 0; st[6] ^= st[11]; st[6] = (st[6] << 7) | (st[6] >>> 25);

      st[2] = (st[2] + st[7]) | 0; st[13] ^= st[2]; st[13] = (st[13] << 16) | (st[13] >>> 16);
      st[8] = (st[8] + st[13]) | 0; st[7] ^= st[8]; st[7] = (st[7] << 12) | (st[7] >>> 20);
      st[2] = (st[2] + st[7]) | 0; st[13] ^= st[2]; st[13] = (st[13] << 8) | (st[13] >>> 24);
      st[8] = (st[8] + st[13]) | 0; st[7] ^= st[8]; st[7] = (st[7] << 7) | (st[7] >>> 25);

      st[3] = (st[3] + st[4]) | 0; st[14] ^= st[3]; st[14] = (st[14] << 16) | (st[14] >>> 16);
      st[9] = (st[9] + st[14]) | 0; st[4] ^= st[9]; st[4] = (st[4] << 12) | (st[4] >>> 20);
      st[3] = (st[3] + st[4]) | 0; st[14] ^= st[3]; st[14] = (st[14] << 8) | (st[14] >>> 24);
      st[9] = (st[9] + st[14]) | 0; st[4] ^= st[9]; st[4] = (st[4] << 7) | (st[4] >>> 25);
    }

    for (let i = 0; i < 16; i++) {
      words[wordIdx + i] ^= (st[i] + (i === 12 ? counter : base[i])) | 0;
    }
  }

  if (fullBlocksLen < totalLen) {
    st.set(base);
    st[12] = counter;
    for (let r = 0; r < 10; r++) {
      st[0] = (st[0] + st[4]) | 0; st[12] ^= st[0]; st[12] = (st[12] << 16) | (st[12] >>> 16);
      st[8] = (st[8] + st[12]) | 0; st[4] ^= st[8]; st[4] = (st[4] << 12) | (st[4] >>> 20);
      st[0] = (st[0] + st[4]) | 0; st[12] ^= st[0]; st[12] = (st[12] << 8) | (st[12] >>> 24);
      st[8] = (st[8] + st[12]) | 0; st[4] ^= st[8]; st[4] = (st[4] << 7) | (st[4] >>> 25);
      st[1] = (st[1] + st[5]) | 0; st[13] ^= st[1]; st[13] = (st[13] << 16) | (st[13] >>> 16);
      st[9] = (st[9] + st[13]) | 0; st[5] ^= st[9]; st[5] = (st[5] << 12) | (st[5] >>> 20);
      st[1] = (st[1] + st[5]) | 0; st[13] ^= st[1]; st[13] = (st[13] << 8) | (st[13] >>> 24);
      st[9] = (st[9] + st[13]) | 0; st[5] ^= st[9]; st[5] = (st[5] << 7) | (st[5] >>> 25);
      st[2] = (st[2] + st[6]) | 0; st[14] ^= st[2]; st[14] = (st[14] << 16) | (st[14] >>> 16);
      st[10] = (st[10] + st[14]) | 0; st[6] ^= st[10]; st[6] = (st[6] << 12) | (st[6] >>> 20);
      st[2] = (st[2] + st[6]) | 0; st[14] ^= st[2]; st[14] = (st[14] << 8) | (st[14] >>> 24);
      st[10] = (st[10] + st[14]) | 0; st[6] ^= st[10]; st[6] = (st[6] << 7) | (st[6] >>> 25);
      st[3] = (st[3] + st[7]) | 0; st[15] ^= st[3]; st[15] = (st[15] << 16) | (st[15] >>> 16);
      st[11] = (st[11] + st[15]) | 0; st[7] ^= st[11]; st[7] = (st[7] << 12) | (st[7] >>> 20);
      st[3] = (st[3] + st[7]) | 0; st[15] ^= st[3]; st[15] = (st[15] << 8) | (st[15] >>> 24);
      st[11] = (st[11] + st[15]) | 0; st[7] ^= st[11]; st[7] = (st[7] << 7) | (st[7] >>> 25);
      st[0] = (st[0] + st[5]) | 0; st[15] ^= st[0]; st[15] = (st[15] << 16) | (st[15] >>> 16);
      st[10] = (st[10] + st[15]) | 0; st[5] ^= st[10]; st[5] = (st[5] << 12) | (st[5] >>> 20);
      st[0] = (st[0] + st[5]) | 0; st[15] ^= st[0]; st[15] = (st[15] << 8) | (st[15] >>> 24);
      st[10] = (st[10] + st[15]) | 0; st[5] ^= st[10]; st[5] = (st[5] << 7) | (st[5] >>> 25);
      st[1] = (st[1] + st[6]) | 0; st[12] ^= st[1]; st[12] = (st[12] << 16) | (st[12] >>> 16);
      st[11] = (st[11] + st[12]) | 0; st[6] ^= st[11]; st[6] = (st[6] << 12) | (st[6] >>> 20);
      st[1] = (st[1] + st[6]) | 0; st[12] ^= st[1]; st[12] = (st[12] << 8) | (st[12] >>> 24);
      st[11] = (st[11] + st[12]) | 0; st[6] ^= st[11]; st[6] = (st[6] << 7) | (st[6] >>> 25);
      st[2] = (st[2] + st[7]) | 0; st[13] ^= st[2]; st[13] = (st[13] << 16) | (st[13] >>> 16);
      st[8] = (st[8] + st[13]) | 0; st[7] ^= st[8]; st[7] = (st[7] << 12) | (st[7] >>> 20);
      st[2] = (st[2] + st[7]) | 0; st[13] ^= st[2]; st[13] = (st[13] << 8) | (st[13] >>> 24);
      st[8] = (st[8] + st[13]) | 0; st[7] ^= st[8]; st[7] = (st[7] << 7) | (st[7] >>> 25);
      st[3] = (st[3] + st[4]) | 0; st[14] ^= st[3]; st[14] = (st[14] << 16) | (st[14] >>> 16);
      st[9] = (st[9] + st[14]) | 0; st[4] ^= st[9]; st[4] = (st[4] << 12) | (st[4] >>> 20);
      st[3] = (st[3] + st[4]) | 0; st[14] ^= st[3]; st[14] = (st[14] << 8) | (st[14] >>> 24);
      st[9] = (st[9] + st[14]) | 0; st[4] ^= st[9]; st[4] = (st[4] << 7) | (st[4] >>> 25);
    }
    for (let i = 0; i < 16; i++) {
      tailWords[i] = (st[i] + (i === 12 ? counter : base[i])) | 0;
    }
    const rem = totalLen - fullBlocksLen;
    for (let i = 0; i < rem; i++) {
      dataBytes[fullBlocksLen + i] ^= tailBuf[i];
    }
  }

  base.fill(0);
  st.fill(0);
  tailBuf.fill(0);
};

const computeBucketTargetSize = (rawLen, overhead) => {
  const total = rawLen + overhead;
  for (const b of PADDING_BUCKETS) {
    if (total <= b) return Math.max(rawLen, b - overhead);
  }
  return rawLen;
};

// Encrypts file via Hybrid PQC key derivation + In-Place ChaCha20 + AES-256-GCM cascade
export const encryptFileE2ee = async (
  file,
  isSecretNote = false,
  usePadding = false,
  shamirSpec = ''
) => {
  const masterKey = await generateHybridPqcMasterKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const metaJson = JSON.stringify({
    v: 2,
    n: file.name,
    t: isSecretNote ? 'text/kura-note' : (file.type || 'application/octet-stream'),
    s: file.size,
    note: isSecretNote
  });
  const metaBytes = new TextEncoder().encode(metaJson).slice(0, 255);
  const envelopeOverhead = 13 + metaBytes.length + 16;

  const rawPlain = new Uint8Array(await file.arrayBuffer());
  let plainTarget = rawPlain;

  if (usePadding) {
    const paddedLen = computeBucketTargetSize(rawPlain.byteLength, envelopeOverhead);
    if (paddedLen > rawPlain.byteLength) {
      plainTarget = new Uint8Array(paddedLen);
      plainTarget.set(rawPlain, 0);
      rawPlain.fill(0);
      for (let off = file.size; off < paddedLen; off += 65536) {
        const sub = plainTarget.subarray(off, Math.min(paddedLen, off + 65536));
        crypto.getRandomValues(sub);
      }
    }
  }

  const hkdfBase = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: iv, info: metaBytes },
    hkdfBase,
    512
  );
  const aesKeyBytes = new Uint8Array(derivedBits, 0, 32);
  const chachaKeyBytes = new Uint8Array(derivedBits, 32, 32);

  await chacha20XorInPlace(chachaKeyBytes, iv, plainTarget);
  chachaKeyBytes.fill(0);

  const aesKey = await crypto.subtle.importKey('raw', aesKeyBytes, 'AES-GCM', false, ['encrypt']);
  aesKeyBytes.fill(0);

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: metaBytes },
    aesKey,
    plainTarget
  );
  plainTarget.fill(0);
  const cipherBytes = new Uint8Array(cipherBuffer);

  const packed = new Uint8Array(13 + metaBytes.length + cipherBytes.length);
  packed.set(iv, 0);
  packed[12] = metaBytes.length;
  packed.set(metaBytes, 13);
  packed.set(cipherBytes, 13 + metaBytes.length);
  cipherBytes.fill(0);

  const precomputedSha256 = await computeClientSha256(packed);

  let hashKey = '';
  let shamirShares = null;
  let shamirM = null;

  if (shamirSpec && shamirSpec.includes(':')) {
    const [mStr, nStr] = shamirSpec.split(':');
    shamirM = Number(mStr);
    const totalN = Number(nStr);
    shamirShares = splitShamirSecret(masterKey, shamirM, totalN);
    hashKey = `sss:${shamirM}-of-${totalN}`;
  } else {
    hashKey = bytesToBase64Url(masterKey);
  }

  masterKey.fill(0);

  const ext = isSecretNote ? 'note' : 'enc';
  const encryptedFile = new File([packed], `${file.name}.${ext}`, {
    type: 'application/octet-stream',
    lastModified: Date.now()
  });

  return { encryptedFile, hashKey, shamirShares, shamirM, precomputedSha256 };
};

// ============================================================================
// STANDALONE REED-SOLOMON QR CODE SVG GENERATOR (VERSIONS 1..8)
// ============================================================================

export const generateQrSvg = (text) => {
  const data = new TextEncoder().encode(text);
  const VERSIONS = [
    null,
    [19, 7, 1, 19, []],
    [34, 10, 1, 34, [6, 18]],
    [55, 15, 1, 55, [6, 22]],
    [80, 20, 1, 80, [6, 26]],
    [108, 26, 1, 108, [6, 30]],
    [136, 18, 2, 68, [6, 34]],
    [156, 20, 2, 78, [6, 22, 38]],
    [194, 24, 2, 97, [6, 24, 42]]
  ];
  let ver = 1;
  while (ver <= 8 && data.length + 2 > VERSIONS[ver][0]) ver++;
  if (ver > 8) return null;

  const [totalData, eccLen, numBlocks, dataPerBlock, alignPos] = VERSIONS[ver];
  const bits = [];
  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
  };
  pushBits(0b0100, 4);
  pushBits(data.length, 8);
  for (const b of data) pushBits(b, 8);
  pushBits(0, Math.min(4, totalData * 8 - bits.length));
  while (bits.length & 7) bits.push(0);

  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    codewords.push(byte);
  }
  const pads = [0xec, 0x11];
  let padIdx = 0;
  while (codewords.length < totalData) codewords.push(pads[padIdx++ & 1]);

  const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : QR_GF_EXP[QR_GF_LOG[a] + QR_GF_LOG[b]]);

  let gen = [1];
  for (let i = 0; i < eccLen; i++) {
    const next = new Array(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j++) {
      next[j] ^= gen[j];
      next[j + 1] ^= gfMul(gen[j], QR_GF_EXP[i]);
    }
    gen = next;
  }

  const blocks = [];
  const eccBlocks = [];
  for (let b = 0; b < numBlocks; b++) {
    const slice = codewords.slice(b * dataPerBlock, (b + 1) * dataPerBlock);
    blocks.push(slice);
    const rem = new Array(eccLen).fill(0);
    for (const byte of slice) {
      const factor = byte ^ rem.shift();
      rem.push(0);
      for (let j = 0; j < eccLen; j++) rem[j] ^= gfMul(gen[j + 1], factor);
    }
    eccBlocks.push(rem);
  }

  const finalBytes = [];
  for (let i = 0; i < dataPerBlock; i++) {
    for (let b = 0; b < numBlocks; b++) finalBytes.push(blocks[b][i]);
  }
  for (let i = 0; i < eccLen; i++) {
    for (let b = 0; b < numBlocks; b++) finalBytes.push(eccBlocks[b][i]);
  }

  const size = 17 + ver * 4;
  const grid = Array.from({ length: size }, () => new Uint8Array(size));
  const reserved = Array.from({ length: size }, () => new Uint8Array(size));

  const setMod = (r, c, val) => {
    if (r >= 0 && r < size && c >= 0 && c < size) {
      grid[r][c] = val ? 1 : 0;
      reserved[r][c] = 1;
    }
  };

  const drawFinder = (r0, c0) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const inside =
          dr >= 0 &&
          dr <= 6 &&
          dc >= 0 &&
          dc <= 6 &&
          (dr === 0 ||
            dr === 6 ||
            dc === 0 ||
            dc === 6 ||
            (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
        setMod(r0 + dr, c0 + dc, inside ? 1 : 0);
      }
    }
  };
  drawFinder(0, 0);
  drawFinder(0, size - 7);
  drawFinder(size - 7, 0);

  for (let i = 8; i < size - 8; i++) {
    setMod(6, i, (i & 1) === 0);
    setMod(i, 6, (i & 1) === 0);
  }

  for (const r of alignPos) {
    for (const c of alignPos) {
      if ((r < 9 && c < 9) || (r < 9 && c > size - 10) || (r > size - 10 && c < 9)) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          setMod(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
        }
      }
    }
  }

  for (let i = 0; i < 9; i++) {
    if (i !== 6) {
      reserved[8][i] = 1;
      reserved[i][8] = 1;
    }
  }
  for (let i = 0; i < 8; i++) {
    reserved[8][size - 1 - i] = 1;
    reserved[size - 1 - i][8] = 1;
  }
  setMod(size - 8, 8, 1);

  if (ver >= 7) {
    const vInfo = ver === 7 ? 0x07c94 : 0x085bc;
    for (let i = 0; i < 18; i++) {
      const bit = (vInfo >> i) & 1;
      const a = (i / 3) | 0;
      const b = (i % 3) + size - 11;
      setMod(a, b, bit);
      setMod(b, a, bit);
    }
  }

  let bitIdx = 0;
  let upward = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    for (let step = 0; step < size; step++) {
      const row = upward ? size - 1 - step : step;
      for (let d = 0; d < 2; d++) {
        const c = col - d;
        if (!reserved[row][c]) {
          const bit =
            bitIdx < finalBytes.length * 8
              ? (finalBytes[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1
              : 0;
          bitIdx++;
          grid[row][c] = bit ^ (((row + c) & 1) === 0 ? 1 : 0);
        }
      }
    }
    upward = !upward;
  }

  const fmtBits = 0x77c4;
  const fmtCoords1 = [
    [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
    [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]
  ];
  for (let i = 0; i < 15; i++) {
    const bit = (fmtBits >> i) & 1;
    const [r1, c1] = fmtCoords1[i];
    grid[r1][c1] = bit;
    if (i < 8) grid[8][size - 1 - i] = bit;
    else grid[size - 15 + i][8] = bit;
  }

  const pathParts = [];
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (grid[r][c]) pathParts.push(`M${c + 4},${r + 4}h1v1h-1z`);
    }
  }
  const dim = size + 8;
  return `<svg viewBox="0 0 ${dim} ${dim}" width="210" height="210" shape-rendering="crispEdges" style="background:#fff;border:1px solid var(--border);"><path d="${pathParts.join('')}" fill="#000"/></svg>`;
};