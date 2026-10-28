import {
  formatBytes,
  sanitizeSafeUrl,
  extractSlugFromUrl
} from './crypto.js';

// ============================================================================
// STORAGE KEYS & DOM REFERENCES
// ============================================================================

const VAULT_STORAGE_KEY = 'kura_ephemeral_vault_v1';
const DAILY_STATS_KEY = 'kura_daily_telemetry_v1';

const vaultList = document.getElementById('vault-list');
const vaultCount = document.getElementById('vault-count');
const fmtSelect = document.getElementById('fmt-select');
const albumBanner = document.getElementById('album-banner');
const albumBannerLink = document.getElementById('album-banner-link');
const albumZipLink = document.getElementById('album-zip-link');

const statVaultSummary = document.getElementById('stat-vault-summary');
const statDailyTraffic = document.getElementById('stat-daily-traffic');
const statCasSaved = document.getElementById('stat-cas-saved');

let cachedCallbacks = null;

// ============================================================================
// TELEMETRY & EXPIRATION HELPERS
// ============================================================================

const getTodayKey = () => new Date().toISOString().slice(0, 10);

export const loadDailyTelemetry = () => {
  try {
    const raw = JSON.parse(localStorage.getItem(DAILY_STATS_KEY) || '{}');
    if (raw.day !== getTodayKey()) {
      return { day: getTodayKey(), uploads: 0, bytes: 0, casSaved: 0 };
    }
    return {
      day: raw.day,
      uploads: Number(raw.uploads) || 0,
      bytes: Number(raw.bytes) || 0,
      casSaved: Number(raw.casSaved) || 0
    };
  } catch (_) {
    return { day: getTodayKey(), uploads: 0, bytes: 0, casSaved: 0 };
  }
};

export const loadVault = () => {
  try {
    const now = Date.now();
    const raw = JSON.parse(localStorage.getItem(VAULT_STORAGE_KEY) || '[]');
    return raw.filter((item) => !item.expiresAt || item.expiresAt > now);
  } catch (_) {
    return [];
  }
};

export const refreshFooterTelemetry = () => {
  const items = loadVault();
  const totalVaultBytes = items.reduce((acc, item) => acc + (Number(item.size) || 0), 0);
  statVaultSummary.textContent = `${items.length} ${items.length === 1 ? 'FILE' : 'FILES'} (${formatBytes(totalVaultBytes)})`;

  const daily = loadDailyTelemetry();
  statDailyTraffic.textContent = `${daily.uploads} ${daily.uploads === 1 ? 'UPLOAD' : 'UPLOADS'} · ${formatBytes(daily.bytes)}`;
  statCasSaved.textContent = formatBytes(daily.casSaved);
};

export const recordDailyUpload = (size, isDedup) => {
  const st = loadDailyTelemetry();
  st.uploads += 1;
  st.bytes += size;
  if (isDedup) st.casSaved += size;
  localStorage.setItem(DAILY_STATS_KEY, JSON.stringify(st));
  refreshFooterTelemetry();
};

export const computeExpiryTimestamp = (policy) => {
  const now = Date.now();
  switch (policy) {
    case '1h':
      return now + 3600 * 1000;
    case '24h':
      return now + 86400 * 1000;
    case '7d':
    case '1v':
    case '5v':
    case '10v':
      return now + 604800 * 1000;
    default:
      return null;
  }
};

export const formatVaultLink = (entry, mode) => {
  const safeName = (entry.name || 'file').replace(/[\[\]<>"]/g, '_');
  const safeUrl = sanitizeSafeUrl(entry.url);
  switch (mode) {
    case 'md':
      return `[${safeName}](${safeUrl})`;
    case 'html':
      return `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${safeName}</a>`;
    case 'bb':
      return `[url=${safeUrl}]${safeName}[/url]`;
    default:
      return safeUrl;
  }
};

export const isPreviewableUrl = (url) => {
  const ext = url.split('#')[0].split('?')[0].split('.').pop().toLowerCase();
  return [
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'bmp', 'ico',
    'mp4', 'webm', 'mov', 'mp3', 'wav', 'ogg', 'flac', 'm4a',
    'pdf', 'txt'
  ].includes(ext);
};

// ============================================================================
// REMOTE DELETION, ALBUM BUNDLING & VAULT DOM RENDERER
// ============================================================================

const deleteRemoteFile = async (entry, btn) => {
  const slug = entry.slug || extractSlugFromUrl(entry.url);
  if (!slug || !entry.deleteKey) return;
  const prev = btn.textContent;
  btn.textContent = '..';
  try {
    const res = await fetch(`/v/${slug}`, {
      method: 'DELETE',
      headers: { 'X-Kura-Delete-Key': entry.deleteKey }
    });
    if (res.ok || res.status === 404) {
      const items = loadVault().filter((i) => i.url !== entry.url);
      localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(items));
      renderVault(cachedCallbacks);
    } else {
      btn.textContent = '!';
      setTimeout(() => {
        btn.textContent = prev;
      }, 1200);
    }
  } catch (_) {
    btn.textContent = '!';
    setTimeout(() => {
      btn.textContent = prev;
    }, 1200);
  }
};

export const createAlbumFromVault = async (btn, onCopy) => {
  const items = loadVault();
  const slugs = items.map((i) => i.slug || extractSlugFromUrl(i.url)).filter(Boolean);
  if (slugs.length === 0) return;

  const prev = btn ? btn.textContent : '';
  if (btn) btn.textContent = '..';

  try {
    const res = await fetch('/album', {
      method: 'POST',
      body: slugs.join('\n')
    });
    if (!res.ok) throw new Error('Album creation failed');
    const albumUrl = sanitizeSafeUrl((await res.text()).trim());
    albumBannerLink.href = albumUrl;
    albumBannerLink.textContent = albumUrl.replace(/^https?:\/\//, '');
    albumZipLink.href = `${albumUrl}/zip`;
    albumBanner.classList.add('visible');
    if (onCopy) await onCopy(albumUrl, btn);
  } catch (_) {
    if (btn) {
      btn.textContent = 'Err';
      setTimeout(() => {
        btn.textContent = prev;
      }, 1400);
    }
  }
};

export const renderVault = (callbacks = cachedCallbacks) => {
  if (callbacks) cachedCallbacks = callbacks;
  const items = loadVault();
  vaultCount.textContent = items.length;
  refreshFooterTelemetry();

  if (items.length === 0) {
    albumBanner.classList.remove('visible');
    vaultList.innerHTML = `
      <div class="vault-empty">
        <span style="color:var(--text-secondary);font-weight:500;">EMPTY VAULT</span>
        <span>Uploads appear here with instant copy, QR, Shamir shares &amp; delete controls.</span>
      </div>
    `;
    return;
  }

  const frag = document.createDocumentFragment();

  items.forEach((item) => {
    const safeUrl = sanitizeSafeUrl(item.url);
    const row = document.createElement('div');
    row.className = 'vault-row';

    const top = document.createElement('div');
    top.className = 'vault-row-top';

    const link = document.createElement('a');
    link.href = safeUrl;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.className = 'vault-link';
    link.textContent = item.name;
    link.title = safeUrl;

    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'btn-action';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', () => {
      if (cachedCallbacks?.onCopy) {
        cachedCallbacks.onCopy(formatVaultLink(item, fmtSelect.value), copyBtn);
      }
    });

    top.appendChild(link);
    top.appendChild(copyBtn);

    const bottom = document.createElement('div');
    bottom.className = 'vault-row-bottom';

    const sub = document.createElement('div');
    sub.className = 'vault-sub';
    const tags = [formatBytes(item.size)];
    if (item.paddedSize && item.paddedSize > item.size) {
      tags.push(`Pad:${formatBytes(item.paddedSize)}`);
    }
    if (item.p2p) tags.push('P2P-Signed');
    if (item.note) tags.push('Note');
    if (item.expiry && item.expiry !== 'never') tags.push(item.expiry);
    if (item.timelock) tags.push(`Lock:${item.timelock}`);
    if (item.shamirM) tags.push(`SSS:${item.shamirM}/${item.shamirShares?.length || 0}`);
    else if (item.e2ee) tags.push('PQC-E2EE');
    if (item.protected) tags.push('Pass');
    if (item.duress) tags.push('Duress');
    if (item.dedup) tags.push('Dedup');
    sub.textContent = tags.join(' · ');

    const secActions = document.createElement('div');
    secActions.className = 'vault-secondary-actions';

    if (item.shamirShares && item.shamirShares.length) {
      const sharesBtn = document.createElement('button');
      sharesBtn.type = 'button';
      sharesBtn.className = 'btn-ghost';
      sharesBtn.style.color = 'var(--success)';
      sharesBtn.textContent = 'Shares';
      sharesBtn.addEventListener('click', () => cachedCallbacks?.onOpenShamir(item));
      secActions.appendChild(sharesBtn);
    }

    if (
      !item.protected &&
      !item.e2ee &&
      !item.p2p &&
      !item.timelock &&
      item.expiry !== '1v' &&
      isPreviewableUrl(safeUrl)
    ) {
      const prevBtn = document.createElement('button');
      prevBtn.type = 'button';
      prevBtn.className = 'btn-ghost';
      prevBtn.textContent = 'View';
      prevBtn.addEventListener('click', () => cachedCallbacks?.onOpenPreview(item));
      secActions.appendChild(prevBtn);
    }

    const qrBtn = document.createElement('button');
    qrBtn.type = 'button';
    qrBtn.className = 'btn-ghost';
    qrBtn.textContent = 'QR';
    qrBtn.addEventListener('click', () => cachedCallbacks?.onOpenQr(item));
    secActions.appendChild(qrBtn);

    if (!item.p2p) {
      const statsBtn = document.createElement('button');
      statsBtn.type = 'button';
      statsBtn.className = 'btn-ghost';
      statsBtn.textContent = 'Stats';
      statsBtn.addEventListener('click', () => cachedCallbacks?.onOpenStats(item));
      secActions.appendChild(statsBtn);
    }

    if (item.deleteKey) {
      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn-ghost btn-danger';
      delBtn.textContent = '×';
      delBtn.title = 'Delete from server';
      delBtn.addEventListener('click', () => deleteRemoteFile(item, delBtn));
      secActions.appendChild(delBtn);
    }

    bottom.appendChild(sub);
    bottom.appendChild(secActions);

    row.appendChild(top);
    row.appendChild(bottom);
    frag.appendChild(row);
  });

  vaultList.replaceChildren(frag);
};

export const saveToVault = (entry, callbacks = cachedCallbacks) => {
  const items = loadVault();
  const filtered = items.filter((i) => i.url !== entry.url);
  filtered.unshift(entry);
  localStorage.setItem(VAULT_STORAGE_KEY, JSON.stringify(filtered.slice(0, 30)));
  renderVault(callbacks);
};

export const purgeLocalVault = () => {
  localStorage.removeItem(VAULT_STORAGE_KEY);
  renderVault(cachedCallbacks);
};