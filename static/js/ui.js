import {
  CLIPBOARD_WIPE_MS,
  formatBytes,
  sanitizeSafeUrl,
  extractSlugFromUrl,
  generateQrSvg
} from './crypto.js';

import {
  loadVault,
  formatVaultLink,
  createAlbumFromVault,
  purgeLocalVault
} from './vault.js';

// ============================================================================
// DOM REFERENCES & UI STATE
// ============================================================================

const THEMES = ['dark', 'light'];

const themeToggleBtn = document.getElementById('theme-toggle');
const codexBtn = document.getElementById('codex-btn');
const cmdPaletteBtn = document.getElementById('cmd-palette-btn');
const panicEscapeBtn = document.getElementById('panic-escape-btn');

const timelockSelect = document.getElementById('timelock-select');
const shamirSelect = document.getElementById('shamir-select');
const passwordInput = document.getElementById('password-input');
const duressInput = document.getElementById('duress-input');
const pasteTextarea = document.getElementById('paste-textarea');

const toggleE2eeBtn = document.getElementById('toggle-e2ee');
const togglePadBtn = document.getElementById('toggle-pad');
const toggleExifBtn = document.getElementById('toggle-exif');
const toggleP2pBtn = document.getElementById('toggle-p2p');

const fmtSelect = document.getElementById('fmt-select');
const albumBannerLink = document.getElementById('album-banner-link');
const albumCopyBtn = document.getElementById('album-copy-btn');

const codexModal = document.getElementById('codex-modal');
const codexCloseBtn = document.getElementById('codex-close-btn');
const codexStartTourBtn = document.getElementById('codex-start-tour-btn');

const tourLayer = document.getElementById('tour-layer');
const tourSpotlight = document.getElementById('tour-spotlight');
const tourCard = document.getElementById('tour-card');
const tourStepNum = document.getElementById('tour-step-num');
const tourStepCat = document.getElementById('tour-step-cat');
const tourTitle = document.getElementById('tour-title');
const tourDesc = document.getElementById('tour-desc');
const tourSkipBtn = document.getElementById('tour-skip-btn');
const tourPrevBtn = document.getElementById('tour-prev-btn');
const tourNextBtn = document.getElementById('tour-next-btn');

const previewModal = document.getElementById('preview-modal');
const previewWindow = document.getElementById('preview-window');
const previewTitle = document.getElementById('preview-title');
const previewBody = document.getElementById('preview-body');
const previewRawLink = document.getElementById('preview-raw-link');
const previewClose = document.getElementById('preview-close');

const cmdModal = document.getElementById('cmd-modal');
const cmdInput = document.getElementById('cmd-input');
const cmdList = document.getElementById('cmd-list');

let clipboardWipeTimer = null;

// ============================================================================
// CLIPBOARD SANITIZATION & PANIC ESCAPE
// ============================================================================

export const copyToClipboard = async (text, btn) => {
  try {
    await navigator.clipboard.writeText(text);
    if (btn) {
      const prev = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(() => {
        btn.textContent = prev;
      }, 1300);
    }
    if (clipboardWipeTimer) clearTimeout(clipboardWipeTimer);
    if (text.includes('#') || text.includes(':')) {
      clipboardWipeTimer = setTimeout(async () => {
        try {
          const cur = await navigator.clipboard.readText();
          if (cur === text) await navigator.clipboard.writeText('');
        } catch (_) {}
      }, CLIPBOARD_WIPE_MS);
    }
  } catch (_) {
    if (btn) btn.textContent = 'Error';
  }
};

export const triggerPanicEscape = () => {
  try {
    passwordInput.value = '';
    duressInput.value = '';
    pasteTextarea.value = '';
    localStorage.clear();
    sessionStorage.clear();
    navigator.clipboard.writeText('');
  } catch (_) {}
  document.body.innerHTML = '';
  window.location.replace('https://en.wikipedia.org/wiki/Special:Random');
};

export const switchTab = (targetId) => {
  document.querySelectorAll('.tab-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.target === targetId);
  });
  document.querySelectorAll('.view-pane').forEach((p) => {
    p.classList.toggle('active', p.id === targetId);
  });
};

// ============================================================================
// PREVIEW, QR, TELEMETRY STATS & SHAMIR MODALS
// ============================================================================

export const openShamirModal = (entry) => {
  if (!entry.shamirShares || !entry.shamirShares.length) return;
  previewWindow.classList.add('compact');
  previewTitle.textContent = `Shamir Key Shares · ${entry.name}`;
  previewRawLink.href = sanitizeSafeUrl(entry.url);
  previewBody.innerHTML = '';

  const wrap = document.createElement('div');
  wrap.style.width = '100%';
  const info = document.createElement('div');
  info.style.cssText = 'font-size:0.66rem;color:var(--text-secondary);line-height:1.45;';
  info.textContent = `Distribute these ${entry.shamirShares.length} shares to separate custodians. Any ${entry.shamirM || 2} shares are required at the download gate to reconstruct the decryption key:`;

  const area = document.createElement('textarea');
  area.className = 'shares-textarea';
  area.readOnly = true;
  area.value = entry.shamirShares.join('\n');

  const copyBtn = document.createElement('button');
  copyBtn.type = 'button';
  copyBtn.className = 'btn-action';
  copyBtn.style.width = '100%';
  copyBtn.style.justifyContent = 'center';
  copyBtn.style.padding = '0.45rem';
  copyBtn.textContent = 'Copy All Shares';
  copyBtn.onclick = () => copyToClipboard(area.value, copyBtn);

  wrap.appendChild(info);
  wrap.appendChild(area);
  wrap.appendChild(copyBtn);
  previewBody.appendChild(wrap);
  previewModal.classList.add('open');
};

export const openQrModal = (entry) => {
  previewWindow.classList.add('compact');
  previewTitle.textContent = `QR · ${entry.name}`;
  previewRawLink.href = sanitizeSafeUrl(entry.url);
  previewBody.innerHTML = '';

  const wrapper = document.createElement('div');
  wrapper.style.textAlign = 'center';
  const svgMarkup = generateQrSvg(entry.url);
  if (svgMarkup) {
    wrapper.innerHTML = svgMarkup;
    const hint = document.createElement('div');
    hint.style.cssText =
      'font-size:0.65rem;color:var(--text-secondary);margin-top:0.7rem;word-break:break-all;';
    hint.textContent = entry.url;
    wrapper.appendChild(hint);
  } else {
    wrapper.innerHTML =
      '<span style="font-size:0.72rem;color:var(--text-secondary);">URL exceeds QR capacity.</span>';
  }
  previewBody.appendChild(wrapper);
  previewModal.classList.add('open');
};

export const openStatsModal = async (entry) => {
  const slug = entry.slug || extractSlugFromUrl(entry.url);
  if (!slug) return;
  previewWindow.classList.add('compact');
  previewTitle.textContent = `Telemetry · ${slug}`;
  previewRawLink.href = sanitizeSafeUrl(entry.url);
  previewBody.innerHTML =
    '<span style="font-size:0.72rem;color:var(--text-secondary);">Querying SQLite node...</span>';
  previewModal.classList.add('open');

  try {
    const res = await fetch(`/stats/${slug}`);
    if (!res.ok) throw new Error('Expired or burned');
    const st = await res.json();
    const table = document.createElement('table');
    table.className = 'stats-table';
    const rows = [
      ['Slug', st.slug],
      ['Stored Size', formatBytes(st.size)],
      ['MIME', st.content_type],
      ['Views', st.max_views ? `${st.views} / ${st.max_views}` : `${st.views}`],
      ['Album', st.album_id || 'None'],
      [
        'Protection',
        [
          st.e2ee ? 'Hybrid PQC E2EE' : null,
          st.shamir_threshold ? `Shamir ${st.shamir_threshold}-Key` : null,
          st.protected ? 'Password' : null,
          st.burn_after_read ? '1-View Burn' : null
        ]
          .filter(Boolean)
          .join(' + ') || 'Public'
      ],
      ['Time-Lock', st.unlock_at ? new Date(st.unlock_at * 1000).toLocaleString() : 'Unlocked'],
      ['Expires', st.expires_at ? new Date(st.expires_at * 1000).toLocaleString() : 'Never'],
      [
        'Last Access',
        st.last_accessed_at ? new Date(st.last_accessed_at * 1000).toLocaleString() : 'Never'
      ]
    ];
    const frag = document.createDocumentFragment();
    rows.forEach(([k, v]) => {
      const tr = document.createElement('tr');
      const td1 = document.createElement('td');
      const td2 = document.createElement('td');
      td1.textContent = k;
      td2.textContent = v;
      tr.appendChild(td1);
      tr.appendChild(td2);
      frag.appendChild(tr);
    });
    table.appendChild(frag);
    previewBody.innerHTML = '';
    previewBody.appendChild(table);
  } catch (_) {
    previewBody.innerHTML =
      '<span style="font-size:0.72rem;color:var(--danger);">File no longer exists or has been burned.</span>';
  }
};

export const openPreviewModal = async (entry) => {
  const safeHref = sanitizeSafeUrl(entry.url);
  previewWindow.classList.remove('compact');
  previewTitle.textContent = `${entry.name} · ${formatBytes(entry.size)}`;
  previewRawLink.href = safeHref;
  previewBody.innerHTML =
    '<span style="font-size:0.72rem;color:var(--text-secondary);">Loading preview...</span>';
  previewModal.classList.add('open');

  const ext = safeHref.split('#')[0].split('?')[0].split('.').pop().toLowerCase();

  if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'bmp', 'ico'].includes(ext)) {
    const img = document.createElement('img');
    img.src = safeHref;
    img.alt = entry.name;
    previewBody.innerHTML = '';
    previewBody.appendChild(img);
  } else if (['mp4', 'webm', 'mov'].includes(ext)) {
    const video = document.createElement('video');
    video.src = safeHref;
    video.controls = true;
    video.autoplay = true;
    previewBody.innerHTML = '';
    previewBody.appendChild(video);
  } else if (['mp3', 'wav', 'ogg', 'flac', 'm4a'].includes(ext)) {
    const audio = document.createElement('audio');
    audio.src = safeHref;
    audio.controls = true;
    previewBody.innerHTML = '';
    previewBody.appendChild(audio);
  } else if (ext === 'pdf') {
    const frame = document.createElement('iframe');
    frame.src = safeHref;
    frame.setAttribute('sandbox', '');
    previewBody.innerHTML = '';
    previewBody.appendChild(frame);
  } else if (ext === 'txt') {
    try {
      const res = await fetch(safeHref);
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const text = await res.text();
      const pre = document.createElement('pre');
      pre.textContent = text;
      previewBody.innerHTML = '';
      previewBody.appendChild(pre);
    } catch (_) {
      previewBody.innerHTML =
        '<span style="font-size:0.72rem;color:var(--text-secondary);">Direct text preview blocked by CORS or expired.</span>';
    }
  }
};

const closePreviewModal = () => {
  previewModal.classList.remove('open');
  previewBody.innerHTML = '';
};

// ============================================================================
// SPOTLIGHT WALKTHROUGH & COMMAND PALETTE (⌘K)
// ============================================================================

const TOUR_STEPS = [
  {
    el: '#dropzone',
    cat: 'UPLOAD',
    title: 'File Dropzone & Auto P2P',
    desc: 'Drop files anywhere on the page. Files up to 10 MiB stream directly via zero-overhead binary PUT; 10–200 MiB use resumable chunks; files over 200 MiB automatically switch to signed WebRTC P2P.',
    prep: () => switchTab('view-drop')
  },
  {
    el: '#mode-tabs',
    cat: 'MODES',
    title: 'Input Mode Selector',
    desc: 'Switch between standard file uploads (Files), text & one-time notes (Text), and command-line snippets (CLI).',
    prep: () => switchTab('view-drop')
  },
  {
    el: '#expiry-select',
    cat: 'EXPIRATION',
    title: 'Retention & View Limits',
    desc: 'Set an automatic expiration timer (1h, 24h, 7d) or delete the file after a fixed number of downloads (1v, 5v, 10v).',
    prep: () => switchTab('view-drop')
  },
  {
    el: '#timelock-select',
    cat: 'TIME-LOCK',
    title: 'Future Release Time-Lock',
    desc: 'Locks the file on the server so it cannot be downloaded or decrypted until the specified time delay (15m, 1h, 6h, 24h, 7d) has elapsed.',
    prep: () => switchTab('view-drop')
  },
  {
    el: '#shamir-select',
    cat: 'SPLIT CUSTODY',
    title: 'Shamir M-of-N Secret Sharing',
    desc: 'Splits the 256-bit PQC-mixed master key into N mathematical shares over GF(256). The URL contains no key; any M shares must be entered at the gate to unlock.',
    prep: () => switchTab('view-drop')
  },
  {
    el: '#password-input',
    cat: 'SECURITY',
    title: 'Password Protection',
    desc: 'Protects your upload with a password hashed using 100,000 rounds of PBKDF2-HMAC-SHA256 plus a hybrid memory matrix.',
    prep: () => switchTab('view-drop')
  },
  {
    el: '#duress-input',
    cat: 'SECURITY',
    title: 'Secondary Wipe Code (Duress)',
    desc: 'Appears when a password is set. Entering this secondary code on the download page immediately deletes the file and its encryption keys.',
    prep: () => {
      switchTab('view-drop');
      duressInput.classList.add('visible');
    }
  },
  {
    el: '#toggle-e2ee',
    cat: 'ENCRYPTION',
    title: 'Hybrid PQC Cascade E2EE',
    desc: 'Derives keys using Ring-LWE lattice mixing and encrypts files in-place via a dual-cipher cascade (32-bit ChaCha20 + AES-256-GCM) with HKDF subkeys.',
    prep: () => {
      if (!passwordInput.value) duressInput.classList.remove('visible');
    }
  },
  {
    el: '#toggle-pad',
    cat: 'TRAFFIC PRIVACY',
    title: 'Discrete Bucket Padding (PAD)',
    desc: 'Pads encrypted files with random bytes to fixed bucket sizes (64 KiB, 512 KiB, 2 MiB, 8 MiB...) to hide exact file sizes from network observers.',
    prep: () => {}
  },
  {
    el: '#toggle-exif',
    cat: 'PRIVACY',
    title: 'EXIF Metadata Removal',
    desc: 'Automatically strips camera details and GPS coordinates from JPEG, PNG, and WebP images before uploading.',
    prep: () => {}
  },
  {
    el: '#toggle-p2p',
    cat: 'TRANSFER',
    title: 'Signed WebRTC P2P Mode',
    desc: 'Streams files of any size directly from your browser to the recipient over WebRTC with HMAC-SHA256 authenticated SDP/ICE signaling.',
    prep: () => {}
  },
  {
    el: '#btn-deploy-note',
    cat: 'NOTES',
    title: 'One-Time Secret Note',
    desc: 'Encrypts text into a 1-view note. When opened, the recipient can copy the text and clear it from memory in one click.',
    prep: () => switchTab('view-paste')
  },
  {
    el: '#btn-deploy-paste',
    cat: 'TEXT',
    title: 'Text & Code Upload',
    desc: 'Uploads plain text or code as a .txt file with built-in syntax highlighting and line numbers.',
    prep: () => switchTab('view-paste')
  },
  {
    el: '#view-cli',
    cat: 'TERMINAL',
    title: 'Command-Line Usage',
    desc: 'Upload directly from your terminal using curl or the lightweight kura.sh shell script.',
    prep: () => switchTab('view-cli')
  },
  {
    el: '#vault-section',
    cat: 'HISTORY',
    title: 'Local Upload Vault',
    desc: 'Keeps track of your recent uploads, Shamir key shares, and deletion keys in local browser storage.',
    prep: () => switchTab('view-drop')
  },
  {
    el: '#btn-create-album',
    cat: 'BUNDLING',
    title: 'ZIP Album Creator',
    desc: 'Groups your current Vault files into a single shareable link with streaming .zip download support.',
    prep: () => {}
  },
  {
    el: '#cmd-palette-btn',
    cat: 'SHORTCUTS',
    title: 'Command Palette (⌘K / Ctrl+K)',
    desc: 'Quickly search and trigger any action, setting, or tab switch from your keyboard.',
    prep: () => {}
  },
  {
    el: '#panic-escape-btn',
    cat: 'QUICK EXIT',
    title: 'Clear Data & Exit (ESC×2)',
    desc: 'Click or double-tap Escape to clear local vault history and clipboard data, then redirect away from the page.',
    prep: () => {}
  },
  {
    el: '#page-footer',
    cat: 'STATUS',
    title: 'System Status & Usage',
    desc: 'Displays live server latency, current Vault size, daily upload count, and storage saved via deduplication.',
    prep: () => {}
  }
];

let currentTourIdx = 0;

const positionTourSpotlight = () => {
  if (!tourLayer.classList.contains('active')) return;
  const step = TOUR_STEPS[currentTourIdx];
  if (!step) return;
  if (step.prep) step.prep();

  const target = document.querySelector(step.el);
  if (!target) return;

  const rect = target.getBoundingClientRect();
  const pad = 6;
  const top = Math.max(4, rect.top - pad);
  const left = Math.max(4, rect.left - pad);
  const width = Math.min(window.innerWidth - 8, rect.width + pad * 2);
  const height = Math.min(window.innerHeight - 8, rect.height + pad * 2);

  tourSpotlight.style.top = `${top}px`;
  tourSpotlight.style.left = `${left}px`;
  tourSpotlight.style.width = `${width}px`;
  tourSpotlight.style.height = `${height}px`;

  tourStepNum.textContent = `STEP ${String(currentTourIdx + 1).padStart(2, '0')} / ${String(TOUR_STEPS.length).padStart(2, '0')}`;
  tourStepCat.textContent = step.cat;
  tourTitle.textContent = step.title;
  tourDesc.textContent = step.desc;

  tourPrevBtn.disabled = currentTourIdx === 0;
  tourNextBtn.textContent = currentTourIdx === TOUR_STEPS.length - 1 ? 'Finish' : 'Next →';

  const cardWidth = 320;
  const cardHeight = tourCard.offsetHeight || 170;
  let cardTop = top + height + 12;
  if (cardTop + cardHeight > window.innerHeight - 12) {
    cardTop = Math.max(12, top - cardHeight - 12);
  }
  let cardLeft = left;
  if (cardLeft + cardWidth > window.innerWidth - 12) {
    cardLeft = Math.max(12, window.innerWidth - cardWidth - 12);
  }

  tourCard.style.top = `${cardTop}px`;
  tourCard.style.left = `${cardLeft}px`;
};

const startFieldTour = () => {
  codexModal.classList.remove('open');
  currentTourIdx = 0;
  tourLayer.classList.add('active');
  positionTourSpotlight();
};

const endFieldTour = () => {
  tourLayer.classList.remove('active');
  if (!passwordInput.value.trim()) duressInput.classList.remove('visible');
  switchTab('view-drop');
};

// ============================================================================
// INITIALIZE UI CONTROLLERS & KEYBOARD LISTENERS
// ============================================================================

export const initUiControllers = (opsecState) => {
  panicEscapeBtn.addEventListener('click', triggerPanicEscape);

  window.addEventListener('pagehide', () => {
    passwordInput.value = '';
    duressInput.value = '';
  });

  passwordInput.addEventListener('input', () => {
    if (passwordInput.value.trim().length > 0) {
      duressInput.classList.add('visible');
    } else if (!duressInput.value.trim().length) {
      duressInput.classList.remove('visible');
    }
  });

  shamirSelect.addEventListener('change', () => {
    if (shamirSelect.value && !opsecState.e2ee) {
      opsecState.e2ee = true;
      toggleE2eeBtn.classList.add('active');
    }
  });

  const savedTheme = localStorage.getItem('kura_theme');
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  let currentTheme = savedTheme || (systemPrefersDark ? 'dark' : 'light');
  if (!THEMES.includes(currentTheme)) currentTheme = 'dark';

  const applyTheme = async (nextTheme, withTransition = true) => {
    if (!withTransition || !document.startViewTransition) {
      document.documentElement.setAttribute('data-theme', nextTheme);
      localStorage.setItem('kura_theme', nextTheme);
      themeToggleBtn.textContent = nextTheme.toUpperCase();
      return;
    }
    const transition = document.startViewTransition(() => {
      document.documentElement.setAttribute('data-theme', nextTheme);
      localStorage.setItem('kura_theme', nextTheme);
      themeToggleBtn.textContent = nextTheme.toUpperCase();
    });
    try {
      await transition.ready;
    } catch (_) {}
  };

  applyTheme(currentTheme, false);

  themeToggleBtn.addEventListener('click', () => {
    const currentIndex = THEMES.indexOf(
      document.documentElement.getAttribute('data-theme') || 'dark'
    );
    const nextTheme = THEMES[(currentIndex + 1) % THEMES.length];
    applyTheme(nextTheme, true);
  });

  if (window.location.origin && window.location.origin !== 'null') {
    document.querySelectorAll('.origin-placeholder').forEach((el) => {
      el.textContent = window.location.origin;
    });
  }

  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.target));
  });

  toggleExifBtn.addEventListener('click', () => {
    opsecState.stripExif = !opsecState.stripExif;
    toggleExifBtn.classList.toggle('active', opsecState.stripExif);
  });

  toggleE2eeBtn.addEventListener('click', () => {
    opsecState.e2ee = !opsecState.e2ee;
    toggleE2eeBtn.classList.toggle('active', opsecState.e2ee);
    if (!opsecState.e2ee) {
      opsecState.pad = false;
      togglePadBtn.classList.remove('active');
      shamirSelect.value = '';
    }
  });

  togglePadBtn.addEventListener('click', () => {
    opsecState.pad = !opsecState.pad;
    togglePadBtn.classList.toggle('active', opsecState.pad);
    if (opsecState.pad && !opsecState.e2ee) {
      opsecState.e2ee = true;
      toggleE2eeBtn.classList.add('active');
    }
  });

  toggleP2pBtn.addEventListener('click', () => {
    opsecState.p2p = !opsecState.p2p;
    toggleP2pBtn.classList.toggle('active', opsecState.p2p);
  });

  document.querySelectorAll('[data-copy-target]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = document.getElementById(btn.dataset.copyTarget);
      copyToClipboard(target.textContent.trim(), btn);
    });
  });

  document.getElementById('btn-create-album').addEventListener('click', (e) => {
    createAlbumFromVault(e.currentTarget, copyToClipboard);
  });

  albumCopyBtn.addEventListener('click', () => {
    copyToClipboard(albumBannerLink.href, albumCopyBtn);
  });

  document.getElementById('btn-copy-all').addEventListener('click', (e) => {
    const items = loadVault();
    if (!items.length) return;
    const mode = fmtSelect.value;
    const joined = items.map((i) => formatVaultLink(i, mode)).join('\n');
    copyToClipboard(joined, e.currentTarget);
  });

  document.getElementById('btn-purge-vault').addEventListener('click', purgeLocalVault);

  previewClose.addEventListener('click', closePreviewModal);
  previewModal.addEventListener('click', (e) => {
    if (e.target === previewModal) closePreviewModal();
  });

  codexBtn.addEventListener('click', () => {
    codexModal.classList.add('open');
  });

  codexCloseBtn.addEventListener('click', startFieldTour);
  codexStartTourBtn.addEventListener('click', startFieldTour);
  codexModal.addEventListener('click', (e) => {
    if (e.target === codexModal) startFieldTour();
  });

  tourPrevBtn.addEventListener('click', () => {
    if (currentTourIdx > 0) {
      currentTourIdx--;
      positionTourSpotlight();
    }
  });

  tourNextBtn.addEventListener('click', () => {
    if (currentTourIdx < TOUR_STEPS.length - 1) {
      currentTourIdx++;
      positionTourSpotlight();
    } else {
      endFieldTour();
    }
  });

  tourSkipBtn.addEventListener('click', endFieldTour);
  window.addEventListener('resize', positionTourSpotlight);

  const COMMANDS = [
    { label: 'Open System Specifications & Guide', hint: 'Specs', run: () => codexBtn.click() },
    { label: 'Start Interactive Interface Walkthrough', hint: 'Guide', run: () => startFieldTour() },
    { label: 'Toggle Theme (Dark / Light)', hint: 'Theme', run: () => themeToggleBtn.click() },
    { label: 'Toggle Hybrid PQC Cascade E2EE', hint: 'E2EE', run: () => toggleE2eeBtn.click() },
    { label: 'Toggle Discrete Bucket Padding (PAD)', hint: 'Padding', run: () => togglePadBtn.click() },
    {
      label: 'Set Shamir Split Key: 2-of-3 Shares',
      hint: 'Shamir',
      run: () => {
        shamirSelect.value = '2:3';
        shamirSelect.dispatchEvent(new Event('change'));
      }
    },
    {
      label: 'Set Shamir Split Key: 3-of-5 Shares',
      hint: 'Shamir',
      run: () => {
        shamirSelect.value = '3:5';
        shamirSelect.dispatchEvent(new Event('change'));
      }
    },
    {
      label: 'Set Time-Lock: Unlock after 1 Hour',
      hint: 'Time-Lock',
      run: () => {
        timelockSelect.value = '1h';
      }
    },
    { label: 'Toggle Signed WebRTC P2P Direct Stream', hint: 'P2P >200M', run: () => toggleP2pBtn.click() },
    {
      label: 'Toggle Secondary Wipe Code Input',
      hint: 'Duress',
      run: () => {
        duressInput.classList.toggle('visible');
        if (duressInput.classList.contains('visible')) duressInput.focus();
      }
    },
    { label: 'Toggle Strip Image EXIF', hint: 'Privacy', run: () => toggleExifBtn.click() },
    {
      label: 'Bundle Vault Files into Album (.zip)',
      hint: 'Album',
      run: () => createAlbumFromVault(document.getElementById('btn-create-album'), copyToClipboard)
    },
    { label: 'Switch to Files Dropzone', hint: 'Tab', run: () => switchTab('view-drop') },
    { label: 'Switch to Text & Secret Note Studio', hint: 'Tab', run: () => switchTab('view-paste') },
    { label: 'Switch to CLI Reference', hint: 'Tab', run: () => switchTab('view-cli') },
    {
      label: 'Clear Local Vault History',
      hint: 'Clear',
      run: () => document.getElementById('btn-purge-vault').click()
    },
    { label: 'Quick Exit & Clear Local Data', hint: 'ESC×2', run: () => triggerPanicEscape() }
  ];

  let filteredCmds = [...COMMANDS];
  let selectedCmdIdx = 0;

  const closeCommandPalette = () => {
    cmdModal.classList.remove('open');
  };

  const renderCommandList = () => {
    const frag = document.createDocumentFragment();
    filteredCmds.forEach((cmd, idx) => {
      const el = document.createElement('div');
      el.className = 'cmd-item' + (idx === selectedCmdIdx ? ' selected' : '');
      const s1 = document.createElement('span');
      s1.textContent = cmd.label;
      const s2 = document.createElement('span');
      s2.className = 'cmd-hint';
      s2.textContent = cmd.hint;
      el.appendChild(s1);
      el.appendChild(s2);
      el.addEventListener('click', () => {
        closeCommandPalette();
        cmd.run();
      });
      frag.appendChild(el);
    });
    cmdList.replaceChildren(frag);
  };

  const openCommandPalette = () => {
    cmdInput.value = '';
    filteredCmds = [...COMMANDS];
    selectedCmdIdx = 0;
    renderCommandList();
    cmdModal.classList.add('open');
    cmdInput.focus();
  };

  cmdPaletteBtn.addEventListener('click', openCommandPalette);
  cmdModal.addEventListener('click', (e) => {
    if (e.target === cmdModal) closeCommandPalette();
  });

  cmdInput.addEventListener('input', () => {
    const q = cmdInput.value.trim().toLowerCase();
    filteredCmds = COMMANDS.filter(
      (c) => c.label.toLowerCase().includes(q) || c.hint.toLowerCase().includes(q)
    );
    selectedCmdIdx = 0;
    renderCommandList();
  });

  let lastEscTime = 0;
  window.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      if (cmdModal.classList.contains('open')) closeCommandPalette();
      else openCommandPalette();
      return;
    }
    if (tourLayer.classList.contains('active')) {
      if (e.key === 'Escape') {
        e.preventDefault();
        endFieldTour();
      } else if (e.key === 'ArrowRight' || e.key === 'Enter') {
        e.preventDefault();
        tourNextBtn.click();
      } else if (e.key === 'ArrowLeft') {
        e.preventDefault();
        tourPrevBtn.click();
      }
      return;
    }
    if (codexModal.classList.contains('open')) {
      if (e.key === 'Escape' || e.key === 'Enter') {
        e.preventDefault();
        startFieldTour();
      }
      return;
    }
    if (cmdModal.classList.contains('open')) {
      if (e.key === 'Escape') {
        e.preventDefault();
        closeCommandPalette();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (filteredCmds.length) {
          selectedCmdIdx = (selectedCmdIdx + 1) % filteredCmds.length;
          renderCommandList();
        }
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (filteredCmds.length) {
          selectedCmdIdx = (selectedCmdIdx - 1 + filteredCmds.length) % filteredCmds.length;
          renderCommandList();
        }
      } else if (e.key === 'Enter' && filteredCmds[selectedCmdIdx]) {
        e.preventDefault();
        const chosen = filteredCmds[selectedCmdIdx];
        closeCommandPalette();
        chosen.run();
      }
      return;
    }
    if (previewModal.classList.contains('open')) {
      if (e.key === 'Escape') closePreviewModal();
      return;
    }
    if (e.key === 'Escape') {
      const now = Date.now();
      if (now - lastEscTime < 400) {
        triggerPanicEscape();
      }
      lastEscTime = now;
    }
  });
};