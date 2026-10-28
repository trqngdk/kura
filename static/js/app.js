import {
  MAX_BYTES,
  RESUMABLE_THRESHOLD,
  formatBytes,
  extractSlugFromUrl,
  computeClientSha256,
  solvePowChallenge,
  scrubImageMetadata,
  encryptFileE2ee
} from './crypto.js';

import { startP2pWormholeSender } from './wormhole.js';
import {
  saveToVault,
  renderVault,
  recordDailyUpload,
  computeExpiryTimestamp
} from './vault.js';
import {
  initUiControllers,
  copyToClipboard,
  openShamirModal,
  openPreviewModal,
  openQrModal,
  openStatsModal
} from './ui.js';

// ============================================================================
// APPLICATION STATE & DOM REFERENCES
// ============================================================================

const consoleFrame = document.getElementById('console-frame');
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('file-input');
const batchHud = document.getElementById('batch-hud');
const batchHudLeft = document.getElementById('batch-hud-left');
const batchHudRight = document.getElementById('batch-hud-right');
const batchHudBar = document.getElementById('batch-hud-bar');
const queueSection = document.getElementById('queue-section');

const expirySelect = document.getElementById('expiry-select');
const timelockSelect = document.getElementById('timelock-select');
const shamirSelect = document.getElementById('shamir-select');
const passwordInput = document.getElementById('password-input');
const duressInput = document.getElementById('duress-input');
const pasteTextarea = document.getElementById('paste-textarea');
const pasteByteCounter = document.getElementById('paste-byte-counter');
const btnDeployPaste = document.getElementById('btn-deploy-paste');
const btnDeployNote = document.getElementById('btn-deploy-note');
const cmdInput = document.getElementById('cmd-input');
const statNodePing = document.getElementById('stat-node-ping');

export const opsecState = {
  stripExif: true,
  e2ee: false,
  pad: false,
  p2p: false
};

const batchState = {
  totalFiles: 0,
  doneFiles: 0,
  totalBytes: 0,
  fileLoaded: new Map(),
  startTime: 0,
  rafPending: false
};

export const vaultModalCallbacks = {
  onOpenShamir: (entry) => openShamirModal(entry),
  onOpenPreview: (entry) => openPreviewModal(entry),
  onOpenQr: (entry) => openQrModal(entry),
  onOpenStats: (entry) => openStatsModal(entry),
  onCopy: (text, btn) => copyToClipboard(text, btn)
};

// ============================================================================
// TELEMETRY & 60FPS BATCH HUD COALESCING
// ============================================================================

const measureNodeLatency = async () => {
  const t0 = performance.now();
  try {
    const res = await fetch('/healthz', { cache: 'no-store' });
    if (res.ok) {
      const rtt = Math.max(1, Math.round(performance.now() - t0));
      statNodePing.textContent = `ONLINE · ${rtt}ms`;
    }
  } catch (_) {
    statNodePing.textContent = 'ONLINE';
  }
};

export const updateBatchHud = () => {
  if (batchState.rafPending) return;
  batchState.rafPending = true;
  requestAnimationFrame(() => {
    batchState.rafPending = false;
    if (batchState.totalFiles === 0) {
      batchHud.classList.remove('visible');
      return;
    }
    batchHud.classList.add('visible');
    let sumLoaded = 0;
    for (const v of batchState.fileLoaded.values()) sumLoaded += v;
    const pct =
      batchState.totalBytes > 0
        ? Math.min(100, Math.round((sumLoaded / batchState.totalBytes) * 100))
        : 100;
    const elapsed = (performance.now() - batchState.startTime) / 1000;
    const speed = elapsed > 0 ? formatBytes(sumLoaded / elapsed) + '/s' : '--';

    batchHudLeft.textContent = `Batch: ${batchState.doneFiles}/${batchState.totalFiles} (${pct}%)`;
    batchHudRight.textContent = `${formatBytes(sumLoaded)} / ${formatBytes(batchState.totalBytes)} · ${speed}`;
    batchHudBar.style.width = `${pct}%`;
  });
};

// ============================================================================
// RESUMABLE CHUNKED UPLOAD PIPELINE (> 10 MiB)
// ============================================================================

const uploadResumableChunked = async ({
  processedFile,
  rawFile,
  fileId,
  clientHash,
  selectedExpiry,
  selectedTimelock,
  selectedPassword,
  selectedDuress,
  useE2ee,
  e2eeKeyFragment,
  shamirShares,
  shamirM,
  statusEl,
  telemetryEl,
  progressEl,
  abortBtn,
  itemEl,
  markBatchDone
}) => {
  let aborted = false;
  const activeController = new AbortController();

  abortBtn.addEventListener('click', () => {
    aborted = true;
    activeController.abort();
    statusEl.textContent = 'Canceled';
    statusEl.style.color = 'var(--warning)';
    progressEl.style.width = '0%';
    abortBtn.remove();
    markBatchDone(0);
  });

  const buildHeaders = (powToken = null) => {
    const h = {
      'X-Content-Sha256': clientHash,
      'X-Kura-Size': String(processedFile.size),
      'X-Kura-Filename': processedFile.name
    };
    if (selectedExpiry && selectedExpiry !== 'never') h['X-Kura-Expire'] = selectedExpiry;
    if (selectedTimelock) h['X-Kura-Timelock'] = selectedTimelock;
    if (shamirM) h['X-Kura-Shamir-M'] = String(shamirM);
    if (selectedPassword.length > 0) h['X-Kura-Password'] = selectedPassword;
    if (selectedDuress.length > 0) h['X-Kura-Duress-Password'] = selectedDuress;
    if (useE2ee) h['X-Kura-E2EE'] = 'hybrid-pqc-v3';
    if (powToken) h['X-Kura-Pow'] = powToken;
    return h;
  };

  try {
    statusEl.textContent = 'Init session...';
    let initRes = await fetch('/upload/resumable/init', {
      method: 'POST',
      headers: buildHeaders(),
      signal: activeController.signal
    });

    if (initRes.status === 429 && initRes.headers.get('X-Kura-Pow-Challenge')) {
      statusEl.textContent = 'Solving PoW...';
      const challenge = initRes.headers.get('X-Kura-Pow-Challenge');
      const diff = Number(initRes.headers.get('X-Kura-Pow-Difficulty') || 16);
      const solved = await solvePowChallenge(challenge, diff);
      if (solved) {
        initRes = await fetch('/upload/resumable/init', {
          method: 'POST',
          headers: buildHeaders(solved),
          signal: activeController.signal
        });
      }
    }

    if (!initRes.ok) {
      throw new Error((await initRes.text()).trim() || `HTTP ${initRes.status}`);
    }

    const session = await initRes.json();
    const { session_id, part_size, total_parts, uploaded_parts } = session;
    const doneSet = new Set(uploaded_parts || []);
    const startTime = performance.now();

    for (let partNum = 1; partNum <= total_parts; partNum++) {
      if (aborted) return;
      const startByte = (partNum - 1) * part_size;
      const endByte = Math.min(processedFile.size, partNum * part_size);

      if (doneSet.has(partNum)) {
        batchState.fileLoaded.set(fileId, Math.min(rawFile.size, endByte));
        updateBatchHud();
        progressEl.style.width = `${Math.round((endByte / processedFile.size) * 100)}%`;
        continue;
      }

      const blobPart = processedFile.slice(startByte, endByte);
      let partUploaded = false;

      for (let attempt = 0; attempt < 3 && !partUploaded; attempt++) {
        if (aborted) return;
        statusEl.textContent = `Part ${partNum}/${total_parts}${attempt > 0 ? ' (retry)' : ''}`;
        const partRes = await fetch(`/upload/resumable/${session_id}/${partNum}`, {
          method: 'PUT',
          body: blobPart,
          signal: activeController.signal
        });
        if (partRes.ok) {
          partUploaded = true;
        } else if (attempt === 2) {
          throw new Error(`part_${partNum}_failed`);
        }
      }

      batchState.fileLoaded.set(fileId, Math.min(rawFile.size, endByte));
      updateBatchHud();
      const pct = Math.round((endByte / processedFile.size) * 100);
      const elapsed = (performance.now() - startTime) / 1000;
      const speed = elapsed > 0 ? formatBytes(endByte / elapsed) + '/s' : '--';
      progressEl.style.width = `${pct}%`;
      telemetryEl.textContent = `${pct}% · ${speed}`;
    }

    statusEl.textContent = 'Assembling R2...';
    const compHeaders = shamirM ? { 'X-Kura-Shamir-M': String(shamirM) } : {};
    const compRes = await fetch(`/upload/resumable/${session_id}/complete`, {
      method: 'POST',
      headers: compHeaders,
      signal: activeController.signal
    });

    abortBtn.remove();
    progressEl.style.width = '0%';
    markBatchDone(rawFile.size);

    if (!compRes.ok) {
      throw new Error((await compRes.text()).trim() || `HTTP ${compRes.status}`);
    }

    const baseUrl = (await compRes.text()).trim();
    const finalUrl = e2eeKeyFragment ? `${baseUrl}#${e2eeKeyFragment}` : baseUrl;
    const deleteKey = compRes.headers.get('X-Kura-Delete-Key') || null;
    const slug = compRes.headers.get('X-Kura-Slug') || extractSlugFromUrl(baseUrl);
    const isDedup = compRes.headers.get('X-Kura-Deduplicated') === '1';

    statusEl.textContent = session.resumed ? 'Resumed & Done' : isDedup ? 'Deduped' : 'Done';
    statusEl.style.color = 'var(--success)';

    recordDailyUpload(rawFile.size, isDedup);

    const entry = {
      name: rawFile.name,
      size: rawFile.size,
      paddedSize: processedFile.size,
      hash: clientHash,
      url: finalUrl,
      slug,
      deleteKey,
      dedup: isDedup,
      expiry: selectedExpiry,
      timelock: selectedTimelock || null,
      expiresAt: computeExpiryTimestamp(selectedExpiry),
      protected: selectedPassword.length > 0,
      duress: selectedDuress.length > 0,
      e2ee: useE2ee,
      shamirM,
      shamirShares,
      ts: Date.now()
    };

    const actionContainer = itemEl.querySelector('.queue-header div');
    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'btn-action';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', () => copyToClipboard(finalUrl, copyBtn));
    actionContainer.appendChild(copyBtn);

    saveToVault(entry, vaultModalCallbacks);
    if (shamirShares && shamirShares.length) openShamirModal(entry);
  } catch (err) {
    if (aborted) return;
    abortBtn.remove();
    progressEl.style.width = '0%';
    statusEl.textContent = `Failed (${err.message || 'Error'})`;
    statusEl.style.color = 'var(--danger)';
    markBatchDone(0);
  }
};

// ============================================================================
// SINGLE-FILE DISPATCHER & DIRECT BINARY STREAMING
// ============================================================================

const processSingleFile = async (rawFile, fileId, options = {}) => {
  const isSecretNote = Boolean(options.isSecretNote);
  const selectedExpiry =
    isSecretNote && expirySelect.value === 'never' ? '1v' : expirySelect.value;
  const selectedTimelock = timelockSelect.value;
  const selectedShamir = shamirSelect.value;
  const selectedPassword = passwordInput.value.trim();
  const selectedDuress = duressInput.value.trim();
  const usePad = opsecState.pad;
  const useE2ee = isSecretNote || Boolean(selectedShamir) || usePad || opsecState.e2ee;

  const itemEl = document.createElement('div');
  itemEl.className = 'queue-item';
  itemEl.innerHTML = `
    <div class="queue-header">
      <span class="queue-filename"></span>
      <div style="display:flex;align-items:center;gap:0.35rem;">
        <span class="queue-status">Preparing...</span>
        <button type="button" class="btn-action btn-abort">Cancel</button>
      </div>
    </div>
    <div class="queue-meta">
      <span class="queue-hash">Hashing...</span>
      <span class="queue-telemetry">${formatBytes(rawFile.size)}</span>
    </div>
    <div class="queue-progress"></div>
  `;

  itemEl.querySelector('.queue-filename').textContent = rawFile.name;
  queueSection.prepend(itemEl);

  const statusEl = itemEl.querySelector('.queue-status');
  const hashEl = itemEl.querySelector('.queue-hash');
  const telemetryEl = itemEl.querySelector('.queue-telemetry');
  const progressEl = itemEl.querySelector('.queue-progress');
  const abortBtn = itemEl.querySelector('.btn-abort');

  const markBatchDone = (finalBytes) => {
    batchState.fileLoaded.set(fileId, finalBytes);
    batchState.doneFiles += 1;
    updateBatchHud();
  };

  if (rawFile.size === 0) {
    statusEl.textContent = 'Empty file';
    statusEl.style.color = 'var(--danger)';
    abortBtn.remove();
    markBatchDone(0);
    return;
  }

  if (opsecState.p2p || rawFile.size > MAX_BYTES) {
    return startP2pWormholeSender({
      rawFile,
      fileId,
      useE2ee,
      statusEl,
      hashEl,
      telemetryEl,
      progressEl,
      abortBtn,
      itemEl,
      markBatchDone,
      onProgress: (loaded) => {
        batchState.fileLoaded.set(fileId, loaded);
        updateBatchHud();
      },
      vaultModalCallbacks
    });
  }

  if (
    selectedPassword.length > 0 &&
    selectedDuress.length > 0 &&
    selectedPassword === selectedDuress
  ) {
    statusEl.textContent = 'Duress == Password';
    statusEl.style.color = 'var(--danger)';
    abortBtn.remove();
    markBatchDone(0);
    return;
  }

  let processedFile = await scrubImageMetadata(rawFile, opsecState.stripExif);
  let e2eeKeyFragment = null;
  let shamirShares = null;
  let shamirM = null;
  let clientHash = null;

  if (useE2ee) {
    statusEl.textContent = usePad ? 'PQC Padding & Encrypting...' : 'PQC Cascade Encrypting...';
    const encResult = await encryptFileE2ee(
      processedFile,
      isSecretNote,
      usePad,
      selectedShamir
    );
    processedFile = encResult.encryptedFile;
    e2eeKeyFragment = encResult.hashKey;
    shamirShares = encResult.shamirShares;
    shamirM = encResult.shamirM;
    clientHash = encResult.precomputedSha256;
  } else {
    clientHash = await computeClientSha256(processedFile);
  }

  if (clientHash) {
    hashEl.textContent = `SHA-256: ${clientHash.slice(0, 12)}…`;
  }

  if (processedFile.size > RESUMABLE_THRESHOLD && clientHash) {
    return uploadResumableChunked({
      processedFile,
      rawFile,
      fileId,
      clientHash,
      selectedExpiry,
      selectedTimelock,
      selectedPassword,
      selectedDuress,
      useE2ee,
      e2eeKeyFragment,
      shamirShares,
      shamirM,
      statusEl,
      telemetryEl,
      progressEl,
      abortBtn,
      itemEl,
      markBatchDone
    });
  }

  const sendViaXhr = (powToken = null) => {
    const xhr = new XMLHttpRequest();
    const startTime = performance.now();
    let lastUiTick = 0;

    abortBtn.onclick = () => {
      xhr.abort();
      statusEl.textContent = 'Canceled';
      statusEl.style.color = 'var(--warning)';
      progressEl.style.width = '0%';
      abortBtn.remove();
      markBatchDone(0);
    };

    const safeName = encodeURIComponent(processedFile.name.replace(/[^a-zA-Z0-9._-]/g, '_'));
    xhr.open('PUT', `/upload/${safeName}`, true);
    if (clientHash) xhr.setRequestHeader('X-Content-Sha256', clientHash);
    if (selectedExpiry && selectedExpiry !== 'never') {
      xhr.setRequestHeader('X-Kura-Expire', selectedExpiry);
    }
    if (selectedTimelock) xhr.setRequestHeader('X-Kura-Timelock', selectedTimelock);
    if (shamirM) xhr.setRequestHeader('X-Kura-Shamir-M', String(shamirM));
    if (selectedPassword.length > 0) xhr.setRequestHeader('X-Kura-Password', selectedPassword);
    if (selectedDuress.length > 0) xhr.setRequestHeader('X-Kura-Duress-Password', selectedDuress);
    if (useE2ee) xhr.setRequestHeader('X-Kura-E2EE', 'hybrid-pqc-v3');
    if (powToken) xhr.setRequestHeader('X-Kura-Pow', powToken);

    xhr.upload.onprogress = (e) => {
      if (!e.lengthComputable) return;
      batchState.fileLoaded.set(fileId, Math.min(rawFile.size, e.loaded));
      updateBatchHud();

      const now = performance.now();
      if (e.loaded < e.total && now - lastUiTick < 32) return;
      lastUiTick = now;

      const pct = Math.round((e.loaded / e.total) * 100);
      const elapsed = (now - startTime) / 1000;
      const speed = elapsed > 0 ? formatBytes(e.loaded / elapsed) + '/s' : '--';
      const remainingBytes = e.total - e.loaded;
      const eta =
        elapsed > 0 && e.loaded > 0 ? Math.ceil(remainingBytes / (e.loaded / elapsed)) + 's' : '--';

      progressEl.style.width = `${pct}%`;

      if (e.loaded === e.total) {
        statusEl.textContent = 'Finalizing...';
        telemetryEl.textContent = formatBytes(processedFile.size);
      } else {
        statusEl.textContent = `${pct}%`;
        telemetryEl.textContent = `${speed} · ${eta}`;
      }
    };

    xhr.onload = async () => {
      const powChallenge = xhr.getResponseHeader('X-Kura-Pow-Challenge');
      if (xhr.status === 429 && powChallenge && !powToken) {
        statusEl.textContent = 'Solving PoW...';
        const diff = Number(xhr.getResponseHeader('X-Kura-Pow-Difficulty') || 16);
        const solved = await solvePowChallenge(powChallenge, diff);
        if (solved) {
          return sendViaXhr(solved);
        }
      }

      abortBtn.remove();
      progressEl.style.width = '0%';
      markBatchDone(rawFile.size);

      if (xhr.status >= 200 && xhr.status < 300) {
        const baseUrl = xhr.responseText.trim();
        const finalUrl = e2eeKeyFragment ? `${baseUrl}#${e2eeKeyFragment}` : baseUrl;
        const deleteKey = xhr.getResponseHeader('X-Kura-Delete-Key') || null;
        const slug = xhr.getResponseHeader('X-Kura-Slug') || extractSlugFromUrl(baseUrl);
        const isDedup = xhr.getResponseHeader('X-Kura-Deduplicated') === '1';

        statusEl.textContent = isDedup ? 'Deduped' : 'Done';
        statusEl.style.color = 'var(--success)';

        recordDailyUpload(rawFile.size, isDedup);

        const entry = {
          name: rawFile.name,
          size: rawFile.size,
          paddedSize: processedFile.size,
          hash: clientHash,
          url: finalUrl,
          slug,
          deleteKey,
          dedup: isDedup,
          note: isSecretNote,
          expiry: selectedExpiry,
          timelock: selectedTimelock || null,
          expiresAt: computeExpiryTimestamp(selectedExpiry),
          protected: selectedPassword.length > 0,
          duress: selectedDuress.length > 0,
          e2ee: useE2ee,
          shamirM,
          shamirShares,
          ts: Date.now()
        };

        const actionContainer = itemEl.querySelector('.queue-header div');
        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'btn-action';
        copyBtn.textContent = 'Copy';
        copyBtn.addEventListener('click', () => copyToClipboard(finalUrl, copyBtn));
        actionContainer.appendChild(copyBtn);

        saveToVault(entry, vaultModalCallbacks);
        if (shamirShares && shamirShares.length) openShamirModal(entry);
      } else {
        const errCode = xhr.responseText.trim() || `HTTP ${xhr.status}`;
        statusEl.textContent = `Failed (${errCode})`;
        statusEl.style.color = 'var(--danger)';
      }
    };

    xhr.onerror = () => {
      abortBtn.remove();
      progressEl.style.width = '0%';
      statusEl.textContent = 'Network error';
      statusEl.style.color = 'var(--danger)';
      markBatchDone(0);
    };

    xhr.send(processedFile);
  };

  sendViaXhr();
};

export const enqueueFiles = (fileList, options = {}) => {
  const files = Array.from(fileList);
  if (!files.length) return;
  if (batchState.doneFiles === batchState.totalFiles) {
    batchState.totalFiles = 0;
    batchState.doneFiles = 0;
    batchState.totalBytes = 0;
    batchState.fileLoaded.clear();
    batchState.startTime = performance.now();
  }
  queueSection.classList.add('visible');
  files.forEach((file) => {
    const fileId = Symbol();
    batchState.totalFiles += 1;
    batchState.totalBytes += file.size;
    batchState.fileLoaded.set(fileId, 0);
    updateBatchHud();
    processSingleFile(file, fileId, options);
  });
};

// ============================================================================
// DRAG-AND-DROP, CLIPBOARD PASTE & TEXT STUDIO BINDINGS
// ============================================================================

let dragCounter = 0;

window.addEventListener('dragenter', (e) => {
  if (!e.dataTransfer?.types?.includes('Files')) return;
  e.preventDefault();
  dragCounter++;
  document.body.classList.add('dragging-file');
  consoleFrame.classList.add('global-dragover');
});

window.addEventListener('dragover', (e) => {
  if (!e.dataTransfer?.types?.includes('Files')) return;
  e.preventDefault();
});

window.addEventListener('dragleave', (e) => {
  if (!e.dataTransfer?.types?.includes('Files')) return;
  e.preventDefault();
  dragCounter = Math.max(0, dragCounter - 1);
  if (dragCounter === 0) {
    document.body.classList.remove('dragging-file');
    consoleFrame.classList.remove('global-dragover');
  }
});

window.addEventListener('drop', (e) => {
  if (!e.dataTransfer?.types?.includes('Files')) return;
  e.preventDefault();
  dragCounter = 0;
  document.body.classList.remove('dragging-file');
  consoleFrame.classList.remove('global-dragover');
  dropzone.classList.remove('dragover');
  if (e.dataTransfer.files.length > 0) {
    enqueueFiles(e.dataTransfer.files);
  }
});

dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    fileInput.click();
  }
});

fileInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) {
    enqueueFiles(e.target.files);
    fileInput.value = '';
  }
});

pasteTextarea.addEventListener('input', () => {
  const bytes = new Blob([pasteTextarea.value]).size;
  pasteByteCounter.textContent = `${formatBytes(bytes)} · UTF-8`;
});

const deployTextPayload = (asSecretNote = false) => {
  const content = pasteTextarea.value;
  if (!content.trim()) return;
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const filename = asSecretNote ? `secret_${Date.now()}.note` : `snippet_${Date.now()}.txt`;
  const file = new File([blob], filename, { type: 'text/plain' });
  pasteTextarea.value = '';
  pasteByteCounter.textContent = '0 B · UTF-8';
  enqueueFiles([file], { isSecretNote: asSecretNote });
};

btnDeployPaste.addEventListener('click', () => deployTextPayload(false));
btnDeployNote.addEventListener('click', () => deployTextPayload(true));
pasteTextarea.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    deployTextPayload(false);
  }
});

window.addEventListener('paste', (e) => {
  if (
    document.activeElement === pasteTextarea ||
    document.activeElement === passwordInput ||
    document.activeElement === duressInput ||
    document.activeElement === cmdInput
  ) {
    return;
  }
  const items = e.clipboardData?.items;
  if (!items) return;

  const pastedFiles = [];
  for (const item of items) {
    if (item.kind === 'file') {
      const f = item.getAsFile();
      if (f) pastedFiles.push(f);
    }
  }

  if (pastedFiles.length > 0) {
    consoleFrame.classList.add('paste-flash');
    setTimeout(() => consoleFrame.classList.remove('paste-flash'), 250);
    enqueueFiles(pastedFiles);
  }
});

// ============================================================================
// BOOTSTRAP
// ============================================================================

initUiControllers(opsecState, vaultModalCallbacks);
renderVault(vaultModalCallbacks);
measureNodeLatency();