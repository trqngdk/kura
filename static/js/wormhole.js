import {
  formatBytes,
  bytesToBase64Url,
  createWormholeSignalSigner,
  generateHybridPqcMasterKey
} from './crypto.js';

import { saveToVault, recordDailyUpload } from './vault.js';
import { copyToClipboard } from './ui.js';

// ============================================================================
// WEBRTC P2P WORMHOLE SENDER & SIGNED SIGNALING CLIENT
// ============================================================================

export const startP2pWormholeSender = async ({
  rawFile,
  useE2ee,
  statusEl,
  hashEl,
  telemetryEl,
  progressEl,
  abortBtn,
  itemEl,
  markBatchDone,
  onProgress,
  vaultModalCallbacks
}) => {
  let aborted = false;
  let pc = null;

  abortBtn.onclick = () => {
    aborted = true;
    if (pc) pc.close();
    statusEl.textContent = 'P2P Canceled';
    statusEl.style.color = 'var(--warning)';
    progressEl.style.width = '0%';
    abortBtn.remove();
    markBatchDone(0);
  };

  try {
    statusEl.textContent = 'Init P2P Room...';
    let cryptoKey = null;
    let hashKey = '';

    if (useE2ee) {
      const rawKey = await generateHybridPqcMasterKey();
      cryptoKey = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
      hashKey = bytesToBase64Url(rawKey);
      rawKey.fill(0);
    }

    const initRes = await fetch('/wormhole/init', {
      method: 'POST',
      headers: {
        'X-Kura-Filename': rawFile.name,
        'X-Kura-Size': String(rawFile.size),
        'X-Kura-E2EE': useE2ee ? 'hybrid-pqc-v3' : '0'
      }
    });
    if (!initRes.ok) throw new Error('Wormhole init failed');

    const { room_id, url, sender_token } = await initRes.json();
    const shareUrl = useE2ee ? `${url}#${hashKey}` : url;
    const signSignal = createWormholeSignalSigner(room_id, sender_token);

    hashEl.textContent = `P2P Room: ${room_id} · Signed Handshake`;
    statusEl.textContent = 'Waiting for peer...';

    const actionContainer = itemEl.querySelector('.queue-header div');
    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'btn-action';
    copyBtn.textContent = 'Copy Link';
    copyBtn.onclick = () => copyToClipboard(shareUrl, copyBtn);
    actionContainer.appendChild(copyBtn);

    saveToVault(
      {
        name: rawFile.name,
        size: rawFile.size,
        url: shareUrl,
        p2p: true,
        e2ee: useE2ee,
        expiry: '30m P2P',
        expiresAt: Date.now() + 1800 * 1000,
        ts: Date.now()
      },
      vaultModalCallbacks
    );

    pc = new RTCPeerConnection({
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun.cloudflare.com:3478' }
      ]
    });

    const dc = pc.createDataChannel('kura-p2p');
    dc.binaryType = 'arraybuffer';
    dc.bufferedAmountLowThreshold = 256 * 1024;

    pc.onicecandidate = async (e) => {
      if (e.candidate && !aborted) {
        const iceBody = JSON.stringify(e.candidate);
        const sig = await signSignal('sender', 'ice', iceBody);
        fetch(`/wormhole/${room_id}/signal?role=sender&kind=ice`, {
          method: 'POST',
          headers: {
            'X-Kura-Wormhole-Token': sender_token,
            'X-Kura-Signal-Sig': sig
          },
          body: iceBody
        }).catch(() => {});
      }
    };

    dc.onopen = async () => {
      statusEl.textContent = 'Peer connected · Streaming...';
      const chunkSize = 64 * 1024;
      let offset = 0;
      const t0 = performance.now();

      while (offset < rawFile.size && !aborted) {
        if (dc.bufferedAmount > 1024 * 1024) {
          await new Promise((r) => {
            dc.onbufferedamountlow = r;
            setTimeout(r, 50);
          });
        }
        const slice = await rawFile.slice(offset, offset + chunkSize).arrayBuffer();
        let payload = slice;
        if (cryptoKey) {
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, slice);
          const packed = new Uint8Array(12 + ct.byteLength);
          packed.set(iv, 0);
          packed.set(new Uint8Array(ct), 12);
          payload = packed.buffer;
        }
        dc.send(payload);
        offset += slice.byteLength;
        if (onProgress) onProgress(offset);

        const pct = Math.min(100, Math.round((offset / rawFile.size) * 100));
        const elapsed = (performance.now() - t0) / 1000;
        const speed = elapsed > 0 ? formatBytes(offset / elapsed) + '/s' : '--';
        progressEl.style.width = `${pct}%`;
        statusEl.textContent = `P2P ${pct}%`;
        telemetryEl.textContent = `${speed}`;
      }

      if (!aborted) {
        dc.send('EOF');
        abortBtn.remove();
        progressEl.style.width = '0%';
        statusEl.textContent = 'P2P Delivered';
        statusEl.style.color = 'var(--success)';
        markBatchDone(rawFile.size);
        recordDailyUpload(rawFile.size, false);
      }
    };

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    const offerBody = JSON.stringify(pc.localDescription);
    const offerSig = await signSignal('sender', 'offer', offerBody);
    const offerRes = await fetch(`/wormhole/${room_id}/signal?role=sender&kind=offer`, {
      method: 'POST',
      headers: {
        'X-Kura-Wormhole-Token': sender_token,
        'X-Kura-Signal-Sig': offerSig
      },
      body: offerBody
    });
    if (!offerRes.ok) throw new Error('Failed to submit signed SDP offer');

    let rev = 0;
    let addedIce = 0;
    while (!aborted) {
      const stRes = await fetch(`/wormhole/${room_id}/state?since=${rev}&wait_ms=8000`);
      if (!stRes.ok) throw new Error('P2P room expired');
      const st = await stRes.json();
      rev = st.revision;

      if (st.answer && !pc.currentRemoteDescription) {
        await pc.setRemoteDescription(new RTCSessionDescription(st.answer));
      }
      if (pc.currentRemoteDescription && st.receiver_ice) {
        while (addedIce < st.receiver_ice.length) {
          try {
            await pc.addIceCandidate(new RTCIceCandidate(st.receiver_ice[addedIce]));
          } catch (_) {}
          addedIce++;
        }
      }
      if (dc.readyState === 'open' || dc.readyState === 'closed') break;
    }
  } catch (err) {
    if (aborted) return;
    abortBtn.remove();
    statusEl.textContent = `P2P Failed (${err.message || 'Error'})`;
    statusEl.style.color = 'var(--danger)';
    markBatchDone(0);
  }
};