/**
 * AI-SIEM REST API Client
 */

const API_BASE = "";

export function getAuthToken() {
  return localStorage.getItem("siem_auth_token") || sessionStorage.getItem("siem_auth_token") || "";
}

export function getAuthHeaders() {
  const token = getAuthToken();
  return token ? { "Authorization": `Bearer ${token}` } : {};
}

export async function fetchDashboardSummary() {
  const res = await fetch(`${API_BASE}/api/dashboard/summary`);
  return res.json();
}

export async function fetchSystemStatus() {
  const res = await fetch(`${API_BASE}/api/status`);
  return res.json();
}

export async function fetchDatasetOverview() {
  const res = await fetch(`${API_BASE}/api/dataset/overview`);
  return res.json();
}

export async function fetchProfilesOverview() {
  const res = await fetch(`${API_BASE}/api/profiles/overview`);
  return res.json();
}

export async function fetchModelBenchmarks() {
  const res = await fetch(`${API_BASE}/api/models/benchmarks`);
  return res.json();
}

export async function predictProfile(profile) {
  const res = await fetch(`${API_BASE}/api/models/predict/profile`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(profile)
  });
  return res.json();
}

export async function predictFlow(flow) {
  const res = await fetch(`${API_BASE}/api/models/predict/flow`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(flow)
  });
  return res.json();
}

export async function uploadThreatFile(file) {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch(`${API_BASE}/api/detect/upload`, {
    method: "POST",
    body: formData
  });
  return res.json();
}

export async function fetchStreamEvent(sessionId = null) {
  const url = sessionId ? `${API_BASE}/api/detect/stream?session_id=${encodeURIComponent(sessionId)}` : `${API_BASE}/api/detect/stream`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchLatestStream(sessionId = null) {
  return fetchStreamEvent(sessionId);
}

export async function fetchDetectionHistory(params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/history${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchCampaigns(params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/campaigns${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}

export async function clearDetectionHistory() {
  const res = await fetch(`${API_BASE}/api/history`, { method: "DELETE" });
  return res.json();
}

export async function clearBatchSummary() {
  const res = await fetch(`${API_BASE}/api/batch/clear`, { method: "POST" });
  return res.json();
}

export async function updateEnsembleConfig(weights, threshold) {
  const res = await fetch(`${API_BASE}/api/ensemble/configure`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ weights, threshold })
  });
  return res.json();
}

export async function fetchAnomalyOverview() {
  const res = await fetch(`${API_BASE}/api/anomaly/overview`);
  return res.json();
}

export async function predictAnomaly(profile) {
  const res = await fetch(`${API_BASE}/api/models/predict/anomaly`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(profile)
  });
  return res.json();
}

export async function chatAssistant(query, context = null) {
  const res = await fetch(`${API_BASE}/api/assistant/chat`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query, context })
  });
  return res.json();
}

export async function fetchSessions(params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/sessions${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchSessionsCount() {
  const res = await fetch(`${API_BASE}/api/sessions/count`);
  return res.json();
}

export async function fetchSessionReport(sessionId) {
  const token = getAuthToken();
  const url = `${API_BASE}/api/sessions/${encodeURIComponent(sessionId)}${token ? '?token=' + encodeURIComponent(token) : ''}`;
  const res = await fetch(url, { headers: getAuthHeaders() });
  return res.json();
}

export async function deleteSession(sessionId) {
  const res = await fetch(`${API_BASE}/api/sessions/${encodeURIComponent(sessionId)}`, {
    method: "DELETE"
  });
  return res.json();
}

export async function fetchSessionThreats(sessionId, params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/sessions/${encodeURIComponent(sessionId)}/threats${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchSessionAnomalies(sessionId, params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/sessions/${encodeURIComponent(sessionId)}/anomalies${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchSessionCampaigns(sessionId, params = {}) {
  const query = new URLSearchParams(params).toString();
  const url = `${API_BASE}/api/sessions/${encodeURIComponent(sessionId)}/campaigns${query ? '?' + query : ''}`;
  const res = await fetch(url);
  return res.json();
}

export async function fetchLatestDrift() {
  const token = getAuthToken();
  const url = `${API_BASE}/api/drift/latest${token ? '?token=' + encodeURIComponent(token) : ''}`;
  const res = await fetch(url, { headers: getAuthHeaders() });
  if (!res.ok) return null;
  return await res.json();
}

export async function fetchDriftHistory(limit = 20) {
  const token = getAuthToken();
  const params = new URLSearchParams({ limit });
  if (token) params.set("token", token);
  const res = await fetch(`${API_BASE}/api/drift/history?${params.toString()}`, { headers: getAuthHeaders() });
  if (!res.ok) return [];
  return await res.json();
}

export async function fetchSessionDrift(sessionId) {
  const token = getAuthToken();
  const url = `${API_BASE}/api/sessions/${encodeURIComponent(sessionId)}/drift${token ? '?token=' + encodeURIComponent(token) : ''}`;
  const res = await fetch(url, { headers: getAuthHeaders() });
  if (!res.ok) return null;
  return await res.json();
}

export async function fetchDriftReference() {
  const token = getAuthToken();
  const url = `${API_BASE}/api/drift/reference${token ? '?token=' + encodeURIComponent(token) : ''}`;
  const res = await fetch(url, { headers: getAuthHeaders() });
  if (!res.ok) return null;
  return await res.json();
}

export async function fetchTrainingOverview() {
  const token = getAuthToken();
  const url = `${API_BASE}/api/training/studio/overview${token ? '?token=' + encodeURIComponent(token) : ''}`;
  const res = await fetch(url, { headers: getAuthHeaders() });
  if (!res.ok) throw new Error(`Failed to load studio overview: ${res.statusText}`);
  return await res.json();
}

export async function validateCandidateDataset(file) {
  const token = getAuthToken();
  const formData = new FormData();
  formData.append("file", file);
  const url = `${API_BASE}/api/training/dataset/validate${token ? '?token=' + encodeURIComponent(token) : ''}`;
  const res = await fetch(url, {
    method: "POST",
    headers: getAuthHeaders(),
    body: formData
  });
  return await res.json();
}

export async function uploadCandidateDataset(file) {
  const token = getAuthToken();
  const formData = new FormData();
  formData.append("file", file);
  const url = `${API_BASE}/api/training/dataset/upload${token ? '?token=' + encodeURIComponent(token) : ''}`;
  const res = await fetch(url, {
    method: "POST",
    headers: getAuthHeaders(),
    body: formData
  });
  return await res.json();
}

export async function trainCandidateModel(datasetId) {
  const token = getAuthToken();
  const url = `${API_BASE}/api/training/candidate/train${token ? '?token=' + encodeURIComponent(token) : ''}`;
  const headers = {
    "Content-Type": "application/json",
    ...getAuthHeaders()
  };
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ dataset_id: datasetId })
  });
  return await res.json();
}

export async function activateCandidateModel(candidateId, approvalNote) {
  const token = getAuthToken();
  const url = `${API_BASE}/api/training/candidate/${encodeURIComponent(candidateId)}/activate${token ? '?token=' + encodeURIComponent(token) : ''}`;
  const headers = {
    "Content-Type": "application/json",
    ...getAuthHeaders()
  };
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ approval_note: approvalNote })
  });
  return await res.json();
}

export async function rollbackCandidateModel(rollbackNote) {
  const token = getAuthToken();
  const url = `${API_BASE}/api/training/candidate/rollback${token ? '?token=' + encodeURIComponent(token) : ''}`;
  const headers = {
    "Content-Type": "application/json",
    ...getAuthHeaders()
  };
  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify({ rollback_note: rollbackNote })
  });
  return await res.json();
}

// =====================================================================
// Chunked Upload & Checkpoint-Based Resumable Processing API
// =====================================================================

export class StreamingSHA256 {
  constructor() {
    this.K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);

    this.H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);

    this.buffer = new Uint8Array(64);
    this.bufferLen = 0;
    this.totalBytes = 0;
    this.W = new Uint32Array(64);
  }

  _processBlock(b) {
    const W = this.W;
    const K = this.K;

    for (let t = 0; t < 16; t++) {
      const idx = t * 4;
      W[t] = ((b[idx] << 24) | (b[idx + 1] << 16) | (b[idx + 2] << 8) | b[idx + 3]) >>> 0;
    }

    for (let t = 16; t < 64; t++) {
      const s0 = (((W[t - 15] >>> 7) | (W[t - 15] << 25)) ^
                  ((W[t - 15] >>> 18) | (W[t - 15] << 14)) ^
                  (W[t - 15] >>> 3)) >>> 0;
      const s1 = (((W[t - 2] >>> 17) | (W[t - 2] << 15)) ^
                  ((W[t - 2] >>> 19) | (W[t - 2] << 13)) ^
                  (W[t - 2] >>> 10)) >>> 0;
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
    }

    let a = this.H[0];
    let b0 = this.H[1];
    let c = this.H[2];
    let d = this.H[3];
    let e = this.H[4];
    let f = this.H[5];
    let g = this.H[6];
    let h = this.H[7];

    for (let t = 0; t < 64; t++) {
      const S1 = (((e >>> 6) | (e << 26)) ^
                  ((e >>> 11) | (e << 21)) ^
                  ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ ((~e) & g)) >>> 0;
      const temp1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^
                  ((a >>> 13) | (a << 19)) ^
                  ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b0) ^ (a & c) ^ (b0 & c)) >>> 0;
      const temp2 = (S0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b0;
      b0 = a;
      a = (temp1 + temp2) >>> 0;
    }

    this.H[0] = (this.H[0] + a) >>> 0;
    this.H[1] = (this.H[1] + b0) >>> 0;
    this.H[2] = (this.H[2] + c) >>> 0;
    this.H[3] = (this.H[3] + d) >>> 0;
    this.H[4] = (this.H[4] + e) >>> 0;
    this.H[5] = (this.H[5] + f) >>> 0;
    this.H[6] = (this.H[6] + g) >>> 0;
    this.H[7] = (this.H[7] + h) >>> 0;
  }

  update(chunk) {
    if (typeof chunk === 'string') {
      chunk = new TextEncoder().encode(chunk);
    } else if (chunk instanceof ArrayBuffer) {
      chunk = new Uint8Array(chunk);
    }

    let offset = 0;
    const len = chunk.length;
    this.totalBytes += len;

    if (this.bufferLen > 0) {
      const need = 64 - this.bufferLen;
      if (len >= need) {
        this.buffer.set(chunk.subarray(0, need), this.bufferLen);
        this._processBlock(this.buffer);
        offset = need;
        this.bufferLen = 0;
      } else {
        this.buffer.set(chunk, this.bufferLen);
        this.bufferLen += len;
        return this;
      }
    }

    while (offset + 64 <= len) {
      this._processBlock(chunk.subarray(offset, offset + 64));
      offset += 64;
    }

    if (offset < len) {
      this.buffer.set(chunk.subarray(offset), 0);
      this.bufferLen = len - offset;
    }

    return this;
  }

  digest() {
    const pad = new Uint8Array(128);
    let padLen = 0;

    pad.set(this.buffer.subarray(0, this.bufferLen), 0);
    padLen = this.bufferLen;

    pad[padLen++] = 0x80;

    if (padLen > 56) {
      while (padLen < 64) pad[padLen++] = 0;
      this._processBlock(pad.subarray(0, 64));
      padLen = 0;
    }

    while (padLen < 56) pad[padLen++] = 0;

    const highBits = Math.floor(this.totalBytes / 0x20000000);
    const lowBits = (this.totalBytes * 8) >>> 0;

    pad[56] = (highBits >>> 24) & 0xff;
    pad[57] = (highBits >>> 16) & 0xff;
    pad[58] = (highBits >>> 8) & 0xff;
    pad[59] = highBits & 0xff;
    pad[60] = (lowBits >>> 24) & 0xff;
    pad[61] = (lowBits >>> 16) & 0xff;
    pad[62] = (lowBits >>> 8) & 0xff;
    pad[63] = lowBits & 0xff;

    this._processBlock(pad.subarray(0, 64));

    let hex = "";
    for (let i = 0; i < 8; i++) {
      hex += this.H[i].toString(16).padStart(8, '0');
    }
    return hex;
  }
}

export async function computeFileSHA256(file, onProgress = null, sliceSize = 2 * 1024 * 1024) {
  const hasher = new StreamingSHA256();
  let offset = 0;
  const total = file.size;

  while (offset < total) {
    const end = Math.min(offset + sliceSize, total);
    const slice = file.slice(offset, end);
    const buffer = await slice.arrayBuffer();
    hasher.update(buffer);
    offset = end;
    if (onProgress) {
      onProgress({
        bytesProcessed: offset,
        totalBytes: total,
        percent: total > 0 ? Math.round((offset / total) * 100) : 100
      });
    }
  }

  return hasher.digest();
}

export async function initUploadSession({ filename, file_size, file_hash, total_chunks }) {
  const res = await fetch(`${API_BASE}/api/upload/init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ filename, file_size, file_hash, total_chunks })
  });
  return res.json();
}

export async function uploadChunk(upload_id, chunk_index, chunk_blob) {
  const formData = new FormData();
  formData.append("upload_id", upload_id);
  formData.append("chunk_index", chunk_index);
  formData.append("chunk_file", chunk_blob, `chunk_${chunk_index}.part`);
  const res = await fetch(`${API_BASE}/api/upload/chunk`, {
    method: "POST",
    body: formData
  });
  return res.json();
}

export async function getUploadStatus(upload_id) {
  const res = await fetch(`${API_BASE}/api/upload/status?upload_id=${encodeURIComponent(upload_id)}`);
  return res.json();
}

const finalizedUploads = new Set();
const activePollingUploads = new Set();

export async function finalizeUpload(upload_id, file_hash) {
  if (finalizedUploads.has(upload_id)) {
    return { upload_id, status: "UPLOAD_COMPLETE", message: "Upload already finalized." };
  }
  const res = await fetch(`${API_BASE}/api/upload/finalize`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ upload_id, file_hash })
  });
  const data = await res.json();
  if (res.ok && !data.error && !data.detail) {
    finalizedUploads.add(upload_id);
  }
  return data;
}

export async function cancelUploadSession(upload_id) {
  const res = await fetch(`${API_BASE}/api/upload/${encodeURIComponent(upload_id)}`, {
    method: "DELETE"
  });
  return res.json();
}

export async function startStreamProcessing(upload_id, batch_size = 20000, sync = false) {
  const res = await fetch(`${API_BASE}/api/process/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ upload_id, batch_size, sync })
  });
  return res.json();
}

export async function getStreamProcessStatus(upload_id, {
  maxRetries = 5,
  retryDelayBaseMs = 1000,
  onRetry = null,
  signal = null
} = {}) {
  let attempt = 0;
  while (true) {
    if (signal?.aborted) {
      throw new Error("Status check aborted.");
    }
    try {
      const res = await fetch(`${API_BASE}/api/process/status?upload_id=${encodeURIComponent(upload_id)}`, {
        signal
      });
      if (!res.ok) {
        if (res.status === 404 || res.status === 400) {
          const body = await res.json().catch(() => ({}));
          throw new Error(body.detail || `Upload session not found (HTTP ${res.status})`);
        }
        throw new Error(`Server returned HTTP ${res.status}`);
      }
      return await res.json();
    } catch (err) {
      if (signal?.aborted) {
        throw new Error("Status check aborted.");
      }
      if (err.message && (err.message.includes("not found") || err.message.includes("HTTP 404"))) {
        throw err;
      }
      attempt++;
      if (attempt > maxRetries) {
        throw new Error(`Status polling connection failed after ${maxRetries} retries: ${err.message || err}`);
      }
      const backoff = Math.min(retryDelayBaseMs * Math.pow(1.5, attempt - 1), 6000);
      if (onRetry) {
        try {
          onRetry({ attempt, maxRetries, delayMs: backoff, error: err.message || String(err) });
        } catch (_) {}
      }
      await new Promise(r => setTimeout(r, backoff));
    }
  }
}

export async function resumeStreamProcessing(upload_id, file_hash = null, batch_size = 20000, sync = false) {
  const res = await fetch(`${API_BASE}/api/process/resume`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ upload_id, file_hash, batch_size, sync })
  });
  return res.json();
}

export async function pauseStreamProcessing(upload_id) {
  const res = await fetch(`${API_BASE}/api/process/pause`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ upload_id })
  });
  return res.json();
}

export async function uploadFileChunked(file, {
  onProgress = null,
  onStatusChange = null,
  chunkSize = 5 * 1024 * 1024,
  batchSize = 20000,
  pollIntervalMs = 800,
  signal = null
} = {}) {
  // Phase 1: Compute Full-File SHA-256 incrementally
  if (onStatusChange) onStatusChange({ phase: "HASHING", percent: 0, message: "Computing incremental SHA-256 checksum..." });
  const fileHash = await computeFileSHA256(file, (p) => {
    if (signal?.aborted) throw new Error("Upload aborted by operator.");
    if (onProgress) onProgress({ phase: "HASHING", ...p });
  });

  if (signal?.aborted) throw new Error("Upload aborted by operator.");

  // Phase 2: Init Upload Handshake / Recovery
  const totalChunks = Math.ceil(file.size / chunkSize) || 1;
  if (onStatusChange) onStatusChange({ phase: "INITIATING", percent: 0, message: "Initializing upload session..." });
  const initRes = await initUploadSession({
    filename: file.name,
    file_size: file.size,
    file_hash: fileHash,
    total_chunks: totalChunks
  });

  if (initRes.error || initRes.detail) {
    throw new Error(initRes.detail?.message || initRes.detail || initRes.error);
  }

  const uploadId = initRes.upload_id;

  // Case A: File was already processed previously
  if (initRes.action === "ALREADY_COMPLETED") {
    if (onStatusChange) onStatusChange({ phase: "COMPLETED", percent: 100, message: "Dataset already processed previously." });
    return await fetchSessionReport(initRes.session_id);
  }

  // Phase 3: Upload Missing Chunks
  const completedSet = new Set(initRes.completed_chunks || []);
  for (let cIdx = 0; cIdx < totalChunks; cIdx++) {
    if (signal?.aborted) throw new Error("Upload aborted by operator.");
    if (completedSet.has(cIdx)) continue;

    const start = cIdx * chunkSize;
    const end = Math.min(start + chunkSize, file.size);
    const slice = file.slice(start, end);

    if (onStatusChange) {
      const upPct = Math.round(((completedSet.size) / totalChunks) * 100);
      onStatusChange({
        phase: "UPLOADING",
        upload_id: uploadId,
        chunk_index: cIdx + 1,
        total_chunks: totalChunks,
        percent: upPct,
        message: `Uploading chunk ${cIdx + 1} of ${totalChunks} (${upPct}%)...`
      });
    }

    const chunkRes = await uploadChunk(uploadId, cIdx, slice);
    if (chunkRes.error || chunkRes.detail) {
      throw new Error(chunkRes.detail || chunkRes.error || `Failed to upload chunk ${cIdx}`);
    }
    completedSet.add(cIdx);
  }

  // Phase 4: Finalize Chunked Upload
  if (onStatusChange) onStatusChange({ phase: "FINALIZING", percent: 100, message: "Validating file integrity on server..." });
  const finRes = await finalizeUpload(uploadId, fileHash);
  if (finRes.error || finRes.detail) {
    throw new Error(finRes.detail || finRes.error || "File finalization failed.");
  }

  // Phase 5: Start Resumable Batch Processing
  if (onStatusChange) onStatusChange({ phase: "PROCESSING_START", percent: 0, upload_id: uploadId, message: "Starting streaming inference engine..." });
  const startRes = await startStreamProcessing(uploadId, batchSize, false);
  if (startRes.error || startRes.detail) {
    throw new Error(startRes.detail || startRes.error || "Failed to start streaming processing.");
  }

  // Phase 6: Poll Processing Status until complete
  if (activePollingUploads.has(uploadId)) {
    throw new Error(`Polling loop is already active for upload session '${uploadId}'.`);
  }
  activePollingUploads.add(uploadId);

  try {
    while (true) {
      if (signal?.aborted) {
        await pauseStreamProcessing(uploadId);
        throw new Error("Processing paused/aborted by operator.");
      }

      await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
      const status = await getStreamProcessStatus(uploadId, {
        maxRetries: 5,
        retryDelayBaseMs: 1200,
        signal,
        onRetry: (retryInfo) => {
          if (onStatusChange) {
            onStatusChange({
              phase: "POLLING_RETRY",
              upload_id: uploadId,
              message: `Network connection hiccup: retrying status check (${retryInfo.attempt}/${retryInfo.maxRetries}). Background processing is continuing...`,
              retryInfo
            });
          }
        }
      });

      if (status.processing_status === "FAILED") {
        throw new Error(status.error_message || "Streaming batch processing failed.");
      }

      if (status.processing_status === "PAUSED") {
        if (onStatusChange) onStatusChange({ phase: "PAUSED", upload_id: uploadId, status });
        return { paused: true, upload_id: uploadId, status };
      }

      if (status.sort_status === "SORTING") {
        if (onStatusChange) onStatusChange({
          phase: "SORTING",
          upload_id: uploadId,
          percent: 5,
          message: "External sort: chronologically ordering network capture flows..."
        });
        continue;
      }

      if (onStatusChange) {
        const bPct = status.progress_percent || 0;
        onStatusChange({
          phase: "PROCESSING",
          upload_id: uploadId,
          percent: bPct,
          completed_batches: status.completed_batches,
          total_batches: status.total_batches,
          processed_rows: status.processed_rows,
          total_rows: status.total_rows,
          metrics: status.metrics || {},
          message: `Processing batch ${status.completed_batches} of ${status.total_batches} (${status.processed_rows?.toLocaleString() || 0} rows)...`
        });
      }

      if (status.processing_status === "COMPLETED") {
        if (onStatusChange) onStatusChange({ phase: "COMPLETED", percent: 100, upload_id: uploadId, message: "Analysis complete. Loading report..." });
        return await fetchSessionReport(status.session_id);
      }
    }
  } finally {
    activePollingUploads.delete(uploadId);
  }
}
