/* ═══════════════════════════════════════════════════════════════════════════
   3GPP Log Analyzer — Frontend Application
   Handles: log upload, analysis, chat, MCP tools, streaming
═══════════════════════════════════════════════════════════════════════════ */

'use strict';

// ──────────────────────────────────────────────────────────────────────────
// State
// ──────────────────────────────────────────────────────────────────────────
const state = {
  analysisResult: null,
  chatHistory: [],
  isAnalyzing: false,
  isChatting: false,
  currentRCA: '',
  currentLogText: '',   // raw log text stored for grounding
};

// ──────────────────────────────────────────────────────────────────────────
// DOM Helpers
// ──────────────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function show(el) { if (el) el.classList.remove('hidden'); }
function hide(el) { if (el) el.classList.add('hidden'); }

function showToast(message, type = 'info', duration = 3500) {
  const t = $('toast');
  t.textContent = message;
  t.className = `toast ${type}`;
  show(t);
  setTimeout(() => hide(t), duration);
}

function setAnalyzingState(analyzing) {
  state.isAnalyzing = analyzing;
  const btn = $('btnAnalyze');
  const icon = $('analyzeIcon');
  const text = $('analyzeText');
  btn.disabled = analyzing;
  icon.textContent = analyzing ? '⏳' : '🔍';
  text.textContent = analyzing ? 'Analyzing...' : 'Analyze Logs';
  if (analyzing) {
    show($('statusBar'));
  } else {
    hide($('statusBar'));
  }
}

// ──────────────────────────────────────────────────────────────────────────
// Drag & Drop + File Input
// ──────────────────────────────────────────────────────────────────────────
const dropZone = $('dropZone');

// Store a pending binary file separately (PCAP can't go into a textarea)
let _pendingFile = null;

dropZone.addEventListener('click', () => $('fileInput').click());

dropZone.addEventListener('dragover', e => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  const file = e.dataTransfer.files[0];
  if (file) loadFile(file);
});

function handleFileSelect(event) {
  const file = event.target.files[0];
  if (file) loadFile(file);
}

function isPcap(file) {
  return /\.(pcap|pcapng)$/i.test(file.name);
}

function loadFile(file) {
  if (isPcap(file)) {
    _pendingFile = file;
    $('logInput').value = '';
    dropZone.querySelector('.drop-zone-text').textContent = `✓ Loaded: ${file.name}`;
    dropZone.querySelector('.drop-zone-hint').textContent =
      `PCAP file ready (${(file.size / 1024).toFixed(1)} KB) — click Analyze`;
    dropZone.classList.add('pcap-loaded');
    showToast(`PCAP loaded: ${file.name}`, 'success');
  } else {
    _pendingFile = null;
    dropZone.classList.remove('pcap-loaded');
    const reader = new FileReader();
    reader.onload = e => {
      $('logInput').value = e.target.result;
      dropZone.querySelector('.drop-zone-text').textContent = `✓ Loaded: ${file.name}`;
      dropZone.querySelector('.drop-zone-hint').textContent =
        `Text file loaded (${(file.size / 1024).toFixed(1)} KB)`;
      showToast(`File loaded: ${file.name}`, 'success');
    };
    reader.readAsText(file);
  }
}

// ──────────────────────────────────────────────────────────────────────────
// Streaming Analysis (SSE) — avoids 30s timeout on Render
// ──────────────────────────────────────────────────────────────────────────
async function analyzeViaStream(logText, fullRCA) {
  return new Promise(async (resolve, reject) => {
    try {
      const res = await fetch('/api/analysis/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ log_text: logText, full_rca: fullRCA }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        return reject(new Error(err.detail || `HTTP ${res.status}`));
      }

      const reader  = res.body.getReader();
      const decoder = new TextDecoder();
      let   buf     = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop(); // keep incomplete line

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const msg = JSON.parse(line.slice(6));

            if (msg.status === 'parsed') {
              $('statusText').textContent =
                `Parsed: ${msg.failures_found} failures found. ${msg.message}`;
            } else if (msg.status === 'rca_start') {
              $('statusText').textContent = msg.message;
            } else if (msg.status === 'error') {
              return reject(new Error(msg.message));
            } else if (msg.status === 'done') {
              return resolve(msg.result);
            }
          } catch (_) {}
        }
      }
      reject(new Error('Stream ended without result'));
    } catch (e) {
      reject(e);
    }
  });
}


function loadSampleLog() {
  const sample = `2024-01-15 10:23:40.001 [RRC] UE-12345 RRCSetupRequest sent to gNB-001
2024-01-15 10:23:40.500 [MAC] RACH procedure started, preamble index=42
2024-01-15 10:23:41.001 [MAC] RACH failure, preamble attempts=preambleTransMax (4/4)
2024-01-15 10:23:41.100 [RRC] T300 timer started (1000ms)
2024-01-15 10:23:42.102 [RRC] RRCSetupFailure cause=t300-Expiry UE-12345
2024-01-15 10:23:42.200 [NAS] 5GMM Registration Request sent (attempt 1)
2024-01-15 10:23:43.001 [MAC] HARQ max retransmissions reached, TB discarded DRB-1
2024-01-15 10:23:43.500 [RLC] maxRetxThreshold reached on SRB1, triggering RLF
2024-01-15 10:23:43.600 [RRC] radioLinkFailure detected, T310 expired N310=3 N311=0
2024-01-15 10:23:43.700 [RRC] RRC Re-establishment initiated cause=radioLinkFailure
2024-01-15 10:23:44.001 [RRC] RRCReestablishmentReject received from cell-002
2024-01-15 10:23:44.100 [RRC] T301 expired, re-establishment failed
2024-01-15 10:23:44.200 [NAS] Registration Reject received cause=#22 (congestion)
2024-01-15 10:23:44.300 [NAS] T3346 started, congestion back-off active
2024-01-15 10:23:44.400 [NGAP] UEContextRelease cause=radio-connection-with-ue-lost UE-12345
2024-01-15 10:23:44.500 [GTP] GTP Context Not Found TEID=0x1A2B3C4D, cause=73
2024-01-15 10:23:45.001 [PDCP] Integrity verification failed on SRB1, MAC-I mismatch
2024-01-15 10:23:45.100 [RRC] RRC release with cause=otherFailure
2024-01-15 10:23:45.200 [NAS] PDU Session Establishment Failure cause=#27 (unknown DNN)
2024-01-15 10:23:50.000 [RRC] UE-12345 attempting new RRC connection after T311 expiry
2024-01-15 10:23:50.500 [MAC] New RACH attempt on cell-003
2024-01-15 10:23:51.001 [RRC] RRCSetup received, connection established on cell-003
2024-01-15 10:23:51.200 [NAS] Registration complete on new cell`;

  $('logInput').value = sample;
  showToast('Sample log loaded', 'info');
}

// ──────────────────────────────────────────────────────────────────────────
// Analysis
// ──────────────────────────────────────────────────────────────────────────
async function analyzeLog() {
  const logText   = $('logInput').value.trim();
  const hasPcap   = !!_pendingFile;
  const fullRCA   = $('chkFullRCA').checked;

  if (!logText && !hasPcap) {
    showToast('Please paste log text, upload a text file, or drop a PCAP file', 'error');
    return;
  }

  setAnalyzingState(true);
  $('statusText').textContent = hasPcap
    ? `Parsing PCAP → extracting 3GPP packets → ${fullRCA ? 'generating RCA...' : 'quick parse...'}`
    : `Parsing logs → MCP tools → RAG → ${fullRCA ? 'Groq LLM RCA...' : 'quick parse...'}`;

  try {
    let data;
    if (hasPcap) {
      // ── Binary PCAP: multipart upload ─────────────────────────────────────
      const form = new FormData();
      form.append('file', _pendingFile);
      form.append('full_rca', fullRCA);
      const res = await fetch('/api/analysis/upload', { method: 'POST', body: form });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }
      data = await res.json();
    } else {
      // ── Plain text: streaming SSE endpoint (avoids 30s timeout on Render) ──
      data = await analyzeViaStream(logText, fullRCA);
    }

    state.analysisResult = data;
    // For PCAP, the parsed log text comes back in rca_report preamble; store what we have
    state.currentLogText = hasPcap
      ? (data.rca_report || '')
      : logText;
    renderResults(data, fullRCA);
    showToast(`Analysis complete — ${data.failures?.length || 0} failures found`, 'success');
    addSystemMessage(
      `✅ Log analyzed — **${data.failures?.length || 0} failure points** detected` +
      (data.layers_found?.length
        ? ` across layers: ${data.layers_found.join(', ')}.`
        : '. No 3GPP failure patterns matched — but you can still ask questions about the raw log content.') +
      ` Ask me anything about this log.`
    );
  } catch (e) {
    showToast(`Analysis failed: ${e.message}`, 'error');
    console.error(e);
  } finally {
    setAnalyzingState(false);
  }
}

// ──────────────────────────────────────────────────────────────────────────
// Render Results
// ──────────────────────────────────────────────────────────────────────────
function renderResults(data, fullRCA) {
  const panel = $('resultsPanel');
  show(panel);

  // Summary stats
  const summary = data.parse_summary || {};
  const failSummary = data.failure_summary || {};
  $('summaryGrid').innerHTML = `
    <div class="summary-stat">
      <div class="stat-value stat-blue">${summary.total_lines || 0}</div>
      <div class="stat-label">Total Lines</div>
    </div>
    <div class="summary-stat">
      <div class="stat-value stat-red">${data.failures?.length || 0}</div>
      <div class="stat-label">Failures Found</div>
    </div>
    <div class="summary-stat">
      <div class="stat-value stat-yellow">${(data.layers_found || []).length}</div>
      <div class="stat-label">Layers Affected</div>
    </div>
    <div class="summary-stat">
      <div class="stat-value stat-green">${data.rag_context_used ? '✓' : '–'}</div>
      <div class="stat-label">RAG Used</div>
    </div>
  `;

  // Show LLM pre-pass notice if applicable
  if (data.llm_prepass_used && data.failures?.length > 0) {
    show($('prepassNotice'));
  } else {
    hide($('prepassNotice'));
  }

  // Failure count badge
  $('failureCount').textContent = summary.total_failures || 0;

  // Failure table
  renderFailureTable(data.failures || []);

  // Chain analysis
  const chain = data.chain_analysis || {};
  if (chain.chains && chain.chains.length > 0) {
    show($('chainCard'));
    renderChainAnalysis(chain);
  }

  // RCA
  if (fullRCA && data.rca_report) {
    show($('rcaCard'));
    state.currentRCA = data.rca_report;
    $('rcaReport').innerHTML = renderMarkdown(data.rca_report);
  }
}

function renderFailureTable(failures) {
  if (failures.length === 0) {
    $('failureTable').innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted)">No failures detected</div>';
    return;
  }

  const rows = failures.map(f => `
    <tr>
      <td class="mono" style="color:var(--text-muted)">${f.line_number}</td>
      <td><span class="layer-badge layer-${f.layer}">${f.layer}</span></td>
      <td style="max-width:200px;white-space:normal;font-size:.78rem">${escHtml(f.failure_type)}</td>
      <td class="mono" style="color:var(--text-muted);font-size:.72rem">${escHtml(f.cause || '—')}</td>
      <td class="spec-ref">${escHtml(f.spec_reference || '')}</td>
      <td class="sev-${f.severity}">${f.severity}</td>
    </tr>
  `).join('');

  $('failureTable').innerHTML = `
    <table class="failure-table">
      <thead>
        <tr>
          <th>Line</th><th>Layer</th><th>Failure Type</th>
          <th>Cause</th><th>3GPP Spec</th><th>Severity</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

function renderChainAnalysis(chain) {
  let html = '';
  if (chain.root_layer) {
    html += `<div class="root-layer-badge">⚡ Root Layer: ${escHtml(chain.root_layer)}</div>`;
  }
  for (const c of chain.chains) {
    html += `
      <div class="chain-item">
        <div class="chain-title">🔗 ${escHtml(c.chain)}</div>
        <div class="chain-desc">${escHtml(c.description)}</div>
        <div class="chain-root">⚠ Likely Root Cause: ${escHtml(c.likely_root)}</div>
        <div class="chain-spec">${escHtml(c['3gpp_ref'] || '')}</div>
      </div>
    `;
  }
  $('chainAnalysis').innerHTML = html;
}

// ──────────────────────────────────────────────────────────────────────────
// Chat
// ──────────────────────────────────────────────────────────────────────────
function handleChatKeydown(event) {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    sendChatMessage();
  }
}

function autoResizeTextarea(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 140) + 'px';
}

async function sendChatMessage() {
  const input = $('chatInput');
  const text = input.value.trim();
  if (!text || state.isChatting) return;

  // Warn — but still allow — if no log is loaded
  if (!state.analysisResult) {
    showToast('No log analyzed yet — assistant will ask you to upload one first', 'info', 3000);
  }

  input.value = '';
  input.style.height = 'auto';

  // Hide welcome screen on first message
  const welcome = document.querySelector('.chat-welcome');
  if (welcome) welcome.style.display = 'none';

  appendChatMessage('user', text);
  state.chatHistory.push({ role: 'user', content: text });

  state.isChatting = true;
  $('btnSend').disabled = true;

  const useRAG    = $('chkRAG').checked;
  const useStream = $('chkStream').checked;

  // Build grounded analysis context + raw log snippet
  let analysisCtx = null;
  let logSnippet  = null;
  if (state.analysisResult) {
    analysisCtx = JSON.stringify(state.analysisResult);
    // Pass up to 8000 chars so LLM can find any field (IMSI, IP, timestamps etc.)
    logSnippet  = state.currentLogText ? state.currentLogText.slice(0, 8000) : null;
  }

  show($('typingIndicator'));

  try {
    if (useStream) {
      await streamChatMessage(analysisCtx, logSnippet, useRAG);
    } else {
      await regularChatMessage(analysisCtx, logSnippet, useRAG);
    }
  } finally {
    hide($('typingIndicator'));
    state.isChatting = false;
    $('btnSend').disabled = false;
    input.focus();
  }
}

async function regularChatMessage(analysisCtx, logSnippet, useRAG) {
  try {
    const res = await fetch('/api/chat/message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages: state.chatHistory,
        analysis_context: analysisCtx,
        log_snippet: logSnippet,
        use_rag: useRAG,
        stream: false,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const data = await res.json();
    const reply = data.response;
    appendChatMessage('bot', reply);
    state.chatHistory.push({ role: 'assistant', content: reply });
    if (data.rag_used) appendRAGIndicator();
  } catch (e) {
    appendChatMessage('bot', `❌ Error: ${e.message}`);
  }
}

async function streamChatMessage(analysisCtx, logSnippet, useRAG) {
  const msgId = 'msg-' + Date.now();
  appendChatMessageStreaming('bot', msgId);

  try {
    const res = await fetch('/api/chat/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages: state.chatHistory,
        analysis_context: analysisCtx,
        log_snippet: logSnippet,
        use_rag: useRAG,
        stream: true,
      }),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let fullText = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = decoder.decode(value, { stream: true });
      for (const line of chunk.split('\n')) {
        if (!line.startsWith('data: ')) continue;
        const data = line.slice(6);
        if (data === '[DONE]') break;
        try {
          const json = JSON.parse(data);
          if (json.error) { fullText += `\n❌ ${json.error}`; break; }
          if (json.token) {
            fullText += json.token;
            updateStreamingMessage(msgId, fullText);
          }
        } catch (_) {}
      }
    }
    state.chatHistory.push({ role: 'assistant', content: fullText });
  } catch (e) {
    updateStreamingMessage(msgId, `❌ Streaming error: ${e.message}`);
  }
}

function sendQuickPrompt(text) {
  $('chatInput').value = text;
  sendChatMessage();
}

function addSystemMessage(text) {
  // Welcome-style system notification in chat
  const welcome = document.querySelector('.chat-welcome');
  if (welcome) welcome.style.display = 'none';
  appendChatMessage('bot', text, true);
}

function appendChatMessage(role, content, isSystem = false) {
  const messages = $('chatMessages');
  const div = document.createElement('div');
  div.className = `chat-message ${role}`;

  const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const avatar = role === 'user' ? '👤' : '🤖';

  div.innerHTML = `
    <div class="msg-avatar">${avatar}</div>
    <div>
      <div class="msg-bubble">${renderMarkdown(content)}</div>
      <div class="msg-timestamp">${now}</div>
    </div>
  `;
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
}

function appendChatMessageStreaming(role, msgId) {
  const messages = $('chatMessages');
  const div = document.createElement('div');
  div.className = `chat-message ${role}`;
  div.id = `wrapper-${msgId}`;

  const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  div.innerHTML = `
    <div class="msg-avatar">🤖</div>
    <div>
      <div class="msg-bubble" id="${msgId}"><span class="stream-cursor">▌</span></div>
      <div class="msg-timestamp">${now}</div>
    </div>
  `;
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
}

function updateStreamingMessage(msgId, text) {
  const el = $(msgId);
  if (el) {
    el.innerHTML = renderMarkdown(text) + '<span class="stream-cursor">▌</span>';
    const messages = $('chatMessages');
    messages.scrollTop = messages.scrollHeight;
  }
}

function appendRAGIndicator() {
  const messages = $('chatMessages');
  const div = document.createElement('div');
  div.style.cssText = 'text-align:center;padding:4px 0;';
  div.innerHTML = '<span style="font-size:.7rem;color:var(--text-muted);background:var(--bg-input);padding:2px 8px;border-radius:99px;border:1px solid var(--border)">📚 3GPP knowledge base used</span>';
  messages.appendChild(div);
}

function clearChat() {
  state.chatHistory = [];
  const messages = $('chatMessages');
  messages.innerHTML = `
    <div class="chat-welcome">
      <div class="welcome-icon">📡</div>
      <div class="welcome-title">3GPP Log Analysis Assistant</div>
      <div class="welcome-text">Upload and analyze logs on the left, then ask me anything.</div>
    </div>
  `;
}

// ──────────────────────────────────────────────────────────────────────────
// MCP Tools Panel
// ──────────────────────────────────────────────────────────────────────────
async function showMCPTools() {
  const panel = $('mcpPanel');
  show(panel);

  try {
    const res = await fetch('/api/chat/mcp-tools');
    const data = await res.json();
    const tools = data.tools || [];

    $('mcpToolList').innerHTML = tools.map(t => `
      <div class="mcp-tool-item" onclick="useMCPTool('${escHtml(t.name)}', '${escHtml(t.description)}')">
        <div class="mcp-tool-name">${escHtml(t.name)}</div>
        <div class="mcp-tool-desc">${escHtml(t.description)}</div>
        <div class="mcp-tool-cat">Category: ${escHtml(t.category)}</div>
      </div>
    `).join('');
  } catch (e) {
    $('mcpToolList').innerHTML = `<div style="padding:10px;color:var(--text-muted)">Could not load tools: ${e.message}</div>`;
  }
}

function hideMCPTools() {
  hide($('mcpPanel'));
}

function useMCPTool(toolName, description) {
  hide($('mcpPanel'));
  $('chatInput').value = `Use the ${toolName} tool: ${description}`;
  $('chatInput').focus();
}

// ──────────────────────────────────────────────────────────────────────────
// Admin Actions
// ──────────────────────────────────────────────────────────────────────────
async function checkStatus() {
  const modal = $('statusModal');
  const body = $('statusModalBody');
  body.innerHTML = 'Loading...';
  show(modal);

  try {
    const res = await fetch('/api/admin/status');
    const s = await res.json();

    const rows = [
      ['Groq API Key', s.groq_api_key_configured ? '✓ Configured' : '✗ Not set',
       s.groq_api_key_configured ? 'ok' : 'err'],
      ['Groq Model', s.groq_model, 'ok'],
      ['Groq Provider', s.groq_provider, 'ok'],
      ['Knowledge Base Files', `${s.knowledge_base_files} files`, s.knowledge_base_files > 0 ? 'ok' : 'warn'],
      ['Vector Store Chunks', `${s.vector_store_chunks} chunks`, s.vector_store_chunks > 0 ? 'ok' : 'warn'],
      ['Vector Store Path', s.vector_store_path, 'ok'],
      ['KB Path', s.knowledge_base_path, 'ok'],
    ];

    body.innerHTML = rows.map(([k, v, cls]) => `
      <div class="status-item">
        <span class="status-key">${escHtml(k)}</span>
        <span class="status-val status-${cls}">${escHtml(String(v))}</span>
      </div>
    `).join('');
  } catch (e) {
    body.innerHTML = `<div style="color:var(--accent-red)">Error: ${e.message}</div>`;
  }
}

async function rebuildIndex() {
  if (!confirm('Re-ingest all knowledge base files into the vector store?')) return;
  try {
    showToast('Rebuilding knowledge base index...', 'info', 10000);
    const res = await fetch('/api/admin/rebuild-index', { method: 'POST' });
    const data = await res.json();
    if (res.ok) {
      showToast(`Index rebuilt: ${data.chunks_ingested} chunks`, 'success');
    } else {
      showToast(`Error: ${data.detail}`, 'error');
    }
  } catch (e) {
    showToast(`Error: ${e.message}`, 'error');
  }
}

// ──────────────────────────────────────────────────────────────────────────
// RCA Actions
// ──────────────────────────────────────────────────────────────────────────
function copyRCA() {
  if (!state.currentRCA) return;
  navigator.clipboard.writeText(state.currentRCA)
    .then(() => showToast('RCA copied to clipboard', 'success'))
    .catch(() => showToast('Copy failed', 'error'));
}

function downloadRCA() {
  if (!state.currentRCA) return;
  const blob = new Blob([state.currentRCA], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `rca_report_${new Date().toISOString().slice(0,10)}.md`;
  a.click();
  URL.revokeObjectURL(url);
}

// ──────────────────────────────────────────────────────────────────────────
// Modal
// ──────────────────────────────────────────────────────────────────────────
function closeModal(id) { hide($(id)); }

// ──────────────────────────────────────────────────────────────────────────
// Markdown Renderer (minimal, no external deps)
// ──────────────────────────────────────────────────────────────────────────
function renderMarkdown(text) {
  if (!text) return '';

  let html = escHtml(text);

  // Code blocks (must be first)
  html = html.replace(/```[\s\S]*?```/g, m => {
    const inner = m.replace(/^```[^\n]*\n?/, '').replace(/```$/, '');
    return `<pre><code>${inner}</code></pre>`;
  });

  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

  // Bold **text** or __text__
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/__([^_]+)__/g, '<strong>$1</strong>');

  // Italic *text* or _text_
  html = html.replace(/\*([^*\n]+)\*/g, '<em>$1</em>');

  // Headers
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');

  // Numbered list
  html = html.replace(/^\d+\.\s+(.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>(\n|$))+/g, m => `<ol>${m}</ol>`);

  // Bullet list
  html = html.replace(/^[-*]\s+(.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>(\n|$))+/g, m => {
    if (m.startsWith('<ol>')) return m;
    return `<ul>${m}</ul>`;
  });

  // Blockquote
  html = html.replace(/^&gt; (.+)$/gm, '<blockquote>$1</blockquote>');

  // Line breaks → paragraphs
  html = html
    .split(/\n{2,}/)
    .map(p => p.trim())
    .filter(Boolean)
    .map(p => {
      if (/^<(h[1-3]|ul|ol|pre|blockquote)/.test(p)) return p;
      return `<p>${p.replace(/\n/g, '<br/>')}</p>`;
    })
    .join('\n');

  return html;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ──────────────────────────────────────────────────────────────────────────
// Init
// ──────────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Load MCP tools on init (for panel)
  fetch('/api/chat/mcp-tools').catch(() => {});
});
