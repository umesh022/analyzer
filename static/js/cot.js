/* ═══════════════════════════════════════════════════════════════════════════
   CoT (Chain-of-Thought) Template Manager — Frontend
   Handles: template selector loading, preview modal, create/edit form
═══════════════════════════════════════════════════════════════════════════ */

'use strict';

// ── State ─────────────────────────────────────────────────────────────────────
const cotState = {
  templates:       [],   // full list from API
  selectedId:      null,
  editingStepCount: 0,
};

// ── Init — load templates into dropdown on page load ─────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadCotTemplates();
});

async function loadCotTemplates() {
  try {
    const res  = await fetch('/api/cot/templates');
    const data = await res.json();
    cotState.templates = data.templates || [];
    populateCotSelect(cotState.templates);
  } catch (e) {
    console.warn('CoT templates load failed:', e.message);
  }
}

function populateCotSelect(templates) {
  const sel = document.getElementById('cotSelect');
  if (!sel) return;

  // Keep the "None" option, rebuild the rest
  sel.innerHTML = '<option value="">— None (standard RCA) —</option>';

  // Group by issue_type
  const groups = {};
  for (const t of templates) {
    const g = t.issue_type || 'Other';
    if (!groups[g]) groups[g] = [];
    groups[g].push(t);
  }

  for (const [groupName, items] of Object.entries(groups)) {
    const og = document.createElement('optgroup');
    og.label = groupName;
    for (const t of items) {
      const opt       = document.createElement('option');
      opt.value       = t.id;
      opt.textContent = `${t.is_builtin ? '★ ' : ''}${t.name}`;
      opt.title       = t.description;
      og.appendChild(opt);
    }
    sel.appendChild(og);
  }
}

// ── Dropdown change ───────────────────────────────────────────────────────────
function onCotChange() {
  const sel  = document.getElementById('cotSelect');
  const id   = sel ? sel.value : '';
  cotState.selectedId = id || null;

  const strip   = document.getElementById('cotActiveStrip');
  const viewBtn = document.getElementById('btnCotPreview');

  if (!id) {
    if (strip)   { strip.classList.add('hidden'); strip.innerHTML = ''; }
    if (viewBtn) { viewBtn.style.display = 'none'; }
    return;
  }

  const tmpl = cotState.templates.find(t => t.id === id);
  if (!tmpl) return;

  if (strip) {
    strip.innerHTML = `
      <span>🧠</span>
      <span class="cot-active-name">${escHtml(tmpl.name)}</span>
      <span class="cot-active-type">${escHtml(tmpl.issue_type)} · ${tmpl.steps_count} steps</span>
      ${tmpl.tags && tmpl.tags.length
        ? `<span style="margin-left:auto;font-size:.72rem;color:var(--text-muted)">${tmpl.tags.slice(0,4).map(escHtml).join(', ')}</span>`
        : ''}
    `;
    strip.classList.remove('hidden');
  }
  if (viewBtn) viewBtn.style.display = '';
}

// ── Preview Modal ─────────────────────────────────────────────────────────────
async function previewCot() {
  const id = cotState.selectedId;
  if (!id) return;

  // Fetch full template
  let tmpl;
  try {
    const res = await fetch(`/api/cot/templates/${id}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    tmpl = await res.json();
  } catch (e) {
    showToast(`Could not load template: ${e.message}`, 'error');
    return;
  }

  document.getElementById('cotPreviewTitle').textContent =
    `🧠 ${tmpl.name}`;

  const body = document.getElementById('cotPreviewBody');
  body.innerHTML = _renderTemplatePreview(tmpl);

  document.getElementById('cotPreviewModal').classList.remove('hidden');
}

function _renderTemplatePreview(tmpl) {
  const tags = (tmpl.tags || []).map(t =>
    `<span style="background:rgba(188,140,255,.12);color:var(--accent-purple);padding:1px 7px;border-radius:99px;font-size:.72rem;">${escHtml(t)}</span>`
  ).join(' ');

  let html = `
    <div class="cot-preview-header">
      <div class="cot-preview-title">${escHtml(tmpl.name)}</div>
      <div class="cot-preview-meta">
        <strong>Issue Type:</strong> ${escHtml(tmpl.issue_type)} &nbsp;·&nbsp;
        ${tmpl.is_builtin ? '★ Built-in' : '⚙ Custom'} &nbsp;·&nbsp;
        ${(tmpl.analysis_steps || []).length} analysis steps
      </div>
      ${tags ? `<div style="margin-top:8px">${tags}</div>` : ''}
      ${tmpl.description
        ? `<div style="margin-top:8px;font-size:.82rem;color:var(--text-secondary)">${escHtml(tmpl.description)}</div>`
        : ''}
    </div>`;

  // Call flow
  if (tmpl.call_flow && tmpl.call_flow.length) {
    html += `<div class="cot-call-flow">
      <div class="cot-call-flow-title">📶 Standard Call Flow</div>`;
    tmpl.call_flow.forEach((step, i) => {
      html += `<div class="cot-call-flow-item">
        <span class="cot-flow-num">${i + 1}.</span>
        <span>${escHtml(step)}</span>
      </div>`;
    });
    html += `</div>`;
  }

  // Analysis steps
  if (tmpl.analysis_steps && tmpl.analysis_steps.length) {
    html += `<div style="font-size:.8rem;font-weight:700;color:var(--text-secondary);
             text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">
             🔍 Analysis Steps</div>`;
    tmpl.analysis_steps.forEach(step => {
      const lookFor = (step.what_to_look_for || []).join(', ');
      html += `
        <div class="cot-step-card">
          <div class="cot-step-num">Step ${step.step}</div>
          <div class="cot-step-title">${escHtml(step.title)}</div>
          <div class="cot-step-spec">📎 ${escHtml(step.spec_ref || '')}</div>
          <div class="cot-step-inst">${escHtml(step.instruction)}</div>
          ${lookFor ? `<div class="cot-step-look"><strong>Look for:</strong> ${escHtml(lookFor)}</div>` : ''}
        </div>`;
    });
  }

  // Expected failure sequence
  if (tmpl.expected_failure_sequence && tmpl.expected_failure_sequence.length) {
    html += `<div class="cot-fail-seq">
      <div class="cot-fail-seq-title">⚡ Expected Failure Sequence</div>`;
    tmpl.expected_failure_sequence.forEach(item => {
      html += `<div class="cot-fail-seq-item">
        <span class="cot-fail-seq-arrow">→</span>
        <span>${escHtml(item)}</span>
      </div>`;
    });
    html += `</div>`;
  }

  return html;
}

// ── Create Modal ──────────────────────────────────────────────────────────────
function openCotModal() {
  // Reset form
  ['cotName','cotIssueType','cotTags','cotDesc','cotCallFlow','cotFailureSeq']
    .forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  document.getElementById('cotStepsContainer').innerHTML = '';
  cotState.editingStepCount = 0;
  // Add first blank step
  addCotStep();
  document.getElementById('cotCreateModal').classList.remove('hidden');
}

function addCotStep() {
  cotState.editingStepCount++;
  const n   = cotState.editingStepCount;
  const div = document.createElement('div');
  div.className = 'cot-step-builder';
  div.id = `cotStep_${n}`;
  div.innerHTML = `
    <div class="cot-step-builder-header">
      <span class="cot-step-builder-num">Step ${n}</span>
      <button class="btn btn-xs btn-ghost" style="color:var(--accent-red)"
              onclick="removeCotStep(${n})" title="Remove step">✕</button>
    </div>
    <div class="cot-step-fields">
      <input class="form-input" id="cs_title_${n}" type="text"
             placeholder="Step title (e.g. Identify RLF trigger)" />
      <input class="form-input" id="cs_spec_${n}" type="text"
             placeholder="3GPP spec ref (e.g. TS 38.331 Sec 5.3.10)" />
      <textarea class="form-textarea" id="cs_inst_${n}" rows="3"
             placeholder="Instructions — what to look for and how to analyse..."></textarea>
      <input class="form-input" id="cs_look_${n}" type="text"
             placeholder="Keywords to look for (comma-separated): T310, N310, radioLinkFailure" />
    </div>`;
  document.getElementById('cotStepsContainer').appendChild(div);
}

function removeCotStep(n) {
  const el = document.getElementById(`cotStep_${n}`);
  if (el) el.remove();
}

async function saveCotTemplate() {
  const name      = document.getElementById('cotName').value.trim();
  const issueType = document.getElementById('cotIssueType').value.trim();
  if (!name || !issueType) {
    showToast('Name and Issue Type are required', 'error');
    return;
  }

  // Collect steps
  const steps = [];
  for (let i = 1; i <= cotState.editingStepCount; i++) {
    const titleEl = document.getElementById(`cs_title_${i}`);
    if (!titleEl || !titleEl.closest('#cotStepsContainer')) continue; // was removed
    const title = titleEl.value.trim();
    if (!title) continue;
    steps.push({
      step:               steps.length + 1,
      title,
      instruction:        (document.getElementById(`cs_inst_${i}`)?.value || '').trim(),
      spec_ref:           (document.getElementById(`cs_spec_${i}`)?.value || '').trim(),
      what_to_look_for:   (document.getElementById(`cs_look_${i}`)?.value || '')
                            .split(',').map(s => s.trim()).filter(Boolean),
    });
  }

  const payload = {
    name,
    issue_type:                  issueType,
    description:                 document.getElementById('cotDesc').value.trim(),
    tags:                        document.getElementById('cotTags').value
                                   .split(',').map(s => s.trim()).filter(Boolean),
    call_flow:                   document.getElementById('cotCallFlow').value
                                   .split('\n').map(s => s.trim()).filter(Boolean),
    analysis_steps:              steps,
    expected_failure_sequence:   document.getElementById('cotFailureSeq').value
                                   .split('\n').map(s => s.trim()).filter(Boolean),
  };

  try {
    const res = await fetch('/api/cot/templates', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    const data = await res.json();
    showToast(`✅ Template "${data.template.name}" created`, 'success');
    closeModal('cotCreateModal');

    // Reload templates and auto-select the new one
    await loadCotTemplates();
    const sel = document.getElementById('cotSelect');
    if (sel) {
      sel.value = data.template.id;
      onCotChange();
    }
  } catch (e) {
    showToast(`Save failed: ${e.message}`, 'error');
  }
}

// ── Escape helper (shared with app.js) ───────────────────────────────────────
function escHtml(str) {
  return String(str || '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
