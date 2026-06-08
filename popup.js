/**
 * Metsuke - popup.js
 * Current-page verdict summary + source + Trust this repo + allowlist + master switch (SPEC §5).
 * Only { enabled, allowlist } is persisted in chrome.storage.sync.
 */
'use strict';

const $ = (id) => document.getElementById(id);

// i18n (chrome.i18n picks _locales by browser language; default en, also zh_TW / ja)
const msg = (k, subs) => {
  try { return chrome.i18n.getMessage(k, subs) || ''; } catch { return ''; }
};
const t = (k, ...subs) => msg(k, subs.length ? subs.map(String) : undefined) || k;
const ruleTitle = (rule) => msg('rule_' + rule.replace(/-/g, '_') + '_title') || rule;
const findingDetail = (f) => (f.detailKey ? msg(f.detailKey, (f.detailParams || []).map(String)) : '');

let settings = { enabled: true, allowlist: [] };
let tabId = null;
let pageStatus = null; // status reported by the content script

// ── Talk to the active tab ─────────────────────────────────────────
function queryStatus() {
  return new Promise((resolve) => {
    if (tabId == null) return resolve(null);
    try {
      chrome.tabs.sendMessage(tabId, { type: 'getStatus' }, (res) => {
        void chrome.runtime.lastError; // no content script (not a supported page)
        resolve(res || null);
      });
    } catch { resolve(null); }
  });
}

function sendToTab(m) {
  return new Promise((resolve) => {
    if (tabId == null) return resolve(null);
    try {
      chrome.tabs.sendMessage(tabId, m, (res) => {
        void chrome.runtime.lastError;
        resolve(res || null);
      });
    } catch { resolve(null); }
  });
}

// ── Render ─────────────────────────────────────────────────────────
const SRC_LABEL = { raw: 'raw', embedded: 'embedded' };

function severityCounts(findings) {
  const high = findings.filter((f) => f.severity === 'high').length;
  const med = findings.filter((f) => f.severity === 'med').length;
  return { high, med };
}

function render() {
  const verdictEl = $('verdict');
  const vbadge = $('vbadge');
  const vt = $('vt');
  const vs = $('vs');
  const findEl = $('findings');
  const trustBtn = $('trustBtn');
  const untrustBtn = $('untrustBtn');
  const rescanBtn = $('rescanBtn');

  const pact = $('pact');
  const pallow = $('pallow');

  verdictEl.className = 'verdict';
  findEl.textContent = '';
  trustBtn.hidden = true;
  untrustBtn.hidden = true;
  rescanBtn.disabled = false;
  pact.style.display = '';
  pallow.style.display = '';

  const s = pageStatus;
  const repoKey = s && s.repoKey;
  const trusted = repoKey && settings.allowlist.includes(repoKey);
  const src = (x) => SRC_LABEL[x] || x || '-';

  if (!s || s.status === 'na') {
    vbadge.textContent = '·';
    vt.textContent = t('pp_na_title');
    vs.textContent = t('pp_na_sub');
    rescanBtn.disabled = true;
  } else if (!settings.enabled || s.status === 'disabled') {
    vbadge.textContent = '✕';
    vt.textContent = t('pp_disabled_title');
    vs.textContent = t('pp_disabled_sub');
    rescanBtn.disabled = true;
  } else if (trusted || s.status === 'trusted') {
    verdictEl.classList.add('ok');
    vbadge.textContent = '✓';
    vt.textContent = t('pp_trusted_title');
    vs.textContent = repoKey || '';
    untrustBtn.hidden = false;
  } else if (s.status === 'analyzing' || s.status === 'idle') {
    vbadge.textContent = '…';
    vt.textContent = t('pp_scanning');
    vs.textContent = s.fileName || '';
  } else if (s.status === 'unreadable') {
    verdictEl.classList.add('warn');
    vbadge.textContent = '?';
    vt.textContent = s.mode === 'repo' ? t('pp_unreadable_repo_title') : t('pp_unreadable_file_title');
    vs.textContent = s.mode === 'repo' ? t('pp_unreadable_repo_sub') : t('pp_unreadable_file_sub');
    trustBtn.hidden = !repoKey;
  } else if (s.status === 'too-large') {
    verdictEl.classList.add('warn');
    vbadge.textContent = '?';
    vt.textContent = t('pp_toolarge_title');
    vs.textContent = t('pp_toolarge_sub');
    trustBtn.hidden = !repoKey;
  } else if (s.status === 'risk') {
    const { high, med } = severityCounts(s.findings);
    const caution = s.level === 'caution';
    // caution (low confidence / medium risk) -> amber; alarm -> coral
    verdictEl.classList.add(caution ? 'warn' : 'risk');
    vbadge.textContent = '⚠';
    vt.textContent = caution ? t('pp_caution_title') : t('pp_risk_title');
    vs.textContent = s.mode === 'repo'
      ? t('pp_vs_repo_counts', high, med, s.scanned || 0)
      : t('pp_vs_file_counts', high, med, src(s.source));
    trustBtn.hidden = !repoKey;
    renderFindings(s.findings, findEl, s.mode === 'repo');
    appendAiCheck(findEl, s);
  } else if (s.status === 'clean') {
    // Clean verdict: keep it minimal - just the verdict + source. No rule-count row,
    // no action buttons, no trust list (nothing actionable when nothing was found).
    verdictEl.classList.add('ok');
    vbadge.textContent = '✓';
    vt.textContent = t('pp_clean_title');
    vs.textContent = s.mode === 'repo'
      ? t('pp_clean_repo_sub', s.scanned || 0)
      : t('pp_clean_file_sub', src(s.source));
    pact.style.display = 'none';
    pallow.style.display = 'none';
  }

  renderAllowlist();
  renderToggle();
}

function renderFindings(findings, el, isRepo) {
  for (const f of findings.slice(0, 8)) {
    const row = document.createElement('div');
    row.className = 'p-row';
    const dot = document.createElement('span');
    dot.className = `sev ${f.severity}`;
    const txt = document.createElement('span');
    txt.className = 'txt';
    const title = ruleTitle(f.rule);
    // repo mode: append the source file so the user knows which entry file matched
    txt.title = (isRepo && f.file ? `${f.file} · ` : '') + (findingDetail(f) || title);
    txt.textContent = isRepo && f.file ? `${title} · ${f.file}` : title;
    row.append(dot, txt);
    if (f.evidence && /RIG-00[345]/.test(f.rule)) {
      const mono = document.createElement('span');
      mono.className = 'mono';
      mono.textContent = f.evidence.length > 22 ? f.evidence.slice(0, 22) + '…' : f.evidence;
      row.appendChild(mono);
    }
    if (f.line) {
      const ln = document.createElement('span');
      ln.className = 'ln';
      ln.textContent = `L${f.line}`;
      // repo mode: go to that file+line; file mode: jump within the current page
      if (isRepo && f.fileUrl) {
        ln.title = t('pp_goto');
        ln.addEventListener('click', () => sendToTab({ type: 'goto', url: `${f.fileUrl}#L${f.line}` }));
      } else {
        ln.title = t('pp_jump');
        ln.addEventListener('click', () => sendToTab({ type: 'reveal', line: f.line }));
      }
      row.appendChild(ln);
    } else if (isRepo && f.fileUrl) {
      const go = document.createElement('span');
      go.className = 'ln';
      go.textContent = '↗';
      go.title = t('pp_goto');
      go.addEventListener('click', () => sendToTab({ type: 'goto', url: f.fileUrl }));
      row.appendChild(go);
    }
    el.appendChild(row);
  }
  if (findings.length > 8) {
    const more = document.createElement('div');
    more.className = 'p-row muted';
    more.textContent = t('pp_more', findings.length - 8);
    el.appendChild(more);
  }
}

// Build a prompt for the user's own trusted LLM to double-check
// (copied to the clipboard only; the user pastes it - nothing is sent out).
function buildLlmPrompt(s) {
  const L = [];
  L.push(t('llm_intro'));
  L.push('');
  L.push(s.mode === 'repo' ? t('llm_repo_label', s.repoKey || '') : t('llm_file_label', s.fileName || ''));
  L.push('');
  L.push(t('llm_findings_label'));
  for (const f of (s.findings || [])) {
    let loc = '';
    if (f.file) loc = ` (${f.file}${f.line ? `:${f.line}` : ''})`;
    else if (f.line) loc = ` (L${f.line})`;
    let line = `- [${f.severity}] ${ruleTitle(f.rule)}${loc}`;
    const det = findingDetail(f);
    if (det) line += ` - ${det}`;
    if (f.evidence) line += ` \`${f.evidence}\``;
    L.push(line);
  }
  L.push('');
  L.push(t('llm_questions'));
  return L.join('\n');
}

function appendAiCheck(el, s) {
  const btn = document.createElement('button');
  btn.className = 'ai-check';
  btn.textContent = t('ui_ai_check');
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(buildLlmPrompt(s));
      btn.textContent = t('ui_ai_check_done');
      btn.classList.add('done');
    } catch {
      btn.textContent = t('ui_ai_check_fail');
    }
  });
  el.appendChild(btn);
}

function renderAllowlist() {
  const el = $('allowlist');
  el.textContent = '';
  if (!settings.allowlist.length) {
    const empty = document.createElement('div');
    empty.className = 'allow-empty';
    empty.textContent = t('pp_allow_empty');
    el.appendChild(empty);
    return;
  }
  for (const repo of settings.allowlist) {
    const row = document.createElement('div');
    row.className = 'allow-row';
    const name = document.createElement('span');
    name.className = 'repo';
    name.textContent = repo;
    name.title = repo;
    const rm = document.createElement('button');
    rm.className = 'rm';
    rm.textContent = '✕';
    rm.title = t('pp_allow_remove');
    rm.setAttribute('aria-label', `${t('pp_allow_remove')} ${repo}`);
    rm.addEventListener('click', () => removeFromAllowlist(repo));
    row.append(name, rm);
    el.appendChild(row);
  }
}

function renderToggle() {
  $('sw').className = 'sw' + (settings.enabled ? '' : ' off');
  $('toggleLabel').textContent = settings.enabled ? t('pp_enabled') : t('pp_disabled');
}

// ── Actions ────────────────────────────────────────────────────────
function saveSettings(patch) {
  Object.assign(settings, patch);
  chrome.storage.sync.set(patch);
}

function removeFromAllowlist(repo) {
  saveSettings({ allowlist: settings.allowlist.filter((r) => r !== repo) });
  refresh(600);
}

$('trustBtn').addEventListener('click', () => {
  const repoKey = pageStatus && pageStatus.repoKey;
  if (!repoKey) return;
  if (!settings.allowlist.includes(repoKey)) {
    saveSettings({ allowlist: settings.allowlist.concat(repoKey) });
  }
  refresh(300);
});

$('untrustBtn').addEventListener('click', () => {
  const repoKey = pageStatus && pageStatus.repoKey;
  if (!repoKey) return;
  removeFromAllowlist(repoKey);
});

$('rescanBtn').addEventListener('click', async () => {
  await sendToTab({ type: 'rescan' });
  pageStatus = Object.assign({}, pageStatus, { status: 'analyzing', findings: [] });
  render();
  refresh(800);
  refresh(2200);
});

$('toggleBtn').addEventListener('click', () => {
  saveSettings({ enabled: !settings.enabled });
  render();
  refresh(500);
});

// ── Startup ────────────────────────────────────────────────────────
function refresh(delay = 0) {
  setTimeout(async () => {
    pageStatus = await queryStatus();
    render();
  }, delay);
}

function applyStaticI18n() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const m = msg(el.dataset.i18n);
    if (m) el.textContent = m;
  });
}

(async function init() {
  applyStaticI18n();
  $('toggleBtn').setAttribute('aria-label', t('pp_enabled'));
  $('ver').textContent = t('pp_ver', chrome.runtime.getManifest().version);
  const data = await chrome.storage.sync.get({ enabled: true, allowlist: [] });
  settings.enabled = data.enabled !== false;
  settings.allowlist = Array.isArray(data.allowlist) ? data.allowlist : [];

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  tabId = tab ? tab.id : null;
  pageStatus = await queryStatus();
  render();
})();
