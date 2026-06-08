/**
 * Metsuke - background.js (MV3 service worker)
 * Only two responsibilities (SPEC §6): proxy the raw fetch (with cookies) and set the badge.
 * No webNavigation, no remote code.
 */
'use strict';

const MAX_FILE_BYTES = 3 * 1024 * 1024; // matches the detector.js threshold (SPEC §3)

// Named raw sources from host_permissions
const ALLOWED_HOSTS = new Set(['raw.githubusercontent.com', 'gitlab.com', 'bitbucket.org']);

const COLOR = { coral: '#DD5238', amber: '#DD901F' };

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg) return;

  if (msg.type === 'ping') { sendResponse({ ok: true }); return; } // warm-up wake

  if (msg.type === 'fetchRaw') {
    fetchRaw(msg.url).then(sendResponse);
    return true; // async response
  }

  if (msg.type === 'badge' && sender.tab && sender.tab.id != null) {
    setBadge(sender.tab.id, msg.high | 0, msg.med | 0, msg.level || null);
  }
});

async function fetchRaw(url) {
  let u;
  try { u = new URL(url); } catch { return { ok: false, reason: 'bad-url' }; }
  if (u.protocol !== 'https:' || !ALLOWED_HOSTS.has(u.hostname)) {
    return { ok: false, reason: 'host-not-allowed' };
  }
  try {
    const res = await fetch(u.href, { credentials: 'include', redirect: 'follow', cache: 'no-cache' });
    if (!res.ok) return { ok: false, status: res.status };

    const len = Number(res.headers.get('content-length') || 0);
    if (len > MAX_FILE_BYTES) return { ok: false, reason: 'too-large' };

    // A raw endpoint should not return HTML; HTML means a login/directory page -> treat as failure to avoid mis-analysis (SPEC §4)
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    if (ct.includes('text/html')) return { ok: false, reason: 'not-a-file' };

    const text = await res.text();
    if (text.length > MAX_FILE_BYTES) return { ok: false, reason: 'too-large' };
    return { ok: true, text };
  } catch (e) {
    return { ok: false, reason: String((e && e.message) || e) };
  }
}

// Badge: colored by the assessed level - alarm (high confidence) -> red "!"; caution (low confidence / medium risk) -> amber "!";
// with no level, fall back to the old rule (high -> red, med -> yellow count); none -> clear (SPEC §5)
function setBadge(tabId, high, med, level) {
  let text = '';
  let color = null;
  if (level === 'alarm') { text = '!'; color = COLOR.coral; }
  else if (level === 'caution') { text = '!'; color = COLOR.amber; }
  else if (high > 0) { text = '!'; color = COLOR.coral; }
  else if (med > 0) { text = String(Math.min(med, 99)); color = COLOR.amber; }

  chrome.action.setBadgeText({ tabId, text });
  if (color) {
    chrome.action.setBadgeBackgroundColor({ tabId, color });
    if (chrome.action.setBadgeTextColor) chrome.action.setBadgeTextColor({ tabId, color: '#FFFFFF' });
  }
}
