/**
 * Metsuke - content.js
 * URL parsing, text fetch (raw → GitHub embedded JSON), idle analysis,
 * Shadow DOM banner, reveal, and self-managed SPA navigation (SPEC §4-§6).
 *
 * Two modes:
 *  - file: real-time analysis of single-file view pages (/blob, /-/blob, /src) (SPEC v1 main path).
 *  - repo: repo home / tree pages, targeted scan of known high-value entry files (v1.1, SPEC §10 change control).
 *    See SCAN_TARGETS for the scan list; no full-tree scan (SPEC §2.2 remains a non-goal).
 *
 * Text fetch failure → silently skip analysis; must not produce false positives (SPEC §4).
 */
(() => {
  'use strict';
  if (window.__metsukeLoaded) return;
  window.__metsukeLoaded = true;

  const detector = globalThis.Metsuke && globalThis.Metsuke.detector;
  if (!detector) return;

  const MAX_FILE_BYTES = detector.THRESHOLDS.MAX_FILE_BYTES;

  // i18n (chrome.i18n picks _locales by browser language; defaults to en, also supports zh_TW / ja)
  const msg = (k, subs) => {
    try { return chrome.i18n.getMessage(k, subs) || ''; } catch { return ''; }
  };
  const t = (k, ...subs) => msg(k, subs.length ? subs.map(String) : undefined) || k;
  const ruleTitle = (rule) =>
    msg('rule_' + rule.replace(/-/g, '_') + '_title') ||
    (detector.RULES[rule] && detector.RULES[rule].title) || rule;
  const findingDetail = (f) =>
    f.detailKey ? msg(f.detailKey, (f.detailParams || []).map(String)) : '';

  // Targeted scan list for repo home pages: "run-on-open / run-on-install" entry files that
  // recur across past campaign reports. Only these requests per repo home page; 404/non-file → silently skip.
  //
  // Staged for time-to-first-signal (SPEC §4): SCAN_HOT is the high-prevalence, high-signal set
  // (run-on-open/install configs + PolinRider's primary injection targets) and is fetched first so a
  // preliminary verdict shows fast; SCAN_TAIL (lower-prevalence entry points, .env-class, secondary
  // config variants) is fetched in a second phase and can upgrade the verdict afterwards.
  const SCAN_HOT = [
    'package.json',
    '.vscode/tasks.json',
    '.vscode/settings.json',
    '.claude/settings.json',
    '.claude/settings.local.json',
    '.gemini/settings.json',       // 2026 "Miasma" worm: SessionStart hook
    '.gemini/settings.local.json',
    '.cursorrules',
    '.cursor/rules/setup.mdc',     // 2026 "Miasma" worm: alwaysApply prompt injection
    '.github/copilot-instructions.md',
    'CLAUDE.md',
    'AGENTS.md',
    'GEMINI.md',
    '.husky/pre-commit',           // 2026 Lazarus new hiding spot (git hooks)
    '.husky/post-checkout',
    '.husky/post-merge',
    'tailwind.config.js',          // PolinRider primary injection targets (~62% of infections)
    'postcss.config.mjs',
    'eslint.config.mjs',
  ];
  const SCAN_TAIL = [
    // Backend entry points: family-A stage-1 loaders hide in conventional server files
    // with no folderOpen vector, so a repo-home scan that only reads config files misses them.
    'index.js',
    'app.js',
    'server.js',
    'src/index.js',
    'server/index.js',
    'server/server.js',
    // .env-class files: dead-drop URLs are stored base64-encoded here (#2/#3 server/config/config.env).
    // .env.example is intentionally excluded (placeholders, not decodable endpoints).
    '.env',
    'config.env',
    'server/config/config.env',
    // Secondary PolinRider config variants.
    'postcss.config.js',
    'tailwind.config.ts',
    'eslint.config.js',
    'next.config.mjs',
    'next.config.js',
    'vite.config.js',
    'vite.config.ts',
    'webpack.config.js',
  ];
  const SCAN_TARGETS = SCAN_HOT.concat(SCAN_TAIL);

  // ── State ────────────────────────────────────────────────────────
  let settings = { enabled: true, allowlist: [] };
  let currentPage = null;        // result of parsePage()
  let verdict = { status: 'idle', mode: 'file', findings: [], source: null };
  let navEpoch = 0;              // navigation generation; discard stale analysis results
  let lastFetch = null;          // single-file text cache { href, text, source }
  const dismissed = new Set();   // hrefs where the user has dismissed the banner

  // ── URL parsing ──────────────────────────────────────────────────
  // Single-file view page
  function parseFile(loc) {
    const host = loc.hostname;
    const path = loc.pathname;
    let m;
    if (host === 'github.com') {
      m = path.match(/^\/([^/]+)\/([^/]+)\/blob\/(.+)$/);
      if (m) return {
        kind: 'file', platform: 'github',
        repoKey: `github.com/${m[1]}/${m[2]}`,
        rawUrl: `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}`,
        filePath: m[3], fileName: decodeURIComponent(m[3].split('/').pop() || ''),
      };
    } else if (host === 'gitlab.com') {
      m = path.match(/^\/(.+?)\/-\/blob\/(.+)$/);
      if (m) return {
        kind: 'file', platform: 'gitlab',
        repoKey: `gitlab.com/${m[1]}`,
        rawUrl: `https://gitlab.com/${m[1]}/-/raw/${m[2]}`,
        filePath: m[2], fileName: decodeURIComponent(m[2].split('/').pop() || ''),
      };
    } else if (host === 'bitbucket.org') {
      m = path.match(/^\/([^/]+)\/([^/]+)\/src\/(.+[^/])$/);
      if (m) return {
        kind: 'file', platform: 'bitbucket',
        repoKey: `bitbucket.org/${m[1]}/${m[2]}`,
        rawUrl: `https://bitbucket.org/${m[1]}/${m[2]}/raw/${m[3]}`,
        filePath: m[3], fileName: decodeURIComponent(m[3].split('/').pop() || ''),
      };
    }
    return null;
  }

  // repo home / tree page (returns the base and ref needed to build raw / blob URLs)
  const RESERVED_GH = new Set([
    'features', 'topics', 'collections', 'trending', 'marketplace', 'sponsors',
    'settings', 'notifications', 'explore', 'about', 'pricing', 'orgs', 'apps',
    'login', 'logout', 'join', 'new', 'search', 'pulls', 'issues', 'codespaces',
  ]);

  function parseRepo(loc) {
    const host = loc.hostname;
    const path = loc.pathname.replace(/\/+$/, '');
    let m;
    if (host === 'github.com') {
      // /owner/repo  or  /owner/repo/tree/<ref>[/subdir]
      m = path.match(/^\/([^/]+)\/([^/]+)(?:\/tree\/([^/]+)(?:\/.*)?)?$/);
      if (m && !RESERVED_GH.has(m[1].toLowerCase())) {
        const ref = m[3] || 'HEAD';
        return {
          kind: 'repo', platform: 'github',
          repoKey: `github.com/${m[1]}/${m[2]}`, ref,
          rawBase: `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${ref}/`,
          blobBase: `https://github.com/${m[1]}/${m[2]}/blob/${ref}/`,
        };
      }
    } else if (host === 'bitbucket.org') {
      m = path.match(/^\/([^/]+)\/([^/]+)(?:\/src\/([^/]+)(?:\/.*)?)?$/);
      if (m) {
        const ref = m[3] || 'HEAD';
        return {
          kind: 'repo', platform: 'bitbucket',
          repoKey: `bitbucket.org/${m[1]}/${m[2]}`, ref,
          rawBase: `https://bitbucket.org/${m[1]}/${m[2]}/raw/${ref}/`,
          blobBase: `https://bitbucket.org/${m[1]}/${m[2]}/src/${ref}/`,
        };
      }
    } else if (host === 'gitlab.com') {
      // GitLab project paths can contain subgroups, hard to reliably infer from the home page; only handle the /-/tree/<ref> form
      m = path.match(/^\/(.+?)\/-\/tree\/([^/]+)(?:\/.*)?$/);
      if (m) {
        const ref = m[2];
        return {
          kind: 'repo', platform: 'gitlab',
          repoKey: `gitlab.com/${m[1]}`, ref,
          rawBase: `https://gitlab.com/${m[1]}/-/raw/${ref}/`,
          blobBase: `https://gitlab.com/${m[1]}/-/blob/${ref}/`,
        };
      }
    }
    return null;
  }

  function parsePage(loc) {
    return parseFile(loc) || parseRepo(loc);
  }

  const isAllowlisted = (key) => !!key && settings.allowlist.includes(key);

  // ── SW communication ─────────────────────────────────────────────
  function sendMessage(msg) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (res) => {
          void chrome.runtime.lastError;
          resolve(res || null);
        });
      } catch { resolve(null); }
    });
  }

  function readGithubEmbedded() {
    try {
      const el =
        document.querySelector('react-app[app-name="react-code-view"] script[data-target="react-app.embeddedData"]') ||
        document.querySelector('script[data-target="react-app.embeddedData"]');
      if (!el) return null;
      const data = JSON.parse(el.textContent);
      const blob = data && data.payload && data.payload.blob;
      if (blob && Array.isArray(blob.rawLines)) return blob.rawLines.join('\n');
    } catch { /* structure changed → treat as failure */ }
    return null;
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // CPU-bound analysis yields for one idle slot (large files don't block page rendering), but waits at most 800ms.
  // Network requests do NOT go here - the caller fires them immediately to avoid being stuck behind idle (previously up to 4s).
  function idleAnalyze(text, ctx) {
    return new Promise((resolve) => {
      const work = () => resolve(detector.analyze(text, ctx));
      if ('requestIdleCallback' in window) requestIdleCallback(work, { timeout: 800 });
      else setTimeout(work, 0);
    });
  }

  // Retry reading GitHub embedded JSON (data may arrive late after SPA navigation; private fallback when raw fails)
  async function readEmbeddedRetry(epoch, tries) {
    for (let i = 0; i < tries; i++) {
      const text = readGithubEmbedded();
      if (text != null) return text;
      await sleep(500);
      if (epoch !== navEpoch) return null;
    }
    return null;
  }

  // ── badge ────────────────────────────────────────────────────────
  function reportBadge() {
    const high = verdict.findings.filter((f) => f.severity === 'high').length;
    const med = verdict.findings.filter((f) => f.severity === 'med').length;
    sendMessage({ type: 'badge', high, med, level: verdict.level || null });
  }

  // ── Single-file analysis: instant preliminary verdict from embedded + raw race correction ──
  // SPEC §4 adjustment: embedded is local and instant → show a preliminary verdict first; once raw arrives, use it as the "final basis" to override.
  async function runFileAnalysis(page, epoch) {
    verdict = { status: 'analyzing', mode: 'file', findings: [], source: null };
    const ctx = { fileName: page.fileName, path: page.filePath };
    let finalized = false; // raw has produced the final verdict
    let shownAlarm = false; // whether an "alarm" banner has already been shown (for escalation re-pop)

    const applyResult = (result, source, scanning) => {
      if (epoch !== navEpoch) return;
      if (result.skipped === 'too-large') {
        verdict = { status: 'too-large', mode: 'file', findings: [], source, scanning: false };
      } else {
        verdict = {
          status: result.findings.length ? 'risk' : 'clean',
          mode: 'file', findings: result.findings, source, scanning: !!scanning,
          level: result.findings.length ? detector.assess(result.findings).level : 'none',
        };
      }
      reportBadge();
      if (verdict.status === 'risk') {
        // Escalation to alarm (e.g. the deep raw pass upgrades a fast preliminary) re-pops once,
        // overriding a prior dismiss; lesser updates respect the dismiss.
        if (verdict.level === 'alarm' && !shownAlarm) dismissed.delete(location.href);
        if (!dismissed.has(location.href)) {
          showBanner(page);
          if (verdict.level === 'alarm') shownAlarm = true;
        } else {
          removeBanner();
        }
      } else {
        removeBanner(); // retract the banner if a preliminary verdict was shown but the final correction is clean
      }
    };

    // Re-evaluation of the same page → analyze directly from cache, no refetch
    if (lastFetch && lastFetch.href === location.href && typeof lastFetch.text === 'string') {
      const r = await idleAnalyze(lastFetch.text, ctx);
      applyResult(r, lastFetch.source);
      return;
    }

    // Path 2 (network, final basis) is fired immediately so it truly runs in parallel with the embedded preliminary verdict below.
    const rawPromise = sendMessage({ type: 'fetchRaw', url: page.rawUrl });

    // Path 1 (local, instant): GitHub embedded JSON → early preliminary verdict, shown before the user clicks clone.
    // raw is already running in the background, so the embedded analysis won't delay it.
    if (page.platform === 'github') {
      const early = readGithubEmbedded();
      if (early != null && early.length <= MAX_FILE_BYTES) {
        // Fast tier for the instant preliminary verdict; the raw pass below runs the full (deep) analysis.
        const r = await idleAnalyze(early, Object.assign({ tier: 'fast' }, ctx));
        if (epoch !== navEpoch) return;
        // raw still running in the background → mark as re-checking, banner shows loading
        if (!finalized) applyResult(r, 'embedded', true);
      }
    }

    // Wait for raw, then override the preliminary verdict using it as the final basis
    const res = await rawPromise;
    if (epoch !== navEpoch) return;

    if (res && res.ok && typeof res.text === 'string') {
      lastFetch = { href: location.href, text: res.text, source: 'raw' };
      const r = await idleAnalyze(res.text, ctx);
      if (epoch !== navEpoch) return;
      finalized = true;
      applyResult(r, 'raw');
      return;
    }
    if (res && res.reason === 'too-large') {
      finalized = true;
      verdict = { status: 'too-large', mode: 'file', findings: [], source: 'raw' };
      reportBadge();
      removeBanner();
      return;
    }

    // raw failed → fall back to embedded (with retries; private GitHub fallback)
    if (page.platform === 'github') {
      const text = await readEmbeddedRetry(epoch, 4);
      if (epoch !== navEpoch) return;
      if (text != null && text.length <= MAX_FILE_BYTES) {
        lastFetch = { href: location.href, text, source: 'embedded' };
        const r = await idleAnalyze(text, ctx);
        if (epoch !== navEpoch) return;
        finalized = true;
        applyResult(r, 'embedded');
        return;
      }
    }

    // Both paths failed → stay silent (if no preliminary verdict was produced earlier)
    if (!finalized && verdict.status === 'analyzing') {
      verdict = { status: 'unreadable', mode: 'file', findings: [], source: null };
      reportBadge();
    }
  }

  // ── repo home targeted scan (two-phase streaming) ──────────────────────────
  // Phase 1 fetches SCAN_HOT (high-signal entry files) so a preliminary verdict shows fast; phase 2
  // fetches SCAN_TAIL and can upgrade it. Each file is analyzed as soon as it returns; the banner pops
  // on the first hit, and re-pops once if the combined level escalates to "alarm" (even after dismiss).
  async function runRepoScan(page, epoch) {
    verdict = { status: 'analyzing', mode: 'repo', findings: [], source: 'raw',
      scanned: 0, scanning: true, pending: SCAN_TARGETS.length };
    let scanned = 0;
    let pending = SCAN_TARGETS.length;
    let shownAlarm = false; // whether an "alarm" banner has already been shown (for escalation re-pop)

    const handle = async (rel, res) => {
      pending--;
      if (epoch !== navEpoch) return;
      verdict.pending = pending;
      if (!(res && res.ok && typeof res.text === 'string' && res.text.length <= MAX_FILE_BYTES)) return;
      scanned++;
      const fileName = rel.split('/').pop();
      const r = await idleAnalyze(res.text, { fileName, path: rel });
      if (epoch !== navEpoch) return;
      verdict.scanned = scanned;
      verdict.pending = pending;
      if (!r.findings.length) return;
      for (const f of r.findings) {
        verdict.findings.push(Object.assign({}, f, { file: rel, fileUrl: page.blobBase + rel }));
      }
      verdict.status = 'risk';
      verdict.scanning = pending > 0;
      // Combine signals across entry files, then decide the banner level.
      verdict.level = detector.assess(verdict.findings).level;
      reportBadge();
      // Escalation to alarm re-pops once, overriding a prior dismiss; lesser updates respect dismiss.
      if (verdict.level === 'alarm' && !shownAlarm) dismissed.delete(location.href);
      if (!dismissed.has(location.href)) {
        showBanner(page);
        if (verdict.level === 'alarm') shownAlarm = true;
      }
    };

    const scanBatch = (targets) => Promise.all(targets.map((rel) =>
      sendMessage({ type: 'fetchRaw', url: page.rawBase + rel }).then((res) => handle(rel, res))));

    // Phase 1 (hot) → preliminary; phase 2 (tail) → upgrade.
    await scanBatch(SCAN_HOT);
    if (epoch !== navEpoch) return;
    await scanBatch(SCAN_TAIL);
    if (epoch !== navEpoch) return;

    // Finalize.
    verdict.scanned = scanned;
    verdict.scanning = false;
    if (verdict.status === 'risk') {
      if (!dismissed.has(location.href)) showBanner(page); // redraw once to drop the loading spinner
    } else {
      verdict.status = scanned === 0 ? 'unreadable' : 'clean';
      reportBadge();
    }
  }

  // ── Dispatch ─────────────────────────────────────────────────────
  function evaluate() {
    navEpoch++;
    const epoch = navEpoch;
    removeBanner();
    currentPage = parsePage(location);
    verdict = { status: 'idle', mode: currentPage ? currentPage.kind : 'file', findings: [], source: null };

    if (!currentPage) { verdict.status = 'na'; reportBadge(); return; }
    if (!settings.enabled) { verdict.status = 'disabled'; reportBadge(); return; }
    if (isAllowlisted(currentPage.repoKey)) { verdict.status = 'trusted'; reportBadge(); return; }

    verdict.status = 'analyzing';
    reportBadge();
    // Start immediately: network requests are no longer stuck behind idle; CPU analysis yields via idleAnalyze inside each function.
    if (currentPage.kind === 'repo') runRepoScan(currentPage, epoch);
    else runFileAnalysis(currentPage, epoch);
  }

  // ── Banner (Shadow DOM, dismissible; SPEC §5) ────────────────────
  let bannerHost = null;

  const LOGO_SVG = `
    <svg viewBox="0 0 128 128" aria-hidden="true">
      <circle cx="64" cy="64" r="63" fill="#FAF5EC"/>
      <circle cx="64" cy="64" r="58" fill="none" stroke="#23252E" stroke-width="4"/>
      <g fill="none" stroke="#23252E">
        <g stroke-width="5">
          <rect x="29.5" y="29.5" width="29" height="29" rx="1.5" transform="rotate(45 44 44)"/>
          <rect x="69.5" y="29.5" width="29" height="29" rx="1.5" transform="rotate(45 84 44)"/>
          <rect x="29.5" y="69.5" width="29" height="29" rx="1.5" transform="rotate(45 44 84)"/>
        </g>
        <g stroke-width="3">
          <rect x="37.5" y="37.5" width="13" height="13" rx="1"/>
          <rect x="77.5" y="37.5" width="13" height="13" rx="1"/>
          <rect x="37.5" y="77.5" width="13" height="13" rx="1"/>
        </g>
      </g>
      <g fill="none" stroke="#DD5238">
        <rect x="69.5" y="69.5" width="29" height="29" rx="1.5" transform="rotate(45 84 84)" stroke-width="5"/>
        <rect x="77.5" y="77.5" width="13" height="13" rx="1" stroke-width="3"/>
      </g>
    </svg>`;

  const BANNER_CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    .wrap {
      position: fixed; top: 14px; left: 50%; transform: translateX(-50%);
      z-index: 2147483646; width: min(720px, calc(100vw - 28px));
      font-family: 'Hanken Grotesk', -apple-system, system-ui, sans-serif;
      color: #23252E; -webkit-font-smoothing: antialiased;
    }
    .wrap.small { width: min(440px, calc(100vw - 28px)); } /* low confidence → smaller amber box */
    .banner {
      border-radius: 13px; background: #FFFDF8;
      /* full coral-red border + 12% transparent same-color ring (design.md-approved focus-ring style, not neon/glow) */
      border: 2px solid #DD5238;
      box-shadow: 0 0 0 3px rgba(221,82,56,.12),
        0 16px 40px -22px rgba(74,54,28,.45), 0 2px 6px -3px rgba(74,54,28,.18);
      overflow: hidden;
    }
    /* caution (low confidence / medium risk only): smaller, amber border, restrained tone */
    .banner.caution {
      border-color: #DD901F;
      box-shadow: 0 0 0 3px rgba(221,144,31,.12),
        0 16px 40px -22px rgba(74,54,28,.45), 0 2px 6px -3px rgba(74,54,28,.18);
    }
    .banner.caution .body { padding: 12px 14px; }
    .banner.caution .head { font-size: 13.5px; }
    .accent { height: 4px; background: #DD5238; }
    .banner.caution .accent { height: 3px; background: #DD901F; }
    .scanning { margin-top: 11px; display: flex; align-items: center; gap: 8px;
      font-size: 12.5px; color: #8E909B; }
    .spinner { width: 13px; height: 13px; border-radius: 50%; flex: none;
      border: 2px solid #F3D9D1; border-top-color: #DD5238;
      animation: mtk-spin .7s linear infinite; }
    @keyframes mtk-spin { to { transform: rotate(360deg); } }
    .body { padding: 15px 17px; }
    .top { display: flex; align-items: center; gap: 12px; }
    .logo { flex: none; width: 32px; height: 32px; }
    .logo svg { width: 100%; height: 100%; display: block; }
    .title { display: flex; flex-direction: column; gap: 2px; flex: 1; min-width: 0; }
    .row1 { display: flex; align-items: center; gap: 9px; }
    .nm { font-family: Georgia, 'Noto Serif TC', serif; font-weight: 600; font-size: 15px; }
    .chip { font-size: 11.5px; font-weight: 600; padding: 3px 9px; border-radius: 999px;
      background: #FBEAE4; color: #8C2C19; }
    .chip.med { background: #FAF0DC; color: #7C4C08; }
    .head { font-size: 15px; font-weight: 600; margin-top: 1px; }
    .actions { display: flex; align-items: center; gap: 8px; flex: none; }
    .btn { font: 600 13px/1 inherit; font-family: inherit; border-radius: 999px; cursor: pointer;
      padding: 8px 15px; border: 1px solid #E0D5BF; background: #FFFFFF; color: #5E6170;
      transition: background .15s; }
    .btn:hover { background: #FAF5EC; }
    .btn:focus-visible { outline: none; box-shadow: 0 0 0 3px rgba(19,102,224,.12); }
    .btn.ghost { border-color: transparent; background: transparent; padding: 8px 10px; color: #8E909B; }
    .findings { margin-top: 13px; border-top: 1px solid #ECE3D2; padding-top: 11px;
      display: flex; flex-direction: column; gap: 9px; }
    .find { display: flex; align-items: flex-start; gap: 11px; font-size: 13.5px; }
    .sev { flex: none; margin-top: 5px; width: 8px; height: 8px; border-radius: 50%; }
    .sev.high { background: #DD5238; } .sev.med { background: #DD901F; }
    .find b { font-weight: 600; } .find span.d { color: #5E6170; }
    .find .file { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12px;
      color: #1366E0; cursor: pointer; }
    .find .file:hover { text-decoration: underline; }
    .mono { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px;
      background: #FBEAE4; color: #8C2C19; padding: 1px 6px; border-radius: 6px; }
    .more { font-size: 12.5px; color: #8E909B; }
    .reveal { margin-top: 11px; font-size: 13px; font-weight: 600; color: #1366E0;
      display: inline-flex; align-items: center; gap: 6px; cursor: pointer; background: none;
      border: none; font-family: inherit; padding: 0; }
    .reveal:hover { text-decoration: underline; }
    .actions-row { margin-top: 11px; display: flex; flex-wrap: wrap; gap: 14px; align-items: center; }
    .ai-check { font-size: 12.5px; font-weight: 600; color: #1366E0; cursor: pointer;
      background: none; border: none; font-family: inherit; padding: 0;
      display: inline-flex; align-items: center; gap: 6px; }
    .ai-check:hover { text-decoration: underline; }
    .ai-check.done { color: #1C9C68; cursor: default; }
  `;

  function removeBanner() {
    if (bannerHost) { bannerHost.remove(); bannerHost = null; }
  }

  function showBanner(page) {
    removeBanner();
    const isRepo = verdict.mode === 'repo';
    const high = verdict.findings.filter((f) => f.severity === 'high').length;
    const med = verdict.findings.filter((f) => f.severity === 'med').length;
    // Combined rule assessment decides the presentation: alarm = large red box, caution = small amber box (less intrusive when reducing false positives)
    const level = verdict.level || 'alarm';
    const isCaution = level === 'caution';

    bannerHost = document.createElement('div');
    bannerHost.id = 'metsuke-banner-host';
    const root = bannerHost.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = BANNER_CSS;
    root.appendChild(style);

    const wrap = document.createElement('div');
    wrap.className = 'wrap' + (isCaution ? ' small' : '');
    const banner = document.createElement('div');
    banner.className = 'banner' + (isCaution ? ' caution' : '');
    banner.setAttribute('role', 'alert');

    const accent = document.createElement('div');
    accent.className = 'accent';
    banner.appendChild(accent);

    const body = document.createElement('div');
    body.className = 'body';

    const top = document.createElement('div');
    top.className = 'top';
    const logo = document.createElement('span');
    logo.className = 'logo';
    logo.innerHTML = LOGO_SVG;
    top.appendChild(logo);

    const title = document.createElement('div');
    title.className = 'title';
    const row1 = document.createElement('div');
    row1.className = 'row1';
    const nm = document.createElement('span');
    nm.className = 'nm';
    nm.textContent = t('brand');
    const chip = document.createElement('span');
    chip.className = 'chip' + (isCaution ? ' med' : '');
    if (isCaution) chip.textContent = high > 0 ? t('ui_chip_possible') : t('ui_chip_med_only', med);
    else if (high > 0) chip.textContent = med > 0 ? t('ui_chip_counts', high, med) : t('ui_chip_high_only', high);
    else chip.textContent = t('ui_chip_med_only', med);
    row1.append(nm, chip);
    const head = document.createElement('div');
    head.className = 'head';
    head.textContent = isCaution ? t('ui_head_caution')
      : (isRepo ? t('ui_head_alarm_repo') : t('ui_head_alarm_file'));
    title.append(row1, head);
    top.appendChild(title);

    const actions = document.createElement('div');
    actions.className = 'actions';
    const trustBtn = document.createElement('button');
    trustBtn.className = 'btn';
    trustBtn.textContent = t('ui_btn_trust');
    trustBtn.addEventListener('click', () => trustRepo(page.repoKey));
    const closeBtn = document.createElement('button');
    closeBtn.className = 'btn ghost';
    closeBtn.setAttribute('aria-label', t('ui_btn_close'));
    closeBtn.textContent = '✕';
    closeBtn.addEventListener('click', () => { dismissed.add(location.href); removeBanner(); });
    actions.append(trustBtn, closeBtn);
    top.appendChild(actions);
    body.appendChild(top);

    const list = document.createElement('div');
    list.className = 'findings';
    const SHOW = 6;
    for (const f of verdict.findings.slice(0, SHOW)) {
      const row = document.createElement('div');
      row.className = 'find';
      const dot = document.createElement('span');
      dot.className = `sev ${f.severity}`;
      const tw = document.createElement('span');
      const b = document.createElement('b');
      b.textContent = ruleTitle(f.rule);
      tw.appendChild(b);
      const det = findingDetail(f);
      if (det) {
        const d = document.createElement('span');
        d.className = 'd';
        d.textContent = ` · ${det}`;
        tw.appendChild(d);
      }
      if (f.evidence && /RIG-00[345]/.test(f.rule)) {
        const mono = document.createElement('span');
        mono.className = 'mono';
        mono.textContent = f.evidence;
        tw.append(' ', mono);
      }
      // repo mode: annotate the source file and make it clickable to navigate
      if (isRepo && f.file) {
        const fileLink = document.createElement('span');
        fileLink.className = 'file';
        fileLink.textContent = ` · ${f.file}${f.line ? `:${f.line}` : ''}`;
        fileLink.title = t('pp_goto');
        fileLink.addEventListener('click', () => {
          location.href = f.line ? `${f.fileUrl}#L${f.line}` : f.fileUrl;
        });
        tw.appendChild(fileLink);
      }
      row.append(dot, tw);
      list.appendChild(row);
    }
    if (verdict.findings.length > SHOW) {
      const more = document.createElement('div');
      more.className = 'more';
      more.textContent = t('ui_more', verdict.findings.length - SHOW);
      list.appendChild(more);
    }
    body.appendChild(list);

    // Not all checks done yet → show loading (spinner + text); redraw to remove it once the scan finishes
    if (verdict.scanning) {
      const sc = document.createElement('div');
      sc.className = 'scanning';
      const sp = document.createElement('span');
      sp.className = 'spinner';
      const tx = document.createElement('span');
      tx.textContent = isRepo
        ? t('ui_scanning_repo', verdict.pending || 0)
        : t('ui_scanning_file');
      sc.append(sp, tx);
      body.appendChild(sc);
    }

    // Action row: reveal (single file) + copy for AI confirmation (especially useful for low-confidence caution)
    const actionsRow = document.createElement('div');
    actionsRow.className = 'actions-row';

    if (!isRepo) {
      const lined = verdict.findings.find((f) => f.line);
      if (lined) {
        const hiddenRule = /RIG-00[12]|RIG-014/.test(lined.rule);
        const reveal = document.createElement('button');
        reveal.className = 'reveal';
        reveal.textContent = hiddenRule
          ? t('ui_reveal_hidden', lined.line)
          : t('ui_reveal_jump', lined.line);
        reveal.addEventListener('click', () => revealLine(lined.line, hiddenRule));
        actionsRow.appendChild(reveal);
      }
    }

    // Copy a summary of the signals for a second opinion from an LLM tool the user trusts (clipboard only, not sent anywhere)
    const aiBtn = document.createElement('button');
    aiBtn.className = 'ai-check';
    aiBtn.textContent = t('ui_ai_check');
    aiBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(buildLlmPrompt(page));
        aiBtn.textContent = t('ui_ai_check_done');
        aiBtn.classList.add('done');
      } catch {
        aiBtn.textContent = t('ui_ai_check_fail');
      }
    });
    actionsRow.appendChild(aiBtn);
    body.appendChild(actionsRow);

    banner.appendChild(body);
    wrap.appendChild(banner);
    root.appendChild(wrap);
    (document.body || document.documentElement).appendChild(bannerHost);
  }

  // ── reveal: jump to line + horizontal scroll (single-file mode only) ──
  function findLineElement(n) {
    return (
      document.querySelector(`#LC${n}`) ||
      document.querySelector(`[data-line-number="${n}"]`) ||
      document.querySelector(`#L${n}`)
    );
  }

  function revealLine(n, scrollRight) {
    const el = findLineElement(n);
    if (!el) return;
    el.scrollIntoView({ block: 'center', behavior: 'smooth' });
    if (scrollRight) {
      let p = el;
      while (p && p !== document.body) {
        if (p.scrollWidth > p.clientWidth + 10) {
          p.scrollTo({ left: p.scrollWidth, behavior: 'smooth' });
          break;
        }
        p = p.parentElement;
      }
    }
    const target = el.closest('[role="row"]') || el;
    const prev = target.style.outline;
    target.style.outline = '2px solid #DD5238';
    target.style.outlineOffset = '-1px';
    setTimeout(() => { target.style.outline = prev; }, 2500);
  }

  // ── Assemble the prompt for an LLM second opinion (clipboard only, not sent anywhere) ──
  function buildLlmPrompt(page) {
    const L = [];
    L.push(t('llm_intro'));
    L.push('');
    L.push(page.kind === 'repo'
      ? t('llm_repo_label', page.repoKey)
      : t('llm_file_label', page.filePath || page.fileName || ''));
    L.push('');
    L.push(t('llm_findings_label'));
    for (const f of verdict.findings) {
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

  // ── allowlist / settings ─────────────────────────────────────────
  function trustRepo(repoKey) {
    if (!repoKey) return;
    chrome.storage.sync.get({ allowlist: [] }, (data) => {
      const list = Array.isArray(data.allowlist) ? data.allowlist : [];
      if (!list.includes(repoKey)) list.push(repoKey);
      chrome.storage.sync.set({ allowlist: list });
    });
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'sync') return;
    if (changes.enabled) settings.enabled = changes.enabled.newValue !== false;
    if (changes.allowlist) settings.allowlist = Array.isArray(changes.allowlist.newValue) ? changes.allowlist.newValue : [];
    evaluate();
  });

  // ── popup messages ───────────────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg) return;
    if (msg.type === 'getStatus') {
      sendResponse({
        status: verdict.status,
        mode: verdict.mode,
        level: verdict.level || null,
        findings: verdict.findings,
        source: verdict.source,
        scanned: verdict.scanned,
        repoKey: currentPage ? currentPage.repoKey : null,
        fileName: currentPage ? currentPage.fileName : null,
        ruleCount: detector.enabledCount,
        enabled: settings.enabled,
      });
    } else if (msg.type === 'rescan') {
      lastFetch = null;
      dismissed.delete(location.href);
      evaluate();
      sendResponse({ ok: true });
    } else if (msg.type === 'reveal' && msg.line) {
      revealLine(msg.line, true);
      sendResponse({ ok: true });
    } else if (msg.type === 'goto' && msg.url) {
      location.href = msg.url;
      sendResponse({ ok: true });
    }
  });

  // ── SPA navigation detection (SPEC §6) ───────────────────────────
  let lastHref = location.href;
  function checkNav() {
    if (location.href !== lastHref) {
      lastHref = location.href;
      lastFetch = null;
      evaluate();
    }
  }
  setInterval(checkNav, 800);
  window.addEventListener('popstate', () => setTimeout(checkNav, 50));
  for (const ev of ['turbo:load', 'turbo:render', 'pjax:end', 'soft-nav:end']) {
    document.addEventListener(ev, () => setTimeout(checkNav, 50));
  }

  // ── Startup ──────────────────────────────────────────────────────
  // Warm-up: wake the MV3 service worker first to reduce cold-start latency on the first raw fetch.
  sendMessage({ type: 'ping' });
  chrome.storage.sync.get({ enabled: true, allowlist: [] }, (data) => {
    settings.enabled = data.enabled !== false;
    settings.allowlist = Array.isArray(data.allowlist) ? data.allowlist : [];
    evaluate();
  });
})();
