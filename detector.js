/**
 * Metsuke - detector.js
 * Pure detection engine: no DOM, no network (SPEC §6).
 * All rules (RIG-001 ~ RIG-014) and threshold constants are locked here;
 * any change to a threshold constant must include before/after test results (SPEC §3 / §10).
 *
 * For rule provenance see docs/SPEC.md appendix A.
 */
(function () {
  'use strict';

  // ── Threshold constants (locked; SPEC §3) ──────────────────────────
  const THRESHOLDS = Object.freeze({
    VISIBLE_COL: 160,                 // right-edge column visible in a normal view
    LONG_LINE: 300,                   // treated as an abnormally long line
    WS_GAP: 50,                       // a run of whitespace treated as "push off-screen" padding
    MIN_PRINTABLE: 0.2,               // if the decoded printable ratio is below this → treat as binary noise and discard
    ENTROPY_MIN: 4.6,                 // RIG-014 high-entropy threshold
    MAX_FILE_BYTES: 3 * 1024 * 1024,  // file size cap 3MB
  });

  const MAX_PER_RULE = 5;     // max findings reported per single rule
  const MAX_FINDINGS = 30;    // overall findings cap

  // Enabled rule set; experimental rules are off by default, promoting to enabled must follow §10.
  const ENABLED = new Set([
    'RIG-001', 'RIG-002', 'RIG-003', 'RIG-004', 'RIG-005', 'RIG-006',
    'RIG-007', 'RIG-008', 'RIG-009', 'RIG-010', 'RIG-011',
    'RIG-013', 'RIG-016', 'RIG-017', 'RIG-018', 'RIG-019', 'RIG-020',
  ]);

  // Each rule: sev = risk severity; conf = confidence of a standalone hit (inverse of
  // false-positive likelihood, low = prone to false positives);
  // family = grouping used by the "combination rule" logic. title is the English fallback;
  // the UI overrides it via the i18n key `rule_RIG_xxx_title` (_locales/). See docs/rules.md.
  const RULES = Object.freeze({
    'RIG-001': { sev: 'high', conf: 'med',  family: 'hidden',  title: 'Off-screen hidden code' },
    'RIG-002': { sev: 'high', conf: 'high', family: 'hidden',  title: 'Whitespace pushes code off-screen' },
    'RIG-003': { sev: 'high', conf: 'high', family: 'c2',      title: 'Reassembled obfuscated C2 address' },
    'RIG-004': { sev: 'high', conf: 'high', family: 'c2',      title: 'Known C2 port (1224/1244)' },
    'RIG-005': { sev: 'high', conf: 'high', family: 'c2',      title: 'base64 decodes to IP:port' },
    'RIG-006': { sev: 'high', conf: 'med',  family: 'exec',    title: 'eval()/Function() dynamic loader' },
    'RIG-007': { sev: 'high', conf: 'high', family: 'exec',    title: 'atob to eval execution chain' },
    'RIG-008': { sev: 'high', conf: 'high', family: 'steal',   title: 'Accesses wallet/key paths' },
    'RIG-009': { sev: 'med',  conf: 'med',  family: 'steal',   title: 'Accesses browser profile directory' },
    'RIG-010': { sev: 'high', conf: 'med',  family: 'install', title: 'Install script downloads/executes' },
    'RIG-011': { sev: 'high', conf: 'high', family: 'c2',      title: 'Install script connects to IP' },
    'RIG-012': { sev: 'med',  conf: 'low',  family: 'dep',     title: 'Dependency from non-registry source' },
    'RIG-013': { sev: 'high', conf: 'high', family: 'agentic', title: 'VS Code run-on-open setting' },
    'RIG-014': { sev: 'med',  conf: 'low',  family: 'hidden',  title: 'Off-screen high-entropy string' },
    'RIG-016': { sev: 'high', conf: 'high', family: 'agentic', title: 'Agent config hook runs on open (Claude/Gemini)' },
    'RIG-017': { sev: 'high', conf: 'high', family: 'agentic', title: 'AI instruction file hidden injection chars' },
    'RIG-018': { sev: 'high', conf: 'high', family: 'agentic', title: 'Git hook (husky) runs on open' },
    'RIG-019': { sev: 'high', conf: 'high', family: 'steal',   title: 'SSH authorized_keys backdoor write' },
    'RIG-020': { sev: 'high', conf: 'med',  family: 'agentic', title: 'AI rules file instructs agent to run a command' },
  });

  // ── Shared patterns ──────────────────────────────────────────────
  const IP_OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
  const IP_RE = new RegExp(`\\b${IP_OCTET}(?:\\.${IP_OCTET}){3}\\b`);
  // Strict ^IP:port$ (RIG-003 / RIG-005 false-positive-reduction design)
  const STRICT_IP_PORT = new RegExp(`^${IP_OCTET}(?:\\.${IP_OCTET}){3}:(\\d{1,5})$`);
  // RIG-004: plaintext C2 port IOC (ESET-DD1)
  const C2_PORT_RE = new RegExp(
    `\\b${IP_OCTET}(?:\\.${IP_OCTET}){3}:(?:1224|1244)\\b|https?://[^\\s'"\`]+:(?:1224|1244)\\b`);

  // Executable / network-behavior tokens (RIG-001/002 tail-segment composite condition)
  const EXEC_TOKEN = new RegExp(
    '(?:\\beval\\s*\\(|\\bnew\\s+Function\\b|\\bFunction\\s*\\(|\\batob\\s*\\(' +
    '|\\bfromCharCode\\b|child_process|\\bexec(?:Sync)?\\s*\\(|\\bspawn(?:Sync)?\\s*\\(' +
    '|\\bfetch\\s*\\(|\\bXMLHttpRequest\\b|\\bWebSocket\\s*\\(' +
    '|https?://[^\\s\'"\\`]+|\\bcurl\\s|\\bwget\\s|\\bpowershell\\b)');
  // Call-style tokens (require stronger evidence when the tail segment is inside a comment, to avoid false positives from alignment comments)
  const CALL_TOKEN = new RegExp(
    '(?:\\beval\\s*\\(|\\bnew\\s+Function\\b|\\bFunction\\s*\\(|\\batob\\s*\\(' +
    '|\\bexec(?:Sync)?\\s*\\(|\\bspawn(?:Sync)?\\s*\\(|\\bfetch\\s*\\(|\\bfromCharCode\\b)');

  // base64 candidate string literals (fragments can be very short, e.g. "NA=="; the real gate is strict decoding)
  const B64_FRAGMENT = /['"`]([A-Za-z0-9+/]{2,}={0,2})['"`]/g;
  const B64_SINGLE_MIN = 12;                                          // minimum length for a single literal
  // Fragment candidates in multi-line array form: ['xxx','yyy','zzz']
  const B64_ARRAY = /\[\s*(?:['"`][A-Za-z0-9+/]{2,}={0,2}['"`]\s*,\s*){1,3}['"`][A-Za-z0-9+/]{2,}={0,2}['"`]\s*,?\s*\]/g;

  // RIG-006: eval/Function dynamic loading (argument contains decode/reassembly traces; pure string-literal arguments are excluded to avoid webpack eval-source-map false positives)
  const LOADER_RE = /(?:\beval|\bnew\s+Function|\bFunction)\s*\(\s*([^)\n]{1,160})/g;
  const DYN_DECODE = /atob\s*\(|fromCharCode|Buffer\.from\s*\(|unescape\s*\(|decodeURIComponent\s*\(|\.join\s*\(|\.reverse\s*\(|\bhex|\\x[0-9a-fA-F]{2}|base64/i;

  // RIG-007: atob → eval chain
  const ATOB_EVAL_DIRECT = /(?:\beval|\bnew\s+Function|\bFunction)\s*\(\s*(?:window\.|self\.|globalThis\.)?atob\s*\(/;
  const ATOB_ASSIGN = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:window\.|self\.|globalThis\.)?atob\s*\(/g;

  // RIG-008: wallet / key paths (SOCKET / U42 direct; 2026 OtterCookie v4 expanded wallet list)
  const WALLET_PATTERNS = [
    { re: /\.config[\\/]+solana|solana[\\/]+id\.json/i,                                    what: 'Solana id.json' },
    { re: /exodus\.wallet|[\\/]\.?config[\\/]+Exodus|Application Support[\\/]+Exodus|AppData[\\/]+Roaming[\\/]+Exodus/i, what: 'Exodus wallet' },
    { re: /Library[\\/]+Keychains|login\.keychain/i,                                       what: 'macOS keychain' },
    { re: /nkbihfbeogaeaoehlefnkodbefgpgknn/,                                              what: 'MetaMask extension data' },
    { re: /bfnaelmomeimhlpmgjnjophhpkkoljpa/,                                              what: 'Phantom extension data' },
    { re: /dmkamcknogkgcdfhhbddcghachkejeap/,                                              what: 'Keplr extension data' },
    { re: /ibnejdfjmmkpcnlpebklmnkoeoihofec/,                                              what: 'TronLink extension data' },
    { re: /fhbohimaelbohpjbbldcngcnapndodjp/,                                              what: 'Binance Chain extension data' },
    { re: /\bUTC--[0-9T:.-]+--[0-9a-fA-F]{40}\b/,                                          what: 'Ethereum keystore' },
    { re: /(?:mnemonic|seedPhrase|seed_phrase|secretRecoveryPhrase)\s*[:=]/i,             what: 'mnemonic / seed phrase' },
  ];

  // RIG-009: browser profile / login-data directories (SOCKET)
  const PROFILE_PATTERNS = [
    { re: /User Data[\\/]+(?:Default|Profile \d+)/,                                                       what: 'Chrome User Data' },
    { re: /AppData[\\/]+(?:Local|Roaming)[\\/]+(?:Google[\\/]+Chrome|BraveSoftware|Microsoft[\\/]+Edge|Mozilla[\\/]+Firefox)/i, what: 'browser AppData directory' },
    { re: /Application Support[\\/]+(?:Google[\\/]+Chrome|BraveSoftware|Firefox)/i,                       what: 'browser profile (macOS)' },
    { re: /\.config[\\/]+(?:google-chrome|BraveSoftware|chromium)/i,                                      what: 'browser profile (Linux)' },
    { re: /['"`]Login Data['"`]|Local Extension Settings/,                                                what: 'Login Data / extension storage' },
  ];

  // RIG-010: install script contains download / inline execution (U42 / SOCKET)
  const INSTALL_EXEC = /\b(?:curl|wget|iwr|invoke-webrequest|certutil|bitsadmin|mshta|rundll32|powershell|pwsh)\b|node\s+(?:-e|--eval)\b|python3?\s+-c\b|base64\s+(?:-d|--decode)\b|https?:\/\//i;
  const INSTALL_KEYS = /^(?:pre|post)?install$|^prepare$|^prepublish$/;

  // RIG-012 (experimental): dependency from a non-registry source
  const NONREG_DEP = /^(?:git\+)?https?:\/\//i;
  const DEP_SECTIONS = ['dependencies', 'devDependencies', 'optionalDependencies'];

  // RIG-013: VS Code run-on-open (Contagious Interview / Void Dokkaebi VS Code tasks infection vector)
  // tasks.json runOn:folderOpen, or settings.json task.allowAutomaticTasks:on
  const VSCODE_AUTORUN = /"runOn"\s*:\s*"folderOpen"|"task\.allowAutomaticTasks"\s*:\s*"on"/;

  // RIG-016: agent config hook runs on open - .claude/settings.json & .gemini/settings.json
  // (Check Point CVE-2025-59536 / CVE-2026-21852; 2026 "Miasma" worm uses SessionStart → node .github/setup.js)
  // A hook command that downloads / connects / runs encoded content...
  const CLAUDE_HOOK_EXEC = /\b(?:curl|wget|iwr|invoke-webrequest|certutil|bitsadmin|mshta|nc|ncat)\b|node\s+(?:-e|--eval)\b|python3?\s+-c\b|base64\s+(?:-d|--decode)\b|\beval\b|\batob\b|https?:\/\/(?!localhost|127\.0\.0\.1)/i;
  // ...or runs an in-repo script via an interpreter (e.g. `node .github/setup.js`) - the Miasma pattern.
  const RUN_LOCAL_SCRIPT = /\b(?:node|deno|bun|ts-node|tsx|python3?|sh|bash|zsh|ruby|perl|php)\b[^\n|;&]*\.(?:js|mjs|cjs|ts|tsx|py|sh|bash|rb|pl|php|mdc)\b/i;
  // Hook event names that fire automatically when the project/session opens (vs. tool-use events).
  const ON_OPEN_EVENT = /^(?:SessionStart|sessionStart|on_session_start|startup)$/;

  // RIG-020: AI rules file gives the agent a plain-text instruction to run a command
  // (2026 "Miasma" worm: .cursor/rules/setup.mdc with alwaysApply:true + "Run `node .github/setup.js`")
  const CURSOR_ALWAYS = /alwaysApply\s*:\s*true/i;
  // "run/execute … <interpreter> <script>" or pointing at setup./install/.github - narrowed to avoid
  // flagging legitimate "run npm test" guidance.
  const AGENT_RUN_INSTRUCTION = /\b(?:run|execute|執行|実行)\b[^\n]{0,60}(?:`[^`\n]*\b(?:node|deno|bun|python3?|sh|bash)\b[^`\n]*\.(?:js|mjs|cjs|ts|py|sh)|\bsetup\.(?:js|mjs|sh|py)|\binstall\.sh\b|\.github\/[^\s`]+\.(?:js|mjs|sh|py))/i;

  // RIG-017: hidden injection characters in AI instruction files
  // Unicode Tag block (U+E0000-U+E007F) = invisible prompt injection in copilot-instructions.md (CVE-2025-53773 class)
  const HIDDEN_TAG = /[\u{E0000}-\u{E007F}]/u;
  // Bidirectional control characters (can hide malicious instructions inside visually reversed text)
  const BIDI_CTRL = /[‪-‮⁦-⁩]/;
  // Runs of zero-width characters (smuggling an invisible payload)
  const ZW_RUN = /[​-‍⁠﻿]{3,}/;

  // RIG-014 (experimental): high-entropy string beyond the right edge
  const HI_ENTROPY_TOKEN = /[A-Za-z0-9+/=]{40,}/g;

  // RIG-018: Git hook (husky) runs on open (2026 Lazarus pivot from tasks.json/postinstall to git hooks)
  // hook files under .husky/ in the repo (or core.hooksPath pointing to an in-repo directory) contain download/network/encoded-execution.
  const HOOK_EXEC = /\b(?:curl|wget|iwr|invoke-webrequest|certutil|bitsadmin|mshta|nc|ncat)\b|node\s+(?:-e|--eval)\b|python3?\s+-c\b|base64\s+(?:-d|--decode)\b|\beval\b|\batob\b|https?:\/\/(?!localhost|127\.0\.0\.1)/i;

  // RIG-019: SSH authorized_keys backdoor (2026 OtterCookie Linux persistence: writes a public key)
  const SSH_BACKDOOR = /authorized_keys/i;
  const SSH_PUBKEY = /ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/]{20,}/;
  const SSH_WRITE = />>\s*[^\n]*authorized_keys|authorized_keys[^\n]*(?:appendFile|writeFile|fs\.append|>>)|echo\s+[^\n]*>>\s*[^\n]*\.ssh/i;

  // ── Utility functions ────────────────────────────────────────────
  function b64decode(s) {
    try {
      if (typeof atob === 'function') return atob(s);
      // Node (test environment) fallback
      return Buffer.from(s, 'base64').toString('binary');
    } catch { return null; }
  }

  function printableRatio(s) {
    if (!s || !s.length) return 0;
    let p = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) p++;
    }
    return p / s.length;
  }

  function shannonEntropy(s) {
    if (!s || !s.length) return 0;
    const freq = new Map();
    for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
    let e = 0;
    for (const n of freq.values()) {
      const p = n / s.length;
      e -= p * Math.log2(p);
    }
    return e;
  }

  function validIpPort(s) {
    const m = STRICT_IP_PORT.exec(s);
    if (!m) return false;
    const port = Number(m[1]);
    return port >= 1 && port <= 65535;
  }

  // Whether a decode candidate is "meaningful text → strict IP:port"
  // printable ratio < MIN_PRINTABLE is treated as binary noise and discarded outright (false-positive-reduction design, SPEC appendix A)
  function decodeToIpPort(joined) {
    const dec = b64decode(joined);
    if (dec == null) return null;
    if (printableRatio(dec) < THRESHOLDS.MIN_PRINTABLE) return null;
    const trimmed = dec.trim();
    return validIpPort(trimmed) ? trimmed : null;
  }

  function permutations(arr) {
    if (arr.length <= 1) return [arr];
    const out = [];
    for (let i = 0; i < arr.length; i++) {
      const rest = arr.slice(0, i).concat(arr.slice(i + 1));
      for (const p of permutations(rest)) out.push([arr[i]].concat(p));
    }
    return out;
  }

  function buildLineIndex(text) {
    const starts = [0];
    for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
    return starts;
  }
  function lineOf(starts, idx) {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= idx) lo = mid; else hi = mid - 1;
    }
    return lo + 1; // 1-based
  }

  function snippet(s, max = 80) {
    s = String(s).replace(/\s+/g, ' ').trim();
    return s.length > max ? s.slice(0, max) + '…' : s;
  }

  // ── Main analysis ────────────────────────────────────────────────
  /**
   * @param {string} text full file contents
   * @param {{fileName?:string, path?:string, includeExperimental?:boolean}} ctx
   * @returns {{findings:Array, skipped:string|null, ruleCount:number}}
   */
  function analyze(text, ctx = {}) {
    const findings = [];
    if (typeof text !== 'string') return { findings, skipped: 'no-text', ruleCount: ENABLED.size };
    if (text.length > THRESHOLDS.MAX_FILE_BYTES) {
      return { findings, skipped: 'too-large', ruleCount: ENABLED.size };
    }

    const perRule = new Map();
    // Language-neutral: detailKey + detailParams are translated by the UI (_locales) into en/zh_TW/ja.
    // title is derived by the UI into an i18n key from the rule; evidence is a technical value (IP/filename/command), language-neutral.
    function add(id, line, detailKey, detailParams, evidence) {
      const meta = RULES[id];
      const n = perRule.get(id) || 0;
      if (n >= MAX_PER_RULE || findings.length >= MAX_FINDINGS) return;
      perRule.set(id, n + 1);
      findings.push({
        rule: id,
        severity: meta.sev,
        confidence: meta.conf,
        family: meta.family,
        detailKey: detailKey || null,
        detailParams: detailParams || [],
        line: line || null,
        evidence: evidence ? snippet(evidence) : null,
        experimental: !ENABLED.has(id),
      });
    }

    const lines = text.split(/\r\n|\r|\n/);
    const starts = buildLineIndex(text);
    const fileName = (ctx.fileName || '').toLowerCase();
    const filePath = (ctx.path || '').toLowerCase();

    // minified / source map file guard: whole file is long lines → skip the right-edge rules (false-positive black hole)
    const nonEmpty = lines.filter((l) => l.trim().length > 0);
    const sorted = nonEmpty.map((l) => l.length).sort((a, b) => a - b);
    const median = sorted.length ? sorted[sorted.length >> 1] : 0;
    const minifiedLike =
      (nonEmpty.length < 5 && text.length > 2000) || median > 200 ||
      /\.min\.(js|css)$|\.map$/.test(fileName);

    const wsGapRe = new RegExp(`[ \\t]{${THRESHOLDS.WS_GAP},}`);

    // ── Per-line rules: RIG-001 / RIG-002 / RIG-014 ──
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length <= THRESHOLDS.VISIBLE_COL) continue;
      const lineNo = i + 1;
      let hit002 = false;

      // RIG-002: whitespace padding pushes code off-screen
      const gm = wsGapRe.exec(line);
      if (gm) {
        const after = line.slice(gm.index + gm[0].length);
        const afterStartsCol = gm.index + gm[0].length;
        if (after.trim() && afterStartsCol >= THRESHOLDS.VISIBLE_COL) {
          const isComment = /^\s*(?:\/\/|\/\*|#)/.test(after);
          // trailing comments for alignment are common → require a call-style token inside a comment to count
          if ((isComment && CALL_TOKEN.test(after)) || (!isComment && EXEC_TOKEN.test(after))) {
            hit002 = true;
            add('RIG-002', lineNo, 'd_RIG_002', [lineNo, gm[0].length], after);
          }
        }
      }

      // RIG-001: hidden code beyond the right edge (skip if the same line was already hit by RIG-002)
      if (!hit002 && !minifiedLike && line.length > THRESHOLDS.LONG_LINE) {
        const tail = line.slice(THRESHOLDS.VISIBLE_COL);
        if (EXEC_TOKEN.test(tail)) {
          add('RIG-001', lineNo, 'd_RIG_001', [lineNo, line.length], tail);
        }
      }

      // RIG-014 (experimental): high-entropy string beyond the right edge
      if (!minifiedLike) {
        const tail = line.slice(THRESHOLDS.VISIBLE_COL);
        let tm;
        HI_ENTROPY_TOKEN.lastIndex = 0;
        while ((tm = HI_ENTROPY_TOKEN.exec(tail)) !== null) {
          if (shannonEntropy(tm[0]) > THRESHOLDS.ENTROPY_MIN) {
            add('RIG-014', lineNo, 'd_RIG_014', [lineNo], tm[0]);
            break;
          }
        }
      }
    }

    // ── RIG-004: plaintext C2 port IOC ──
    {
      const re = new RegExp(C2_PORT_RE.source, 'g');
      let m;
      while ((m = re.exec(text)) !== null) {
        add('RIG-004', lineOf(starts, m.index), 'd_RIG_004', [], m[0]);
      }
    }

    // ── RIG-003 / RIG-005: base64 C2 reconstruction ──
    // RIG-005: decode a single literal directly
    {
      const re = new RegExp(B64_FRAGMENT.source, 'g');
      let m;
      while ((m = re.exec(text)) !== null) {
        const frag = m[1];
        if (frag.length < B64_SINGLE_MIN) continue;
        const ip = decodeToIpPort(frag);
        if (ip) add('RIG-005', lineOf(starts, m.index), 'd_RIG_005', [ip], ip);
      }
    }
    // RIG-003: fragmentation + swap reassembly (per-line groups + array groups; full permutations ≤ 4 fragments)
    {
      const tryGroup = (frags, lineNo) => {
        if (frags.length < 2 || frags.length > 4) return;
        if (!frags.some((f) => f.length >= 8)) return; // at least one fragment of substantial length
        for (const perm of permutations(frags)) {
          const ip = decodeToIpPort(perm.join(''));
          if (ip) {
            add('RIG-003', lineNo, 'd_RIG_003', [ip], ip);
            return;
          }
        }
      };
      // per-line
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].length < 16 || lines[i].indexOf('"') < 0 && lines[i].indexOf("'") < 0 && lines[i].indexOf('`') < 0) continue;
        const re = new RegExp(B64_FRAGMENT.source, 'g');
        const frags = [];
        let m;
        while ((m = re.exec(lines[i])) !== null && frags.length <= 5) frags.push(m[1]);
        tryGroup(frags, i + 1);
      }
      // cross-line array
      const ar = new RegExp(B64_ARRAY.source, 'g');
      let am;
      while ((am = ar.exec(text)) !== null) {
        const re = new RegExp(B64_FRAGMENT.source, 'g');
        const frags = [];
        let m;
        while ((m = re.exec(am[0])) !== null) frags.push(m[1]);
        tryGroup(frags, lineOf(starts, am.index));
      }
    }

    // ── RIG-006: eval / Function dynamic loader ──
    {
      const re = new RegExp(LOADER_RE.source, 'g');
      let m;
      while ((m = re.exec(text)) !== null) {
        const arg = m[1].trim();
        // a pure string-literal argument (e.g. webpack eval-source-map) does not count
        if (/^['"`]/.test(arg)) continue;
        if (DYN_DECODE.test(arg)) {
          add('RIG-006', lineOf(starts, m.index), 'd_RIG_006', [], m[0]);
        }
      }
    }

    // ── RIG-007: atob → eval chain ──
    {
      if (ATOB_EVAL_DIRECT.test(text)) {
        const idx = text.search(ATOB_EVAL_DIRECT);
        add('RIG-007', lineOf(starts, idx), 'd_RIG_007_direct', [], text.slice(idx, idx + 60));
      } else {
        const re = new RegExp(ATOB_ASSIGN.source, 'g');
        let m;
        while ((m = re.exec(text)) !== null) {
          const name = m[1].replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          const evalUse = new RegExp(`(?:\\beval|\\bnew\\s+Function|\\bFunction)\\s*\\(\\s*${name}\\b`);
          if (evalUse.test(text)) {
            add('RIG-007', lineOf(starts, m.index), 'd_RIG_007_var', [m[1]], m[0]);
          }
        }
      }
    }

    // ── RIG-008: wallet / key paths ──
    for (const p of WALLET_PATTERNS) {
      const m = p.re.exec(text);
      if (m) add('RIG-008', lineOf(starts, m.index), 'd_RIG_008', [p.what], m[0]);
    }

    // ── RIG-009: browser profile directory ──
    for (const p of PROFILE_PATTERNS) {
      const m = p.re.exec(text);
      if (m) add('RIG-009', lineOf(starts, m.index), 'd_RIG_009', [p.what], m[0]);
    }

    // ── RIG-019: SSH authorized_keys backdoor write ──
    if (SSH_BACKDOOR.test(text) && (SSH_WRITE.test(text) || SSH_PUBKEY.test(text))) {
      const idx = text.search(SSH_BACKDOOR);
      add('RIG-019', lineOf(starts, idx), 'd_RIG_019', [], '~/.ssh/authorized_keys');
    }

    // ── RIG-010 / RIG-011 / RIG-012: package.json ──
    if (fileName === 'package.json') {
      let pkg = null;
      try { pkg = JSON.parse(text); } catch { /* invalid JSON → skip */ }
      if (pkg && pkg.scripts && typeof pkg.scripts === 'object') {
        for (const [key, val] of Object.entries(pkg.scripts)) {
          if (!INSTALL_KEYS.test(key) || typeof val !== 'string') continue;
          const idx = text.indexOf(val.slice(0, 60));
          const lineNo = idx >= 0 ? lineOf(starts, idx) : null;
          if (INSTALL_EXEC.test(val)) {
            add('RIG-010', lineNo, 'd_RIG_010', [key], val);
          }
          if (IP_RE.test(val)) {
            add('RIG-011', lineNo, 'd_RIG_011', [key], val);
          }
        }
      }
      // RIG-012 (experimental): dependency from a non-registry source
      if (pkg) {
        for (const sec of DEP_SECTIONS) {
          const deps = pkg[sec];
          if (!deps || typeof deps !== 'object') continue;
          for (const [dep, spec] of Object.entries(deps)) {
            if (typeof spec === 'string' && NONREG_DEP.test(spec)) {
              const idx = text.indexOf(spec);
              add('RIG-012', idx >= 0 ? lineOf(starts, idx) : null, 'd_RIG_012', [dep, sec], spec);
            }
          }
        }
      }
    }

    // ── RIG-013: VS Code run-on-open (.vscode/tasks.json | settings.json) ──
    if (filePath.includes('.vscode/')) {
      const m = VSCODE_AUTORUN.exec(text);
      if (m) add('RIG-013', lineOf(starts, m.index), 'd_RIG_013', [], m[0]);
    }

    // ── RIG-018: Git hook (husky) runs on open ──
    // hook files under .husky/ in the repo contain download/network/encoded-execution (triggered on commit/checkout)
    if (filePath.includes('.husky/') || /^(?:pre-commit|post-checkout|post-merge|post-install|pre-push)$/.test(fileName)) {
      const lines2 = text.split(/\r\n|\r|\n/);
      for (let i = 0; i < lines2.length; i++) {
        const ln = lines2[i];
        if (/^\s*#/.test(ln)) continue; // skip comments
        if (HOOK_EXEC.test(ln)) {
          add('RIG-018', i + 1, 'd_RIG_018', [], ln.trim());
          break;
        }
      }
    }

    // ── RIG-016: agent config hook runs on open (.claude/ & .gemini/ settings*.json) ──
    if ((filePath.includes('.claude/') || filePath.includes('.gemini/')) && /^settings(?:\.local)?\.json$/.test(fileName)) {
      let cfg = null;
      try { cfg = JSON.parse(text); } catch { /* invalid JSON → skip */ }
      if (cfg && cfg.hooks && typeof cfg.hooks === 'object') {
        // Walk per hook event so we can treat "on open" events (SessionStart) as autorun.
        const collect = (node, out) => {
          if (Array.isArray(node)) { node.forEach((n) => collect(n, out)); return; }
          if (node && typeof node === 'object') {
            for (const [k, v] of Object.entries(node)) {
              if (k === 'command' && typeof v === 'string') out.push(v);
              else if (v && typeof v === 'object') collect(v, out);
            }
          }
        };
        for (const [event, val] of Object.entries(cfg.hooks)) {
          const cmds = [];
          collect(val, cmds);
          const onOpen = ON_OPEN_EVENT.test(event); // SessionStart etc. = runs the moment you open the project
          for (const cmd of cmds) {
            // On-open events: any command is autorun. Other events: only flag suspicious commands
            // (download/network/encoded-exec, or running an in-repo script like `node .github/setup.js`).
            if (onOpen || CLAUDE_HOOK_EXEC.test(cmd) || RUN_LOCAL_SCRIPT.test(cmd)) {
              const idx = text.indexOf(cmd.slice(0, 40));
              add('RIG-016', idx >= 0 ? lineOf(starts, idx) : null, 'd_RIG_016', [], cmd);
            }
          }
        }
      }
    }

    // ── RIG-017 / RIG-020: AI instruction & rules files ──
    // Trigger files: copilot-instructions.md / CLAUDE.md / AGENTS.md / GEMINI.md / .cursorrules
    //               / .cursor/rules/*.mdc / *instructions*.md under .github
    {
      const isCursorRule = filePath.includes('.cursor/rules/') || fileName === '.cursorrules' || fileName.endsWith('.mdc');
      const isInstructionFile =
        /^(?:copilot-instructions|claude|agents|gemini)\.md$/.test(fileName) ||
        isCursorRule ||
        (filePath.includes('.github/') && /instructions.*\.md$/.test(fileName)) ||
        fileName.endsWith('.instructions.md');
      if (isInstructionFile) {
        // RIG-017: hidden / invisible injection characters
        const tag = HIDDEN_TAG.exec(text);
        if (tag) add('RIG-017', lineOf(starts, tag.index), 'd_RIG_017_tag', [], null);
        else if (BIDI_CTRL.test(text)) add('RIG-017', lineOf(starts, text.search(BIDI_CTRL)), 'd_RIG_017_bidi', [], null);
        else if (ZW_RUN.test(text)) add('RIG-017', lineOf(starts, text.search(ZW_RUN)), 'd_RIG_017_zw', [], null);

        // RIG-020: plain-text instruction telling the agent to run a script (Miasma cursor rule)
        // Only on cursor rule files: alwaysApply:true + a "run <interpreter> <script>" instruction.
        if (isCursorRule && AGENT_RUN_INSTRUCTION.test(text) && (CURSOR_ALWAYS.test(text) || RUN_LOCAL_SCRIPT.test(text))) {
          const idx = text.search(AGENT_RUN_INSTRUCTION);
          add('RIG-020', lineOf(starts, idx), 'd_RIG_020', [], text.slice(idx, idx + 70).split(/\r?\n/)[0]);
        }
      }
    }

    const active = ctx.includeExperimental
      ? findings
      : findings.filter((f) => !f.experimental);

    return { findings: active, skipped: null, ruleCount: ENABLED.size };
  }

  // Combination-rule evaluation (the core of false-positive reduction). Takes findings (a single-file
  // result, or an aggregation across entry files in repo mode) and returns a presentation level
  // for the UI to decide the banner style:
  //   alarm   = high-confidence large red banner (a direct strong signal, or a multi-stage pattern combining ≥2 different families)
  //   caution = low-confidence small orange banner (a single false-positive-prone signal / medium risk only)
  // For the design rationale see docs/rules.md.
  function assess(findings) {
    const list = Array.isArray(findings) ? findings : [];
    if (!list.length) return { level: 'none', high: 0, med: 0, families: [], combo: false, reason: 'no-findings' };

    const high = list.filter((f) => f.severity === 'high').length;
    const med = list.filter((f) => f.severity === 'med').length;
    const families = [...new Set(list.map((f) => f.family).filter(Boolean))];
    const combo = families.length >= 2;                                  // multi-stage: hidden code + execution + C2…
    const strongDirect = list.some((f) => f.severity === 'high' && f.confidence === 'high');

    let level, reason;
    if (strongDirect) { level = 'alarm'; reason = 'direct-strong'; }
    else if (combo) { level = 'alarm'; reason = 'combination'; }
    else { level = 'caution'; reason = 'low-confidence-single'; }       // false-positive-prone → small orange box

    return { level, high, med, families, combo, reason };
  }

  const api = {
    analyze,
    assess,
    THRESHOLDS,
    RULES,
    ENABLED,
    enabledCount: ENABLED.size,
  };

  // shared by the content script (isolated world) and Node tests
  const root = typeof globalThis !== 'undefined' ? globalThis : self;
  root.Metsuke = root.Metsuke || {};
  root.Metsuke.detector = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})();
