# 目付 Metsuke - Repo Interview Guard

**目付 (Metsuke)** is the Edo-era word for an official who *watches for wrongdoing*.
The extension analyzes source files on GitHub / GitLab / Bitbucket the moment you
open them, and warns when a file shows traits of a malicious "fake-interview"
repository. **It only warns - it never modifies or blocks the page.**

> 守望而不阻擋。 ・ 警戒すれども、妨げず。

Available in English, 繁體中文, and 日本語 (follows the browser language).

## Structure

| File | Responsibility |
|---|---|
| `manifest.json` | MV3; only the `storage` permission + named host permissions |
| `detector.js` | Pure detection engine (no DOM / no network); rules RIG-001~020 and threshold constants |
| `content.js` | URL parsing, text fetch (raw -> GitHub embedded JSON), idle analysis, Shadow DOM banner, reveal, SPA navigation detection |
| `background.js` | Service worker: proxy the raw fetch (with cookies), set the badge |
| `popup.html/css/js` | Verdict summary, trust list (allowlist), master switch |
| `tests/run.js` | Positive rule fixtures + false-positive corpus (0 high-severity FP gate) |
| `_locales/{en,zh_TW,ja}` | i18n message catalogs (English default) |

## Development

```sh
# Run the detection-engine tests (required whenever threshold constants change)
node tests/run.js

# Build a Web Store zip + unpacked dir
bash scripts/pack.sh
```

Load it locally: `chrome://extensions` -> Developer mode -> "Load unpacked" -> pick this directory.

## Two analysis modes

- **File pages** (`/blob`, `/-/blob`, `/src`): real-time analysis of the single file you open.
- **Repo home / tree pages**: a targeted scan of fixed high-value entry files
  (`package.json`, `.vscode/tasks.json`, `.vscode/settings.json`, `.claude/settings*.json`,
  `.gemini/settings*.json`, `.cursorrules`, `.cursor/rules/setup.mdc`,
  `.github/copilot-instructions.md`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.husky/*`) -
  so you are warned on the landing page without opening each file. Findings are tagged with
  their source file and are click-through.

## Detection rules (17 enabled)

RIG-001 off-screen hidden code · RIG-002 whitespace pushes code off-screen ·
RIG-003 spliced/reordered base64 C2 · RIG-004 known C2 port 1224/1244 ·
RIG-005 base64 decodes to IP:port · RIG-006 eval/Function loader ·
RIG-007 atob -> eval chain · RIG-008 wallet/key paths · RIG-009 browser profile dir (med) ·
RIG-010 install script downloads/executes · RIG-011 install script connects to IP ·
RIG-013 VS Code run-on-open · RIG-016 agent hooks run-on-open (Claude/Gemini) ·
RIG-017 AI instruction file hidden injection chars ·
RIG-018 husky git hook run-on-open · RIG-019 SSH authorized_keys backdoor ·
RIG-020 AI rules file instructs the agent to run a command.

Experimental (off by default): RIG-012 (non-registry dependency source),
RIG-014 (off-screen high-entropy string).

The full rule-to-intel mapping (severity / confidence / family, combination rules,
and 2026 threat-report sources) lives in `detector.js` and the internal rules doc.

## Alert tiers (false-positive reduction)

Every rule carries **severity x confidence x family**, and `detector.assess()` decides how to show it:

- **alarm - full coral banner**: a high-confidence strong signal (known C2 port, wallet path,
  hidden injection chars...), or **two or more different families together** (multi-stage chain).
- **caution - smaller amber banner**: a single easily-misjudged signal (a legitimate postinstall
  can also use `curl`) or medium risk only - low-key, not intrusive.

The banner pops on the first dangerous signal; while the scan is still running it shows a loading
spinner, then updates when done.

## Privacy

No collection, no transmission, no sale; all analysis runs locally. The only network request
fetches the raw source of the file you are already viewing, from the same code host you are on.
Only `{ enabled, allowlist }` is stored, in `chrome.storage.sync`. See `PRIVACY.md`.
