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

`Trigger` is what makes a rule applicable: **content** rules match any fetched text
(file-primary - the malicious source usually lives in a file you open); **path-gated**
rules only fire on a specific config/instruction file (repo-primary - those files are
exactly what the repo-home scan fetches).

| Rule | Detects | Trigger | File | Repo | Primary |
|---|---|---|:--:|:--:|:--:|
| RIG-001 | Off-screen hidden code | content | ✓ | ✓ | file |
| RIG-002 | Whitespace pushes code off-screen | content | ✓ | ✓ | file |
| RIG-003 | Spliced/reordered base64 C2 | content | ✓ | ✓ | file |
| RIG-004 | Known C2 port 1224/1244 | content | ✓ | ✓ | file |
| RIG-005 | base64 decodes to IP:port | content | ✓ | ✓ | file |
| RIG-006 | eval()/Function() dynamic loader | content | ✓ | ✓ | file |
| RIG-007 | atob -> eval execution chain | content | ✓ | ✓ | file |
| RIG-008 | Accesses wallet/key paths | content | ✓ | ✓ | file |
| RIG-009 | Accesses browser profile dir (med) | content | ✓ | ✓ | file |
| RIG-019 | SSH authorized_keys backdoor write | content | ✓ | ✓ | file |
| RIG-010 | Install script downloads/executes | `package.json` | ✓ | ✓ | repo |
| RIG-011 | Install script connects to IP | `package.json` | ✓ | ✓ | repo |
| RIG-013 | VS Code run-on-open setting | `.vscode/` | ✓ | ✓ | repo |
| RIG-016 | Agent hooks run on open (Claude/Gemini) | `.claude/`·`.gemini/` settings | ✓ | ✓ | repo |
| RIG-017 | AI instruction file hidden injection chars | instruction/rules files | ✓ | ✓ | repo |
| RIG-018 | Git hook (husky) runs on open | `.husky/` | ✓ | ✓ | repo |
| RIG-020 | AI rules file instructs the agent to run a command | `.cursor/rules`·`.cursorrules` | ✓ | ✓ | repo |

Experimental (off by default):

| Rule | Detects | Trigger |
|---|---|---|
| RIG-012 | Dependency from a non-registry source | `package.json` |
| RIG-014 | Off-screen high-entropy string | content |

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
