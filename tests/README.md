# Metsuke detector tests

The detector's behaviour is pinned by an assertion suite that runs both locally (Node) and remotely
(Cloudflare Worker), from a single source of truth.

| File | Role |
|---|---|
| `suite.js` | Runtime-agnostic assertions, `runSuite(detector) → { pass, fail, failures, coverage, metrics }` |
| `run.js` | Node adapter (`node tests/run.js`) — prints the report, sets the exit code |
| `../worker/index.js` | Cloudflare Worker — runs the same `suite.js` in workerd, served at `GET /test` |

## How to run

```sh
# Local (executing a real file is fine; do NOT use `node --check` or `node -e "<malware-ish>"` — EDR kills them)
node tests/run.js

# Remote (real workerd, zero local Node) — see ../worker/README.md to deploy
curl -fsS https://metsuke-detector-tests.gesarlin0803.workers.dev/test
```

## Evaluation metrics

The suite reports more than pass/fail. Each case in the **rule coverage matrix** is a labelled
sample, so the run yields a small confusion-matrix-style summary:

| Metric | Meaning | Green value |
|---|---|---|
| `pass` / `fail` | raw assertion counts (matrix + detailed property checks + coverage gate + threshold locks) | `fail = 0` |
| `cases.positive` / `cases.negative` | how many "should fire" vs "should stay silent" cases exist | — |
| `recall` | TP / (TP+FN) — fraction of positive cases that actually fire (a miss = false negative) | `1.0` |
| `specificity` | TN / (TN+FP) — fraction of negative cases that stay silent (a fire = false positive) | `1.0` |
| `ruleCoverage.covered / total` | enabled rules that carry **both** a positive and a negative case | `21 / 21` |
| `ruleCoverage.missingPositive/Negative` | enabled rules lacking either kind | `[]` |

**Coverage gate:** the suite asserts every *enabled* rule has ≥1 positive **and** ≥1 negative case.
Add a rule → the gate fails until you give it both, so coverage cannot silently regress.

A regression is now legible: `recall < 1` means a real malicious pattern stopped firing (a new
**false negative**); `specificity < 1` means a benign look-alike started firing (a new
**false positive**) — exactly the two failure modes this detector trades off.

## Test inventory (rule coverage matrix)

Data-driven cases in `suite.js` (`expectRule(rule, 'pos'|'neg', …)`). Positives must fire; negatives —
the false-positive guards — must stay silent. All payloads are inert (reserved IPs, meaningless decodes).

| Rule | Positive (should fire) | Negative (must stay silent) |
|---|---|---|
| RIG-001 off-screen code | long comment tail w/ `execSync`; long code line tail w/ `fetch` | long line of pure data; minified single line (skipped) |
| RIG-002 whitespace push | big gap + `fetch`; big gap + `child_process` | aligned comment w/ a URL; big gap + ordinary code |
| RIG-003 spliced base64 C2 | same-line swapped fragments; multi-line array | fragments decoding to ordinary text; single literal |
| RIG-004 C2 port 1224/1244 | `http://IP:1224`; `IP:1244` | ordinary port 8080; `1224` not used as a port |
| RIG-005 base64→IP:port | base64 of `IP:port`; base64 of `http://IP:port/path` | ordinary base64 text; base64 of a **domain** URL |
| RIG-006 eval/Function loader | `eval(hexDecode(...))`; `Function.constructor('require', …)` | webpack eval-source-map literal; `eval(plainVar)` |
| RIG-007 atob→eval | `eval(atob(...))`; `var=atob; eval(var)` | `atob` assigned, never eval-ed; `eval` without `atob` |
| RIG-008 wallet/key paths | Solana `id.json`; MetaMask extension id | bare `mnemonic` declaration; prose mentioning wallets |
| RIG-009 browser profile dir | Chrome `User Data/Default`; Firefox `AppData/Roaming` | mentions "Chrome" only; a non-profile `Default/` dir |
| RIG-010 install download/exec | `curl \| sh`; `powershell -enc` | normal build (`tsc`/`husky`); local `dist` script |
| RIG-011 install connects to IP | `curl` to IP; `ping` IP | hits a domain (no IP); normal script |
| RIG-013 VS Code run-on-open | `runOn:folderOpen`; `allowAutomaticTasks:on` | normal build task; `runOn:default` |
| RIG-016 agent hooks on open | `SessionStart` runs script; `PreToolUse` `curl\|sh` | formatting hook; benign lint command |
| RIG-017 hidden injection chars | Unicode Tag chars; zero-width run | emoji ZWJ sequence; tag char in a non-instruction file |
| RIG-018 husky on open | `curl\|sh`; `node -e` eval | lint-staged hook; suspicious token only in a comment |
| RIG-019 SSH authorized_keys | `appendFile`; `echo >>` | docs mentioning it; `ssh-keygen` tool |
| RIG-020 AI rules run command | "Run `node .github/setup.js`"; "Execute `bash …`" | legit guidance only; no run instruction |
| RIG-021 dead-drop resolver | `atob` var → `axios.get`; inline `fetch(Buffer.from base64)` | plain `axios.get(env)`; `atob` → render (no network) |
| RIG-022 response→eval | `axios` resp → `eval(r.data…)`; `fetch` → `Function(res.data)` | `eval(local.value)`; `eval(store.data)` w/ only an import |
| RIG-023 whole env exfil | `JSON.stringify(process.env)` → `fetch`; spread → `URLSearchParams` | debug log + unrelated import; single-var telemetry |
| RIG-024 lifecycle in-repo script | `prepare`→`server/server.js`; `postinstall`→`.github/setup.js` | `node ./scripts/build.js`; normal build pipeline |
| RIG-025 payload after module export *(PolinRider)* | config export then appended `eval` blob; `module.exports` then `fromCharCode` eval | normal config (export only); long asset string but no exec |
| RIG-026 anti-forensic git rewrite | `--amend --no-verify` + `date -s` + force push; `Set-Date` + `git push --force` | legit force-push (no clock tamper); sets date but no git rewrite |
| RIG-012 *(experimental)* | non-registry dependency URL | normal semver dependency |

> Experimental rules (off by default) are not part of the enabled-rule coverage gate. RIG-014
> (off-screen high-entropy string) is exercised indirectly by the minified/entropy FP corpus rather
> than a dedicated matrix case.

Beyond the matrix, `suite.js` also keeps **property-level** assertions the matrix can't express:
line numbers, `family`/`confidence`/`evidence` of findings, `assess()` alarm-vs-caution tiering and
combination chains, the broader false-positive corpus, and the locked threshold constants (SPEC §3).

## Adding a case

Add a line to the relevant block in `suite.js`:

```js
expectRule('RIG-021', 'neg', 'short description', '<inert source text>', { fileName: 'x.js', path: 'optional/path' });
```

`pos` → the target rule must appear; `neg` → it must be absent. Coverage and metrics update
automatically. Keep payloads inert (reserved-range IPs `10.x`/`192.0.2.x`/`198.51.100.x`/`203.0.113.x`,
decodes that mean nothing). Re-run `node tests/run.js`; then `wrangler deploy` to refresh the remote endpoint.
