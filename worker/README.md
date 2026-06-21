# Metsuke detector test Worker

Runs the detector's full assertion suite inside Cloudflare's **workerd** runtime and exposes it
as an HTTP endpoint. This lets you verify the detector from anywhere with a plain HTTPS request —
the local machine never has to run `node` over the malware-pattern fixtures.

## ⚠️ Do not run the EDR-blocked checks locally

The dev machine's endpoint-security agent (EDR) **kills (exit 137)** Node invocations that look
like malware analysis, which silently distorts results. Avoid these locally:

- ❌ `node --check <file>` — the syntax-check parse trips the EDR
- ❌ `node -e "<inline code with eval/atob/fetch/process.env/…>"` — inline malware-pattern strings trip it

Use instead:

- ✅ `node tests/run.js` — executing a real file is fine (canonical local run)
- ✅ a temp file for quick probes: write `tests/_probe.js`, run `node tests/_probe.js`, then delete it
- ✅ **this Worker's `GET /test`** — runs the same suite entirely off your machine (highest fidelity)

## Why this exists

On the dev machine the local EDR kills `node --check` and `node -e "<inline script with malware
patterns>"` (exit 137), which distorts ad-hoc verification. `node tests/run.js` itself runs fine,
but routing tests through a deployed Worker means:

- verification is a single `curl`, no local `node` over flagged code;
- the suite runs in **workerd**, which is much closer to the extension's content-script isolated
  world (no DOM, no Node, native `atob`/`btoa`) than Node is — higher-fidelity than `node tests/run.js`.

## Single source of truth

The assertions live in [`../tests/suite.js`](../tests/suite.js) and are runtime-agnostic
(`runSuite(detector) → { pass, fail, failures }`, no `process`/`console`/fs). Both consumers share it:

| Consumer | How |
|---|---|
| Node (`node tests/run.js`) | `require` detector + suite, print report, set exit code |
| Worker (`worker/index.js`) | `import` both for side-effects (they attach to `globalThis`), serve `GET /test` |

No drift between local and remote — the same `suite.js` runs in both.

## Deploy (one-time)

```sh
npm install            # installs wrangler (devDependency)
npx wrangler login     # browser auth to your Cloudflare account
npx wrangler deploy    # publishes to https://metsuke-detector-tests.gesarlin0803.workers.dev
```

## Run the tests remotely

```sh
curl -fsS https://metsuke-detector-tests.gesarlin0803.workers.dev/test
```

Returns HTTP **200** when green, **500** when red, with a JSON report:

```json
{
  "ok": true,
  "runtime": "cloudflare-workers (workerd)",
  "rules": 21,
  "pass": 118,
  "fail": 0,
  "durationMs": 12,
  "failures": []
}
```

`npm run test:remote` wraps the curl (set `METSUKE_TEST_URL` to your worker base URL first).

## Local dev (optional)

`npx wrangler dev` serves the worker on `http://localhost:8787` via a local workerd. Note this still
spins up a local `node`/esbuild toolchain, so the point of the deployed endpoint is to avoid that.

## Not part of the extension

`scripts/pack.sh` and `.github/workflows/release.yml` ship a fixed whitelist of runtime files
(`manifest.json`, `detector.js`, `content.js`, …). This Worker, `package.json`, `wrangler.jsonc`
and `node_modules/` are **not** bundled into the published extension.

## Optional CI

To run this in the cloud automatically, either keep the existing GitHub Actions step
(`node tests/run.js` in `release.yml`) or connect the repo to **Cloudflare Workers Builds** and set
the build/test command to `node tests/run.js` (or `npx wrangler deploy` to redeploy this endpoint on push).
