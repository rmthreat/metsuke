/**
 * Metsuke - detector test Worker (Cloudflare Workers / workerd).
 *
 * Runs the exact same assertion suite as `node tests/run.js`, but inside the real workerd
 * runtime — which is far closer to the extension's content-script isolated world (no DOM, no
 * Node, native atob/btoa) than Node is. Deploy once, then verify from anywhere with a plain
 * HTTPS request, so the local machine never has to run `node` on the malware-pattern fixtures
 * (which the local EDR kills, distorting results).
 *
 *   GET /test  → JSON report { ok, pass, fail, failures, ... }; HTTP 200 when green, 500 when red.
 *
 * detector.js and tests/suite.js are CommonJS/IIFE modules that attach their API to globalThis
 * (root.Metsuke / root.MetsukeTests). We import them for their side-effects and read globalThis.
 */
import '../detector.js';
import '../tests/suite.js';

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== '/test' && url.pathname !== '/') {
      return new Response('Metsuke detector test worker.\nGET /test for the JSON report.\n', {
        status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    }

    const detector = globalThis.Metsuke && globalThis.Metsuke.detector;
    const runSuite = globalThis.MetsukeTests && globalThis.MetsukeTests.runSuite;
    if (!detector || !runSuite) {
      return new Response(JSON.stringify({ ok: false, error: 'detector/suite not loaded' }), {
        status: 500, headers: { 'content-type': 'application/json; charset=utf-8' },
      });
    }

    const started = Date.now();
    const { pass, fail, failures, metrics } = runSuite(detector);
    const body = {
      ok: fail === 0,
      runtime: 'cloudflare-workers (workerd)',
      rules: detector.enabledCount,
      pass,
      fail,
      metrics,
      durationMs: Date.now() - started,
      failures,
    };
    return new Response(JSON.stringify(body, null, 2), {
      status: fail === 0 ? 200 : 500,
      headers: { 'content-type': 'application/json; charset=utf-8' },
    });
  },
};
