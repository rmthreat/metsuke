/**
 * Metsuke - detector unit tests, Node runner (`node tests/run.js`).
 *
 * The assertions themselves live in tests/suite.js (runtime-agnostic) so the exact same suite
 * also runs in the Cloudflare Worker (worker/index.js → GET /test). This file is just the Node
 * adapter: load the detector, run the suite, print a report, set the exit code.
 *
 * SPEC §9 DoD: positive fixtures fire; false-positive corpus produces 0 high-severity findings.
 * SPEC §10: any change to threshold constants must include before/after test results.
 */
'use strict';

const detector = require('../detector.js');
const { runSuite } = require('./suite.js');

const { pass, fail, failures, metrics } = runSuite(detector);

console.log(`\n${pass} passed, ${fail} failed`);
if (metrics) {
  const m = metrics;
  console.log(
    `coverage: ${m.ruleCoverage.covered}/${m.ruleCoverage.total} rules have pos+neg | ` +
    `cases: ${m.cases.positive} pos / ${m.cases.negative} neg | ` +
    `recall ${m.recall} · specificity ${m.specificity}`);
  if (m.ruleCoverage.missingPositive.length) console.log(`  ⚠ missing positive: ${m.ruleCoverage.missingPositive.join(', ')}`);
  if (m.ruleCoverage.missingNegative.length) console.log(`  ⚠ missing negative: ${m.ruleCoverage.missingNegative.join(', ')}`);
}
for (const f of failures) {
  console.error(`✗ ${f.name}`);
  if (f.info) console.error('  ', JSON.stringify(f.info, null, 1).slice(0, 500));
}
process.exit(fail ? 1 : 0);
