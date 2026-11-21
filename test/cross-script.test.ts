/**
 * Cross-script and scope-sensitivity regressions.
 *
 * Two bugs that only show up on realistic multi-file pages:
 *  - a `var` declared in one classic script protects a read in another;
 *  - two locals with the same name in different functions must not share taint.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { scan } from '../src/scan.ts';
import { parseScripts } from '../src/js/parse.ts';
import { extractGlobalReads, topLevelVarNames } from '../src/js/globals.ts';
import { propagateTaint, applyTaint } from '../src/js/taint.ts';
import { PROFILES } from '../src/html/profiles.ts';

const PAGE = {
  html: '<!doctype html><html><body><div id="sink"></div></body></html>',
  regions: [{ name: 'sink', selector: '#sink', profile: PROFILES.unsafeInnerHtml() }],
};

test('a var in one classic script protects a read in another', () => {
  const result = scan({
    page: PAGE,
    scripts: [
      { id: 'config.js', code: `var RUNTIME_CONFIG = { assetHost: '/cdn/' };` },
      {
        id: 'bundle.js',
        code: `var s=document.createElement('script'); s.src = window.RUNTIME_CONFIG.assetHost; document.head.appendChild(s);`,
      },
    ],
  });
  const hit = result.findings.find((f) => f.name === 'RUNTIME_CONFIG');
  assert.equal(hit, undefined, 'var in another script must protect the name');
});

test('an undeclared config in one script stays clobberable in another', () => {
  const result = scan({
    page: PAGE,
    scripts: [
      { id: 'bundle.js', code: `fetch(window.ANALYTICS_CONFIG.endpoint);` },
    ],
  });
  const hit = result.findings.find((f) => f.name === 'ANALYTICS_CONFIG');
  assert.ok(hit, 'undeclared config should still be reported');
  assert.equal(hit.severity === 'critical' || hit.severity === 'high', true);
});

test('topLevelVarNames finds var and function but not let/const/class', () => {
  const { parsed } = parseScripts([{ id: 's', code: `var A=1; function B(){} let C=2; const D=3; class E{}` }]);
  const names = topLevelVarNames(parsed[0]!);
  assert.equal(names.has('A'), true);
  assert.equal(names.has('B'), true);
  assert.equal(names.has('C'), false);
  assert.equal(names.has('D'), false);
  assert.equal(names.has('E'), false);
});

test('same-named locals in different functions do not share taint', () => {
  // `t` in the first function is a config (sink); `t` in the second is a
  // document element. Flow-insensitive, name-keyed taint would leak the first
  // `t`'s sink onto the second function's getElementById read.
  const code = `
    function a(){ var t = window.ANALYTICS_CONFIG || {}; var n = t.endpoint; fetch(n); }
    function b(){ var t = document.getElementById('app'); t.innerHTML = ''; }
  `;
  const { parsed } = parseScripts([{ id: 's', code }]);
  const reads = applyTaint(extractGlobalReads(parsed[0]!), new Map([['s', propagateTaint(parsed[0]!)]]));
  const gebi = reads.find((r) => r.name === 'getElementById');
  assert.ok(gebi);
  assert.equal(gebi.usages.includes('url-sink'), false, 'getElementById must not inherit another local t');
});
