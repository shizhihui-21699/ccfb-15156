/**
 * Precision tests: clean, modern code must produce no findings.
 *
 * A security scanner that reports phantom issues gets switched off. These tests
 * pin the environment and shadowing handling that keeps real-world modules
 * quiet while still detecting genuine clobbering.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseScripts } from '../src/js/parse.ts';
import { extractGlobalReads } from '../src/js/globals.ts';
import { applyTaint, propagateTaint } from '../src/js/taint.ts';
import { analyze } from '../src/analysis/exploitability.ts';
import { analyzePage } from '../src/html/page.ts';
import { PROFILES } from '../src/html/profiles.ts';
import { isEnvironmentGlobal, looksLikeNodeModule } from '../src/js/environment.ts';

function findingsFor(code: string, kind: 'script' | 'module' = 'script') {
  const page = analyzePage({
    html: '<!doctype html><body><div id="s"></div></body>',
    regions: [{ name: 's', selector: '#s', profile: PROFILES.unsafeInnerHtml() }],
  });
  const { parsed } = parseScripts([{ id: 'x', code, kind }]);
  const reads = applyTaint(extractGlobalReads(parsed[0]!), new Map([['x', propagateTaint(parsed[0]!)]]));
  return analyze(reads, page.regions);
}

test('Node/CommonJS globals are recognised', () => {
  for (const name of ['require', 'process', 'Buffer', 'module', 'exports', '__dirname', 'setImmediate']) {
    assert.equal(isEnvironmentGlobal(name), true, `${name} should be an environment global`);
  }
  assert.equal(isEnvironmentGlobal('APP_CONFIG'), false);
});

test('CommonJS module patterns produce no findings', () => {
  const code = `
    var fs = require('fs');
    module.exports = function (opts) {
      var self = this;
      self.path = opts.path;
      process.nextTick(function () { fs.readFile(self.path, Buffer.alloc(0), function(){}); });
    };
  `;
  const result = findingsFor(code);
  assert.equal(result.findings.length, 0, result.findings.map((f) => f.name).join(','));
});

test('a local named self is not the window alias', () => {
  const code = `
    function ZipFile(fileSize) {
      var self = this;
      self.fileSize = fileSize;
      self.read = function () { return self.fileSize; };
    }
  `;
  const result = findingsFor(code);
  assert.equal(result.findings.length, 0);
});

test('ES module re-exports are not global reads', () => {
  const code = `
    export * as Token from './token.js';
    export { Parser } from './parser.js';
  `;
  const result = findingsFor(code, 'module');
  assert.equal(result.findings.length, 0);
});

test('looksLikeNodeModule separates server code from browser code', () => {
  assert.equal(looksLikeNodeModule("const fs = require('fs'); module.exports = {};"), true);
  assert.equal(looksLikeNodeModule("document.getElementById('x'); var a = window.CONFIG;"), false);
  // A file with both markers stays in scope.
  assert.equal(looksLikeNodeModule("var a = require('x'); document.body;"), false);
});

test('real library sources yield no findings', (t) => {
  const here = dirname(fileURLToPath(import.meta.url));
  const root = resolve(here, '..');
  const candidates = [
    'node_modules/yauzl/index.js',
    'node_modules/streamx/index.js',
    'node_modules/lru-cache/index.js',
  ].map((p) => resolve(root, p));
  const present = candidates.filter((p) => existsSync(p));
  if (present.length === 0) {
    t.skip('sample libraries not installed');
    return;
  }
  for (const path of present) {
    const code = readFileSync(path, 'utf8');
    const result = findingsFor(code, 'script');
    assert.equal(
      result.findings.length,
      0,
      `${path}: unexpected findings ${result.findings.map((f) => `${f.name}/${f.severity}`).join(', ')}`,
    );
  }
});
