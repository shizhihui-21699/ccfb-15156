/**
 * Unit tests for the analysis engine: severity, categories, impact, and the
 * protection/skip logic.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyze } from '../src/analysis/exploitability.ts';
import type { GlobalRead } from '../src/js/globals.ts';
import type { InjectionRegion, SanitizerProfile } from '../src/html/page.ts';
import { analyzePage } from '../src/html/page.ts';
import { PROFILES } from '../src/html/profiles.ts';

function read(over: Partial<GlobalRead>): GlobalRead {
  return {
    name: 'CONFIG',
    scope: 'window',
    kind: 'window-property',
    declaration: 'none',
    usages: ['property-read'],
    propertyPath: [],
    position: { line: 1, column: 0 },
    original: null,
    scriptId: 'app.js',
    looksLikeConfig: true,
    ...over,
  };
}

function region(profile: SanitizerProfile = PROFILES.unsafeInnerHtml()): InjectionRegion {
  const page = analyzePage({
    html: '<!doctype html><html><body><div id="sink"></div></body></html>',
    regions: [{ name: 'sink', selector: '#sink', profile }],
  });
  return page.regions[0]!;
}

test('a config global flowing to a URL sink is critical', () => {
  const result = analyze([read({ usages: ['url-sink'], name: 'APP_CONFIG' })], [region()]);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0]!.severity, 'critical');
  assert.equal(result.findings[0]!.impact, 'url-load');
  assert.equal(result.findings[0]!.category, 'config-global');
});

test('a protected var read is skipped', () => {
  const result = analyze([read({ declaration: 'var' })], [region()]);
  assert.equal(result.findings.length, 0);
  assert.ok(result.skipped.some((s) => s.reason.includes('beats named access')));
});

test('a window builtin is skipped', () => {
  const result = analyze([read({ name: 'fetch', kind: 'window-property' })], [region()]);
  assert.equal(result.findings.length, 0);
  assert.ok(result.skipped.some((s) => s.reason.includes('window built-in')));
});

test('document.location is skipped as unforgeable', () => {
  const result = analyze(
    [read({ name: 'location', scope: 'document', kind: 'document-property' })],
    [region()],
  );
  assert.equal(result.findings.length, 0);
});

test('document.cookie is a data-leak finding', () => {
  const result = analyze(
    [read({ name: 'cookie', scope: 'document', kind: 'document-property', looksLikeConfig: false })],
    [region()],
  );
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0]!.impact, 'data-leak');
  assert.equal(result.findings[0]!.category, 'document-member');
});

test('document.getElementById shadowing is reported but not as a takeover', () => {
  const result = analyze(
    [read({ name: 'getElementById', scope: 'document', kind: 'document-property', usages: ['call'], looksLikeConfig: false })],
    [region()],
  );
  assert.equal(result.findings.length, 1);
  assert.ok(['low', 'medium'].includes(result.findings[0]!.severity));
});

test('a pure document factory helper call is not a takeover', () => {
  const result = analyze(
    [read({ name: 'createElement', scope: 'document', kind: 'document-property', usages: ['call'], looksLikeConfig: false })],
    [region()],
  );
  // Either filtered, or only a low/info note — never a high finding.
  for (const f of result.findings) {
    assert.ok(['low', 'info'].includes(f.severity), `createElement should not be ${f.severity}`);
  }
});

test('a name with no reachable plan is not a finding', () => {
  const result = analyze([read({ name: 'APP_CONFIG', usages: ['url-sink'] })], [region(PROFILES.strictNoIdName())]);
  assert.equal(result.findings.length, 0);
});

test('findings are sorted by severity', () => {
  const result = analyze(
    [
      read({ name: 'CFG', usages: ['property-read'], looksLikeConfig: false }),
      read({ name: 'APP_CONFIG', usages: ['url-sink'] }),
    ],
    [region()],
  );
  assert.ok(result.findings.length >= 2);
  assert.equal(result.findings[0]!.severity, 'critical');
});

test('engines are split into affected and safe', () => {
  const result = analyze([read({ name: 'APP_CONFIG', usages: ['url-sink'] })], [region()], {
    engines: ['chrome', 'firefox'],
  });
  assert.equal(result.findings.length, 1);
  assert.deepEqual(result.findings[0]!.affectedEngines, ['chrome', 'firefox']);
});
