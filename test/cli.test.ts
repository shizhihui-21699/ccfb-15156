/**
 * CLI tests: exercise the full path from a spec file to rendered output, using
 * the fixtures on disk, so the tested surface matches what users run.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, copyFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { runCli } from '../src/cli.ts';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => resolve(here, 'fixtures', name, 'spec.json');

test('vulnerable fixture reports a critical config finding', () => {
  const { exitCode, output } = runCli([fixture('vulnerable')]);
  assert.equal(exitCode, 0);
  assert.match(output, /CRITICAL/);
  assert.match(output, /APP_CONFIG/);
  assert.match(output, /url-load/);
});

test('vulnerable fixture emits a fix block per category', () => {
  const { output } = runCli([fixture('vulnerable')]);
  assert.match(output, /Fix for clobbered config global/);
  assert.match(output, /Strip `id` and `name`/);
});

test('safe fixture reports no findings', () => {
  const { output } = runCli([fixture('safe')]);
  assert.match(output, /No exploitable clobbering found/);
});

test('--json produces parseable structured output', () => {
  const { output } = runCli([fixture('vulnerable'), '--json']);
  const parsed = JSON.parse(output);
  assert.equal(parsed.tool, 'clobber-scan');
  assert.ok(parsed.summary.findings >= 1);
  assert.ok(Array.isArray(parsed.findings));
  assert.equal(parsed.model.measuredAt.length > 0, true);
});

test('--fail-on critical exits non-zero for the vulnerable fixture', () => {
  const { exitCode } = runCli([fixture('vulnerable'), '--fail-on', 'critical']);
  assert.equal(exitCode, 1);
});

test('--fail-on critical exits zero for the safe fixture', () => {
  const { exitCode } = runCli([fixture('safe'), '--fail-on', 'critical']);
  assert.equal(exitCode, 0);
});

test('--engines restricts the model', () => {
  const { output } = runCli([fixture('vulnerable'), '--json', '--engines', 'firefox']);
  const parsed = JSON.parse(output);
  for (const f of parsed.findings) {
    for (const e of f.affectedEngines) assert.equal(e, 'firefox');
  }
});

test('--engines rejects unknown engines', () => {
  const { exitCode, output } = runCli([fixture('safe'), '--engines', 'netscape']);
  assert.equal(exitCode, 2);
  assert.match(output, /unknown engine/);
});

test('--help prints usage', () => {
  const { exitCode, output } = runCli(['--help']);
  assert.equal(exitCode, 0);
  assert.match(output, /Usage: clobber-scan/);
});

test('missing spec exits 2 with a message', () => {
  const { exitCode, output } = runCli(['/nonexistent/spec.json']);
  assert.equal(exitCode, 2);
  assert.match(output, /failed to load spec/);
});

test('inline html and code in a spec work', () => {
  const dir = mkdtempSync(join(tmpdir(), 'clobber-spec-'));
  const specPath = join(dir, 'spec.json');
  writeFileSync(
    specPath,
    JSON.stringify({
      page: {
        html: '<!doctype html><html><body><div id="s"></div></body></html>',
        regions: [{ name: 's', selector: '#s', profile: 'unsafeInnerHtml' }],
      },
      scripts: [
        {
          id: 'app.js',
          code: "var s=document.createElement('script'); s.src = APP_CONFIG + ''; document.head.appendChild(s);",
        },
      ],
    }),
  );
  const { output } = runCli([specPath, '--json']);
  const parsed = JSON.parse(output);
  assert.ok(parsed.findings.some((f: { name: string }) => f.name === 'APP_CONFIG'));
});
