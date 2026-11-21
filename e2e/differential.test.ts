/**
 * Differential validation: the scanner and real browsers judge the same pages
 * independently, and the suite asserts they agree.
 *
 * For each corpus case we check two things:
 *
 *  1. The scanner's verdict (does it report the expected finding, at roughly the
 *     expected severity?) matches the declared expectation.
 *  2. Running the case's probe in each engine produces the fired/not-fired
 *     outcome the scanner's engine model predicts.
 *
 * The second check is the important one: it is what stops the tool's browser
 * model from silently drifting away from real behaviour.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { CASES } from './corpus.ts';
import type { TestCase } from './corpus.ts';
import { availableEngines, runProbe } from './browser.ts';
import type { EngineName } from './browser.ts';
import { scan } from '../src/scan.ts';
import type { ScanResult } from '../src/scan.ts';
import { PROFILES } from '../src/html/profiles.ts';


type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function scanCase(c: TestCase): ScanResult {
  return scan({
    page: {
      html: c.page.html,
      regions: c.page.regions.map((r) => ({
        name: r.name,
        selector: r.selector,
        profile: (PROFILES as unknown as Record<string, () => ReturnType<typeof PROFILES.unsafeInnerHtml>>)[r.profile]!(),
      })),
    },
    scripts: c.scripts.map((s) => ({ id: s.id, code: s.code, kind: s.kind ?? 'script' })),
  });
}

const engines = availableEngines();

// ---------------------------------------------------------------------------
// Static-only assertions: run even when no browser is available.
// ---------------------------------------------------------------------------

for (const c of CASES) {
  test(`scan: ${c.id}`, () => {
    const result = scanCase(c);
    if (c.expectedFinding) {
      const finding = result.findings.find((f) => f.name === c.expectedFinding);
      assert.ok(
        finding,
        `expected a finding for "${c.expectedFinding}" but got: ${result.findings.map((f) => f.name).join(', ') || '(none)'}`,
      );
      if (c.expectedSeverity) {
        assert.ok(
          SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[c.expectedSeverity],
          `expected severity >= ${c.expectedSeverity}, got ${finding.severity} for ${c.expectedFinding}`,
        );
      }
    } else {
      assert.equal(
        result.findings.length,
        0,
        `expected no findings but got: ${result.findings.map((f) => `${f.name}(${f.severity})`).join(', ')}`,
      );
    }
  });
}

// ---------------------------------------------------------------------------
// Differential assertions: only when at least one engine is available.
// ---------------------------------------------------------------------------

for (const c of CASES) {
  test(`browser: ${c.id}`, async (t) => {
    if (engines.length === 0) {
      t.skip('no browser engines available (run `npm run setup:browsers`)');
      return;
    }
    const result = scanCase(c);
    const finding = c.expectedFinding ? result.findings.find((f) => f.name === c.expectedFinding) : null;

    for (const engine of engines) {
      const expected = expectedFiredFor(c, engine, finding?.affectedEngines);
      const outcome = await runProbe(
        engine,
        {
          html: c.page.html,
          scripts: [{ path: `/${c.scripts[0]?.id ?? 'app.js'}`, body: c.scripts[0]?.code ?? '', kind: c.scripts[0]?.kind }],
          attackerBody: 'window.__fired = true;',
        },
        c.probe.injectInto,
        c.probe.payload,
        c.probe.signal,
      );
      assert.equal(
        outcome.fired,
        expected,
        `${c.id} in ${engine}: expected fired=${expected}, got ${outcome.fired} (raw=${JSON.stringify(outcome.raw)}; errors=${outcome.pageErrors.join(' | ')})`,
      );
    }
  });
}

function expectedFiredFor(
  c: TestCase,
  engine: EngineName,
  affected: Array<'chrome' | 'firefox' | 'webkit'> | undefined,
): boolean {
  const exp = c.probe.expectedEngines ?? 'all';
  if (exp === 'none') return false;
  if (exp === 'all') return affected ? affected.includes(engine) : true;
  return exp.includes(engine);
}
