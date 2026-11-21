/**
 * Report rendering.
 *
 * Two formats: a human-readable text report for terminals and code review, and
 * a structured JSON report for CI. Both come from the same ScanResult so they
 * never disagree.
 *
 * Text reports are grouped by category and print remediation once per category,
 * because the fix for a clobbered config global and the fix for a clobbered
 * `document.cookie` are different but identical across all instances of each.
 */

import type { ScanResult } from '../scan.ts';
import type { Finding, FindingCategory, Severity } from '../analysis/exploitability.ts';
import { ENGINE_LABELS } from '../model/engine-semantics.ts';
import { probeProvenance } from '../model/builtins.ts';

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

const CATEGORY_LABEL: Record<FindingCategory, string> = {
  'config-global': 'Clobbered config global',
  'document-member': 'Clobbered document member',
  'library-global': 'Clobbered library global',
  'generic-global': 'Clobbered global',
};

/** Category-specific remediation, kept short; the generic checklist is last. */
const CATEGORY_FIX: Record<FindingCategory, string[]> = {
  'config-global': [
    'Keep configuration in a module-scoped `const` that is not reachable as a window property, and read it directly (not through `window.X`).',
    'If a global is unavoidable, create it with `window.CONFIG = {...}` (or a top-level `var`) before any untrusted HTML can be parsed; an own property wins over named access.',
    'Validate loaded script/asset URLs against an allowlist so a hostile base URL cannot load code.',
  ],
  'document-member': [
    'Capture document members before rendering untrusted HTML (`const getById = document.getElementById.bind(document)`), or call through the prototype (`Document.prototype.getElementById.call(document, id)`).',
    'Do not read `document.cookie` / `document.title` in code that runs after untrusted markup is in the DOM; read them once at startup.',
  ],
  'library-global': [
    'Load third-party libraries into a private variable instead of a public global, or verify the type before use (`if (typeof jQuery !== "function") throw ...`).',
  ],
  'generic-global': [
    'Declare the name as a module-scoped binding and reference it directly, or assign `window.<name>` explicitly before untrusted HTML is parsed.',
  ],
};

const GENERIC_FIX = [
  'Strip `id` and `name` from all elements in untrusted regions (e.g. DOMPurify with `FORBID_ATTR: ["id","name"]`); this removes the clobbering primitive entirely.',
  'Strip URL-bearing attributes (`href`, `src`, `data`, `action`) from elements inside rendered content, or force them through a URL allowlist.',
  'Adopt Trusted Types so every injection sink requires an explicit policy.',
];

function engineList(f: Finding): string {
  if (f.affectedEngines.length === 0) return 'none';
  if (f.affectedEngines.length === 3) return 'all engines';
  return f.affectedEngines.map((e) => ENGINE_LABELS[e]).join(', ');
}

function describePlan(f: Finding): string {
  // Collapse duplicate plans that differ only by region, then show the fewest
  // elements (simplest injection) and name the region(s).
  const regions = new Map<string, number>();
  for (const p of f.plans) regions.set(p.region.name, (regions.get(p.region.name) ?? 0) + 1);
  const regionText = [...regions.keys()].join(', ');
  const simplest = [...f.plans].sort((a, b) => a.elements.length - b.elements.length)[0];
  if (!simplest) return 'no injection region can supply this name';
  const markup = simplest.elements.map((e) => e.describe()).join(' inside ');
  return `${markup}  (region: ${regionText})`;
}

/** Render a human-readable report. */
export function renderText(result: ScanResult, options: { color?: boolean } = {}): string {
  const lines: string[] = [];
  const prov = probeProvenance();
  lines.push(`DOM clobbering scan — engine model measured ${prov.measuredAt}`);
  lines.push(
    `scripts=${result.stats.scripts}  reads=${result.stats.reads}  regions=${result.regions.filter((r) => r.element).length}  findings=${result.findings.length}`,
  );
  if (result.parseFailures.length) {
    lines.push(`parse failures: ${result.parseFailures.length}`);
    for (const f of result.parseFailures) lines.push(`  - ${f.message}`);
  }
  lines.push('');

  if (result.findings.length === 0) {
    lines.push('No exploitable clobbering found.');
    const unreachable = result.skipped.filter((s) => s.reason.includes('no injection region'));
    if (unreachable.length) {
      lines.push('');
      lines.push('Unprotected reads that no injection region can reach (for review):');
      for (const s of unreachable.slice(0, 15)) {
        lines.push(`  - ${s.read.name}  ${s.read.scriptId}:${s.read.position.line}`);
      }
      if (unreachable.length > 15) lines.push(`  ... and ${unreachable.length - 15} more`);
    }
    return lines.join('\n') + '\n';
  }

  // Group by category in a fixed, impact-ordered sequence.
  const order: FindingCategory[] = [
    'config-global',
    'library-global',
    'document-member',
    'generic-global',
  ];
  for (const category of order) {
    const group = result.findings.filter((f) => f.category === category);
    if (group.length === 0) continue;
    lines.push(`== ${CATEGORY_LABEL[category]} (${group.length}) ==`);
    lines.push('');
    for (const f of group) {
      lines.push(`  [${SEVERITY_LABEL[f.severity]}] ${f.name}  — impact: ${f.impact}`);
      lines.push(`      read:   ${f.read.scriptId}:${f.read.position.line}:${f.read.position.column} (${f.read.kind})`);
      lines.push(`      where:  ${engineList(f)}`);
      lines.push(`      inject: ${describePlan(f)}`);
      lines.push(`      why:`);
      for (const r of f.reasons) lines.push(`        - ${r}`);
      lines.push('');
    }
    lines.push(`  Fix for ${CATEGORY_LABEL[category].toLowerCase()}:`);
    for (const r of CATEGORY_FIX[category]) lines.push(`    - ${r}`);
    lines.push(`  Also, for every untrusted region:`);
    for (const r of GENERIC_FIX) lines.push(`    - ${r}`);
    lines.push('');
  }
  return lines.join('\n');
}

export interface JsonReport {
  tool: 'clobber-scan';
  model: { measuredAt: string; method: string };
  summary: {
    findings: number;
    bySeverity: Record<Severity, number>;
    byCategory: Record<FindingCategory, number>;
    scripts: number;
    reads: number;
    regions: number;
    parseFailures: number;
  };
  findings: Array<{
    id: string;
    name: string;
    category: FindingCategory;
    impact: string;
    severity: Severity;
    scope: string;
    read: {
      scriptId: string;
      line: number;
      column: number;
      kind: string;
      declaration: string;
      usages: string[];
      propertyPath: string[];
      original: unknown;
    };
    affectedEngines: string[];
    safeEngines: string[];
    injection: Array<{
      region: string;
      elements: Array<{ tag: string; describe: string }>;
    }>;
    reasons: string[];
    remediation: string[];
  }>;
  parseFailures: Array<{ scriptId: string; detail: string }>;
}

/** Render a machine-readable report. */
export function renderJson(result: ScanResult): JsonReport {
  const prov = probeProvenance();
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  const byCategory: Record<FindingCategory, number> = {
    'config-global': 0,
    'document-member': 0,
    'library-global': 0,
    'generic-global': 0,
  };
  for (const f of result.findings) {
    bySeverity[f.severity]++;
    byCategory[f.category]++;
  }
  return {
    tool: 'clobber-scan',
    model: prov,
    summary: {
      findings: result.findings.length,
      bySeverity,
      byCategory,
      scripts: result.stats.scripts,
      reads: result.stats.reads,
      regions: result.regions.filter((r) => r.element).length,
      parseFailures: result.parseFailures.length,
    },
    findings: result.findings.map((f) => ({
      id: f.id,
      name: f.name,
      category: f.category,
      impact: f.impact,
      severity: f.severity,
      scope: f.scope,
      read: {
        scriptId: f.read.scriptId,
        line: f.read.position.line,
        column: f.read.position.column,
        kind: f.read.kind,
        declaration: f.read.declaration,
        usages: f.read.usages,
        propertyPath: f.read.propertyPath,
        original: f.read.original,
      },
      affectedEngines: f.affectedEngines,
      safeEngines: f.safeEngines,
      injection: f.plans.map((p) => ({
        region: p.region.name,
        elements: p.elements.map((e) => ({ tag: e.tagName, describe: e.describe() })),
      })),
      reasons: f.reasons,
      remediation: [...CATEGORY_FIX[f.category], ...GENERIC_FIX],
    })),
    parseFailures: result.parseFailures.map((p) => ({ scriptId: p.scriptId, detail: p.detail })),
  };
}
