/**
 * `clobber-scan` command line entry point.
 *
 * Usage:
 *   clobber-scan <spec.json> [--json] [--fail-on high] [--engines chrome,firefox]
 *
 * The spec file describes a page, its injection regions, and its scripts:
 *
 *   {
 *     "page": { "htmlFile": "page.html", "regions": [ ... ] },
 *     "scripts": [ { "id": "bundle.js", "path": "bundle.js" } ]
 *   }
 *
 * Paths are resolved relative to the spec file. A spec can also inline the
 * HTML (`"html"`) and inline script code (`"code"`), which keeps tests and
 * fixtures self-contained.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { parseArgs } from 'node:util';

import { ENGINES } from './model/engine-semantics.ts';
import type { Engine } from './model/engine-semantics.ts';
import { scan } from './scan.ts';
import type { ScanResult } from './scan.ts';
import type { PageSpec, RegionSpec } from './html/page.ts';
import type { ScriptSource } from './js/parse.ts';
import { PROFILES } from './html/profiles.ts';
import { renderJson, renderText } from './report/render.ts';
import type { Severity } from './analysis/exploitability.ts';

interface SpecFile {
  page: {
    html?: string;
    htmlFile?: string;
    regions: Array<{ name: string; selector: string; profile?: keyof typeof PROFILES }>;
  };
  scripts: Array<{ id: string; path?: string; code?: string; kind?: 'script' | 'module' }>;
  engines?: Engine[];
}

const SEVERITY_ORDER: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function loadSpec(specPath: string): { page: PageSpec; scripts: ScriptSource[]; engines?: Engine[] } {
  const raw = JSON.parse(readFileSync(specPath, 'utf8')) as SpecFile;
  const base = dirname(resolve(specPath));

  const html = raw.page.html ?? readFileSync(join(base, raw.page.htmlFile!), 'utf8');
  const regions: RegionSpec[] = raw.page.regions.map((r) => ({
    name: r.name,
    selector: r.selector,
    profile: r.profile ? PROFILES[r.profile]() : PROFILES.unsafeInnerHtml(),
  }));

  const scripts: ScriptSource[] = raw.scripts.map((s) => {
    if (s.code != null) return { id: s.id, code: s.code, kind: s.kind ?? 'script' };
    if (s.path) return { id: s.id, path: s.path, code: readFileSync(join(base, s.path), 'utf8'), kind: s.kind ?? 'script' } as ScriptSource;
    throw new Error(`script "${s.id}" has neither "path" nor "code"`);
  });

  return { page: { html, regions }, scripts, engines: raw.engines };
}

function usage(): string {
  return `Usage: clobber-scan <spec.json> [options]

Options:
  --json                 emit JSON instead of text
  --out <file>           write the report to a file
  --fail-on <severity>   exit non-zero when a finding at or above this severity exists
                         (one of: info, low, medium, high, critical)
  --engines <list>       restrict the engine model (comma-separated)
  -h, --help             show this help
`;
}

export interface CliResult {
  exitCode: number;
  output: string;
}

/**
 * Run the CLI. Returned rather than calling process.exit so tests can drive it
 * directly.
 */
export function runCli(argv: readonly string[]): CliResult {
  let parsedArgs;
  try {
    parsedArgs = parseArgs({
      args: argv as string[],
      allowPositionals: true,
      options: {
        json: { type: 'boolean', default: false },
        out: { type: 'string' },
        'fail-on': { type: 'string' },
        engines: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    });
  } catch (err) {
    return { exitCode: 2, output: `${err instanceof Error ? err.message : String(err)}\n\n${usage()}` };
  }
  const { values, positionals } = parsedArgs;

  if (values.help || positionals.length === 0) {
    return { exitCode: values.help ? 0 : 2, output: usage() };
  }

  const specPath = positionals[0]!;
  let input;
  try {
    input = loadSpec(specPath);
  } catch (err) {
    return { exitCode: 2, output: `failed to load spec ${specPath}: ${err instanceof Error ? err.message : String(err)}\n` };
  }

  let engines: readonly Engine[] | undefined = input.engines;
  if (values.engines) {
    const wanted = values.engines.split(',').map((s) => s.trim()).filter(Boolean) as Engine[];
    const unknown = wanted.filter((e) => !ENGINES.includes(e));
    if (unknown.length) {
      return { exitCode: 2, output: `unknown engine(s): ${unknown.join(', ')} (known: ${ENGINES.join(', ')})\n` };
    }
    engines = wanted;
  }

  let result: ScanResult;
  try {
    result = scan({ page: input.page, scripts: input.scripts, ...(engines ? { engines } : {}) });
  } catch (err) {
    return { exitCode: 2, output: `scan failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n` };
  }

  const output = values.json ? JSON.stringify(renderJson(result), null, 2) + '\n' : renderText(result);

  if (values.out) {
    writeFileSync(values.out, output, 'utf8');
  }

  let exitCode = 0;
  if (values['fail-on']) {
    const threshold = values['fail-on'] as Severity;
    if (!(threshold in SEVERITY_ORDER)) {
      return { exitCode: 2, output: `unknown --fail-on severity "${threshold}"\n` };
    }
    const worst = result.findings.reduce(
      (m, f) => Math.max(m, SEVERITY_ORDER[f.severity]),
      -1,
    );
    if (worst >= SEVERITY_ORDER[threshold]) exitCode = 1;
  }

  return { exitCode, output };
}

const isMain = process.argv[1] && import.meta.url === `file://${resolve(process.argv[1])}`;
if (isMain) {
  const { exitCode, output } = runCli(process.argv.slice(2));
  process.stdout.write(output);
  process.exit(exitCode);
}
