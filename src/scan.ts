/**
 * Scan orchestration: page + scripts in, finding report out.
 *
 * This is the single entry point the CLI and tests share, so a report produced
 * in a test is byte-for-byte what the tool emits on the command line.
 */

import { readFileSync } from 'node:fs';
import type { Engine } from './model/engine-semantics.ts';
import { ENGINES } from './model/engine-semantics.ts';
import { loadEngineBuiltins } from './model/builtins.ts';
import type { EngineBuiltins } from './model/engine-semantics.ts';
import type { ScriptSource } from './js/parse.ts';
import { parseScripts, ScriptParseError } from './js/parse.ts';
import { extractGlobalReads } from './js/globals.ts';
import { propagateTaint, applyTaint } from './js/taint.ts';
import type { PageSpec } from './html/page.ts';
import { analyzePage } from './html/page.ts';
import type { InjectionRegion } from './html/page.ts';
import type { Finding, SkippedRead } from './analysis/exploitability.ts';
import { analyze } from './analysis/exploitability.ts';

export interface ScanInput {
  /** Page specification: HTML plus declared injection regions. */
  page: PageSpec;
  /** Scripts loaded by the page (inline and external), already extracted. */
  scripts: readonly ScriptSource[];
  engines?: readonly Engine[];
}

export interface ScanResult {
  findings: Finding[];
  skipped: SkippedRead[];
  regions: InjectionRegion[];
  parseFailures: ScriptParseError[];
  /** Diagnostics for the report. */
  stats: {
    scripts: number;
    reads: number;
    taintIterations: number;
  };
}

/**
 * Run a full scan.
 */
export function scan(input: ScanInput, builtins: Record<Engine, EngineBuiltins> = loadEngineBuiltins()): ScanResult {
  const engines = input.engines ?? ENGINES;
  const { parsed, failures } = parseScripts(input.scripts);

  const rawReads = parsed.flatMap((p) => extractGlobalReads(p));

  let taintIterations = 0;
  const taintByScript = new Map<string, ReturnType<typeof propagateTaint>>();
  for (const p of parsed) {
    const t = propagateTaint(p);
    taintIterations += t.iterations;
    taintByScript.set(p.source.id, t);
  }
  const reads = applyTaint(rawReads, taintByScript);

  const page = analyzePage(input.page);
  const { findings, skipped } = analyze(reads, page.regions, { engines, builtins });

  return {
    findings,
    skipped,
    regions: page.regions,
    parseFailures: failures,
    stats: {
      scripts: parsed.length,
      reads: reads.length,
      taintIterations,
    },
  };
}

/** Convenience: read script sources from disk. */
export function readScripts(files: readonly { id: string; path: string; kind?: 'script' | 'module' }[]): ScriptSource[] {
  return files.map((f) => ({ id: f.id, kind: f.kind ?? 'script', code: readFileSync(f.path, 'utf8') }));
}
