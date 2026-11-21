/**
 * JavaScript parsing and normalisation.
 *
 * Pages ship bundled, minified, possibly ES-module code. This module turns
 * one or more script sources into a single analysable program with:
 *
 *  - a stable source identity for every file,
 *  - a parse that survives both script and module syntax,
 *  - optional source-map support so findings point at original files,
 *  - per-script scope analysis used later to tell declared globals from free
 *    identifiers.
 *
 * It deliberately does not try to *beautify* or rename anything: the analyzer
 * works on names and scopes, not formatting, so minified input needs no
 * deobfuscation step.
 */

import * as acorn from 'acorn';
import * as eslintScope from 'eslint-scope';
import { SourceMapConsumer } from 'source-map-js';
import type * as estree from 'estree';

export interface ScriptSource {
  /** Stable id, typically the file path or bundle URL. */
  id: string;
  code: string;
  /** `module` when loaded as an ES module, else `script`. */
  kind?: 'script' | 'module';
  /** Raw source-map JSON, if one is available. */
  sourceMap?: string;
}

export interface SourcePosition {
  line: number;
  column: number;
}

export interface OriginalLocation {
  source: string;
  line: number;
  column: number;
}

export interface ParsedScript {
  source: ScriptSource;
  ast: acorn.Program;
  scopeManager: eslintScope.ScopeManager;
  /** Maps a generated position back to the original file, when a source map exists. */
  originalPosition: (pos: SourcePosition) => OriginalLocation | null;
}

export class ScriptParseError extends Error {
  readonly scriptId: string;
  readonly detail: string;
  constructor(scriptId: string, detail: string) {
    super(`failed to parse ${scriptId}: ${detail}`);
    this.name = 'ScriptParseError';
    this.scriptId = scriptId;
    this.detail = detail;
  }
}

const ACORN_OPTIONS = {
  ecmaVersion: 'latest',
  allowReturnOutsideFunction: true,
  allowAwaitOutsideFunction: true,
  allowHashBang: true,
  locations: true,
  ranges: true,
} as const;

/**
 * Parse a single script, trying the declared kind first and then the other one.
 * Bundlers emit both shapes; a mismatch between how a file was *loaded* and how
 * the analyzer *parses* it would change scope conclusions, so we record the
 * kind that actually parsed.
 */
export function parseScript(source: ScriptSource): ParsedScript {
  const preferred = source.kind ?? 'script';
  const attempts: Array<'script' | 'module'> =
    preferred === 'module' ? ['module', 'script'] : ['script', 'module'];

  let ast: acorn.Program | null = null;
  let usedKind: 'script' | 'module' = preferred;
  let firstError: unknown = null;
  for (const kind of attempts) {
    try {
      ast = acorn.parse(source.code, {
        ...ACORN_OPTIONS,
        sourceType: kind,
      }) as acorn.Program;
      usedKind = kind;
      break;
    } catch (err) {
      if (!firstError) firstError = err;
    }
  }
  if (!ast) {
    const detail = firstError instanceof Error ? firstError.message : String(firstError);
    throw new ScriptParseError(source.id, detail);
  }

  const scopeManager = eslintScope.analyze(ast as unknown as estree.Program, {
    ecmaVersion: 2022,
    sourceType: usedKind,
    optimistic: true,
    ignoreEval: true,
    // Direct eval can introduce bindings we cannot see; we handle eval reads
    // separately in the analyzer rather than widening every scope here.
    impliedStrict: usedKind === 'module',
  });

  const originalPosition = makeOriginalPosition(source);

  return {
    source: { ...source, kind: usedKind },
    ast,
    scopeManager,
    originalPosition,
  };
}

function makeOriginalPosition(
  source: ScriptSource,
): (pos: SourcePosition) => OriginalLocation | null {
  if (!source.sourceMap) return () => null;
  let consumer: SourceMapConsumer | null = null;
  try {
    consumer = new SourceMapConsumer(JSON.parse(source.sourceMap));
  } catch {
    return () => null;
  }
  const c = consumer;
  if (!c) return () => null;
  return (pos) => {
    try {
      const orig = c.originalPositionFor({
        line: pos.line,
        column: pos.column,
      });
      if (orig.source == null || orig.line == null) return null;
      return { source: orig.source, line: orig.line, column: orig.column ?? 0 };
    } catch {
      return null;
    }
  };
}

/**
 * Parse a list of scripts. Failures are returned rather than thrown so the CLI
 * can report unparsable third-party bundles without abandoning the scan.
 */
export interface ParseBatchResult {
  parsed: ParsedScript[];
  failures: ScriptParseError[];
}

export function parseScripts(sources: readonly ScriptSource[]): ParseBatchResult {
  const parsed: ParsedScript[] = [];
  const failures: ScriptParseError[] = [];
  for (const s of sources) {
    try {
      parsed.push(parseScript(s));
    } catch (err) {
      if (err instanceof ScriptParseError) failures.push(err);
      else
        failures.push(
          new ScriptParseError(s.id, err instanceof Error ? err.message : String(err)),
        );
    }
  }
  return { parsed, failures };
}
