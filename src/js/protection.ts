/**
 * Protection: is a global read actually shielded from named-element access?
 *
 * This is where the measured declaration semantics turn into a yes/no. The
 * result feeds exploitability, and every verdict carries a reason so the report
 * can explain itself.
 */

import type { DeclarationProvenance, GlobalRead, ReadKind } from './globals.ts';

export type Protection =
  | 'declared-var' // top-level var/function: own window property wins
  | 'declared-import' // module import: never a global
  | 'lexical-bare-read' // top-level let/const, read as a bare identifier
  | 'lexical-window-read' // top-level let/const, read as window.X (UNSAFE)
  | 'undeclared' // free name: falls through to named access (UNSAFE)
  | 'document-member' // document.* read: only `location` is safe
  | 'unknown';

export interface ProtectionVerdict {
  protection: Protection;
  /** True when a DOM element cannot supply this lookup. */
  protectedFromClobber: boolean;
  reason: string;
}

function isWindowOrGlobalKind(kind: ReadKind): boolean {
  return (
    kind === 'window-property' ||
    kind === 'window-computed' ||
    kind === 'self-property' ||
    kind === 'globalThis-property' ||
    kind === 'this-property' ||
    kind === 'destructured-window'
  );
}

function isDocumentKind(kind: ReadKind): boolean {
  return kind === 'document-property' || kind === 'document-computed' || kind === 'destructured-document';
}

/**
 * Decide whether a single read is shielded by JavaScript semantics.
 *
 * Document-read shielding depends on the engine's protected-property list and
 * is handled by the reachability model; here we only classify the obvious
 * `document.location` case and defer the rest.
 */
export function protectionOf(read: GlobalRead): ProtectionVerdict {
  if (isDocumentKind(read.kind)) {
    return {
      protection: 'document-member',
      protectedFromClobber: false,
      reason:
        'read of a document member; named access shadows Document.prototype (only document.location is unforgeable)',
    };
  }

  if (read.declaration === 'import') {
    return {
      protection: 'declared-import',
      protectedFromClobber: true,
      reason: 'module import binding; not reachable as a global',
    };
  }

  if (read.kind === 'bare-identifier') {
    switch (read.declaration) {
      case 'var':
        return {
          protection: 'declared-var',
          protectedFromClobber: true,
          reason: 'top-level var/function installs an own window property that beats named access',
        };
      case 'lexical':
        return {
          protection: 'lexical-bare-read',
          protectedFromClobber: true,
          reason: 'top-level let/const/class is lexical; the bare identifier resolves to it',
        };
      case 'none':
      default:
        return {
          protection: 'undeclared',
          protectedFromClobber: false,
          reason: 'undeclared free identifier falls through to the global object and named access',
        };
    }
  }

  if (isWindowOrGlobalKind(read.kind)) {
    if (read.declaration === 'var') {
      return {
        protection: 'declared-var',
        protectedFromClobber: true,
        reason: 'top-level var/function property on window beats named access',
      };
    }
    if (read.declaration === 'none') {
      return {
        protection: 'undeclared',
        protectedFromClobber: false,
        reason:
          'no window property exists for this name, so the window.X lookup falls through to named access',
      };
    }
    // A top-level let/const does NOT install a window property. Reading the
    // name through `window` therefore reaches named access while the lexical
    // binding is invisible. This is the bundled-code hazard.
    return {
      protection: 'lexical-window-read',
      protectedFromClobber: false,
      reason:
        'top-level let/const does not create a window property; window.X bypasses the lexical binding and reaches named access',
    };
  }

  return {
    protection: 'unknown',
    protectedFromClobber: false,
    reason: 'unclassified access shape',
  };
}

/** Convenience: the declaration kinds that make a read unsafe. */
export function isUnprotectedRead(read: GlobalRead): boolean {
  return !protectionOf(read).protectedFromClobber;
}
