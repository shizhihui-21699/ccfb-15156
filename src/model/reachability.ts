/**
 * Name reachability: given a name read from a page and the measured builtin
 * sets, decide whether named-element access can supply that name in each
 * engine, and in what shape.
 *
 * This is deliberately separate from "is the page vulnerable". Here we only ask
 * *can a DOM element with this id/name be observed through this lookup*.
 */

import type { Engine, EngineBuiltins, NamedAccessShape } from './engine-semantics.ts';
import { ENGINES, UNFORGEABLE_DOCUMENT_PROPERTIES } from './engine-semantics.ts';
import { loadEngineBuiltins } from './builtins.ts';

/** Where a name is being read from. */
export type AccessRoot = 'window' | 'document' | 'bare';

export interface Reachability {
  engine: Engine;
  /** True when an element with this name becomes visible through the lookup. */
  reachable: boolean;
  /** Why the name is or is not reachable. */
  reason:
    | 'free-name' // not a builtin: any contributing element is visible
    | 'shadows-prototype-member' // document only: element shadows Document.prototype
    | 'shadowed-by-builtin' // window: an existing chain member wins
    | 'unforgeable'; // document.location
}

/**
 * Can an element named `name` be observed through `root` in `engine`?
 *
 * - `window` is `[Global]`: named access is consulted only for names absent
 *   from the entire Window prototype chain.
 * - `document` is `[LegacyOverrideBuiltIns]`: named access precedes the
 *   prototype chain, so it shadows everything except own unforgeable props.
 * - `bare` identifier: behaves like `window` for *undeclared* names; callers
 *   that know a top-level declaration exists must not call this as `bare`
 *   (the analyzer resolves declarations first and treats declared names as
 *   protected).
 */
export function nameReachability(
  root: AccessRoot,
  name: string,
  builtins: EngineBuiltins,
): Reachability {
  const engine = builtins.engine;
  if (root === 'bare') {
    // An undeclared bare identifier falls through to the global object, whose
    // named access behaves like window.
    return builtins.windowChain.has(name)
      ? { engine, reachable: false, reason: 'shadowed-by-builtin' }
      : { engine, reachable: true, reason: 'free-name' };
  }
  if (root === 'window') {
    return builtins.windowChain.has(name)
      ? { engine, reachable: false, reason: 'shadowed-by-builtin' }
      : { engine, reachable: true, reason: 'free-name' };
  }
  // document
  if (UNFORGEABLE_DOCUMENT_PROPERTIES.has(name) || builtins.documentOwn.has(name)) {
    return { engine, reachable: false, reason: 'unforgeable' };
  }
  if (builtins.documentChain.has(name)) {
    return { engine, reachable: true, reason: 'shadows-prototype-member' };
  }
  return { engine, reachable: true, reason: 'free-name' };
}

/** Reachability for a name across every engine. */
export function reachabilityByEngine(
  root: AccessRoot,
  name: string,
  builtins = loadEngineBuiltins(),
): Record<Engine, Reachability> {
  const out = {} as Record<Engine, Reachability>;
  for (const engine of ENGINES) out[engine] = nameReachability(root, name, builtins[engine]);
  return out;
}

/**
 * The shape a lookup takes when *several* elements contribute the same window
 * name. Chrome and WebKit always give an HTMLCollection. Firefox gives the
 * first id-based contributor as a plain element, and only falls back to an
 * HTMLCollection when every contributor is name-based.
 *
 * `contributors` describes how each element contributed. Order matters (tree
 * order), because Firefox returns the first id contributor.
 */
export function multiContributorShape(
  engine: Engine,
  contributors: ReadonlyArray<{ via: 'id' | 'name' }>,
): NamedAccessShape {
  if (contributors.length <= 1) return 'single-element';
  if (engine === 'firefox') {
    const hasIdContributor = contributors.some((c) => c.via === 'id');
    if (hasIdContributor) return 'single-element';
    return 'html-collection';
  }
  return 'html-collection';
}
