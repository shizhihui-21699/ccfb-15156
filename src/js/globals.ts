/**
 * Global-read extraction.
 *
 * Scripts read globals in many shapes. This module turns a parsed program into
 * a list of *observations*: a name, how it was read, and whether the read is
 * protected by a top-level declaration.
 *
 * The key semantic split, measured in all three engines:
 *
 *  - A `var`/`function` declaration at top level installs an own property on
 *    `window`. Named access never beats it, so `window.X` is protected.
 *  - A top-level `let`/`const`/`class` is lexical. Bare `X` resolves to it,
 *    but `window.X` / `self.X` / `globalThis.X` do **not** — those fall through
 *    to named access and can be clobbered. This is the most under-appreciated
 *    hazard in bundled code, where everything lives in one module scope.
 *  - An undeclared free identifier falls through to the global object, so it is
 *    clobberable exactly like `window.X`.
 *
 * Reads are also classified by *use* (a URL sink, a config lookup, a call, a
 * typeof guard) because that drives exploitability in the next stage.
 */

import * as walk from 'acorn-walk';
import type * as estree from 'estree';
import type { ParsedScript, SourcePosition } from './parse.ts';
import { isEnvironmentGlobal } from './environment.ts';

export type ReadKind =
  | 'bare-identifier' // `CONFIG`
  | 'window-property' // `window.CONFIG`
  | 'globalThis-property' // `globalThis.CONFIG`
  | 'self-property' // `self.CONFIG`
  | 'this-property' // `this.CONFIG` at top level
  | 'window-computed' // `window['CONFIG']`
  | 'document-property' // `document.cookie`
  | 'document-computed' // `document['cookie']`
  | 'destructured-window' // `const { CONFIG } = window`
  | 'destructured-document'; // `const { cookie } = document`

export type DeclarationProvenance =
  | 'none' // no top-level binding: free global
  | 'var' // var/function: protected own property on window
  | 'lexical' // let/const/class: bare reads safe, window.X reads unsafe
  | 'import'; // module import: shadowed entirely, not global

/** How the value is then used. */
export type UsageKind =
  | 'type-test' // typeof X, X == null, Boolean(X)
  | 'call' // X(), X.y(), new X()
  | 'property-read' // X.y
  | 'index-read' // X[...]
  | 'iteration' // for..of X, spread, Array.from(X)
  | 'url-sink' // flows into src/href/action/fetch/import
  | 'string-coerce' // `${X}`, X + '', String(X)
  | 'assignment-target' // X = ...

export interface GlobalRead {
  /** The identifier or property name being read. */
  name: string;
  /** Whether the lookup targets the global object or the Document. */
  scope: 'window' | 'document';
  kind: ReadKind;
  declaration: DeclarationProvenance;
  usages: UsageKind[];
  /** Property path read beneath the name, e.g. ['cdn'] for `CONFIG.cdn`. */
  propertyPath: string[];
  /** Position in the generated script. */
  position: SourcePosition;
  /** Original position after source-map lookup, when available. */
  original: { source: string; line: number; column: number } | null;
  /** Script the read came from. */
  scriptId: string;
  /** True when the read looks like a config/settings lookup by name. */
  looksLikeConfig: boolean;
}

/** Which object a read kind targets: the global object or the Document. */
const KIND_SCOPE: Record<ReadKind, 'window' | 'document'> = {
  'bare-identifier': 'window',
  'window-property': 'window',
  'globalThis-property': 'window',
  'self-property': 'window',
  'this-property': 'window',
  'window-computed': 'window',
  'destructured-window': 'window',
  'document-property': 'document',
  'document-computed': 'document',
  'destructured-document': 'document',
};

/** Identifiers that refer to the global object itself. */
export const WINDOW_ALIASES = new Set(['window', 'self', 'globalThis', 'frames', 'parent', 'top']);
export const DOCUMENT_ALIASES = new Set(['document']);

/** Property names that are URL sinks when one reads `<expr>.PROP`. */
const URL_SINK_PROPS = new Set([
  'src',
  'href',
  'action',
  'formAction',
  'data',
  'poster',
  'srcset',
  'ping',
]);

/** Callee names that consume a URL. */
const URL_SINK_CALLEES = new Set(['fetch', 'import', 'open', 'assign', 'replace', 'navigate']);

function isWindowRoot(name: string): boolean {
  return WINDOW_ALIASES.has(name);
}

function isDocumentRoot(name: string): boolean {
  return DOCUMENT_ALIASES.has(name);
}

/** Names that are clearly application config/settings globals. */
const CONFIG_NAME =
  /^(?:[A-Z][A-Z0-9_]*_(?:CONFIG|SETTINGS|ENV|OPTIONS)|APP_[A-Z0-9_]+|CONFIG|config|settings|__INITIAL_STATE__|__NEXT_DATA__|__APP_CONFIG__|__ENV__|initialState|jQuery|\$|gapi|_)$/;

function looksLikeConfigName(name: string): boolean {
  return CONFIG_NAME.test(name) || /(?:Config|Settings|Options|Env)$/.test(name);
}

/** Collect names imported by a module (these are never globals). */
function importedNames(parsed: ParsedScript): Set<string> {
  const names = new Set<string>();
  for (const node of parsed.ast.body) {
    if (node.type !== 'ImportDeclaration') continue;
    for (const spec of node.specifiers) names.add(spec.local.name);
  }
  return names;
}

/**
 * Determine how a name declared at the global scope behaves.
 */
export function declarationProvenance(parsed: ParsedScript, name: string): DeclarationProvenance {
  const globalScope = parsed.scopeManager.globalScope;
  if (!globalScope) return 'none';
  for (const v of globalScope.variables) {
    if (v.name !== name) continue;
    if (v.defs.some((d) => d.type === 'ImportBinding')) return 'import';
    if (v.defs.some((d) => d.type === 'FunctionName' || d.type === 'ClassName')) return 'var';
    const kinds = v.defs
      .filter((d) => d.type === 'Variable')
      .map((d) => (d.parent as { kind?: string } | null | undefined)?.kind);
    if (kinds.includes('var')) return 'var';
    if (kinds.some((k) => k === 'let' || k === 'const')) return 'lexical';
  }
  return 'none';
}

interface Chain {
  /** Root identifier or expression text. */
  root: estree.Expression;
  /** Property names from the root outward. '*' marks a dynamic index. */
  properties: string[];
  /** The outermost MemberExpression in the chain. */
  outermost: estree.Node;
}

/**
 * Walk down `node.object` while it is a MemberExpression to find the root.
 * The outermost member expression of the chain is `node` itself (callers pass
 * the outer node); walk down to the root and collect properties root-first.
 */
function resolveChain(node: estree.MemberExpression): Chain {
  const properties: string[] = [];
  let current: estree.Expression = node;
  for (;;) {
    // Optional chaining wraps each link in a ChainExpression
    // (`a?.b?.c` → Chain(Member(Chain(Member(a,b)),c))); unwrap so the chain
    // walk sees the underlying member expressions.
    if ((current as estree.Node).type === 'ChainExpression') {
      current = (current as unknown as { expression: estree.Expression }).expression;
      continue;
    }
    if (current.type !== 'MemberExpression') break;
    if (!current.computed && current.property.type === 'Identifier') {
      properties.unshift(current.property.name);
    } else if (current.computed && current.property.type === 'Literal') {
      properties.unshift(String(current.property.value));
    } else {
      properties.unshift('*');
    }
    current = current.object as estree.Expression;
  }
  return { root: current, properties, outermost: node };
}

interface UseContext {
  usages: Set<UsageKind>;
}

/**
 * Classify how the value produced by `chainOutermost` is used, by looking at
 * its parent node.
 */
function classifyUsage(node: estree.Node, parent: estree.Node | undefined): UseContext {
  const usages = new Set<UsageKind>();
  if (!parent) {
    usages.add('property-read');
    return { usages };
  }
  switch (parent.type) {
    case 'CallExpression':
    case 'NewExpression':
      usages.add('call');
      break;
    case 'UnaryExpression':
      if (parent.operator === 'typeof' || parent.operator === 'void' || parent.operator === '!') {
        usages.add('type-test');
      } else {
        usages.add('property-read');
      }
      break;
    case 'BinaryExpression':
      if (parent.operator === '+') usages.add('string-coerce');
      else if (parent.operator === '===' || parent.operator === '==' || parent.operator === '!==') {
        usages.add('type-test');
      } else usages.add('property-read');
      break;
    case 'AssignmentExpression':
      if (parent.left === node) {
        usages.add('assignment-target');
      } else {
        // RHS: is the LHS a URL-ish property?
        const urlSink = assignmentTargetIsUrlSink(parent.left);
        usages.add(urlSink ? 'url-sink' : 'property-read');
      }
      break;
    case 'SpreadElement':
    case 'AwaitExpression':
      usages.add('iteration');
      break;
    case 'TemplateLiteral':
      usages.add('string-coerce');
      break;
    case 'IfStatement':
    case 'ConditionalExpression':
    case 'LogicalExpression':
      usages.add('type-test');
      break;
    case 'VariableDeclarator':
      // `var u = window.CONFIG.cdn` — the value is being captured; if the
      // captured name is URL-ish, flag it, otherwise a plain read.
      usages.add('property-read');
      break;
    case 'ReturnStatement':
    case 'FunctionExpression':
    case 'ArrowFunctionExpression':
    case 'Property':
      usages.add('property-read');
      break;
    case 'MemberExpression':
      // e.g. `CONFIG.cdn` where the chain resolver already flattened it; this
      // occurs when the node we recorded was an inner property. Treat as read.
      usages.add('property-read');
      break;
    default:
      usages.add('property-read');
  }
  return { usages };
}

/** A property path whose final segment is a URL-bearing attribute. */
function pathIsUrlSink(propertyPath: readonly string[]): boolean {
  if (propertyPath.length === 0) return false;
  const last = propertyPath[propertyPath.length - 1];
  return last !== undefined && URL_SINK_PROPS.has(last);
}

function assignmentTargetIsUrlSink(left: estree.Node): boolean {
  if (left.type === 'MemberExpression') {
    if (!left.computed && left.property.type === 'Identifier') {
      if (URL_SINK_PROPS.has(left.property.name)) return true;
    } else if (left.computed && left.property.type === 'Literal') {
      if (URL_SINK_PROPS.has(String(left.property.value))) return true;
    }
  }
  if (left.type === 'Identifier' && left.name === 'location') return true;
  return false;
}

/** True when a call expression consumes its first argument as a URL. */
function calleeIsUrlSink(callee: estree.Node): boolean {
  if (callee.type === 'Identifier') return URL_SINK_CALLEES.has(callee.name);
  if (callee.type === 'MemberExpression' && !callee.computed && callee.property.type === 'Identifier') {
    return URL_SINK_CALLEES.has(callee.property.name);
  }
  return false;
}

/**
 * Build a map from identifier node to whether the reference resolves to a
 * *local* (non-global) binding. Bare identifiers that resolve locally are not
 * global reads at all and must not be reported.
 */
function localBindingMap(parsed: ParsedScript): Map<estree.Node, boolean> {
  const map = new Map<estree.Node, boolean>();
  const globalScope = parsed.scopeManager.globalScope;
  const scopes = parsed.scopeManager.scopes;
  for (const scope of scopes) {
    const isGlobal = scope === globalScope;
    for (const ref of scope.references) {
      const resolved = ref.resolved;
      if (!resolved) continue; // unresolved => free global, handled as global
      // A binding whose defining scope is the global scope is still "global".
      const defScope = resolved.scope;
      const defIsGlobal = defScope === globalScope;
      if (!isGlobal || !defIsGlobal) {
        map.set(ref.identifier as unknown as estree.Node, !defIsGlobal);
      }
    }
  }
  return map;
}

/**
 * Extract every global read from one parsed script.
 */
export function extractGlobalReads(parsed: ParsedScript): GlobalRead[] {
  const imported = importedNames(parsed);
  const reads: GlobalRead[] = [];
  const isModule = parsed.source.kind === 'module';
  const local = localBindingMap(parsed);

  const push = (
    name: string,
    kind: ReadKind,
    node: estree.Node,
    parent: estree.Node | undefined,
    propertyPath: string[],
    usageNode: estree.Node = node,
  ) => {
    if (!name) return;
    if (imported.has(name)) return;
    // Environment globals (`require`, `process`, `Buffer`, `setTimeout`, ...)
    // cannot be supplied by an element id/name in a meaningful way; they are
    // not application-controlled config.
    if (isEnvironmentGlobal(name)) return;
    const loc = node.loc?.start;
    const position = { line: loc?.line ?? 0, column: loc?.column ?? 0 };
    // Classify the *outermost* expression of the chain, so `CONFIG.cdn` in
    // `s.src = CONFIG.cdn` is seen as feeding a URL sink rather than as an
    // inner member access.
    const { usages } = classifyUsage(usageNode, parent);
    // A call whose callee consumes a URL argument makes this read a url-sink.
    if (parent && parent.type === 'CallExpression' && calleeIsUrlSink(parent.callee)) {
      usages.add('url-sink');
    }
    const declaration = declarationFor(kind, name, parsed, imported);
    // A path whose final segment is a URL-bearing attribute (`CONFIG.cdn.src`,
    // `CONFIG.scriptURL`) is a URL sink regardless of the surrounding parent.
    if (pathIsUrlSink(propertyPath)) usages.add('url-sink');
    reads.push({
      name,
      scope: KIND_SCOPE[kind],
      kind,
      declaration,
      usages: [...usages],
      propertyPath,
      position,
      original: parsed.originalPosition(position),
      scriptId: parsed.source.id,
      looksLikeConfig: looksLikeConfigName(name),
    });
  };

  walk.ancestor(parsed.ast, {
    MemberExpression(node: estree.MemberExpression, ancestors: estree.Node[]) {
      // Only process the outermost member expression of a chain.
      const parent = ancestors[ancestors.length - 2];
      if (parent && parent.type === 'MemberExpression' && parent.object === node) return;

      const chain = resolveChain(node);
      const root = chain.root;
      const props = chain.properties;
      if (props.length === 0) return;

      // A root identifier that resolves to a local binding is not the global
      // object, however it is named. This matters for CommonJS/Node code where
      // `self`, `window`, `globalThis` or `document` are frequently locals
      // (`var self = this;`), and treating them as globals would invent reads.
      if (root.type === 'Identifier' && local.get(root as unknown as estree.Node) === true) {
        return;
      }

      // For window/document/this roots the *first* property is the clobbered
      // name and the rest is the nested path (`window.CONFIG.cdn` → name
      // CONFIG, path [cdn]). For an identifier root the identifier itself is
      // the name and every property is the path (`CONFIG.cdn.x` → name CONFIG,
      // path [cdn, x]).
      if (root.type === 'Identifier' && isWindowRoot(root.name)) {
        // Writing `window.X = ...` is not a read of a clobberable value.
        if (parent && parent.type === 'AssignmentExpression' && parent.left === node) return;
        if (parent && parent.type === 'UpdateExpression') return;
        const head = props[0]!;
        if (head === '*') return;
        const kind: ReadKind = root.name === 'self' ? 'self-property'
          : root.name === 'globalThis' ? 'globalThis-property'
          : node.computed ? 'window-computed' : 'window-property';
        push(head, kind, node, parent, props.slice(1), node);
        return;
      }
      if (root.type === 'Identifier' && isDocumentRoot(root.name)) {
        if (parent && parent.type === 'AssignmentExpression' && parent.left === node) return;
        if (parent && parent.type === 'UpdateExpression') return;
        const head = props[0]!;
        if (head === '*') return;
        push(head, node.computed ? 'document-computed' : 'document-property', node, parent, props.slice(1), node);
        return;
      }
      if (root.type === 'ThisExpression' && !isModule) {
        // `this` is the global object only at the top level of a classic
        // script. Inside any function `this` is call-site dependent, so a
        // `this.X` read there says nothing about globals.
        if (!isTopLevelThis(ancestors)) return;
        const head = props[0]!;
        if (head === '*') return;
        push(head, 'this-property', node, parent, props.slice(1), node);
        return;
      }
      // Identifier-rooted chain (`CONFIG.cdn`, `jQuery.ajax`): the root is a
      // bare global read, and every property beneath it is the captured path.
      // A root that resolves to a local binding is not a global read.
      if (root.type === 'Identifier') {
        if (local.get(root as unknown as estree.Node) === true) return;
        // `window.X = val` is a write; not a clobberable read.
        if (parent && parent.type === 'AssignmentExpression' && parent.left === node) return;
        push(root.name, 'bare-identifier', root, parent, props, node);
      }
    },

    Identifier(node: estree.Identifier, ancestors: estree.Node[]) {
      const parent = ancestors[ancestors.length - 2];
      if (!parent) return;
      if (isNonReferenceIdentifier(node, parent)) return;
      // The root of any member chain is handled by the MemberExpression
      // visitor (which records the captured property path). Only record
      // identifiers used as plain values.
      if (parent.type === 'MemberExpression' && parent.object === node) return;
      // Skip window/document aliases used as values (`x = window`).
      if (isWindowRoot(node.name) || isDocumentRoot(node.name)) return;
      if (imported.has(node.name)) return;
      // Skip references that resolve to a local (function/block) binding.
      if (local.get(node as unknown as estree.Node) === true) return;
      // A write (`window.X = ...`, `X = ...`, `X++`) is not a read of a
      // clobberable value: the attacker's element would be overwritten.
      if (isWriteOnlyReference(node, parent)) return;
      push(node.name, 'bare-identifier', node, parent, []);
    },

    VariableDeclarator(node: estree.VariableDeclarator) {
      if (node.id.type !== 'ObjectPattern' || !node.init) return;
      const init = node.init;
      let rootKind: 'window' | 'document' | null = null;
      if (init.type === 'Identifier' && isWindowRoot(init.name)) rootKind = 'window';
      else if (init.type === 'Identifier' && isDocumentRoot(init.name)) rootKind = 'document';
      if (!rootKind) return;
      for (const p of node.id.properties) {
        if (p.type !== 'Property' || p.computed) continue;
        let key: string | null = null;
        if (p.key.type === 'Identifier') key = p.key.name;
        else if (p.key.type === 'Literal') key = p.key.value != null ? String(p.key.value) : null;
        if (!key) continue;
        push(
          key,
          rootKind === 'window' ? 'destructured-window' : 'destructured-document',
          p,
          undefined,
          [],
        );
      }
    },
  } as never);

  return mergeReads(reads);
}

function declarationFor(
  kind: ReadKind,
  name: string,
  parsed: ParsedScript,
  imported: Set<string>,
): DeclarationProvenance {
  if (imported.has(name)) return 'import';
  // Report the declaration truthfully for every access shape. `declarationOf`
  // (protection.ts) then interprets it per shape: `none` means a free global
  // for bare reads, and also means "no window property" for window reads.
  void kind;
  return declarationProvenance(parsed, name);
}

/**
 * True when a node sits at the top level of the program (no enclosing function,
 * method, or class field initialiser). `this` only refers to the global object
 * there.
 */
function isTopLevelThis(ancestors: estree.Node[]): boolean {
  for (const n of ancestors) {
    switch (n.type) {
      case 'FunctionDeclaration':
      case 'FunctionExpression':
      case 'ArrowFunctionExpression':
      case 'PropertyDefinition':
      case 'MethodDefinition':
      case 'StaticBlock':
        return false;
      default:
        break;
    }
  }
  return true;
}

/** True when this identifier is only written (assignment target or update). */
function isWriteOnlyReference(node: estree.Identifier, parent: estree.Node): boolean {
  if (parent.type === 'AssignmentExpression' && parent.left === node) return true;
  if (parent.type === 'UpdateExpression') return true;
  return false;
}

function isNonReferenceIdentifier(node: estree.Identifier, parent: estree.Node): boolean {
  switch (parent.type) {
    case 'MemberExpression':
      return parent.property === node && !parent.computed;
    case 'Property':
      return parent.key === node && !parent.computed && !parent.shorthand;
    case 'PropertyDefinition':
      return parent.key === node && !parent.computed;
    case 'MethodDefinition':
      return parent.key === node && !parent.computed;
    case 'LabeledStatement':
    case 'BreakStatement':
    case 'ContinueStatement':
      return true;
    case 'ImportSpecifier':
    case 'ImportDefaultSpecifier':
    case 'ImportNamespaceSpecifier':
    case 'ExportSpecifier':
      return true;
    case 'ExportAllDeclaration':
      return parent.exported === node;
    case 'ExportNamedDeclaration':
      return parent.source != null; // re-export names are not local reads
    case 'VariableDeclarator':
      return parent.id === node;
    case 'FunctionDeclaration':
    case 'FunctionExpression':
      return parent.id === node || (parent.params as estree.Node[]).includes(node);
    case 'ArrowFunctionExpression':
      return (parent.params as estree.Node[]).includes(node);
    case 'ClassDeclaration':
    case 'ClassExpression':
      return parent.id === node;
    case 'CatchClause':
      return parent.param === node;
    default:
      return false;
  }
}

/**
 * Merge duplicate observations of the same name+kind so the report shows one
 * entry with every usage and the deepest property path observed.
 */
function mergeReads(reads: GlobalRead[]): GlobalRead[] {
  const key = (r: GlobalRead) => `${r.scriptId}\u0000${r.kind}\u0000${r.name}`;
  const byKey = new Map<string, GlobalRead>();
  for (const r of reads) {
    const k = key(r);
    const prev = byKey.get(k);
    if (!prev) {
      byKey.set(k, { ...r, usages: [...r.usages], propertyPath: [...r.propertyPath] });
      continue;
    }
    const usages = new Set([...prev.usages, ...r.usages]);
    const propertyPath =
      r.propertyPath.length > prev.propertyPath.length ? r.propertyPath : prev.propertyPath;
    byKey.set(k, { ...prev, usages: [...usages], propertyPath });
  }
  return [...byKey.values()];
}
