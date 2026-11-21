/**
 * Lightweight taint propagation.
 *
 * Real (and bundled) code almost never uses a clobberable global directly in a
 * dangerous position:
 *
 *     var c = window.CONFIG || {};
 *     var u = c.cdn;
 *     s.src = u;
 *
 * The read that matters (`window.CONFIG`) is three assignments away from the
 * sink. This pass connects them: it propagates "derived from a clobberable
 * global" through local variables (assignments, declarations, simple aliases,
 * member reads, and destructuring), then marks the originating reads whose
 * taint reaches a URL/call sink.
 *
 * The pass is intra-procedural and flow-insensitive. That over-approximates
 * (a variable assigned in one branch taints readers in another), which is the
 * safe direction for a detector: it can report a *possible* flow that a human
 * then confirms. It never invents a flow that does not exist in the AST.
 */

import * as walk from 'acorn-walk';
import type * as estree from 'estree';
import type { GlobalRead, UsageKind } from './globals.ts';
import { DOCUMENT_ALIASES, WINDOW_ALIASES } from './globals.ts';
import type { ParsedScript } from './parse.ts';

/** A reference to a clobberable global: window-scoped name or document member. */
interface GlobalRef {
  name: string;
  scope: 'window' | 'document';
}

/** Unique key for a (scope, name) pair. */
function refKey(r: GlobalRef): string {
  return `${r.scope}\u0000${r.name}`;
}

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
const URL_SINK_CALLEES = new Set([
  'fetch',
  'importScripts',
  'open',
  'assign',
  'replace',
  'navigate',
]);

/**
 * Extract every clobberable global referenced inside an expression, following
 * known local aliases as it goes. This is the taint source set for a value.
 */
function collectRefs(
  node: estree.Node | null | undefined,
  aliases: ReadonlyMap<string, Set<string>>,
  out: Set<string>,
  seenAliases: Set<string> = new Set(),
): void {
  if (!node) return;
  if (node.type === 'MemberExpression') {
    const root = rootOfMember(node);
    if (root) {
      if (root.type === 'Identifier' && WINDOW_ALIASES.has(root.name)) {
        const prop = staticPropertyName(node);
        if (prop) out.add(refKey({ name: prop, scope: 'window' }));
      } else if (root.type === 'Identifier' && DOCUMENT_ALIASES.has(root.name)) {
        const prop = staticPropertyName(node);
        if (prop) out.add(refKey({ name: prop, scope: 'document' }));
      } else if (root.type === 'Identifier') {
        const alias = aliases.get(root.name);
        if (alias && !seenAliases.has(root.name)) {
          seenAliases.add(root.name);
          for (const k of alias) out.add(k);
        }
      } else if (root.type === 'ThisExpression') {
        // this.CONFIG at top level is a global read; include it conservatively.
        const prop = staticPropertyName(node);
        if (prop) out.add(refKey({ name: prop, scope: 'window' }));
      }
    }
  } else if (node.type === 'Identifier') {
    const alias = aliases.get(node.name);
    if (alias && !seenAliases.has(node.name)) {
      seenAliases.add(node.name);
      for (const k of alias) out.add(k);
    }
  }
  // Recurse into children (generic visitor).
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'range' || key === 'start' || key === 'end' || key === 'type') continue;
    const child = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(child)) {
      for (const c of child) if (isNode(c)) collectRefs(c, aliases, out, seenAliases);
    } else if (isNode(child)) {
      collectRefs(child, aliases, out, seenAliases);
    }
  }
}

function isNode(v: unknown): v is estree.Node {
  return typeof v === 'object' && v !== null && typeof (v as { type?: unknown }).type === 'string';
}

function rootOfMember(node: estree.MemberExpression): estree.Node {
  let cur: estree.Node = node;
  while (cur.type === 'MemberExpression') cur = cur.object;
  return cur;
}

function staticPropertyName(node: estree.MemberExpression): string | null {
  if (!node.computed && node.property.type === 'Identifier') return node.property.name;
  if (node.computed && node.property.type === 'Literal' && node.property.value != null) {
    return String(node.property.value);
  }
  return null;
}

/** All names declared anywhere in the script (any scope). */
function collectDeclaredNames(parsed: ParsedScript): Set<string> {
  const names = new Set<string>();
  for (const scope of parsed.scopeManager.scopes) {
    for (const v of scope.variables) names.add(v.name);
  }
  return names;
}

/** Is this member-expression access reading a URL-bearing property? */
function memberIsUrlProperty(node: estree.MemberExpression): boolean {
  const prop = staticPropertyName(node);
  if (prop == null) return false;
  if (URL_SINK_PROPS.has(prop)) return true;
  // `window.location` / `document.location` assignment navigates.
  if (prop === 'location') {
    const root = rootOfMember(node);
    if (root.type === 'Identifier') return WINDOW_ALIASES.has(root.name) || DOCUMENT_ALIASES.has(root.name);
  }
  return false;
}

export interface TaintResult {
  /** Extra usages to merge into each read, keyed by scope+name. */
  usagesByRef: Map<string, Set<UsageKind>>;
  /** Number of alias iterations performed (diagnostics). */
  iterations: number;
}

/**
 * Run the taint pass over one parsed script.
 */
export function propagateTaint(parsed: ParsedScript): TaintResult {
  // aliases: local name -> set of global ref keys it derives from.
  const aliases = new Map<string, Set<string>>();

  // Seed aliases from declarations/assignments, iterating to a fixpoint so
  // alias chains resolve (b === a; c === b).
  // Free identifiers that are not declared anywhere in this script behave as
  // globals. Seed them as their own taint source so a chain like
  // `(jQuery && jQuery.cdn) + '.js'` credits window.jQuery.
  const declared = collectDeclaredNames(parsed);
  const freeGlobals = new Set<string>();

  const seeders: Array<{ local: string; node: estree.Node | null }> = [];
  walk.simple(parsed.ast, {
    VariableDeclarator(node: estree.VariableDeclarator) {
      if (node.id.type === "Identifier") seeders.push({ local: node.id.name, node: node.init ?? null });
    },
    AssignmentExpression(node: estree.AssignmentExpression) {
      if (node.left.type === "Identifier") seeders.push({ local: node.left.name, node: node.right ?? null });
    },
    // Destructuring from a member of the global object: const { cdn } = window.CONFIG
    ObjectPattern() {
      /* handled below via VariableDeclarator */
    },
  } as never);

  // Destructuring seeds: `const { cdn } = window.CONFIG` taints local cdn, and
  // so does `const { CONFIG } = window` (the whole point of that pattern).
  walk.simple(parsed.ast, {
    VariableDeclarator(node: estree.VariableDeclarator) {
      if (node.id.type !== 'ObjectPattern' || !node.init) return;
      // Case 1: source is `window`/`document` itself — each bound name names a
      // property to read from that object.
      if (node.init.type === 'Identifier') {
        const initName = node.init.name;
        const scope: 'window' | 'document' | null = WINDOW_ALIASES.has(initName)
          ? 'window'
          : DOCUMENT_ALIASES.has(initName)
            ? 'document'
            : null;
        if (scope) {
          for (const p of node.id.properties) {
            if (p.type !== 'Property') continue;
            let key: string | null = null;
            if (!p.computed && p.key.type === 'Identifier') key = p.key.name;
            else if (!p.computed && p.key.type === 'Literal' && p.key.value != null) key = String(p.key.value);
            if (!key) continue;
            const local = p.value.type === 'Identifier' ? p.value.name : null;
            if (!local) continue;
            const set = aliases.get(local) ?? new Set<string>();
            set.add(refKey({ name: key, scope }));
            aliases.set(local, set);
          }
          return;
        }
      }
      // Case 2: source is an expression that already carries taint.
      const src = new Set<string>();
      collectRefs(node.init, aliases, src);
      if (src.size === 0) return;
      for (const p of node.id.properties) {
        if (p.type !== 'Property') continue;
        let local: string | null = null;
        if (p.value.type === 'Identifier') local = p.value.name;
        if (local) {
          const set = aliases.get(local) ?? new Set<string>();
          for (const k of src) set.add(k);
          aliases.set(local, set);
        }
      }
    },
  } as never);

  // Seed free globals: every identifier reference not declared locally and not
  // a known builtin alias is a window property an element could supply.
  walk.simple(parsed.ast, {
    Identifier(node: estree.Identifier) {
      if (declared.has(node.name)) return;
      if (WINDOW_ALIASES.has(node.name) || DOCUMENT_ALIASES.has(node.name)) return;
      freeGlobals.add(node.name);
    },
  } as never);
  for (const g of freeGlobals) {
    const set = aliases.get(g) ?? new Set<string>();
    set.add(refKey({ name: g, scope: 'window' }));
    aliases.set(g, set);
  }

  let iterations = 0;
  for (let changed = true; changed && iterations < 12; ) {
    changed = false;
    iterations++;
    for (const { local, node } of seeders) {
      const refs = new Set<string>();
      collectRefs(node, aliases, refs);
      if (refs.size === 0) continue;
      const cur = aliases.get(local) ?? new Set<string>();
      const before = cur.size;
      for (const r of refs) cur.add(r);
      if (cur.size !== before) {
        aliases.set(local, cur);
        changed = true;
      }
    }
  }

  const usagesByRef = new Map<string, Set<UsageKind>>();
  const addUsage = (key: string, u: UsageKind) => {
    const s = usagesByRef.get(key) ?? new Set<UsageKind>();
    s.add(u);
    usagesByRef.set(key, s);
  };

  // Find sink sites and credit every tainted ref that reaches them.
  walk.simple(parsed.ast, {
    AssignmentExpression(node: estree.AssignmentExpression) {
      // Assigning to `location` / `location.href` navigates, which is a URL
      // sink just as much as assigning to a script's src.
      const isNavigation =
        (node.left.type === 'Identifier' && node.left.name === 'location') ||
        (node.left.type === 'MemberExpression' && memberIsUrlProperty(node.left));
      if (!isNavigation) return;
      const refs = new Set<string>();
      collectRefs(node.right, aliases, refs);
      for (const r of refs) addUsage(r, 'url-sink');
    },
    CallExpression(node: estree.CallExpression) {
      const callee = node.callee;
      let isSink = false;
      if (callee.type === 'Identifier' && URL_SINK_CALLEES.has(callee.name)) isSink = true;
      if (
        callee.type === 'MemberExpression' &&
        !callee.computed &&
        callee.property.type === 'Identifier' &&
        URL_SINK_CALLEES.has(callee.property.name)
      ) {
        isSink = true;
      }
      if (!isSink) return;
      for (const arg of node.arguments) {
        if (arg.type === 'SpreadElement') {
          const refs = new Set<string>();
          collectRefs(arg.argument, aliases, refs);
          for (const r of refs) addUsage(r, 'url-sink');
          continue;
        }
        const refs = new Set<string>();
        collectRefs(arg, aliases, refs);
        for (const r of refs) addUsage(r, 'url-sink');
      }
    },
    // String coercion of a tainted value is itself a signal.
    TemplateLiteral(node: estree.TemplateLiteral) {
      for (const expr of node.expressions) {
        const refs = new Set<string>();
        collectRefs(expr, aliases, refs);
        for (const r of refs) addUsage(r, 'string-coerce');
      }
    },
  } as never);

  return { usagesByRef, iterations };
}

/**
 * Merge taint-derived usages into extracted reads. A read gains a usage when
 * any script's taint analysis attributed that usage to its (scope, name).
 */
export function applyTaint(
  reads: readonly GlobalRead[],
  taintByScript: ReadonlyMap<string, TaintResult>,
): GlobalRead[] {
  return reads.map((read) => {
    const taint = taintByScript.get(read.scriptId);
    if (!taint) return read;
    const scope = read.scope;
    const key = refKey({ name: read.name, scope });
    const extra = taint.usagesByRef.get(key);
    if (!extra || extra.size === 0) return read;
    const usages = new Set<UsageKind>(read.usages);
    for (const u of extra) usages.add(u);
    return { ...read, usages: [...usages] };
  });
}
